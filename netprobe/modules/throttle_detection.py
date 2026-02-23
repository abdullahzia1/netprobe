"""
Throttling / Traffic-Shaping Detection Module

Measures download throughput across different conditions and flags statistical
anomalies that suggest an ISP is selectively throttling certain traffic:

- HTTP vs HTTPS (same payload size)
- Small vs large transfers
- Multiple sequential samples to compute mean / stddev
"""

from __future__ import annotations

import io
import statistics
import time
from dataclasses import dataclass, field
from typing import Optional

import requests

HTTP_TIMEOUT = 30
SAMPLE_ROUNDS = 3

# Public test files hosted by well-known CDNs.
# We test two size classes: ~1 KB ("small") and ~1 MB ("large").
TEST_TARGETS = {
    "small_https": "https://www.google.com/robots.txt",
    "small_http":  "http://www.google.com/robots.txt",
    "large_https": "https://speed.cloudflare.com/__down?bytes=1048576",
    "large_http":  "http://speed.cloudflare.com/__down?bytes=1048576",
}

UPLOAD_URL = "https://httpbin.org/post"
UPLOAD_SIZES = {"small": 1024, "large": 256 * 1024}


@dataclass
class SpeedSample:
    label: str
    url: str
    bytes_transferred: int
    duration_s: float
    speed_kbps: float
    timestamp: str = ""


@dataclass
class ThrottleIndicator:
    comparison: str
    suspicious: bool
    details: str
    ratio: Optional[float] = None


@dataclass
class ThrottleReport:
    download_samples: list[SpeedSample] = field(default_factory=list)
    upload_samples: list[SpeedSample] = field(default_factory=list)
    indicators: list[ThrottleIndicator] = field(default_factory=list)
    summary: str = ""


def _ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _download_sample(label: str, url: str) -> SpeedSample:
    start = time.monotonic()
    try:
        resp = requests.get(url, timeout=HTTP_TIMEOUT, stream=True,
                            headers={"User-Agent": "NetProbe/1.0"})
        total = 0
        for chunk in resp.iter_content(chunk_size=8192):
            total += len(chunk)
        elapsed = time.monotonic() - start
        speed = (total * 8) / max(elapsed, 0.001) / 1000  # kbps
        return SpeedSample(label=label, url=url,
                           bytes_transferred=total,
                           duration_s=round(elapsed, 3),
                           speed_kbps=round(speed, 2),
                           timestamp=_ts())
    except Exception as exc:
        elapsed = time.monotonic() - start
        return SpeedSample(label=label, url=url, bytes_transferred=0,
                           duration_s=round(elapsed, 3), speed_kbps=0.0,
                           timestamp=_ts())


def _upload_sample(label: str, url: str, size: int) -> SpeedSample:
    payload = b"\x00" * size
    start = time.monotonic()
    try:
        resp = requests.post(url, data=payload, timeout=HTTP_TIMEOUT,
                             headers={"User-Agent": "NetProbe/1.0",
                                      "Content-Type": "application/octet-stream"})
        elapsed = time.monotonic() - start
        speed = (size * 8) / max(elapsed, 0.001) / 1000
        return SpeedSample(label=label, url=url, bytes_transferred=size,
                           duration_s=round(elapsed, 3),
                           speed_kbps=round(speed, 2),
                           timestamp=_ts())
    except Exception as exc:
        elapsed = time.monotonic() - start
        return SpeedSample(label=label, url=url, bytes_transferred=0,
                           duration_s=round(elapsed, 3), speed_kbps=0.0,
                           timestamp=_ts())


def _avg(samples: list[SpeedSample]) -> float:
    speeds = [s.speed_kbps for s in samples if s.speed_kbps > 0]
    return statistics.mean(speeds) if speeds else 0.0


def _stddev(samples: list[SpeedSample]) -> float:
    speeds = [s.speed_kbps for s in samples if s.speed_kbps > 0]
    return statistics.stdev(speeds) if len(speeds) >= 2 else 0.0


def _compare(label_a: str, avg_a: float,
             label_b: str, avg_b: float,
             threshold: float = 0.40) -> ThrottleIndicator:
    """Flag if the slower channel is < (1 - threshold) of the faster one."""
    if avg_a == 0 and avg_b == 0:
        return ThrottleIndicator(
            comparison=f"{label_a} vs {label_b}",
            suspicious=False,
            details="Both measurements returned zero; cannot compare.",
        )
    faster = max(avg_a, avg_b)
    slower = min(avg_a, avg_b)
    ratio = slower / faster if faster else 0
    suspicious = ratio < (1 - threshold)

    faster_label = label_a if avg_a >= avg_b else label_b
    slower_label = label_b if avg_a >= avg_b else label_a

    details = (
        f"{faster_label} avg={max(avg_a, avg_b):.1f} kbps, "
        f"{slower_label} avg={min(avg_a, avg_b):.1f} kbps, "
        f"ratio={ratio:.2f}"
    )
    if suspicious:
        details += (
            f" — {slower_label} is >{threshold*100:.0f}% slower, "
            f"suggesting selective throttling."
        )

    return ThrottleIndicator(
        comparison=f"{label_a} vs {label_b}",
        suspicious=suspicious,
        details=details,
        ratio=round(ratio, 3),
    )


def _check_jitter(samples: list[SpeedSample], label: str) -> ThrottleIndicator:
    """High jitter (coefficient of variation > 0.5) can indicate shaping."""
    speeds = [s.speed_kbps for s in samples if s.speed_kbps > 0]
    if len(speeds) < 2:
        return ThrottleIndicator(
            comparison=f"{label} jitter",
            suspicious=False,
            details="Not enough samples to compute jitter.",
        )
    mean = statistics.mean(speeds)
    sd = statistics.stdev(speeds)
    cv = sd / mean if mean else 0

    suspicious = cv > 0.50
    details = (
        f"mean={mean:.1f} kbps, stddev={sd:.1f}, CV={cv:.2f}"
    )
    if suspicious:
        details += " — high variance may indicate traffic shaping bursts."

    return ThrottleIndicator(
        comparison=f"{label} jitter",
        suspicious=suspicious,
        details=details,
        ratio=round(cv, 3),
    )


def run(rounds: int = SAMPLE_ROUNDS,
        progress_callback=None) -> ThrottleReport:
    """
    Perform download and upload speed measurements, then compare across
    protocols and payload sizes to detect selective throttling.
    """
    report = ThrottleReport()

    buckets: dict[str, list[SpeedSample]] = {k: [] for k in TEST_TARGETS}

    for r in range(1, rounds + 1):
        for label, url in TEST_TARGETS.items():
            if progress_callback:
                progress_callback(
                    f"[Throttle] Download round {r}/{rounds}: {label}")
            sample = _download_sample(label, url)
            report.download_samples.append(sample)
            buckets[label].append(sample)

    upload_buckets: dict[str, list[SpeedSample]] = {}
    for size_label, size in UPLOAD_SIZES.items():
        upload_buckets[size_label] = []
        for r in range(1, rounds + 1):
            if progress_callback:
                progress_callback(
                    f"[Throttle] Upload round {r}/{rounds}: {size_label}")
            sample = _upload_sample(f"upload_{size_label}", UPLOAD_URL, size)
            report.upload_samples.append(sample)
            upload_buckets[size_label].append(sample)

    # --- Comparisons ---
    avg_small_https = _avg(buckets["small_https"])
    avg_small_http = _avg(buckets["small_http"])
    avg_large_https = _avg(buckets["large_https"])
    avg_large_http = _avg(buckets["large_http"])

    report.indicators.append(
        _compare("small_http", avg_small_http,
                 "small_https", avg_small_https))
    report.indicators.append(
        _compare("large_http", avg_large_http,
                 "large_https", avg_large_https))
    report.indicators.append(
        _compare("large_https", avg_large_https,
                 "small_https", avg_small_https, threshold=0.60))

    for label, samples in buckets.items():
        report.indicators.append(_check_jitter(samples, label))

    if upload_buckets:
        avg_up_small = _avg(upload_buckets.get("small", []))
        avg_up_large = _avg(upload_buckets.get("large", []))
        if avg_up_small and avg_up_large:
            report.indicators.append(
                _compare("upload_small", avg_up_small,
                         "upload_large", avg_up_large, threshold=0.50))

    suspicious_count = sum(1 for i in report.indicators if i.suspicious)
    if suspicious_count == 0:
        report.summary = "No throttling anomalies detected."
    else:
        report.summary = (
            f"{suspicious_count} anomaly(ies) detected — "
            f"selective throttling may be occurring."
        )

    return report
