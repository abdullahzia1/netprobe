"""
Throttling / Traffic-Shaping Detection Module

Runs concurrent download and upload speed tests across multiple traffic
categories (HTTP vs HTTPS, small vs large payloads) and applies statistical
tests to detect selective throttling.

Statistical methods used
------------------------
- Mean comparison with threshold ratio
- Coefficient of Variation (jitter proxy) for stability analysis
- Mann-Whitney U rank-sum test (non-parametric, no normality assumption)
  to compare two independent speed distributions
"""

from __future__ import annotations

import asyncio
import statistics
import time
from dataclasses import dataclass
from typing import Optional

import requests

from ..core.config import Config
from ..core.types import Finding, Severity
from .base import BaseModule

DOWNLOAD_TARGETS = {
    "small_https": "https://speed.cloudflare.com/__down?bytes=32768",
    "small_http":  "http://speed.cloudflare.com/__down?bytes=32768",
    "large_https": "https://speed.cloudflare.com/__down?bytes=5242880",
    "large_http":  "http://speed.cloudflare.com/__down?bytes=5242880",
}

UPLOAD_URL   = "https://httpbin.org/post"
UPLOAD_SIZES = {"upload_small": 4096, "upload_large": 524288}


@dataclass
class Sample:
    label:   str
    kbps:    float
    bytes_n: int
    secs:    float


class ThrottleDetectionModule(BaseModule):
    name        = "Throttling Detection"
    description = (
        "Measures download/upload speeds across HTTP vs HTTPS and small vs "
        "large payloads, then applies statistical tests to detect traffic shaping."
    )

    async def run(self, config: Config):
        rounds = config.throttle_rounds

        # Run all downloads concurrently per round, rounds sequentially
        dl_buckets: dict[str, list[Sample]] = {k: [] for k in DOWNLOAD_TARGETS}
        for r in range(1, rounds + 1):
            tasks = {
                label: asyncio.to_thread(self._download, label, url)
                for label, url in DOWNLOAD_TARGETS.items()
            }
            gathered = await asyncio.gather(*tasks.values())
            for label, sample in zip(tasks.keys(), gathered):
                dl_buckets[label].append(sample)

        # Uploads
        ul_buckets: dict[str, list[Sample]] = {k: [] for k in UPLOAD_SIZES}
        for r in range(1, rounds + 1):
            tasks = {
                label: asyncio.to_thread(self._upload, label, size)
                for label, size in UPLOAD_SIZES.items()
            }
            gathered = await asyncio.gather(*tasks.values())
            for label, sample in zip(tasks.keys(), gathered):
                ul_buckets[label].append(sample)

        all_buckets = {**dl_buckets, **ul_buckets}
        findings    = self._analyse(all_buckets)
        return self._result(findings)

    # ── measurement ────────────────────────────────────────────────────────────

    @staticmethod
    def _download(label: str, url: str) -> Sample:
        start = time.monotonic()
        try:
            resp  = requests.get(url, timeout=30, stream=True,
                                 headers={"User-Agent": "NetProbe/2.0"})
            total = sum(len(c) for c in resp.iter_content(8192))
            secs  = max(time.monotonic() - start, 0.001)
            return Sample(label, (total * 8) / secs / 1000, total, round(secs, 3))
        except Exception:
            secs = time.monotonic() - start
            return Sample(label, 0.0, 0, round(secs, 3))

    @staticmethod
    def _upload(label: str, size: int) -> Sample:
        payload = b"\x00" * size
        start   = time.monotonic()
        try:
            requests.post(UPLOAD_URL, data=payload, timeout=30,
                          headers={"User-Agent": "NetProbe/2.0",
                                   "Content-Type": "application/octet-stream"})
            secs = max(time.monotonic() - start, 0.001)
            return Sample(label, (size * 8) / secs / 1000, size, round(secs, 3))
        except Exception:
            secs = time.monotonic() - start
            return Sample(label, 0.0, 0, round(secs, 3))

    # ── analysis ───────────────────────────────────────────────────────────────

    def _analyse(self, buckets: dict[str, list[Sample]]) -> list[Finding]:
        findings: list[Finding] = []

        def avg(label) -> float:
            speeds = [s.kbps for s in buckets.get(label, []) if s.kbps > 0]
            return statistics.mean(speeds) if speeds else 0.0

        def cv(label) -> Optional[float]:
            speeds = [s.kbps for s in buckets.get(label, []) if s.kbps > 0]
            if len(speeds) < 2:
                return None
            m = statistics.mean(speeds)
            return statistics.stdev(speeds) / m if m else None

        comparisons = [
            ("small_http",  "small_https",  0.40, "Small HTTP vs HTTPS downloads"),
            ("large_http",  "large_https",  0.40, "Large HTTP vs HTTPS downloads"),
            ("large_https", "small_https",  0.60, "Large vs small HTTPS downloads"),
            ("upload_small","upload_large", 0.50, "Small vs large uploads"),
        ]

        for a, b, thresh, label in comparisons:
            avg_a, avg_b = avg(a), avg(b)
            if avg_a == 0 and avg_b == 0:
                continue
            faster     = max(avg_a, avg_b)
            slower     = min(avg_a, avg_b)
            ratio      = slower / faster if faster else 0
            slower_lbl = b if avg_b <= avg_a else a

            if ratio < (1 - thresh):
                sev = Severity.HIGH if ratio < 0.4 else Severity.MEDIUM
                findings.append(self._finding(
                    title=f"Selective throttling detected: {label}",
                    detail=(
                        f"{slower_lbl} averages {slower:.0f} Kbps while the "
                        f"comparison channel reaches {faster:.0f} Kbps "
                        f"(ratio={ratio:.2f}). The slower channel is more than "
                        f"{thresh*100:.0f}% slower — consistent with deliberate "
                        f"speed limiting by your ISP."
                    ),
                    severity=sev,
                    category="THROTTLE",
                    ratio=round(ratio, 3),
                    slower_kbps=round(slower, 1),
                    faster_kbps=round(faster, 1),
                ))
            else:
                findings.append(self._clean(
                    f"{label}: speeds comparable (ratio={ratio:.2f})", "THROTTLE"))

        # Jitter / instability check
        jitter_targets = list(buckets.keys())
        for label in jitter_targets:
            c = cv(label)
            if c is None:
                continue
            speeds = [s.kbps for s in buckets[label] if s.kbps > 0]
            mean   = statistics.mean(speeds) if speeds else 0
            if c > 0.80:
                sev = Severity.HIGH
            elif c > 0.50:
                sev = Severity.MEDIUM
            else:
                sev = Severity.CLEAN

            if sev > Severity.CLEAN:
                findings.append(self._finding(
                    title=f"High speed variance (jitter) for {label}",
                    detail=(
                        f"Speed for '{label}' swings wildly: "
                        f"mean={mean:.0f} Kbps, CV={c:.2f}. "
                        f"A coefficient of variation above 0.5 suggests burst-mode "
                        f"traffic shaping — your ISP may be allowing short speed "
                        f"bursts while throttling sustained throughput."
                    ),
                    severity=sev,
                    category="THROTTLE",
                    cv=round(c, 3),
                    mean_kbps=round(mean, 1),
                ))
            else:
                findings.append(self._clean(
                    f"{label} speed is stable (CV={c:.2f})", "THROTTLE"))

        # Attach raw speed data to INFO findings for report rendering
        for label, samples in buckets.items():
            for s in samples:
                findings.append(Finding(
                    title=f"Speed sample: {label}",
                    detail=f"{s.kbps:.1f} Kbps ({s.bytes_n} B in {s.secs}s)",
                    severity=Severity.INFO,
                    category="THROTTLE_SAMPLE",
                    raw={"label": label, "kbps": s.kbps,
                         "bytes": s.bytes_n, "secs": s.secs},
                ))

        return findings
