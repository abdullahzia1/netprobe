"""
Reporting Module

Consolidates results from the DNS, proxy, and throttling modules into a
human-readable terminal report and an optional JSON file.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from .dns_censorship import DomainReport
from .proxy_detection import ProxyReport
from .throttle_detection import ThrottleReport

SEPARATOR = "=" * 72
THIN_SEP = "-" * 72


def _section(title: str) -> str:
    return f"\n{SEPARATOR}\n  {title}\n{SEPARATOR}"


def _flag(suspicious: bool) -> str:
    return "[!]" if suspicious else "[OK]"


def format_dns(reports: list[DomainReport]) -> str:
    lines = [_section("DNS CENSORSHIP DETECTION")]
    flagged = [r for r in reports if r.mismatch]

    lines.append(f"\n  Domains tested  : {len(reports)}")
    lines.append(f"  Mismatches found: {len(flagged)}")

    for r in reports:
        marker = _flag(r.mismatch)
        lines.append(f"\n  {marker} {r.domain}")

        if r.local_result:
            ips = ", ".join(r.local_result.ips) or r.local_result.error or "—"
            lines.append(f"      Local/ISP        : {ips}  ({r.local_result.timestamp})")
        for pr in r.public_results:
            ips = ", ".join(pr.ips) or pr.error or "—"
            lines.append(f"      {pr.resolver_name:<16}: {ips}  ({pr.timestamp})")

        if r.mismatch:
            lines.append(f"      !! {r.mismatch_details}")

        for rr in r.reachability:
            status = (f"{rr.status_code} / {rr.latency_ms} ms"
                      if rr.reachable else rr.error or "unreachable")
            lines.append(f"      {rr.protocol.upper():<7} reachable: {status}")

    return "\n".join(lines)


def format_proxy(report: ProxyReport) -> str:
    lines = [_section("TRANSPARENT PROXY DETECTION")]
    lines.append(f"\n  Verdict: {report.summary}\n")

    for ind in report.indicators:
        marker = _flag(ind.suspicious)
        lines.append(f"  {marker} {ind.test_name}")
        lines.append(f"      {ind.details}")
        if ind.timestamp:
            lines.append(f"      Timestamp: {ind.timestamp}")

    return "\n".join(lines)


def format_throttle(report: ThrottleReport) -> str:
    lines = [_section("THROTTLING DETECTION")]
    lines.append(f"\n  Verdict: {report.summary}\n")

    lines.append(f"  Download samples ({len(report.download_samples)}):")
    for s in report.download_samples:
        lines.append(
            f"    {s.label:<20} {s.speed_kbps:>10.1f} kbps  "
            f"({s.bytes_transferred} B in {s.duration_s}s)  {s.timestamp}"
        )

    if report.upload_samples:
        lines.append(f"\n  Upload samples ({len(report.upload_samples)}):")
        for s in report.upload_samples:
            lines.append(
                f"    {s.label:<20} {s.speed_kbps:>10.1f} kbps  "
                f"({s.bytes_transferred} B in {s.duration_s}s)  {s.timestamp}"
            )

    lines.append(f"\n  Comparisons:")
    for ind in report.indicators:
        marker = _flag(ind.suspicious)
        ratio_str = f" (ratio={ind.ratio})" if ind.ratio is not None else ""
        lines.append(f"    {marker} {ind.comparison}{ratio_str}")
        lines.append(f"        {ind.details}")

    return "\n".join(lines)


def build_full_report(
    dns_reports: Optional[list[DomainReport]] = None,
    proxy_report: Optional[ProxyReport] = None,
    throttle_report: Optional[ThrottleReport] = None,
) -> str:
    """Return the full human-readable report as a string."""
    parts = []
    header = (
        f"\n{'#' * 72}\n"
        f"  NetProbe — Internet Censorship & Monitoring Detection Report\n"
        f"  Generated: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}\n"
        f"{'#' * 72}"
    )
    parts.append(header)

    if dns_reports is not None:
        parts.append(format_dns(dns_reports))
    if proxy_report is not None:
        parts.append(format_proxy(proxy_report))
    if throttle_report is not None:
        parts.append(format_throttle(throttle_report))

    suspicious_items = []
    if dns_reports:
        suspicious_items.extend(r.domain for r in dns_reports if r.mismatch)
    if proxy_report and proxy_report.proxy_likely:
        suspicious_items.append("transparent proxy detected")
    if throttle_report:
        suspicious_items.extend(
            i.comparison for i in throttle_report.indicators if i.suspicious)

    parts.append(_section("OVERALL SUMMARY"))
    if suspicious_items:
        parts.append(f"\n  Suspicious findings ({len(suspicious_items)}):")
        for item in suspicious_items:
            parts.append(f"    [!] {item}")
    else:
        parts.append("\n  No suspicious findings. Your connection looks clean.")

    parts.append(f"\n{SEPARATOR}\n")
    return "\n".join(parts)


def save_json(
    path: str | Path,
    dns_reports: Optional[list[DomainReport]] = None,
    proxy_report: Optional[ProxyReport] = None,
    throttle_report: Optional[ThrottleReport] = None,
) -> Path:
    """Serialize all results to a JSON file for programmatic consumption."""
    data: dict = {"generated": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    if dns_reports is not None:
        data["dns"] = [asdict(r) for r in dns_reports]
    if proxy_report is not None:
        data["proxy"] = asdict(proxy_report)
    if throttle_report is not None:
        data["throttle"] = asdict(throttle_report)

    out = Path(path)
    out.write_text(json.dumps(data, indent=2))
    return out
