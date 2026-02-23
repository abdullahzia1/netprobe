"""
DNS Censorship Detection Module

Compares DNS resolution results from the local ISP resolver against trusted
public resolvers (Google 8.8.8.8, Cloudflare 1.1.1.1) to surface tampering,
injection, or blocking.  Optionally probes HTTP/HTTPS reachability.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from typing import Optional

import dns.resolver
import requests

PUBLIC_RESOLVERS: dict[str, str] = {
    "Google": "8.8.8.8",
    "Cloudflare": "1.1.1.1",
}

DEFAULT_DOMAINS = [
    "google.com",
    "twitter.com",
    "facebook.com",
    "wikipedia.org",
    "reddit.com",
    "youtube.com",
    "signal.org",
    "torproject.org",
    "bbc.com",
    "protonmail.com",
]

HTTP_TIMEOUT = 10


@dataclass
class DNSResult:
    domain: str
    resolver_name: str
    resolver_ip: Optional[str]
    ips: list[str]
    error: Optional[str] = None
    timestamp: str = ""


@dataclass
class ReachabilityResult:
    domain: str
    protocol: str
    status_code: Optional[int] = None
    reachable: bool = False
    error: Optional[str] = None
    latency_ms: Optional[float] = None
    timestamp: str = ""


@dataclass
class DomainReport:
    domain: str
    local_result: Optional[DNSResult] = None
    public_results: list[DNSResult] = field(default_factory=list)
    mismatch: bool = False
    mismatch_details: str = ""
    reachability: list[ReachabilityResult] = field(default_factory=list)


def _ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _resolve_with(domain: str, server: Optional[str], name: str) -> DNSResult:
    """Resolve *domain* using a specific DNS server (or system default)."""
    resolver = dns.resolver.Resolver()
    if server:
        resolver.nameservers = [server]
    resolver.lifetime = 5.0

    try:
        answers = resolver.resolve(domain, "A")
        ips = sorted(rdata.address for rdata in answers)
        return DNSResult(domain=domain, resolver_name=name,
                         resolver_ip=server, ips=ips, timestamp=_ts())
    except Exception as exc:
        return DNSResult(domain=domain, resolver_name=name,
                         resolver_ip=server, ips=[], error=str(exc),
                         timestamp=_ts())


def _check_reachability(domain: str, protocol: str) -> ReachabilityResult:
    url = f"{protocol}://{domain}"
    try:
        start = time.monotonic()
        resp = requests.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True,
                            headers={"User-Agent": "NetProbe/1.0"})
        latency = (time.monotonic() - start) * 1000
        return ReachabilityResult(
            domain=domain, protocol=protocol, status_code=resp.status_code,
            reachable=resp.status_code < 500, latency_ms=round(latency, 1),
            timestamp=_ts(),
        )
    except Exception as exc:
        return ReachabilityResult(
            domain=domain, protocol=protocol, error=str(exc), timestamp=_ts(),
        )


def _ips_differ_significantly(local_ips: list[str],
                              public_ips: list[str]) -> bool:
    """
    Heuristic: if there is zero overlap between IP sets the result is
    suspicious.  Partial overlap (CDN fan-out) is considered normal.
    """
    if not local_ips or not public_ips:
        return True
    return len(set(local_ips) & set(public_ips)) == 0


def _subnet(ip: str) -> str:
    parts = ip.split(".")
    return ".".join(parts[:3])


def _subnets_differ(local_ips: list[str], public_ips: list[str]) -> bool:
    """Check whether resolved IPs are even in different /24 subnets."""
    local_nets = {_subnet(ip) for ip in local_ips}
    public_nets = {_subnet(ip) for ip in public_ips}
    return len(local_nets & public_nets) == 0


def run(domains: Optional[list[str]] = None,
        test_reachability: bool = False,
        progress_callback=None) -> list[DomainReport]:
    """
    Run DNS censorship checks for every domain in *domains*.

    Returns a list of `DomainReport` objects with mismatch analysis and
    optional reachability results.
    """
    if domains is None:
        domains = DEFAULT_DOMAINS

    reports: list[DomainReport] = []

    for idx, domain in enumerate(domains, 1):
        if progress_callback:
            progress_callback(f"[DNS] ({idx}/{len(domains)}) checking {domain}")

        report = DomainReport(domain=domain)

        report.local_result = _resolve_with(domain, None, "Local/ISP")

        for name, ip in PUBLIC_RESOLVERS.items():
            report.public_results.append(_resolve_with(domain, ip, name))

        all_public_ips: set[str] = set()
        for pr in report.public_results:
            all_public_ips.update(pr.ips)

        local_ips = report.local_result.ips

        if report.local_result.error and not any(
                pr.error for pr in report.public_results):
            report.mismatch = True
            report.mismatch_details = (
                "Local DNS resolution failed while public resolvers succeeded "
                "— possible DNS-level block."
            )
        elif _ips_differ_significantly(local_ips, list(all_public_ips)):
            report.mismatch = True
            if _subnets_differ(local_ips, list(all_public_ips)):
                report.mismatch_details = (
                    f"IPs from local resolver ({', '.join(local_ips)}) are in "
                    f"entirely different subnets from public resolvers "
                    f"({', '.join(sorted(all_public_ips))}) — likely DNS "
                    f"tampering."
                )
            else:
                report.mismatch_details = (
                    f"No IP overlap: local={', '.join(local_ips)} vs "
                    f"public={', '.join(sorted(all_public_ips))}. Could be "
                    f"geo-routing or manipulation."
                )

        if test_reachability:
            for proto in ("http", "https"):
                report.reachability.append(_check_reachability(domain, proto))

        reports.append(report)

    return reports
