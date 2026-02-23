"""
Transparent Proxy Detection Module

Detects whether HTTP requests are being silently intercepted by a transparent
proxy.  Techniques used:

1. **Header injection** – send a request with a known Via / X-Forwarded-For
   header and inspect the response for unexpected proxy-added headers.
2. **Double Host header** – some proxies mangle or reject double-Host
   requests differently from origin servers.
3. **HTTP vs HTTPS body comparison** – compare response bodies; a proxy that
   only intercepts plaintext HTTP will produce different content.
4. **TTL / hop-count analysis** – compare the IP TTL between a direct HTTPS
   connection and a plain HTTP connection to the same host.  A transparent
   proxy sitting in-path will decrement the TTL differently.
"""

from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

import requests

PROXY_HEADERS = [
    "via", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
    "x-real-ip", "x-proxy-id", "x-cache", "x-squid-error",
    "x-bluecoat-via",
]

TEST_URLS = [
    "http://httpbin.org/headers",
    "http://example.com",
]

HTTP_TIMEOUT = 12


@dataclass
class ProxyIndicator:
    """A single signal that may indicate transparent proxying."""
    test_name: str
    suspicious: bool
    details: str
    timestamp: str = ""


@dataclass
class ProxyReport:
    indicators: list[ProxyIndicator] = field(default_factory=list)
    proxy_likely: bool = False
    summary: str = ""


def _ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _check_proxy_headers(url: str = "http://httpbin.org/headers") -> ProxyIndicator:
    """
    Request a header-echo service over plain HTTP.  If a transparent proxy
    is in the path it often adds Via / X-Forwarded-* headers that we did
    not send.
    """
    try:
        resp = requests.get(
            url, timeout=HTTP_TIMEOUT,
            headers={"User-Agent": "NetProbe/1.0",
                     "Accept": "application/json"},
        )
        body = resp.text.lower()
        found = [h for h in PROXY_HEADERS
                 if h in resp.headers or h in body]
        if found:
            return ProxyIndicator(
                test_name="Proxy Header Injection",
                suspicious=True,
                details=(f"Proxy-related headers detected in response: "
                         f"{', '.join(found)}"),
                timestamp=_ts(),
            )
        return ProxyIndicator(
            test_name="Proxy Header Injection",
            suspicious=False,
            details="No proxy-related headers found.",
            timestamp=_ts(),
        )
    except Exception as exc:
        return ProxyIndicator(
            test_name="Proxy Header Injection",
            suspicious=False,
            details=f"Test could not complete: {exc}",
            timestamp=_ts(),
        )


def _check_double_host() -> ProxyIndicator:
    """
    Send a raw HTTP/1.1 request with two Host headers.  Compliant servers
    reject this (400); many proxies silently pick one.
    """
    host = "example.com"
    request_bytes = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Host: evil.example.com\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    try:
        sock = socket.create_connection((host, 80), timeout=HTTP_TIMEOUT)
        sock.sendall(request_bytes)
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()

        status_line = response.split(b"\r\n", 1)[0].decode(errors="replace")

        if "400" in status_line:
            return ProxyIndicator(
                test_name="Double Host Header",
                suspicious=False,
                details=f"Server rejected double-Host as expected ({status_line}).",
                timestamp=_ts(),
            )

        return ProxyIndicator(
            test_name="Double Host Header",
            suspicious=True,
            details=(f"Server accepted double-Host request ({status_line}). "
                     f"A proxy may have stripped the duplicate header."),
            timestamp=_ts(),
        )
    except Exception as exc:
        return ProxyIndicator(
            test_name="Double Host Header",
            suspicious=False,
            details=f"Test could not complete: {exc}",
            timestamp=_ts(),
        )


def _compare_http_https(domain: str = "example.com") -> ProxyIndicator:
    """
    Fetch the same resource over HTTP and HTTPS and compare content length.
    A transparent proxy that injects content (ads, JS, block pages) will
    cause a size divergence.
    """
    try:
        r_http = requests.get(f"http://{domain}", timeout=HTTP_TIMEOUT,
                              headers={"User-Agent": "NetProbe/1.0"})
        r_https = requests.get(f"https://{domain}", timeout=HTTP_TIMEOUT,
                               headers={"User-Agent": "NetProbe/1.0"})

        len_http = len(r_http.content)
        len_https = len(r_https.content)
        diff_pct = abs(len_http - len_https) / max(len_http, len_https, 1) * 100

        if diff_pct > 15:
            return ProxyIndicator(
                test_name="HTTP vs HTTPS Body Comparison",
                suspicious=True,
                details=(f"Content length diverges by {diff_pct:.1f}% "
                         f"(HTTP={len_http} B, HTTPS={len_https} B). "
                         f"Possible content injection on plaintext channel."),
                timestamp=_ts(),
            )
        return ProxyIndicator(
            test_name="HTTP vs HTTPS Body Comparison",
            suspicious=False,
            details=(f"Content lengths similar (HTTP={len_http} B, "
                     f"HTTPS={len_https} B, diff={diff_pct:.1f}%)."),
            timestamp=_ts(),
        )
    except Exception as exc:
        return ProxyIndicator(
            test_name="HTTP vs HTTPS Body Comparison",
            suspicious=False,
            details=f"Test could not complete: {exc}",
            timestamp=_ts(),
        )


def _check_ttl_difference(host: str = "example.com") -> ProxyIndicator:
    """
    Compare TCP-level TTL for connections on port 80 vs port 443.  A
    transparent proxy intercepting port 80 will have a different hop
    distance from the real server on port 443.
    """
    def _get_ttl(target_host: str, port: int) -> Optional[int]:
        try:
            sock = socket.create_connection((target_host, port),
                                            timeout=HTTP_TIMEOUT)
            if hasattr(socket, "IP_TTL"):
                ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            else:
                ttl = None
            sock.close()
            return ttl
        except Exception:
            return None

    ttl_80 = _get_ttl(host, 80)
    ttl_443 = _get_ttl(host, 443)

    if ttl_80 is None or ttl_443 is None:
        return ProxyIndicator(
            test_name="TTL Hop-Count Analysis",
            suspicious=False,
            details=(f"Could not obtain TTL values (port 80={ttl_80}, "
                     f"port 443={ttl_443}). Skipping."),
            timestamp=_ts(),
        )

    diff = abs(ttl_80 - ttl_443)
    if diff > 2:
        return ProxyIndicator(
            test_name="TTL Hop-Count Analysis",
            suspicious=True,
            details=(f"TTL differs by {diff} hops (port 80 TTL={ttl_80}, "
                     f"port 443 TTL={ttl_443}). Suggests an in-path device "
                     f"on the plaintext channel."),
            timestamp=_ts(),
        )
    return ProxyIndicator(
        test_name="TTL Hop-Count Analysis",
        suspicious=False,
        details=(f"TTLs are consistent (port 80 TTL={ttl_80}, "
                 f"port 443 TTL={ttl_443}, diff={diff})."),
        timestamp=_ts(),
    )


def run(progress_callback=None) -> ProxyReport:
    """Execute all transparent-proxy detection tests and return a report."""
    report = ProxyReport()

    tests = [
        ("Header injection check", _check_proxy_headers),
        ("Double-Host header check", _check_double_host),
        ("HTTP vs HTTPS body comparison", lambda: _compare_http_https()),
        ("TTL hop-count analysis", lambda: _check_ttl_difference()),
    ]

    for label, fn in tests:
        if progress_callback:
            progress_callback(f"[Proxy] {label}")
        report.indicators.append(fn())

    suspicious_count = sum(1 for i in report.indicators if i.suspicious)
    report.proxy_likely = suspicious_count >= 2
    if suspicious_count == 0:
        report.summary = "No transparent proxy indicators detected."
    elif report.proxy_likely:
        report.summary = (
            f"{suspicious_count}/{len(report.indicators)} tests flagged — "
            f"transparent proxy is LIKELY in path."
        )
    else:
        report.summary = (
            f"{suspicious_count}/{len(report.indicators)} tests flagged — "
            f"inconclusive, but worth monitoring."
        )

    return report
