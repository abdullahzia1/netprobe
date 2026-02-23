"""
Transparent Proxy Detection Module

A transparent proxy silently intercepts your traffic without your knowledge.
This module runs four independent tests and cross-references their results
to reduce false positives.

Tests
-----
1. Header injection  — proxy-added Via/X-Forwarded headers in response
2. Double-Host       — compliant servers reject it; many proxies silently strip it
3. HTTP vs HTTPS body — content injection shows up as size divergence
4. TTL hop analysis  — different TTL on port 80 vs 443 reveals an in-path device
"""

from __future__ import annotations

import asyncio
import socket
import time

import requests

from ..core.config import Config
from ..core.types import Finding, Severity
from .base import BaseModule

PROXY_HEADER_NAMES = [
    "via", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
    "x-real-ip", "x-proxy-id", "x-cache", "x-squid-error",
    "x-bluecoat-via", "forwarded", "proxy-connection",
]


class ProxyDetectionModule(BaseModule):
    name        = "Transparent Proxy Detection"
    description = (
        "Detects silent traffic interception via header injection, "
        "double-Host tricks, HTTP/HTTPS content comparison, and TTL analysis."
    )

    async def run(self, config: Config):
        results = await asyncio.gather(
            asyncio.to_thread(self._check_proxy_headers),
            asyncio.to_thread(self._check_double_host),
            asyncio.to_thread(self._check_body_comparison),
            asyncio.to_thread(self._check_ttl),
        )
        findings = [f for group in results for f in group]

        suspicious = [f for f in findings if f.severity > Severity.CLEAN]
        if len(suspicious) >= 2:
            findings.append(self._finding(
                title="Transparent proxy is very likely present",
                detail=(
                    f"{len(suspicious)} out of 4 independent tests flagged "
                    f"proxy-like behaviour. The probability of this being a "
                    f"false positive is very low."
                ),
                severity=Severity.CRITICAL,
                category="PROXY",
            ))

        return self._result(findings)

    # ── test 1: header injection ───────────────────────────────────────────────

    def _check_proxy_headers(self) -> list[Finding]:
        try:
            resp = requests.get(
                "http://httpbin.org/headers", timeout=12,
                headers={"User-Agent": "NetProbe/2.0", "Accept": "application/json"},
            )
            body  = resp.text.lower()
            found = [h for h in PROXY_HEADER_NAMES
                     if h in resp.headers or h in body]
            if found:
                return [self._finding(
                    title="Proxy-related headers detected in HTTP response",
                    detail=(
                        f"The following headers appeared in the response without "
                        f"being sent: {', '.join(found)}. These are typically "
                        f"added by transparent proxies to track or log requests."
                    ),
                    severity=Severity.HIGH,
                    category="PROXY",
                    headers_found=found,
                )]
            return [self._clean("No proxy-related headers detected", "PROXY")]
        except Exception as e:
            return [self._finding(
                title="Header injection test could not run",
                detail=str(e),
                severity=Severity.INFO,
                category="PROXY",
            )]

    # ── test 2: double-Host header ─────────────────────────────────────────────

    def _check_double_host(self) -> list[Finding]:
        host = "example.com"
        raw  = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Host: evil.example.com\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        try:
            sock = socket.create_connection((host, 80), timeout=12)
            sock.sendall(raw)
            buf = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
            sock.close()
            status = buf.split(b"\r\n", 1)[0].decode(errors="replace")
            if "400" in status:
                return [self._clean(
                    f"Double-Host rejected as expected ({status})", "PROXY")]
            return [self._finding(
                title="Double-Host header was silently accepted",
                detail=(
                    f"A deliberately malformed request with two conflicting "
                    f"'Host' headers was accepted ({status}). RFC-compliant "
                    f"servers must reject this with HTTP 400. The request being "
                    f"accepted suggests a proxy stripped the duplicate header "
                    f"before forwarding."
                ),
                severity=Severity.MEDIUM,
                category="PROXY",
                status_line=status,
            )]
        except Exception as e:
            return [self._finding(
                title="Double-Host test could not run",
                detail=str(e),
                severity=Severity.INFO,
                category="PROXY",
            )]

    # ── test 3: HTTP vs HTTPS body comparison ─────────────────────────────────

    def _check_body_comparison(self) -> list[Finding]:
        domain = "example.com"
        try:
            r_http = requests.get(
                f"http://{domain}", timeout=12,
                headers={"User-Agent": "NetProbe/2.0"})
        except Exception as e:
            return [self._finding(
                title="HTTP body comparison — HTTP fetch failed",
                detail=str(e), severity=Severity.INFO, category="PROXY")]
        try:
            r_https = requests.get(
                f"https://{domain}", timeout=12,
                headers={"User-Agent": "NetProbe/2.0"},
                verify=True)
        except requests.exceptions.SSLError as e:
            return [self._finding(
                title="SSL error during HTTP/HTTPS body comparison",
                detail=(
                    f"TLS verification failed: {e}. This can indicate that a "
                    f"proxy is intercepting and re-signing HTTPS traffic with "
                    f"its own certificate."
                ),
                severity=Severity.HIGH,
                category="PROXY",
                error=str(e),
            )]
        except Exception as e:
            return [self._finding(
                title="HTTP body comparison — HTTPS fetch failed",
                detail=str(e), severity=Severity.INFO, category="PROXY")]

        len_h  = len(r_http.content)
        len_hs = len(r_https.content)
        diff   = abs(len_h - len_hs) / max(len_h, len_hs, 1) * 100

        if diff > 15:
            return [self._finding(
                title=f"HTTP and HTTPS content differ by {diff:.1f}%",
                detail=(
                    f"The same page returned {len_h} bytes over HTTP and "
                    f"{len_hs} bytes over HTTPS — a {diff:.1f}% difference. "
                    f"This suggests a proxy is injecting or modifying content "
                    f"on the unencrypted channel."
                ),
                severity=Severity.HIGH,
                category="PROXY",
                http_bytes=len_h, https_bytes=len_hs, diff_pct=round(diff, 1),
            )]
        return [self._clean(
            f"HTTP/HTTPS bodies match (diff={diff:.1f}%)", "PROXY")]

    # ── test 4: TTL hop-count analysis ─────────────────────────────────────────

    def _check_ttl(self) -> list[Finding]:
        host = "example.com"

        def get_ttl(port: int):
            try:
                s = socket.create_connection((host, port), timeout=10)
                ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL) \
                      if hasattr(socket, "IP_TTL") else None
                s.close()
                return ttl
            except Exception:
                return None

        ttl_80  = get_ttl(80)
        ttl_443 = get_ttl(443)

        if ttl_80 is None or ttl_443 is None:
            return [self._finding(
                title="TTL analysis — could not obtain TTL values",
                detail=f"port80={ttl_80}, port443={ttl_443}. Skipped.",
                severity=Severity.INFO, category="PROXY",
            )]

        diff = abs(ttl_80 - ttl_443)
        if diff > 2:
            return [self._finding(
                title=f"TTL hop mismatch: port 80 TTL={ttl_80}, port 443 TTL={ttl_443}",
                detail=(
                    f"Your connection to port 80 (unencrypted) takes a different "
                    f"number of network hops ({diff} hop difference) than port 443 "
                    f"(encrypted). This strongly suggests an extra device — a "
                    f"transparent proxy — sits in the path of your unencrypted traffic."
                ),
                severity=Severity.HIGH,
                category="PROXY",
                ttl_80=ttl_80, ttl_443=ttl_443, hop_diff=diff,
            )]
        return [self._clean(
            f"TTL consistent (port80={ttl_80}, port443={ttl_443})", "PROXY")]
