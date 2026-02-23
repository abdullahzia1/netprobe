"""
SNI Filtering Detection Module

Modern censorship systems often ignore DNS entirely and instead perform
Deep Packet Inspection (DPI) on the TLS ClientHello message.  The Server
Name Indication (SNI) extension is sent in plaintext and tells the server
(and any eavesdropper) which hostname you are connecting to.

An SNI-based firewall can:
  • Drop/RST the connection the moment it sees a blocked SNI value
  • Let through connections with unknown or no SNI (to avoid breaking things)
  • Selectively throttle connections based on SNI

Detection method
----------------
For each domain we:
  1. Resolve the domain's real IP via a trusted public resolver (bypasses DNS)
  2. Attempt a TLS connection to that IP with the real SNI → baseline
  3. Attempt a TLS connection to the same IP with a random bogus SNI
  4. Attempt a TLS connection with NO SNI

Interpretation matrix
---------------------
  real SNI fails, bogus SNI succeeds  → SNI-based blocking confirmed
  real SNI fails, no SNI succeeds     → SNI-based blocking likely
  real SNI fails, bogus fails too     → IP-level blocking or server down
  all succeed                         → no filtering detected
  real SNI slower than bogus by >50%  → possible SNI-based throttling
"""

from __future__ import annotations

import asyncio
import random
import ssl
import string
import time
from typing import Optional

import dns.resolver

from ..core.config import Config
from ..core.types import Finding, Severity
from .base import BaseModule


class SNIDetectionModule(BaseModule):
    name        = "SNI Filtering Detection"
    description = (
        "Tests whether your ISP blocks or throttles connections based on the "
        "SNI field in the TLS handshake — the most common modern censorship technique."
    )

    async def run(self, config: Config):
        sem = asyncio.Semaphore(config.concurrency)
        tasks = [
            self._test_domain(domain, config, sem)
            for domain in config.domains
        ]
        nested = await asyncio.gather(*tasks)
        findings = [f for group in nested for f in group]
        return self._result(findings)

    # ── per-domain ────────────────────────────────────────────────────────────

    async def _test_domain(self,
                            domain: str,
                            config: Config,
                            sem: asyncio.Semaphore) -> list[Finding]:
        async with sem:
            # Resolve via public DNS (bypasses ISP DNS tampering)
            ip = await asyncio.to_thread(self._resolve_public, domain)
            if not ip:
                return [self._finding(
                    title=f"Could not resolve {domain} via public DNS for SNI test",
                    detail="Skipping SNI test for this domain.",
                    severity=Severity.INFO,
                    category="SNI",
                    domain=domain,
                )]

            bogus_sni = self._random_sni()
            timeout   = config.tls_timeout

            # Three connection attempts — run concurrently
            real_t, bogus_t, none_t = await asyncio.gather(
                self._tls_connect_time(ip, domain,   timeout),
                self._tls_connect_time(ip, bogus_sni, timeout),
                self._tls_connect_time(ip, None,      timeout),
            )

            return self._interpret(domain, ip, real_t, bogus_t, none_t)

    # ── TLS probing ───────────────────────────────────────────────────────────

    @staticmethod
    async def _tls_connect_time(
            ip: str,
            sni: Optional[str],
            timeout: float) -> Optional[float]:
        """
        Attempt a TLS handshake to *ip*:443 with the given SNI.
        Returns elapsed seconds on success, None on failure.
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        start = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 443, ssl=ctx,
                                        server_hostname=sni),
                timeout=timeout,
            )
            elapsed = time.monotonic() - start
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return round(elapsed, 3)
        except Exception:
            return None

    # ── interpretation ────────────────────────────────────────────────────────

    def _interpret(self,
                   domain: str,
                   ip: str,
                   real_t:  Optional[float],
                   bogus_t: Optional[float],
                   none_t:  Optional[float]) -> list[Finding]:
        findings: list[Finding] = []

        real_ok  = real_t  is not None
        bogus_ok = bogus_t is not None
        none_ok  = none_t  is not None

        # ── Case 1: real blocked, decoy succeeds ──────────────────────────────
        if not real_ok and (bogus_ok or none_ok):
            alt = "bogus SNI" if bogus_ok else "no SNI"
            findings.append(self._finding(
                title=f"SNI-based blocking confirmed for {domain}",
                detail=(
                    f"A TLS connection to {domain}'s server ({ip}) fails when "
                    f"the correct SNI '{domain}' is sent, but SUCCEEDS when a "
                    f"{alt} is used instead. "
                    f"This is the fingerprint of SNI-based deep packet inspection: "
                    f"your ISP's firewall is reading the hostname from your "
                    f"encrypted connection handshake and blocking it."
                ),
                severity=Severity.CRITICAL,
                category="SNI",
                domain=domain,
                ip=ip,
                real_sni_ms=None,
                bogus_sni_ms=bogus_t,
                no_sni_ms=none_t,
            ))
            return findings

        # ── Case 2: everything fails → IP-level block ─────────────────────────
        if not real_ok and not bogus_ok and not none_ok:
            findings.append(self._finding(
                title=f"Port 443 appears fully blocked for {domain} ({ip})",
                detail=(
                    f"TLS connections to {ip} fail regardless of SNI value. "
                    f"This suggests IP-level blocking rather than SNI-based filtering. "
                    f"Combined with DNS findings, this may indicate layered censorship."
                ),
                severity=Severity.HIGH,
                category="SNI",
                domain=domain,
                ip=ip,
            ))
            return findings

        # ── Case 3: all succeed → check for timing-based throttling ──────────
        if real_ok and bogus_ok:
            ratio = real_t / bogus_t if bogus_t else 1
            if ratio > 2.0:
                findings.append(self._finding(
                    title=f"SNI-based handshake delay for {domain}",
                    detail=(
                        f"TLS handshake with real SNI '{domain}' took "
                        f"{real_t*1000:.0f} ms, but with a random SNI took "
                        f"{bogus_t*1000:.0f} ms (ratio={ratio:.1f}x). "
                        f"Significant delays on real SNIs suggest the DPI system "
                        f"is inspecting and potentially logging these connections."
                    ),
                    severity=Severity.MEDIUM,
                    category="SNI",
                    domain=domain,
                    ip=ip,
                    real_sni_ms=round(real_t * 1000, 1),
                    bogus_sni_ms=round(bogus_t * 1000, 1),
                    ratio=round(ratio, 2),
                ))
            else:
                findings.append(self._clean(
                    f"{domain}: no SNI filtering detected "
                    f"(real={real_t*1000:.0f}ms, bogus={bogus_t*1000:.0f}ms)",
                    "SNI", domain,
                ))

        return findings

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _resolve_public(domain: str) -> Optional[str]:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8"]
        resolver.lifetime    = 5.0
        try:
            return next(iter(resolver.resolve(domain, "A"))).address
        except Exception:
            return None

    @staticmethod
    def _random_sni() -> str:
        rand = "".join(random.choices(string.ascii_lowercase, k=12))
        return f"{rand}.netprobe-test.invalid"
