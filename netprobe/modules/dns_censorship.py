"""
DNS Censorship Detection Module

Concurrently resolves each domain against the local/ISP resolver and multiple
trusted public resolvers (Google, Cloudflare, Quad9).  DNS answers that
diverge significantly are flagged as potential tampering.

Additionally compares UDP vs TCP DNS responses for the same domain —
TCP is much harder to forge/inject, so a mismatch is strong evidence of
DNS injection on the UDP channel.

Optional: HTTP/HTTPS reachability test per domain.
"""

from __future__ import annotations

import asyncio
import socket
import time
from typing import Optional

import dns.asyncresolver
import dns.resolver
import requests

from ..core.config import Config
from ..core.types import Finding, Severity
from .base import BaseModule


class DNSCensorshipModule(BaseModule):
    name        = "DNS Censorship"
    description = (
        "Compares local ISP DNS answers against Google, Cloudflare, and Quad9. "
        "Also compares UDP vs TCP DNS to detect injection attacks."
    )

    async def run(self, config: Config):
        sem = asyncio.Semaphore(config.concurrency)
        tasks = [
            self._check_domain(domain, config, sem)
            for domain in config.domains
        ]
        nested: list[list[Finding]] = await asyncio.gather(*tasks)
        findings = [f for group in nested for f in group]
        return self._result(findings)

    # ── per-domain orchestration ───────────────────────────────────────────────

    async def _check_domain(self,
                             domain: str,
                             config: Config,
                             sem: asyncio.Semaphore) -> list[Finding]:
        async with sem:
            findings: list[Finding] = []

            # Resolve concurrently across all resolvers
            resolver_map = {"Local/ISP": None, **config.public_resolvers}
            tasks = {
                name: self._resolve(domain, server)
                for name, server in resolver_map.items()
            }
            results: dict[str, list[str] | str] = {}
            for name, coro in tasks.items():
                results[name] = await coro   # keep ordered; fast enough

            local_ips  = results["Local/ISP"]
            public_all: set[str] = set()
            for name, ips in results.items():
                if name != "Local/ISP" and isinstance(ips, list):
                    public_all.update(ips)

            # Compare local vs public
            findings += self._compare(domain, local_ips, public_all, results)

            # UDP vs TCP comparison (anti-injection)
            findings += await self._udp_vs_tcp(domain)

            # Reachability
            if config.test_reachability:
                findings += await asyncio.to_thread(
                    self._reachability, domain)

            return findings

    # ── DNS resolution ─────────────────────────────────────────────────────────

    async def _resolve(self,
                       domain: str,
                       server: Optional[str]) -> list[str] | str:
        resolver = dns.asyncresolver.Resolver()
        if server:
            resolver.nameservers = [server]
        resolver.lifetime = 5.0
        try:
            answers = await resolver.resolve(domain, "A")
            return sorted(rdata.address for rdata in answers)
        except Exception as exc:
            return f"ERROR:{exc}"

    async def _udp_vs_tcp(self, domain: str) -> list[Finding]:
        """Resolve via UDP and TCP to the same public server; flag mismatches."""
        server = "8.8.8.8"
        try:
            udp_ips = await self._resolve(domain, server)

            # TCP DNS on port 53
            tcp_ips: list[str] = await asyncio.to_thread(
                self._resolve_tcp, domain, server)

            if isinstance(udp_ips, str) or isinstance(tcp_ips, str):
                return []

            if set(udp_ips) != set(tcp_ips):
                return [self._finding(
                    title=f"UDP/TCP DNS mismatch for {domain}",
                    detail=(
                        f"Google's DNS server returned different IPs over UDP "
                        f"({', '.join(udp_ips)}) vs TCP "
                        f"({', '.join(tcp_ips)}). TCP responses are cryptographically "
                        f"harder to forge — this mismatch strongly suggests DNS "
                        f"injection or packet manipulation on the UDP channel."
                    ),
                    severity=Severity.HIGH,
                    category="DNS",
                    domain=domain,
                    udp_ips=udp_ips, tcp_ips=tcp_ips,
                )]
        except Exception:
            pass
        return []

    @staticmethod
    def _resolve_tcp(domain: str, server: str) -> list[str]:
        import dns.resolver as _res
        resolver = _res.Resolver()
        resolver.nameservers = [server]
        resolver.lifetime = 5.0
        # Force TCP
        resolver.use_tcp = True
        try:
            answers = resolver.resolve(domain, "A")
            return sorted(rdata.address for rdata in answers)
        except Exception:
            return []

    # ── comparison logic ───────────────────────────────────────────────────────

    def _compare(self,
                 domain: str,
                 local: list[str] | str,
                 public_all: set[str],
                 all_results: dict) -> list[Finding]:
        findings = []

        local_error = isinstance(local, str) and local.startswith("ERROR:")
        has_public  = bool(public_all)

        if local_error and has_public:
            findings.append(self._finding(
                title=f"DNS blocked for {domain}",
                detail=(
                    f"Your ISP's DNS server could not resolve {domain}, "
                    f"but Google, Cloudflare, and Quad9 all found it successfully. "
                    f"This is the simplest form of DNS-based censorship: your ISP is "
                    f"refusing to tell you where the site is."
                ),
                severity=Severity.HIGH,
                category="DNS",
                domain=domain,
                local_error=str(local),
            ))
            return findings

        if local_error or not local:
            return findings  # both sides failed — network issue, not censorship

        local_ips = local if isinstance(local, list) else []

        overlap = set(local_ips) & public_all
        if not overlap and public_all:
            # Check if they're even in the same /24
            def subnet(ip): return ".".join(ip.split(".")[:3])
            local_nets  = {subnet(ip) for ip in local_ips}
            public_nets = {subnet(ip) for ip in public_all}
            same_nets   = local_nets & public_nets

            severity = Severity.HIGH if not same_nets else Severity.MEDIUM
            detail = (
                f"Your ISP says {domain} is at {', '.join(local_ips)}, but "
                f"Google/Cloudflare/Quad9 say it's at "
                f"{', '.join(sorted(public_all))}. "
            )
            if not same_nets:
                detail += (
                    "These are in entirely different network blocks — very likely "
                    "DNS tampering that redirects you to a different server."
                )
            else:
                detail += (
                    "They're in the same network range, which could be normal "
                    "geographic routing — but combined with other findings warrants attention."
                )
            findings.append(self._finding(
                title=f"DNS mismatch for {domain}",
                detail=detail,
                severity=severity,
                category="DNS",
                domain=domain,
                local_ips=local_ips,
                public_ips=sorted(public_all),
            ))
        else:
            findings.append(self._clean(
                f"{domain}: DNS consistent across all resolvers", "DNS", domain))

        return findings

    # ── reachability ───────────────────────────────────────────────────────────

    def _reachability(self, domain: str) -> list[Finding]:
        findings = []
        for proto in ("http", "https"):
            url = f"{proto}://{domain}"
            try:
                start = time.monotonic()
                resp  = requests.get(url, timeout=10, allow_redirects=True,
                                     headers={"User-Agent": "NetProbe/2.0"})
                ms    = (time.monotonic() - start) * 1000
                if resp.status_code >= 400:
                    findings.append(self._finding(
                        title=f"{domain} returns HTTP {resp.status_code} over {proto.upper()}",
                        detail=(
                            f"The server responded with an error code "
                            f"({resp.status_code}), which may indicate a block page."
                        ),
                        severity=Severity.MEDIUM,
                        category="REACHABILITY",
                        domain=domain,
                        status_code=resp.status_code,
                        latency_ms=round(ms, 1),
                    ))
                else:
                    findings.append(self._clean(
                        f"{domain} reachable over {proto.upper()} "
                        f"({resp.status_code}, {ms:.0f} ms)", "REACHABILITY", domain))
            except requests.exceptions.SSLError as e:
                findings.append(self._finding(
                    title=f"SSL error reaching {domain} over HTTPS",
                    detail=(
                        f"The TLS handshake failed: {e}. "
                        f"This can indicate certificate forgery or a misconfigured "
                        f"interception proxy."
                    ),
                    severity=Severity.HIGH,
                    category="REACHABILITY",
                    domain=domain,
                    error=str(e),
                ))
            except Exception as e:
                findings.append(self._finding(
                    title=f"{domain} unreachable over {proto.upper()}",
                    detail=f"Connection failed: {e}",
                    severity=Severity.MEDIUM,
                    category="REACHABILITY",
                    domain=domain,
                    error=str(e),
                ))
        return findings
