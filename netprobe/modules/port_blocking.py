"""
Port Blocking Detection Module

Many censorship regimes block entire protocol ports rather than (or in
addition to) specific domains.  This prevents use of:
  - VPNs (OpenVPN 1194, WireGuard 51820, PPTP 1723)
  - The Tor anonymity network (9001, 9030, 9050)
  - Secure email (465, 587 SMTPS, 993 IMAPS)
  - Alternative HTTPS (8443)
  - Encrypted messaging (5222 XMPP, 4430)

Method
------
For each port we attempt a TCP connection with a short timeout.
The outcome is classified as:
  OPEN     — connection completed (port reachable)
  CLOSED   — connection refused immediately (host reachable, port not listening)
  FILTERED — connection timed out (firewall silently drops packets)

Only FILTERED results indicate active ISP-level blocking; CLOSED simply
means no service is running on that port at the test host.

We test against multiple hosts to avoid false positives from a single
host being down.
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass
from typing import Optional

from ..core.config import Config
from ..core.types import Finding, Severity
from .base import BaseModule

# Well-known hosts used as connectivity probes per category
PROBE_HOSTS: dict[str, list[str]] = {
    "Web":       ["example.com", "cloudflare.com"],
    "VPN":       ["vpn.mullvad.net", "vpn.protonvpn.com"],
    "Tor":       ["104.244.72.115", "193.23.244.244"],   # public Tor relays
    "Email":     ["smtp.gmail.com", "smtp.mailgun.org"],
    "Messaging": ["xmpp.org", "jabber.org"],
}


@dataclass
class PortOutcome:
    host:   str
    port:   int
    status: str    # "open" | "closed" | "filtered"
    ms:     float


class PortBlockingModule(BaseModule):
    name        = "Port Blocking Detection"
    description = (
        "Tests TCP connectivity on ports used by VPNs, Tor, email, and messaging "
        "to detect protocol-level censorship by the ISP."
    )

    async def run(self, config: Config):
        tasks = []
        for category, ports in config.port_targets.items():
            hosts = PROBE_HOSTS.get(category, [config.port_test_host])
            for host in hosts:
                for port in ports:
                    tasks.append(
                        self._probe(host, port, config.port_timeout, category))

        outcomes: list[tuple[str, PortOutcome]] = await asyncio.gather(*tasks)
        findings = self._analyse(outcomes, config)
        return self._result(findings)

    # ── probing ───────────────────────────────────────────────────────────────

    async def _probe(self,
                     host: str,
                     port: int,
                     timeout: float,
                     category: str) -> tuple[str, PortOutcome]:
        outcome = await asyncio.to_thread(
            self._tcp_probe, host, port, timeout)
        return (category, outcome)

    @staticmethod
    def _tcp_probe(host: str, port: int, timeout: float) -> PortOutcome:
        import time
        start = time.monotonic()
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.close()
            ms = (time.monotonic() - start) * 1000
            return PortOutcome(host, port, "open", round(ms, 1))
        except ConnectionRefusedError:
            ms = (time.monotonic() - start) * 1000
            return PortOutcome(host, port, "closed", round(ms, 1))
        except (socket.timeout, TimeoutError, OSError):
            ms = (time.monotonic() - start) * 1000
            return PortOutcome(host, port, "filtered", round(ms, 1))

    # ── analysis ─────────────────────────────────────────────────────────────

    def _analyse(self,
                 outcomes: list[tuple[str, PortOutcome]],
                 config: Config) -> list[Finding]:
        findings: list[Finding] = []

        # Group: category → port → list of outcomes
        from collections import defaultdict
        grouped: dict[str, dict[int, list[PortOutcome]]] = defaultdict(
            lambda: defaultdict(list))
        for cat, o in outcomes:
            grouped[cat][o.port].append(o)

        for cat, port_map in grouped.items():
            for port, port_outcomes in port_map.items():
                filtered = [o for o in port_outcomes if o.status == "filtered"]
                open_    = [o for o in port_outcomes if o.status == "open"]
                total    = len(port_outcomes)

                # If ALL probes to this port timed out → likely ISP block
                if len(filtered) == total and total >= 1:
                    # Confirm it's not just the host being unreachable
                    # by checking if port 443 to the same host works
                    sev = Severity.HIGH if cat in ("VPN", "Tor") else Severity.MEDIUM
                    hosts_str = ", ".join(o.host for o in filtered)
                    findings.append(self._finding(
                        title=f"Port {port} ({cat}) appears BLOCKED",
                        detail=(
                            f"TCP connections to port {port} timed out on "
                            f"all tested hosts ({hosts_str}). "
                            f"A timeout — unlike a refused connection — means "
                            f"the packets are being silently dropped, typically "
                            f"by a firewall or ISP-level filter. "
                            f"This blocks {cat} traffic that relies on this port."
                        ),
                        severity=sev,
                        category="PORT",
                        port=port,
                        protocol_category=cat,
                        hosts_tested=hosts_str,
                    ))
                elif open_:
                    findings.append(self._clean(
                        f"Port {port} ({cat}) is reachable", "PORT"))
                else:
                    # Mixed — some filtered, some refused — inconclusive
                    findings.append(self._finding(
                        title=f"Port {port} ({cat}) — mixed results",
                        detail=(
                            f"{len(filtered)}/{total} probe hosts timed out. "
                            f"May be partial blocking or host availability issues."
                        ),
                        severity=Severity.LOW,
                        category="PORT",
                        port=port,
                        protocol_category=cat,
                    ))

        return findings
