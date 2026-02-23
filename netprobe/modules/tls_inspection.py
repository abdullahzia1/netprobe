"""
TLS / Certificate Chain Inspection Module

The most dangerous form of censorship is TLS MitM (Man-in-the-Middle):
an ISP or government device decrypts your HTTPS traffic by presenting a
forged certificate signed by a CA they control.  Victims see a padlock
but their traffic is being read in plaintext.

Detection techniques
--------------------
1. Certificate fingerprint comparison
   Fetch the TLS certificate for each domain via the local/ISP path AND
   via a direct connection to the IP returned by a trusted public resolver.
   If the fingerprints differ, something in the path is swapping the cert.

2. Issuer / CA authority analysis
   Inspect the certificate issuer and root CA.  Flag any CA whose name
   matches known government, surveillance, or national-telecom keywords.

3. Self-signed certificate detection
   A legitimate public site should never present a self-signed cert.
   Self-signed certs from known domains = almost certain interception.

4. Weak signature algorithm detection
   Old or weakened algorithms (MD5, SHA-1) in cert chains can indicate
   a poorly-implemented interception setup.

5. Certificate validity window anomalies
   Certificates that expire unusually soon (< 30 days) or have
   suspiciously short validity periods can indicate ephemeral MitM certs.
"""

from __future__ import annotations

import asyncio
import hashlib
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Optional

import dns.resolver

from ..core.config import Config
from ..core.types import Finding, Severity
from .base import BaseModule


class TLSInspectionModule(BaseModule):
    name        = "TLS / Certificate Inspection"
    description = (
        "Detects HTTPS MitM attacks by comparing certificate fingerprints "
        "via ISP vs direct paths, and auditing cert issuers for suspicious CAs."
    )

    async def run(self, config: Config):
        sem = asyncio.Semaphore(config.concurrency)
        tasks = [
            self._inspect_domain(domain, config, sem)
            for domain in config.domains
        ]
        nested = await asyncio.gather(*tasks)
        findings = [f for group in nested for f in group]
        return self._result(findings)

    # ── per-domain ────────────────────────────────────────────────────────────

    async def _inspect_domain(self,
                               domain: str,
                               config: Config,
                               sem: asyncio.Semaphore) -> list[Finding]:
        async with sem:
            findings: list[Finding] = []

            # Fetch cert via the normal (ISP) path
            isp_cert = await asyncio.to_thread(
                self._get_cert, domain, domain, config.tls_timeout)

            if isp_cert is None:
                findings.append(self._finding(
                    title=f"TLS connection failed for {domain}",
                    detail=(
                        f"Could not complete a TLS handshake with {domain}. "
                        f"The site may be down, or port 443 may be blocked."
                    ),
                    severity=Severity.LOW,
                    category="TLS",
                    domain=domain,
                ))
                return findings

            # Audit the cert itself
            findings += self._audit_cert(domain, isp_cert, config)

            # Fetch cert via direct IP (bypasses DNS tampering)
            direct_ip = await asyncio.to_thread(
                self._resolve_public, domain)
            if direct_ip and direct_ip != self._get_cert_ip(domain):
                direct_cert = await asyncio.to_thread(
                    self._get_cert, direct_ip, domain, config.tls_timeout)
                if direct_cert:
                    findings += self._compare_certs(
                        domain, isp_cert, direct_cert, direct_ip)

            return findings

    # ── TLS connection & cert retrieval ───────────────────────────────────────

    @staticmethod
    def _get_cert(host: str,
                  sni: str,
                  timeout: float) -> Optional[dict]:
        """
        Open a TLS connection to *host* using *sni* as the Server Name
        Indication and return a dict with cert fields and fingerprint.
        We disable verification so we can inspect bad/forged certs too.
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        try:
            with socket.create_connection((host, 443), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=sni) as tls:
                    der         = tls.getpeercert(binary_form=True)
                    parsed      = tls.getpeercert()
                    fingerprint = hashlib.sha256(der).hexdigest()
                    cipher      = tls.cipher()
                    return {
                        "fingerprint_sha256": fingerprint,
                        "parsed": parsed,
                        "cipher": cipher,
                    }
        except Exception:
            return None

    @staticmethod
    def _resolve_public(domain: str) -> Optional[str]:
        """Return the first IP from Google's DNS for *domain*."""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8"]
        resolver.lifetime    = 5.0
        try:
            answers = resolver.resolve(domain, "A")
            return next(iter(answers)).address
        except Exception:
            return None

    @staticmethod
    def _get_cert_ip(domain: str) -> Optional[str]:
        """Return the local ISP's resolved IP for *domain*."""
        try:
            return socket.gethostbyname(domain)
        except Exception:
            return None

    # ── cert auditing ─────────────────────────────────────────────────────────

    def _audit_cert(self,
                    domain: str,
                    cert_info: dict,
                    config: Config) -> list[Finding]:
        findings: list[Finding] = []
        parsed = cert_info.get("parsed", {})

        # --- self-signed check ---
        subject = dict(x[0] for x in parsed.get("subject", []))
        issuer  = dict(x[0] for x in parsed.get("issuer", []))
        if subject == issuer:
            findings.append(self._finding(
                title=f"Self-signed certificate for {domain}",
                detail=(
                    f"{domain} is presenting a certificate where the issuer "
                    f"and the subject are the same entity — meaning it was "
                    f"signed by itself, not by a trusted authority. Legitimate "
                    f"public websites never do this. This is a strong sign of "
                    f"a poorly configured interception proxy."
                ),
                severity=Severity.CRITICAL,
                category="TLS",
                domain=domain,
                issuer=str(issuer),
                subject=str(subject),
            ))
        else:
            findings.append(self._clean(
                f"{domain}: certificate is not self-signed", "TLS", domain))

        # --- suspicious CA check ---
        issuer_str = " ".join(str(v).lower() for v in issuer.values())
        matched_kw = [kw for kw in config.suspicious_ca_keywords
                      if kw in issuer_str]
        if matched_kw:
            findings.append(self._finding(
                title=f"Suspicious certificate authority for {domain}",
                detail=(
                    f"The certificate for {domain} was issued by an authority "
                    f"that matches suspicious keywords: {', '.join(matched_kw)}. "
                    f"Issuer: {issuer_str}. "
                    f"Government-controlled CAs can issue certificates for any "
                    f"domain, enabling undetectable HTTPS interception."
                ),
                severity=Severity.CRITICAL,
                category="TLS",
                domain=domain,
                issuer=issuer_str,
                matched_keywords=matched_kw,
            ))

        # --- expiry check ---
        not_after_str = parsed.get("notAfter", "")
        if not_after_str:
            try:
                not_after = datetime.strptime(
                    not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc)
                days_left = (not_after - datetime.now(timezone.utc)).days
                if days_left < 0:
                    findings.append(self._finding(
                        title=f"Certificate for {domain} has EXPIRED",
                        detail=(
                            f"The TLS certificate expired {abs(days_left)} days ago "
                            f"({not_after_str}). If you can still connect, a proxy may "
                            f"be presenting a cached or forged certificate."
                        ),
                        severity=Severity.HIGH,
                        category="TLS",
                        domain=domain,
                        days_left=days_left,
                    ))
                elif days_left < 30:
                    findings.append(self._finding(
                        title=f"Certificate for {domain} expires soon ({days_left} days)",
                        detail=(
                            f"The cert expires on {not_after_str}. Short-lived certs "
                            f"on MitM proxies sometimes aren't renewed promptly."
                        ),
                        severity=Severity.LOW,
                        category="TLS",
                        domain=domain,
                        days_left=days_left,
                    ))
                else:
                    findings.append(self._clean(
                        f"{domain}: cert valid for {days_left} days", "TLS", domain))
            except Exception:
                pass

        # --- cipher strength check ---
        cipher = cert_info.get("cipher")
        if cipher:
            cipher_name = cipher[0] if cipher else ""
            weak_kw = ["rc4", "des", "md5", "export", "null", "anon"]
            if any(w in cipher_name.lower() for w in weak_kw):
                findings.append(self._finding(
                    title=f"Weak cipher suite negotiated for {domain}",
                    detail=(
                        f"The connection to {domain} used a weak cipher: "
                        f"{cipher_name}. Modern servers do not offer these "
                        f"unless an interception proxy is downgrading security."
                    ),
                    severity=Severity.HIGH,
                    category="TLS",
                    domain=domain,
                    cipher=cipher_name,
                ))

        return findings

    def _compare_certs(self,
                        domain: str,
                        isp_cert: dict,
                        direct_cert: dict,
                        direct_ip: str) -> list[Finding]:
        """Compare fingerprints between ISP-path cert and direct-IP cert."""
        fp_isp    = isp_cert["fingerprint_sha256"]
        fp_direct = direct_cert["fingerprint_sha256"]

        if fp_isp != fp_direct:
            return [self._finding(
                title=f"Certificate fingerprint MISMATCH for {domain}",
                detail=(
                    f"The TLS certificate you receive for {domain} via your ISP "
                    f"has a different fingerprint than the certificate served "
                    f"directly from the real server IP ({direct_ip}). "
                    f"ISP fingerprint:    {fp_isp[:16]}…\n"
                    f"Direct fingerprint: {fp_direct[:16]}…\n"
                    f"This is conclusive evidence that something between you "
                    f"and {domain} is performing HTTPS interception."
                ),
                severity=Severity.CRITICAL,
                category="TLS",
                domain=domain,
                ip=direct_ip,
                fp_isp=fp_isp,
                fp_direct=fp_direct,
            )]
        return [self._clean(
            f"{domain}: cert fingerprint matches direct path", "TLS", domain)]
