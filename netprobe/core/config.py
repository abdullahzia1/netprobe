"""
Central configuration dataclass.

One Config object is created from CLI arguments and passed to every module.
Modules must not read sys.argv or environment variables directly — they
receive everything they need through Config.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


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

PUBLIC_RESOLVERS: dict[str, str] = {
    "Google":     "8.8.8.8",
    "Cloudflare": "1.1.1.1",
    "Quad9":      "9.9.9.9",
}

# Ports tested by the port-blocking module
CENSORED_PORTS: dict[str, list[int]] = {
    "Web":      [80, 443, 8080, 8443],
    "VPN":      [1194, 1723, 51820, 500],
    "Tor":      [9001, 9030, 9050, 9150],
    "Email":    [25, 465, 587, 993, 995],
    "Messaging":[5222, 5223, 4430],
}

# Well-known government / national-telco CAs that indicate MitM
SUSPICIOUS_CA_KEYWORDS = [
    "government", "ministry", "national", "state", "pkioverheid",
    "iran", "china", "surveillance",
    "pta", "nca", "telecom","imran khan", "pti", "pmln", "russia", "turkmenistan", "kazakh",
]


@dataclass
class Config:
    # ── domains ──────────────────────────────────────────────────────────────
    domains: list[str] = field(default_factory=lambda: list(DEFAULT_DOMAINS))

    # ── module toggles ────────────────────────────────────────────────────────
    run_dns:      bool = True
    run_proxy:    bool = True
    run_throttle: bool = True
    run_tls:      bool = True
    run_sni:      bool = True
    run_ports:    bool = True

    # ── dns options ───────────────────────────────────────────────────────────
    test_reachability: bool = False
    public_resolvers:  dict[str, str] = field(
        default_factory=lambda: dict(PUBLIC_RESOLVERS))

    # ── throttle options ──────────────────────────────────────────────────────
    throttle_rounds: int = 3

    # ── port options ──────────────────────────────────────────────────────────
    port_targets: dict[str, list[int]] = field(
        default_factory=lambda: dict(CENSORED_PORTS))
    port_test_host: str = "example.com"
    port_timeout:   float = 5.0

    # ── tls / sni options ─────────────────────────────────────────────────────
    tls_timeout: float = 8.0
    suspicious_ca_keywords: list[str] = field(
        default_factory=lambda: list(SUSPICIOUS_CA_KEYWORDS))

    # ── engine options ────────────────────────────────────────────────────────
    module_timeout: float = 120.0    # per-module async timeout (seconds)
    concurrency:    int   = 6        # max concurrent domain checks

    # ── storage ───────────────────────────────────────────────────────────────
    db_path: Path = field(default_factory=lambda: Path("netprobe.db"))

    # ── output ────────────────────────────────────────────────────────────────
    json_output: Optional[Path] = None
    html_output: Path = field(default_factory=lambda: Path("index.html"))
    quiet:       bool = False

    @classmethod
    def from_args(cls, args) -> "Config":
        """Build a Config from parsed argparse Namespace."""
        cfg = cls()

        if args.domains:
            cfg.domains = _load_domain_file(args.domains)

        cfg.test_reachability = getattr(args, "reachability", False)
        cfg.throttle_rounds   = getattr(args, "rounds", 3)
        cfg.quiet             = getattr(args, "quiet", False)

        if getattr(args, "json", None):
            cfg.json_output = Path(args.json)
        # html_output always defaults to index.html at the working directory

        # module toggles
        only_flags = [
            args.dns_only, args.proxy_only, args.throttle_only,
            args.tls_only, args.sni_only, args.ports_only,
        ]
        if any(only_flags):
            cfg.run_dns      = bool(args.dns_only)
            cfg.run_proxy    = bool(args.proxy_only)
            cfg.run_throttle = bool(args.throttle_only)
            cfg.run_tls      = bool(args.tls_only)
            cfg.run_sni      = bool(args.sni_only)
            cfg.run_ports    = bool(args.ports_only)

        if getattr(args, "db", None):
            cfg.db_path = Path(args.db)

        return cfg


def _load_domain_file(path: str) -> list[str]:
    lines = Path(path).read_text().splitlines()
    return [l.strip() for l in lines
            if l.strip() and not l.startswith("#")]
