"""
NetProbe CLI — run censorship, proxy, and throttling detection from the
command line.

Usage examples:
    python -m netprobe                    # run all checks with defaults
    python -m netprobe --dns-only         # DNS checks only
    python -m netprobe --reachability     # also test HTTP/HTTPS reach
    python -m netprobe --json report.json # save machine-readable output
    python -m netprobe --domains d.txt    # custom domain list (one per line)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .modules import dns_censorship, proxy_detection, throttle_detection
from .modules.report import build_full_report, save_json


def _print_progress(msg: str) -> None:
    print(f"  {msg}", flush=True)


def _load_domains(path: str) -> list[str]:
    lines = Path(path).read_text().splitlines()
    return [l.strip() for l in lines if l.strip() and not l.startswith("#")]


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="netprobe",
        description="Detect internet censorship, transparent proxies, and "
                    "selective throttling.",
    )
    p.add_argument(
        "--domains", metavar="FILE",
        help="Text file with one domain per line (default: built-in list).",
    )
    p.add_argument(
        "--reachability", action="store_true",
        help="Also test HTTP/HTTPS reachability for each domain.",
    )
    p.add_argument(
        "--rounds", type=int, default=3, metavar="N",
        help="Number of speed-test rounds per target (default: 3).",
    )
    p.add_argument(
        "--json", metavar="FILE",
        help="Save results as JSON to FILE.",
    )

    group = p.add_argument_group("module selection (default: run all)")
    group.add_argument("--dns-only", action="store_true",
                       help="Run only DNS censorship checks.")
    group.add_argument("--proxy-only", action="store_true",
                       help="Run only transparent proxy detection.")
    group.add_argument("--throttle-only", action="store_true",
                       help="Run only throttling detection.")

    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    run_all = not (args.dns_only or args.proxy_only or args.throttle_only)
    run_dns = run_all or args.dns_only
    run_proxy = run_all or args.proxy_only
    run_throttle = run_all or args.throttle_only

    dns_reports = None
    proxy_report = None
    throttle_report = None

    domains = None
    if args.domains:
        domains = _load_domains(args.domains)

    if run_dns:
        print("\n>> Starting DNS censorship detection …")
        dns_reports = dns_censorship.run(
            domains=domains,
            test_reachability=args.reachability,
            progress_callback=_print_progress,
        )

    if run_proxy:
        print("\n>> Starting transparent proxy detection …")
        proxy_report = proxy_detection.run(
            progress_callback=_print_progress,
        )

    if run_throttle:
        print("\n>> Starting throttling detection …")
        throttle_report = throttle_detection.run(
            rounds=args.rounds,
            progress_callback=_print_progress,
        )

    report_text = build_full_report(
        dns_reports=dns_reports,
        proxy_report=proxy_report,
        throttle_report=throttle_report,
    )
    print(report_text)

    if args.json:
        out = save_json(args.json,
                        dns_reports=dns_reports,
                        proxy_report=proxy_report,
                        throttle_report=throttle_report)
        print(f"  JSON report saved to {out.resolve()}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
