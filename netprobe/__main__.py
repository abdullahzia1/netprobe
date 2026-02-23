"""
NetProbe v2 — Async CLI

After every scan index.html is automatically written (or overwritten) in
the current working directory so it is always ready to deploy to GitHub Pages.

Usage examples
--------------
    python -m netprobe                        # all modules, defaults
    python -m netprobe --dns-only             # one module
    python -m netprobe --reachability         # include HTTP/S reachability
    python -m netprobe --json out.json        # also save machine-readable JSON
    python -m netprobe --domains sites.txt    # custom domain list
    python -m netprobe --history              # show past scan results
    python -m netprobe --rounds 5 --quiet     # more speed samples, no progress
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from .core.config import Config
from .core.engine import Engine
from .core.storage import Storage
from .core.types import RunResult
from .modules.dns_censorship    import DNSCensorshipModule
from .modules.port_blocking     import PortBlockingModule
from .modules.proxy_detection   import ProxyDetectionModule
from .modules.report            import save_json, terminal_report
from .modules.sni_detection     import SNIDetectionModule
from .modules.throttle_detection import ThrottleDetectionModule
from .modules.tls_inspection    import TLSInspectionModule


def _parse(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="netprobe",
        description="Detect internet censorship, transparent proxies, "
                    "TLS interception, SNI filtering, and throttling.",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    p.add_argument("--domains",  metavar="FILE",
                   help="Text file, one domain per line.")
    p.add_argument("--reachability", action="store_true",
                   help="Also test HTTP/HTTPS reachability per domain.")
    p.add_argument("--rounds",   type=int, default=3, metavar="N",
                   help="Speed-test rounds per target (default: 3).")
    p.add_argument("--json",     metavar="FILE",
                   help="Also save raw JSON results to FILE.")
    p.add_argument("--db",       metavar="FILE", default="netprobe.db",
                   help="SQLite database path (default: netprobe.db).")
    p.add_argument("--quiet",    action="store_true",
                   help="Suppress progress output; only print final report.")
    p.add_argument("--no-colour", action="store_true",
                   help="Disable terminal colour codes.")

    p.add_argument("--history",  action="store_true",
                   help="Show the last 15 scan summaries from the database.")

    grp = p.add_argument_group("module selection (default: run all)")
    grp.add_argument("--dns-only",      action="store_true")
    grp.add_argument("--proxy-only",    action="store_true")
    grp.add_argument("--throttle-only", action="store_true")
    grp.add_argument("--tls-only",      action="store_true")
    grp.add_argument("--sni-only",      action="store_true")
    grp.add_argument("--ports-only",    action="store_true")

    return p.parse_args(argv)


async def _show_history(db_path: str) -> None:
    storage = Storage(db_path)
    rows    = await storage.recent_runs(15)
    if not rows:
        print("  No scan history found.")
        return
    print(f"\n{'─'*72}")
    print(f"  {'ID':<5} {'Timestamp':<22} {'Score':>5}  {'Flagged':>7}  "
          f"{'Duration':>9}  Modules")
    print(f"{'─'*72}")
    for r in rows:
        import json
        mods = ", ".join(json.loads(r["modules_run"] or "[]"))
        print(f"  {r['id']:<5} {r['timestamp']:<22} {r['overall_score']:>5}  "
              f"{r['total_flagged']:>7}  {r['duration_ms']:>8.0f}ms  {mods}")
    print(f"{'─'*72}\n")


async def _run(args: argparse.Namespace) -> int:
    if args.history:
        await _show_history(args.db)
        return 0

    config = Config.from_args(args)

    engine = Engine(config)

    def _progress(msg: str) -> None:
        print(msg, flush=True)

    if config.run_dns:
        engine.register(DNSCensorshipModule().run(config), "DNS Censorship")
    if config.run_proxy:
        engine.register(ProxyDetectionModule().run(config), "Transparent Proxy")
    if config.run_tls:
        engine.register(TLSInspectionModule().run(config), "TLS Inspection")
    if config.run_sni:
        engine.register(SNIDetectionModule().run(config), "SNI Filtering")
    if config.run_throttle:
        engine.register(ThrottleDetectionModule().run(config), "Throttling")
    if config.run_ports:
        engine.register(PortBlockingModule().run(config), "Port Blocking")

    run_result: RunResult = await engine.run(
        progress=_progress if not config.quiet else None)

    # ── terminal report ───────────────────────────────────────────────────────
    use_colour = not args.no_colour and sys.stdout.isatty()
    print(terminal_report(run_result, use_colour=use_colour))

    # ── persist to SQLite ────────────────────────────────────────────────────
    storage = Storage(config.db_path)
    run_id  = await storage.save(run_result)
    if not config.quiet:
        print(f"  Run #{run_id} saved to {config.db_path}")

    # ── JSON export ───────────────────────────────────────────────────────────
    if config.json_output:
        out = save_json(run_result, config.json_output)
        print(f"  JSON saved to {out.resolve()}")

    # ── HTML report (always written to index.html) ────────────────────────────
    from generate_report import build_html
    import json as _json, dataclasses
    raw  = _json.loads(_json.dumps(dataclasses.asdict(run_result), default=str))
    html = build_html(raw)
    config.html_output.write_text(html, encoding="utf-8")
    print(f"  HTML report → {config.html_output.resolve()}")

    return 0


def main(argv=None) -> int:
    args = _parse(argv)
    return asyncio.run(_run(args))


if __name__ == "__main__":
    sys.exit(main())
