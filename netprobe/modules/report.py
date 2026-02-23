"""
Report Module — terminal + JSON output from the new type system.

Accepts RunResult (list of ModuleResult / Finding) and renders a
clear, colour-coded terminal report.  JSON export is also available
for machine consumption and the HTML generator.
"""

from __future__ import annotations

import dataclasses
import json
import time
from pathlib import Path
from typing import Optional

from ..core.types import Finding, ModuleResult, RunResult, Severity

SEP  = "=" * 72
THIN = "-" * 72

SEV_COLOUR = {
    Severity.CLEAN:    "\033[32m",   # green
    Severity.INFO:     "\033[36m",   # cyan
    Severity.LOW:      "\033[33m",   # yellow
    Severity.MEDIUM:   "\033[33m",   # yellow
    Severity.HIGH:     "\033[31m",   # red
    Severity.CRITICAL: "\033[35m",   # magenta
}
RESET = "\033[0m"


def _c(sev: Severity, text: str, use_colour: bool = True) -> str:
    if not use_colour:
        return text
    return f"{SEV_COLOUR.get(sev, '')}{text}{RESET}"


def _severity_badge(sev: Severity) -> str:
    return f"[{sev.label.upper():<8}]"


def terminal_report(run: RunResult, use_colour: bool = True) -> str:
    lines: list[str] = []

    lines.append(f"\n{'#' * 72}")
    lines.append(f"  NetProbe v2 — Internet Censorship & Monitoring Detection")
    lines.append(f"  Scan completed: {run.timestamp}")
    lines.append(f"  Total duration: {run.duration_ms:.0f} ms")
    lines.append(f"  Overall score:  {run.overall_score}/100  "
                 f"({run.total_flagged} suspicious finding(s))")
    lines.append(f"{'#' * 72}")

    for mod in run.modules:
        lines.append(f"\n{SEP}")
        lines.append(f"  MODULE: {mod.module_name}")
        lines.append(f"  {mod.module_description}")
        lines.append(f"  Score: {mod.score}/100  |  "
                     f"Duration: {mod.duration_ms:.0f} ms  |  "
                     f"Summary: {mod.summary}")
        lines.append(SEP)

        if mod.error:
            lines.append(f"  !! Module error: {mod.error}")
            continue

        # Only print non-clean, non-sample findings here
        display = [f for f in mod.findings
                   if f.severity > Severity.CLEAN
                   and f.category != "THROTTLE_SAMPLE"]
        if not display:
            lines.append("  ✅  No issues detected.")
        else:
            for f in display:
                badge = _severity_badge(f.severity)
                coloured_badge = _c(f.severity, badge, use_colour)
                lines.append(f"\n  {coloured_badge} {f.title}")
                # Wrap detail at 68 chars
                for part in _wrap(f.detail, 68):
                    lines.append(f"      {part}")
                if f.domain:
                    lines.append(f"      Domain    : {f.domain}")
                if f.ip:
                    lines.append(f"      IP        : {f.ip}")
                lines.append(f"      Timestamp : {f.timestamp}")

    # ── overall summary ───────────────────────────────────────────────────────
    lines.append(f"\n{SEP}")
    lines.append("  OVERALL SUMMARY")
    lines.append(SEP)
    all_flagged = [f for m in run.modules for f in m.flagged_findings
                   if f.category != "THROTTLE_SAMPLE"]
    if not all_flagged:
        lines.append("  ✅  No suspicious findings. Connection looks clean.")
    else:
        by_sev: dict[Severity, list[Finding]] = {}
        for f in all_flagged:
            by_sev.setdefault(f.severity, []).append(f)
        for sev in sorted(by_sev.keys(), reverse=True):
            for f in by_sev[sev]:
                tag = _c(sev, _severity_badge(sev), use_colour)
                lines.append(f"  {tag} {f.title}")
    lines.append(f"\n{SEP}\n")

    return "\n".join(lines)


def save_json(run: RunResult, path: str | Path) -> Path:
    """Serialize a RunResult to a JSON file."""

    def _ser(obj):
        if dataclasses.is_dataclass(obj):
            return dataclasses.asdict(obj)
        if isinstance(obj, Severity):
            return {"value": int(obj), "label": obj.label}
        raise TypeError(f"Not serializable: {type(obj)}")

    out = Path(path)
    raw = dataclasses.asdict(run)
    out.write_text(json.dumps(raw, indent=2, default=str))
    return out


# ── helpers ────────────────────────────────────────────────────────────────────

def _wrap(text: str, width: int) -> list[str]:
    words, lines, current = text.split(), [], []
    length = 0
    for w in words:
        if length + len(w) + 1 > width and current:
            lines.append(" ".join(current))
            current, length = [], 0
        current.append(w)
        length += len(w) + 1
    if current:
        lines.append(" ".join(current))
    return lines or [""]
