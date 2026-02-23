"""
Shared data types for the entire NetProbe ecosystem.

Every module produces Finding objects, wrapped in a ModuleResult.
This single contract lets the engine, storage, and report layers remain
completely decoupled from module internals.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional


class Severity(IntEnum):
    """Ordered severity levels.  Higher = worse."""
    CLEAN    = 0
    INFO     = 10
    LOW      = 25
    MEDIUM   = 50
    HIGH     = 75
    CRITICAL = 100

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @property
    def emoji(self) -> str:
        return {
            self.CLEAN:    "✅",
            self.INFO:     "ℹ️",
            self.LOW:      "🟡",
            self.MEDIUM:   "🟠",
            self.HIGH:     "🔴",
            self.CRITICAL: "🚨",
        }[self]


@dataclass
class Finding:
    """
    A single discrete observation produced by a module.

    Attributes:
        title    — short human-readable label
        detail   — full explanation; should be understandable to non-experts
        severity — how serious this is
        category — which detection category (DNS / TLS / SNI / PROXY / etc.)
        domain   — domain under test, if applicable
        ip       — IP address observed, if applicable
        timestamp— ISO-8601 wall-clock time when this finding was recorded
        raw      — arbitrary extra data for JSON export / programmatic use
    """
    title:     str
    detail:    str
    severity:  Severity
    category:  str
    domain:    str = ""
    ip:        str = ""
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    raw:       dict[str, Any] = field(default_factory=dict)


@dataclass
class ModuleResult:
    """
    Aggregated output from a single detection module.

    score — 0-100 derived from the worst Finding severity; used for the
            overall dashboard.  0 = fully clean, 100 = critical issue.
    """
    module_name:        str
    module_description: str
    findings:           list[Finding] = field(default_factory=list)
    summary:            str = ""
    duration_ms:        float = 0.0
    error:              str = ""
    timestamp:          str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S%z"))

    @property
    def score(self) -> int:
        if not self.findings:
            return 0
        return max(int(f.severity) for f in self.findings)

    @property
    def worst_severity(self) -> Severity:
        if not self.findings:
            return Severity.CLEAN
        return Severity(self.score)

    @property
    def flagged_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity > Severity.CLEAN]


@dataclass
class RunResult:
    """Complete output of one full NetProbe scan."""
    run_id:     Optional[int]           # set by Storage after persisting
    timestamp:  str
    duration_ms: float
    modules:    list[ModuleResult] = field(default_factory=list)

    @property
    def overall_score(self) -> int:
        if not self.modules:
            return 0
        return max(m.score for m in self.modules)

    @property
    def total_flagged(self) -> int:
        return sum(len(m.flagged_findings) for m in self.modules)
