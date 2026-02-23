"""
BaseModule — the interface every detection module must implement.

To add a new detection module:

    1. Create netprobe/modules/my_module.py
    2. Define a class inheriting from BaseModule
    3. Set  name  and  description  class attributes
    4. Implement  async def run(self, config: Config) -> ModuleResult
    5. Register the module in __main__.py

The engine calls run() with a timeout and handles all exceptions, so
modules can raise freely without breaking the scan.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod

from ..core.config import Config
from ..core.types import Finding, ModuleResult, Severity


class BaseModule(ABC):
    """Abstract base for all NetProbe detection modules."""

    name:        str = "unnamed"
    description: str = ""

    @abstractmethod
    async def run(self, config: Config) -> ModuleResult:
        """Execute all tests in this module and return a ModuleResult."""

    # ── helpers available to every module ─────────────────────────────────────

    def _result(self, findings: list[Finding], summary: str = "") -> ModuleResult:
        """Convenience constructor for ModuleResult."""
        if not summary:
            flagged = [f for f in findings if f.severity > Severity.CLEAN]
            if not flagged:
                summary = "All checks passed — no issues detected."
            else:
                worst = max(f.severity for f in flagged)
                summary = (
                    f"{len(flagged)} finding(s), worst severity: "
                    f"{worst.label} {worst.emoji}"
                )
        return ModuleResult(
            module_name=self.name,
            module_description=self.description,
            findings=findings,
            summary=summary,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        )

    @staticmethod
    def _finding(title: str,
                 detail: str,
                 severity: Severity,
                 category: str,
                 domain: str = "",
                 ip: str = "",
                 **raw) -> Finding:
        return Finding(
            title=title, detail=detail, severity=severity,
            category=category, domain=domain, ip=ip,
            raw=raw,
        )

    @staticmethod
    def _clean(title: str, category: str, domain: str = "") -> Finding:
        return Finding(
            title=title,
            detail="No issue detected.",
            severity=Severity.CLEAN,
            category=category,
            domain=domain,
        )
