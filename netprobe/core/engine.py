"""
Async Engine — orchestrates concurrent module execution.

Each registered module runs inside asyncio.wait_for() so a slow or hanging
module cannot block the rest of the scan.  Progress is reported through an
optional async callback so CLI and future GUI consumers can both use it.
"""

from __future__ import annotations

import asyncio
import time
from typing import Callable, Coroutine, Optional

from .config import Config
from .types import ModuleResult, RunResult


ProgressFn = Callable[[str], None]


class Engine:
    """
    Drives the full scan lifecycle:

        engine = Engine(config)
        result = await engine.run(progress_callback=print)
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        self._modules: list[tuple[str, Coroutine]] = []

    # ── module registration ───────────────────────────────────────────────────

    def register(self, coro: Coroutine, name: str) -> None:
        """Queue a module coroutine for execution."""
        self._modules.append((name, coro))

    # ── execution ─────────────────────────────────────────────────────────────

    async def run(self,
                  progress: Optional[ProgressFn] = None) -> RunResult:
        start = time.monotonic()
        ts    = time.strftime("%Y-%m-%dT%H:%M:%S%z")

        def _emit(msg: str) -> None:
            if progress and not self.config.quiet:
                progress(msg)

        tasks = []
        for name, coro in self._modules:
            tasks.append(self._run_module(name, coro, _emit))

        results: list[ModuleResult] = await asyncio.gather(*tasks)

        total_ms = (time.monotonic() - start) * 1000
        return RunResult(
            run_id=None,
            timestamp=ts,
            duration_ms=round(total_ms, 1),
            modules=results,
        )

    async def _run_module(self,
                          name: str,
                          coro: Coroutine,
                          emit: ProgressFn) -> ModuleResult:
        emit(f"\n{'─'*60}")
        emit(f"▶  Starting: {name}")
        start = time.monotonic()
        try:
            result: ModuleResult = await asyncio.wait_for(
                coro, timeout=self.config.module_timeout)
        except asyncio.TimeoutError:
            elapsed = (time.monotonic() - start) * 1000
            result = ModuleResult(
                module_name=name,
                module_description="",
                summary=f"Module timed out after {self.config.module_timeout:.0f}s.",
                duration_ms=round(elapsed, 1),
                error="timeout",
            )
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            result = ModuleResult(
                module_name=name,
                module_description="",
                summary=f"Module crashed: {exc}",
                duration_ms=round(elapsed, 1),
                error=str(exc),
            )

        elapsed = (time.monotonic() - start) * 1000
        result.duration_ms = round(elapsed, 1)
        emit(f"✔  Done: {name}  ({result.duration_ms:.0f} ms)  "
             f"score={result.score}  findings={len(result.flagged_findings)}")
        return result
