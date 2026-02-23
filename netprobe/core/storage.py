"""
SQLite Time-Series Storage

Every scan is persisted so users can track censorship trends over time.
The schema is append-only: we never update rows, only insert new ones.

Tables
------
runs     — one row per scan, stores metadata and overall score
findings — one row per Finding, linked to a run

Usage
-----
    storage = Storage("netprobe.db")
    await storage.save(run_result)
    history = await storage.recent_runs(10)
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from pathlib import Path
from typing import Optional

from .types import Finding, ModuleResult, RunResult, Severity

DDL = """
CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    duration_ms REAL,
    overall_score INTEGER,
    total_flagged INTEGER,
    modules_run TEXT    -- JSON list of module names
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL REFERENCES runs(id),
    module_name TEXT    NOT NULL,
    category    TEXT,
    domain      TEXT,
    ip          TEXT,
    severity    INTEGER,
    severity_label TEXT,
    title       TEXT,
    detail      TEXT,
    timestamp   TEXT,
    raw_json    TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_run   ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_sev   ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_domain ON findings(domain);
"""


class Storage:
    def __init__(self, db_path: str | Path = "netprobe.db") -> None:
        self._path = str(db_path)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path)
        conn.row_factory = sqlite3.Row
        conn.executescript(DDL)
        conn.commit()
        return conn

    # run in a thread so we don't block the event loop
    async def _execute(self, fn):
        return await asyncio.to_thread(fn)

    async def save(self, run: RunResult) -> int:
        """Persist a RunResult and return the generated run_id."""

        def _save():
            conn = self._connect()
            cur  = conn.cursor()
            cur.execute(
                """INSERT INTO runs
                   (timestamp, duration_ms, overall_score, total_flagged, modules_run)
                   VALUES (?,?,?,?,?)""",
                (
                    run.timestamp,
                    run.duration_ms,
                    run.overall_score,
                    run.total_flagged,
                    json.dumps([m.module_name for m in run.modules]),
                ),
            )
            run_id = cur.lastrowid

            for mod in run.modules:
                for f in mod.findings:
                    cur.execute(
                        """INSERT INTO findings
                           (run_id, module_name, category, domain, ip,
                            severity, severity_label, title, detail,
                            timestamp, raw_json)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            run_id,
                            mod.module_name,
                            f.category,
                            f.domain,
                            f.ip,
                            int(f.severity),
                            f.severity.label,
                            f.title,
                            f.detail,
                            f.timestamp,
                            json.dumps(f.raw),
                        ),
                    )
            conn.commit()
            conn.close()
            return run_id

        run_id = await self._execute(_save)
        run.run_id = run_id
        return run_id

    async def recent_runs(self, limit: int = 20) -> list[dict]:
        """Return the most recent *limit* run summaries."""

        def _fetch():
            conn = self._connect()
            rows = conn.execute(
                """SELECT id, timestamp, duration_ms, overall_score,
                          total_flagged, modules_run
                   FROM runs ORDER BY id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
            conn.close()
            return [dict(r) for r in rows]

        return await self._execute(_fetch)

    async def findings_for_domain(self,
                                   domain: str,
                                   limit: int = 50) -> list[dict]:
        """Fetch recent findings for a specific domain across all runs."""

        def _fetch():
            conn = self._connect()
            rows = conn.execute(
                """SELECT f.*, r.timestamp as run_ts
                   FROM findings f JOIN runs r ON f.run_id = r.id
                   WHERE f.domain = ?
                   ORDER BY f.id DESC LIMIT ?""",
                (domain, limit),
            ).fetchall()
            conn.close()
            return [dict(r) for r in rows]

        return await self._execute(_fetch)

    async def severity_trend(self, days: int = 30) -> list[dict]:
        """Daily max severity score — useful for plotting trends."""

        def _fetch():
            conn = self._connect()
            rows = conn.execute(
                """SELECT date(timestamp) as day,
                          MAX(overall_score) as max_score,
                          COUNT(*) as num_runs
                   FROM runs
                   WHERE timestamp >= date('now', ?)
                   GROUP BY day ORDER BY day""",
                (f"-{days} days",),
            ).fetchall()
            conn.close()
            return [dict(r) for r in rows]

        return await self._execute(_fetch)
