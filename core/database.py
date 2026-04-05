"""
Guard SOC - Incident Database Layer
Stores every alert, detection result, and pipeline run permanently.
Uses Python's built-in sqlite3 — zero extra dependencies.
"""
import sqlite3
import json
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# Database lives in the project root
DB_PATH = Path(__file__).parent.parent / "guard_soc.db"


def get_connection() -> sqlite3.Connection:
    """Returns a database connection with row factory for dict-like access."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Creates the database and all tables on first run.
    Safe to call multiple times — uses IF NOT EXISTS.
    """
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                agent       TEXT    NOT NULL,
                status      TEXT    NOT NULL,
                threat_level TEXT   NOT NULL,
                payload     TEXT,
                result      TEXT    NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pipeline_runs (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT    NOT NULL,
                threat_type     TEXT    NOT NULL,
                payload         TEXT,
                detection       TEXT,
                ir_response     TEXT,
                threat_intel    TEXT,
                report          TEXT,
                deadman_fired   INTEGER DEFAULT 0,
                final_status    TEXT    NOT NULL
            )
        """)
        conn.commit()
    logger.info("Guard SOC database initialised at %s", DB_PATH)


def save_incident(agent: str, status: str, threat_level: str, payload: str, result: dict) -> int:
    """
    Saves a single detection agent result to the incidents table.
    Returns the new row ID.
    """
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO incidents (timestamp, agent, status, threat_level, payload, result)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.utcnow().isoformat(),
                agent,
                status,
                threat_level,
                str(payload)[:2000],  # cap payload size
                json.dumps(result)
            )
        )
        conn.commit()
        incident_id = cursor.lastrowid
        logger.info("Incident #%d saved — Agent: %s | Status: %s | Level: %s", incident_id, agent, status, threat_level)
        return incident_id


def save_pipeline_run(
    threat_type: str,
    payload: str,
    detection: dict,
    ir_response: dict = None,
    threat_intel: dict = None,
    report: dict = None,
    deadman_fired: bool = False,
    final_status: str = "COMPLETED"
) -> int:
    """
    Saves a complete orchestrator pipeline run to the pipeline_runs table.
    Returns the new row ID.
    """
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO pipeline_runs
                (timestamp, threat_type, payload, detection, ir_response, threat_intel, report, deadman_fired, final_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.utcnow().isoformat(),
                threat_type,
                str(payload)[:2000],
                json.dumps(detection) if detection else None,
                json.dumps(ir_response) if ir_response else None,
                json.dumps(threat_intel) if threat_intel else None,
                json.dumps(report) if report else None,
                1 if deadman_fired else 0,
                final_status
            )
        )
        conn.commit()
        run_id = cursor.lastrowid
        logger.info("Pipeline run #%d saved — Type: %s | Final: %s | Deadman: %s", run_id, threat_type, final_status, deadman_fired)
        return run_id


def get_all_incidents(limit: int = 100) -> list:
    """Returns the most recent incidents, newest first."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_all_pipeline_runs(limit: int = 50) -> list:
    """Returns the most recent pipeline runs, newest first."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM pipeline_runs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_incident_stats() -> dict:
    """Returns aggregate stats for the dashboard."""
    with get_connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        dangerous = conn.execute("SELECT COUNT(*) FROM incidents WHERE status = 'DANGEROUS'").fetchone()[0]
        critical = conn.execute("SELECT COUNT(*) FROM incidents WHERE threat_level = 'CRITICAL'").fetchone()[0]
        pipeline_runs = conn.execute("SELECT COUNT(*) FROM pipeline_runs").fetchone()[0]
        deadman_activations = conn.execute("SELECT COUNT(*) FROM pipeline_runs WHERE deadman_fired = 1").fetchone()[0]
        return {
            "total_incidents": total,
            "dangerous_incidents": dangerous,
            "critical_incidents": critical,
            "total_pipeline_runs": pipeline_runs,
            "deadman_activations": deadman_activations
        }
