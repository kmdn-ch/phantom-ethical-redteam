"""SQLite persistence layer for Phantom v3 mission data.

Each mission session maps to a single ``.db`` file.  The database uses
WAL journal mode for concurrent read access (live monitoring dashboards)
and foreign keys for referential integrity.  All queries use parameterized
placeholders -- no f-string interpolation in SQL, ever.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from agent.models.events import Event, EventType, Severity
from agent.models.findings import (
    ActionRecord,
    Finding,
    Hypothesis,
    HypothesisConfidence,
    TargetInfo,
)
from agent.models.state import MissionPhase, MissionState

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schema -- applied idempotently on first connection
# ---------------------------------------------------------------------------

_SCHEMA_SQL = """\
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS missions (
    id                TEXT PRIMARY KEY,
    phase             TEXT NOT NULL DEFAULT 'init',
    previous_phase    TEXT,
    turn              INTEGER NOT NULL DEFAULT 0,
    scope_hash        TEXT NOT NULL DEFAULT '',
    started_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    stealth_profile   TEXT NOT NULL DEFAULT 'normal',
    stall_count       INTEGER NOT NULL DEFAULT 0,
    total_findings    INTEGER NOT NULL DEFAULT 0,
    current_target    TEXT,
    error_message     TEXT,
    schema_version    INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS events (
    id                TEXT PRIMARY KEY,
    mission_id        TEXT NOT NULL REFERENCES missions(id),
    timestamp         TEXT NOT NULL,
    turn              INTEGER NOT NULL,
    event_type        TEXT NOT NULL,
    phase             TEXT NOT NULL,
    tool_name         TEXT,
    tool_input_json   TEXT,
    tool_output       TEXT,
    tool_duration_ms  INTEGER,
    severity          TEXT,
    target            TEXT,
    title             TEXT,
    description       TEXT,
    evidence          TEXT,
    cve_ids_json      TEXT,
    cvss_score        REAL,
    reasoning         TEXT,
    parent_event_ids  TEXT,
    metadata_json     TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_mission ON events(mission_id);
CREATE INDEX IF NOT EXISTS idx_events_turn    ON events(turn);
CREATE INDEX IF NOT EXISTS idx_events_type    ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)
    WHERE severity IN ('critical', 'high', 'medium');
CREATE INDEX IF NOT EXISTS idx_events_target  ON events(target)
    WHERE target IS NOT NULL;

CREATE TABLE IF NOT EXISTS findings (
    id                TEXT PRIMARY KEY,
    mission_id        TEXT NOT NULL REFERENCES missions(id),
    severity          TEXT NOT NULL DEFAULT 'info',
    category          TEXT NOT NULL DEFAULT '',
    title             TEXT NOT NULL DEFAULT '',
    target            TEXT NOT NULL DEFAULT '',
    evidence          TEXT NOT NULL DEFAULT '',
    tool_source       TEXT NOT NULL DEFAULT '',
    timestamp         TEXT NOT NULL,
    cvss              REAL,
    cve_id            TEXT,
    remediation       TEXT,
    screenshot_path   TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_target   ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_mission  ON findings(mission_id);

CREATE TABLE IF NOT EXISTS actions (
    id                TEXT PRIMARY KEY,
    mission_id        TEXT NOT NULL REFERENCES missions(id),
    tool              TEXT NOT NULL DEFAULT '',
    parameters_json   TEXT,
    result_summary    TEXT NOT NULL DEFAULT '',
    findings_produced TEXT,
    timestamp         TEXT NOT NULL,
    success           INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_actions_mission ON actions(mission_id);

CREATE TABLE IF NOT EXISTS hypotheses (
    id                TEXT PRIMARY KEY,
    mission_id        TEXT NOT NULL REFERENCES missions(id),
    statement         TEXT NOT NULL DEFAULT '',
    confidence        TEXT NOT NULL DEFAULT 'speculative',
    evidence_for      TEXT,
    evidence_against  TEXT,
    created_turn      INTEGER NOT NULL DEFAULT 0,
    last_updated_turn INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_hypotheses_mission ON hypotheses(mission_id);

CREATE TABLE IF NOT EXISTS targets (
    host              TEXT NOT NULL,
    mission_id        TEXT NOT NULL REFERENCES missions(id),
    ports_json        TEXT,
    services_json     TEXT,
    technologies_json TEXT,
    os_guess          TEXT,
    PRIMARY KEY (host, mission_id)
);

CREATE INDEX IF NOT EXISTS idx_targets_mission ON targets(mission_id);

CREATE TABLE IF NOT EXISTS graph_nodes (
    id                TEXT PRIMARY KEY,
    mission_id        TEXT NOT NULL REFERENCES missions(id),
    node_type         TEXT NOT NULL,
    label             TEXT NOT NULL,
    description       TEXT DEFAULT '',
    severity          TEXT DEFAULT 'none',
    phase             TEXT,
    turn              INTEGER,
    timestamp         TEXT NOT NULL,
    event_id          TEXT,
    fingerprint       TEXT,
    metadata_json     TEXT,
    UNIQUE (fingerprint, mission_id)
);

CREATE INDEX IF NOT EXISTS idx_gnodes_mission ON graph_nodes(mission_id);
CREATE INDEX IF NOT EXISTS idx_gnodes_type    ON graph_nodes(node_type);

CREATE TABLE IF NOT EXISTS graph_edges (
    id                TEXT PRIMARY KEY,
    mission_id        TEXT NOT NULL REFERENCES missions(id),
    source_id         TEXT NOT NULL REFERENCES graph_nodes(id),
    target_id         TEXT NOT NULL REFERENCES graph_nodes(id),
    edge_type         TEXT NOT NULL,
    label             TEXT DEFAULT '',
    turn              INTEGER,
    timestamp         TEXT NOT NULL,
    metadata_json     TEXT
);

CREATE INDEX IF NOT EXISTS idx_gedges_mission ON graph_edges(mission_id);
CREATE INDEX IF NOT EXISTS idx_gedges_source  ON graph_edges(source_id);
CREATE INDEX IF NOT EXISTS idx_gedges_target  ON graph_edges(target_id);
"""

SCHEMA_VERSION = 1


class MissionDB:
    """SQLite persistence wrapper for a single Phantom mission database.

    Usage::

        db = MissionDB("/path/to/mission.db")
        db.save_state(state)
        db.save_event(event)
        db.close()
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = str(Path(db_path).resolve())
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self.init_schema()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def init_schema(self) -> None:
        """Apply the full schema idempotently (CREATE IF NOT EXISTS)."""
        self._conn.executescript(_SCHEMA_SQL)
        logger.debug("Schema applied to %s", self._db_path)

    # ------------------------------------------------------------------
    # Mission state
    # ------------------------------------------------------------------

    def save_state(self, mission_state: MissionState) -> None:
        """Upsert the mission state (single row per mission_id)."""
        self._conn.execute(
            """INSERT OR REPLACE INTO missions
               (id, phase, previous_phase, turn, scope_hash, started_at,
                updated_at, stealth_profile, stall_count, total_findings,
                current_target, error_message, schema_version)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                mission_state.mission_id,
                mission_state.phase.value,
                mission_state.previous_phase.value
                if mission_state.previous_phase
                else None,
                mission_state.turn,
                mission_state.scope_hash,
                mission_state.started_at.isoformat(),
                mission_state.updated_at.isoformat(),
                mission_state.stealth_profile,
                mission_state.stall_count,
                mission_state.total_findings,
                mission_state.current_target,
                mission_state.error_message,
                SCHEMA_VERSION,
            ),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def save_event(self, event: Event) -> None:
        """Persist an immutable Event record."""
        self._conn.execute(
            """INSERT OR IGNORE INTO events
               (id, mission_id, timestamp, turn, event_type, phase,
                tool_name, tool_input_json, tool_output, tool_duration_ms,
                severity, target, title, description, evidence,
                cve_ids_json, cvss_score, reasoning, parent_event_ids,
                metadata_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event.id,
                event.mission_id,
                event.timestamp.isoformat(),
                event.turn,
                event.event_type.value,
                event.phase,
                event.tool_name,
                json.dumps(event.tool_input) if event.tool_input else None,
                event.tool_output,
                event.tool_duration_ms,
                event.severity.value if event.severity != Severity.NONE else None,
                event.target,
                event.title,
                event.description,
                event.evidence,
                json.dumps(event.cve_ids) if event.cve_ids else None,
                event.cvss_score,
                event.reasoning,
                json.dumps(event.parent_event_ids) if event.parent_event_ids else None,
                json.dumps(event.metadata) if event.metadata else None,
            ),
        )
        self._conn.commit()

    def load_events(self, mission_id: str) -> list[Event]:
        """Load the event timeline for a mission, ordered chronologically."""
        rows = self._conn.execute(
            "SELECT * FROM events WHERE mission_id = ? ORDER BY timestamp ASC",
            (mission_id,),
        ).fetchall()
        return [self._row_to_event(row) for row in rows]

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def save_finding(self, finding: Finding, mission_id: str) -> None:
        """Persist a Finding record."""
        self._conn.execute(
            """INSERT OR REPLACE INTO findings
               (id, mission_id, severity, category, title, target, evidence,
                tool_source, timestamp, cvss, cve_id, remediation,
                screenshot_path)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding.id,
                mission_id,
                finding.severity,
                finding.category,
                finding.title,
                finding.target,
                finding.evidence,
                finding.tool_source,
                finding.timestamp.isoformat(),
                finding.cvss,
                finding.cve_id,
                finding.remediation,
                finding.screenshot_path,
            ),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def save_action(self, action: ActionRecord, mission_id: str) -> None:
        """Persist an ActionRecord."""
        self._conn.execute(
            """INSERT OR REPLACE INTO actions
               (id, mission_id, tool, parameters_json, result_summary,
                findings_produced, timestamp, success)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                action.id,
                mission_id,
                action.tool,
                json.dumps(action.parameters) if action.parameters else None,
                action.result_summary,
                json.dumps(action.findings_produced)
                if action.findings_produced
                else None,
                action.timestamp.isoformat(),
                1 if action.success else 0,
            ),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Hypotheses
    # ------------------------------------------------------------------

    def save_hypothesis(self, hypothesis: Hypothesis, mission_id: str) -> None:
        """Persist a Hypothesis."""
        self._conn.execute(
            """INSERT OR REPLACE INTO hypotheses
               (id, mission_id, statement, confidence, evidence_for,
                evidence_against, created_turn, last_updated_turn)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                hypothesis.id,
                mission_id,
                hypothesis.statement,
                hypothesis.confidence.value,
                json.dumps(hypothesis.evidence_for)
                if hypothesis.evidence_for
                else None,
                json.dumps(hypothesis.evidence_against)
                if hypothesis.evidence_against
                else None,
                hypothesis.created_turn,
                hypothesis.last_updated_turn,
            ),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Targets
    # ------------------------------------------------------------------

    def save_target(self, target: TargetInfo, mission_id: str) -> None:
        """Persist a TargetInfo record."""
        self._conn.execute(
            """INSERT OR REPLACE INTO targets
               (host, mission_id, ports_json, services_json,
                technologies_json, os_guess)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                target.host,
                mission_id,
                json.dumps(target.ports) if target.ports else None,
                json.dumps({str(k): v for k, v in target.services.items()})
                if target.services
                else None,
                json.dumps(target.technologies) if target.technologies else None,
                target.os_guess,
            ),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Attack Graph
    # ------------------------------------------------------------------

    def save_graph(
        self,
        mission_id: str,
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> None:
        """Persist the full attack graph (nodes and edges).

        Accepts serialized node/edge dicts (as produced by AttackGraph's
        internal structures).  Uses INSERT OR IGNORE to avoid duplicates
        on repeated saves.
        """
        for node in nodes:
            self._conn.execute(
                """INSERT OR IGNORE INTO graph_nodes
                   (id, mission_id, node_type, label, description, severity,
                    phase, turn, timestamp, event_id, fingerprint,
                    metadata_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    node["id"],
                    mission_id,
                    node.get("node_type", ""),
                    node.get("label", ""),
                    node.get("description", ""),
                    node.get("severity", "none"),
                    node.get("phase"),
                    node.get("turn"),
                    node.get("timestamp", datetime.utcnow().isoformat()),
                    node.get("event_id"),
                    node.get("fingerprint"),
                    json.dumps(node.get("metadata")) if node.get("metadata") else None,
                ),
            )
        for edge in edges:
            self._conn.execute(
                """INSERT OR IGNORE INTO graph_edges
                   (id, mission_id, source_id, target_id, edge_type, label,
                    turn, timestamp, metadata_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    edge["id"],
                    mission_id,
                    edge["source_id"],
                    edge["target_id"],
                    edge.get("edge_type", ""),
                    edge.get("label", ""),
                    edge.get("turn"),
                    edge.get("timestamp", datetime.utcnow().isoformat()),
                    json.dumps(edge.get("metadata")) if edge.get("metadata") else None,
                ),
            )
        self._conn.commit()

    def load_graph(
        self, mission_id: str
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Load all graph nodes and edges for a mission."""
        node_rows = self._conn.execute(
            "SELECT * FROM graph_nodes WHERE mission_id = ?", (mission_id,)
        ).fetchall()
        edge_rows = self._conn.execute(
            "SELECT * FROM graph_edges WHERE mission_id = ?", (mission_id,)
        ).fetchall()
        nodes = [dict(r) for r in node_rows]
        edges = [dict(r) for r in edge_rows]
        # Deserialize JSON columns
        for n in nodes:
            if n.get("metadata_json"):
                n["metadata"] = json.loads(n["metadata_json"])
            else:
                n["metadata"] = {}
            del n["metadata_json"]
        for e in edges:
            if e.get("metadata_json"):
                e["metadata"] = json.loads(e["metadata_json"])
            else:
                e["metadata"] = {}
            del e["metadata_json"]
        return nodes, edges

    # ------------------------------------------------------------------
    # Full mission load / list
    # ------------------------------------------------------------------

    def load_mission(self, mission_id: str) -> dict[str, Any]:
        """Reconstruct the full persisted state for a mission.

        Returns a dict with keys: state, findings, actions, hypotheses,
        targets, events, graph_nodes, graph_edges.
        """
        # State
        row = self._conn.execute(
            "SELECT * FROM missions WHERE id = ?", (mission_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"Mission {mission_id!r} not found in database")

        state = MissionState(
            mission_id=row["id"],
            phase=MissionPhase(row["phase"]),
            previous_phase=MissionPhase(row["previous_phase"])
            if row["previous_phase"]
            else None,
            turn=row["turn"],
            scope_hash=row["scope_hash"],
            started_at=datetime.fromisoformat(row["started_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            stealth_profile=row["stealth_profile"],
            stall_count=row["stall_count"],
            total_findings=row["total_findings"],
            current_target=row["current_target"],
            error_message=row["error_message"],
        )

        # Findings
        finding_rows = self._conn.execute(
            "SELECT * FROM findings WHERE mission_id = ?", (mission_id,)
        ).fetchall()
        findings = [self._row_to_finding(r) for r in finding_rows]

        # Actions
        action_rows = self._conn.execute(
            "SELECT * FROM actions WHERE mission_id = ?", (mission_id,)
        ).fetchall()
        actions = [self._row_to_action(r) for r in action_rows]

        # Hypotheses
        hyp_rows = self._conn.execute(
            "SELECT * FROM hypotheses WHERE mission_id = ?", (mission_id,)
        ).fetchall()
        hypotheses = [self._row_to_hypothesis(r) for r in hyp_rows]

        # Targets
        target_rows = self._conn.execute(
            "SELECT * FROM targets WHERE mission_id = ?", (mission_id,)
        ).fetchall()
        targets = [self._row_to_target(r) for r in target_rows]

        # Events
        events = self.load_events(mission_id)

        # Graph
        graph_nodes, graph_edges = self.load_graph(mission_id)

        return {
            "state": state,
            "findings": findings,
            "actions": actions,
            "hypotheses": hypotheses,
            "targets": targets,
            "events": events,
            "graph_nodes": graph_nodes,
            "graph_edges": graph_edges,
        }

    def list_missions(self) -> list[dict[str, Any]]:
        """List all missions with a summary (id, phase, turn, findings, timestamps)."""
        rows = self._conn.execute(
            """SELECT id, phase, turn, total_findings, started_at, updated_at,
                      current_target, stealth_profile
               FROM missions ORDER BY updated_at DESC"""
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()

    def __enter__(self) -> MissionDB:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> Event:
        """Convert a database row back to an Event model."""
        cve_ids = json.loads(row["cve_ids_json"]) if row["cve_ids_json"] else []
        parent_ids = (
            json.loads(row["parent_event_ids"]) if row["parent_event_ids"] else []
        )
        metadata = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
        tool_input = (
            json.loads(row["tool_input_json"]) if row["tool_input_json"] else None
        )

        return Event(
            id=row["id"],
            mission_id=row["mission_id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            turn=row["turn"],
            event_type=EventType(row["event_type"]),
            phase=row["phase"],
            tool_name=row["tool_name"],
            tool_input=tool_input,
            tool_output=row["tool_output"],
            tool_duration_ms=row["tool_duration_ms"],
            severity=Severity(row["severity"]) if row["severity"] else Severity.NONE,
            target=row["target"],
            title=row["title"],
            description=row["description"],
            evidence=row["evidence"],
            cve_ids=cve_ids,
            cvss_score=row["cvss_score"],
            reasoning=row["reasoning"],
            parent_event_ids=parent_ids,
            metadata=metadata,
        )

    @staticmethod
    def _row_to_finding(row: sqlite3.Row) -> Finding:
        return Finding(
            id=row["id"],
            severity=row["severity"],
            category=row["category"],
            title=row["title"],
            target=row["target"],
            evidence=row["evidence"],
            tool_source=row["tool_source"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            cvss=row["cvss"],
            cve_id=row["cve_id"],
            remediation=row["remediation"],
            screenshot_path=row["screenshot_path"],
        )

    @staticmethod
    def _row_to_action(row: sqlite3.Row) -> ActionRecord:
        params = json.loads(row["parameters_json"]) if row["parameters_json"] else {}
        findings_produced = (
            json.loads(row["findings_produced"]) if row["findings_produced"] else []
        )
        return ActionRecord(
            id=row["id"],
            tool=row["tool"],
            parameters=params,
            result_summary=row["result_summary"],
            findings_produced=findings_produced,
            timestamp=datetime.fromisoformat(row["timestamp"]),
            success=bool(row["success"]),
        )

    @staticmethod
    def _row_to_hypothesis(row: sqlite3.Row) -> Hypothesis:
        evidence_for = json.loads(row["evidence_for"]) if row["evidence_for"] else []
        evidence_against = (
            json.loads(row["evidence_against"]) if row["evidence_against"] else []
        )
        return Hypothesis(
            id=row["id"],
            statement=row["statement"],
            confidence=HypothesisConfidence(row["confidence"]),
            evidence_for=evidence_for,
            evidence_against=evidence_against,
            created_turn=row["created_turn"],
            last_updated_turn=row["last_updated_turn"],
        )

    @staticmethod
    def _row_to_target(row: sqlite3.Row) -> TargetInfo:
        ports = json.loads(row["ports_json"]) if row["ports_json"] else []
        services = {}
        if row["services_json"]:
            raw = json.loads(row["services_json"])
            services = {int(k): v for k, v in raw.items()}
        techs = json.loads(row["technologies_json"]) if row["technologies_json"] else []
        return TargetInfo(
            host=row["host"],
            ports=ports,
            services=services,
            technologies=techs,
            os_guess=row["os_guess"],
        )
