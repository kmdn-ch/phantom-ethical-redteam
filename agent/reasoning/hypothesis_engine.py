"""Hypothesis-driven mission engine for Phantom v3.

Instead of running for a fixed number of turns, the mission is driven by a
priority queue of attack hypotheses.  Each hypothesis represents a testable
belief about the target system.  When a hypothesis is confirmed or disproved,
the engine automatically generates follow-up hypotheses based on finding type
and seeded domain knowledge.

The mission runs until one of these termination conditions is met:
  - All hypotheses are confirmed or disproved (queue exhausted, nothing in progress)
  - No new hypotheses are generated for N consecutive rounds (``dry_round_threshold``)
  - Maximum wall-clock time is exceeded (``max_wall_seconds``)
  - The caller signals stop (``force_stop()``)

Designed to be a drop-in engine alongside the PAOR loop in orchestrator.py.
It does NOT own the loop itself — it provides hypothesis scheduling and
follow-up generation that the orchestrator consults each turn.
"""

from __future__ import annotations

import heapq
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Priority constants (higher = tested first, maps to a min-heap negation)
# ---------------------------------------------------------------------------
PRI_CRITICAL = 1.0
PRI_HIGH = 0.8
PRI_MEDIUM = 0.6
PRI_LOW = 0.4
PRI_BACKGROUND = 0.2

# Finding types recognised by the follow-up generator
_FINDING_INJECTION = "injection"
_FINDING_EXPOSURE = "exposure"
_FINDING_AUTH = "auth"
_FINDING_CVE = "cve"
_FINDING_PORT = "port"
_FINDING_PANEL = "panel"

# Ports that trigger dedicated follow-up hypotheses
_PORT_SSH = {22}
_PORT_DB = {3306, 5432, 1433}

# Number of consecutive rounds with zero new hypotheses before is_exhausted() → True
_DEFAULT_DRY_ROUND_THRESHOLD = 3

# Default wall-clock cap (seconds).  None = no limit.
_DEFAULT_MAX_WALL_SECONDS: Optional[float] = None


# ---------------------------------------------------------------------------
# Core data model
# ---------------------------------------------------------------------------


class HypothesisStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    CONFIRMED = "confirmed"
    DISPROVED = "disproved"


@dataclass
class QueuedHypothesis:
    """A testable belief about the target, enriched for queue scheduling.

    This is the engine-internal representation.  It intentionally does not
    extend ``agent.reasoning.types.Hypothesis`` so that the engine remains
    self-contained and does not depend on modules owned by other agents.
    """

    id: str = field(default_factory=lambda: f"qh_{uuid.uuid4().hex[:8]}")
    statement: str = ""
    priority: float = PRI_MEDIUM  # 0.0 – 1.0, higher = test sooner
    category: str = (
        "general"  # injection | exposure | auth | cve | port | panel | recon
    )
    status: HypothesisStatus = HypothesisStatus.PENDING
    evidence: list[str] = field(default_factory=list)
    parent_id: Optional[str] = None  # ID of the hypothesis that spawned this one
    created_at: float = field(default_factory=time.time)
    tested_at: Optional[float] = None
    result: Optional[str] = None  # free-text result summary from the tester

    # ------------------------------------------------------------------
    # Heap comparison (min-heap negated to behave as max-heap by priority)
    # ------------------------------------------------------------------

    def __lt__(self, other: "QueuedHypothesis") -> bool:
        # Invert so that highest priority floats to the front of the heap.
        return self.priority > other.priority

    def __le__(self, other: "QueuedHypothesis") -> bool:
        return self.priority >= other.priority

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, QueuedHypothesis):
            return NotImplemented
        return self.id == other.id

    def __hash__(self) -> int:
        return hash(self.id)


# ---------------------------------------------------------------------------
# Follow-up generation rules
# ---------------------------------------------------------------------------


def _followups_for_injection(parent_id: str, context: str) -> list[QueuedHypothesis]:
    """Generate injection-specific follow-up hypotheses."""
    ctx = f" on {context}" if context else ""
    return [
        QueuedHypothesis(
            statement=f"Blind boolean-based SQLi exploitable{ctx}",
            priority=PRI_HIGH,
            category="injection",
            parent_id=parent_id,
        ),
        QueuedHypothesis(
            statement=f"Time-based SQLi exploitable{ctx}",
            priority=PRI_HIGH,
            category="injection",
            parent_id=parent_id,
        ),
        QueuedHypothesis(
            statement=f"Server-Side Template Injection (SSTI) present{ctx}",
            priority=PRI_HIGH,
            category="injection",
            parent_id=parent_id,
        ),
    ]


def _followups_for_exposure(parent_id: str, context: str) -> list[QueuedHypothesis]:
    ctx = f" at {context}" if context else ""
    return [
        QueuedHypothesis(
            statement=f"Exposed credentials readable{ctx} (env vars, config files, .htpasswd)",
            priority=PRI_HIGH,
            category="exposure",
            parent_id=parent_id,
        ),
        QueuedHypothesis(
            statement=f"Backup or archive files accessible{ctx} (.bak, .zip, .tar.gz, ~)",
            priority=PRI_MEDIUM,
            category="exposure",
            parent_id=parent_id,
        ),
    ]


def _followups_for_auth(parent_id: str, context: str) -> list[QueuedHypothesis]:
    ctx = f" on {context}" if context else ""
    return [
        QueuedHypothesis(
            statement=f"Password reuse across services{ctx}",
            priority=PRI_HIGH,
            category="auth",
            parent_id=parent_id,
        ),
        QueuedHypothesis(
            statement=f"Session token forgeable or predictable{ctx}",
            priority=PRI_HIGH,
            category="auth",
            parent_id=parent_id,
        ),
        QueuedHypothesis(
            statement=f"Privilege escalation possible after authentication{ctx}",
            priority=PRI_CRITICAL,
            category="auth",
            parent_id=parent_id,
        ),
    ]


def _followups_for_cve(parent_id: str, context: str) -> list[QueuedHypothesis]:
    ctx = f" affecting {context}" if context else ""
    return [
        QueuedHypothesis(
            statement=f"CVE{ctx} exploitable remotely without authentication",
            priority=PRI_CRITICAL,
            category="cve",
            parent_id=parent_id,
        ),
        QueuedHypothesis(
            statement=f"Lateral movement possible via CVE{ctx}",
            priority=PRI_HIGH,
            category="cve",
            parent_id=parent_id,
        ),
    ]


def _followups_for_port(parent_id: str, port: int) -> list[QueuedHypothesis]:
    if port in _PORT_SSH:
        return [
            QueuedHypothesis(
                statement=f"Weak or default SSH credentials on port {port}",
                priority=PRI_HIGH,
                category="auth",
                parent_id=parent_id,
            ),
            QueuedHypothesis(
                statement=f"SSH key reuse or exposed private key for port {port}",
                priority=PRI_MEDIUM,
                category="auth",
                parent_id=parent_id,
            ),
        ]
    if port in _PORT_DB:
        return [
            QueuedHypothesis(
                statement=f"Default or blank database credentials on port {port}",
                priority=PRI_HIGH,
                category="auth",
                parent_id=parent_id,
            ),
            QueuedHypothesis(
                statement=f"Database on port {port} directly accessible from the internet",
                priority=PRI_CRITICAL,
                category="exposure",
                parent_id=parent_id,
            ),
        ]
    return []


def _followups_for_panel(parent_id: str, context: str) -> list[QueuedHypothesis]:
    ctx = f" at {context}" if context else ""
    return [
        QueuedHypothesis(
            statement=f"Default credentials accepted by admin panel{ctx}",
            priority=PRI_CRITICAL,
            category="auth",
            parent_id=parent_id,
        ),
        QueuedHypothesis(
            statement=f"Authentication bypass possible on admin panel{ctx}",
            priority=PRI_CRITICAL,
            category="auth",
            parent_id=parent_id,
        ),
        QueuedHypothesis(
            statement=f"Privilege escalation possible from admin panel{ctx}",
            priority=PRI_HIGH,
            category="auth",
            parent_id=parent_id,
        ),
    ]


def _generate_followups(
    parent_id: str,
    finding: dict,
) -> list[QueuedHypothesis]:
    """Derive follow-up hypotheses from a single raw finding dict.

    The finding dict may contain any combination of:
      - ``type``    : one of injection | exposure | auth | cve | port | panel
      - ``title``   : free-text description used as context
      - ``url``     : URL context
      - ``port``    : integer port number (for port findings)
      - ``cve``     : CVE identifier (for CVE findings)
    """
    ftype = str(finding.get("type", "")).lower()
    context = (
        finding.get("url") or finding.get("title", "")[:80] or finding.get("host", "")
    )

    if ftype == _FINDING_INJECTION:
        return _followups_for_injection(parent_id, context)
    if ftype == _FINDING_EXPOSURE:
        return _followups_for_exposure(parent_id, context)
    if ftype == _FINDING_AUTH:
        return _followups_for_auth(parent_id, context)
    if ftype == _FINDING_CVE:
        return _followups_for_cve(parent_id, context)
    if ftype == _FINDING_PORT:
        port = int(finding.get("port", 0))
        return _followups_for_port(parent_id, port)
    if ftype == _FINDING_PANEL:
        return _followups_for_panel(parent_id, context)
    # Unknown finding type — no follow-ups generated
    return []


# ---------------------------------------------------------------------------
# HypothesisEngine
# ---------------------------------------------------------------------------


class HypothesisEngine:
    """Drives the mission via a priority queue of attack hypotheses.

    Instead of counting turns, the mission runs until:
    - All hypotheses are confirmed/disproved
    - No new hypotheses are generated for N consecutive rounds
    - Max wall-clock time exceeded
    - User interrupts (caller calls ``force_stop()``)

    Parameters
    ----------
    dry_round_threshold:
        Number of consecutive rounds with zero new or pending hypotheses
        before ``is_exhausted()`` returns True.
    max_wall_seconds:
        Maximum wall-clock time (seconds) before ``is_exhausted()`` returns
        True.  None means no time limit.
    """

    def __init__(
        self,
        dry_round_threshold: int = _DEFAULT_DRY_ROUND_THRESHOLD,
        max_wall_seconds: Optional[float] = _DEFAULT_MAX_WALL_SECONDS,
    ) -> None:
        self._dry_round_threshold = dry_round_threshold
        self._max_wall_seconds = max_wall_seconds
        self._start_time: float = time.time()

        # Min-heap of (negated_priority, insertion_order, QueuedHypothesis)
        # Using negated priority so the highest priority pops first from heapq.
        self._heap: list[tuple[float, int, QueuedHypothesis]] = []
        self._insertion_counter: int = 0

        # Registry of all hypotheses (by ID) for status tracking
        self._registry: dict[str, QueuedHypothesis] = {}

        # Hypotheses currently being tested (popped from heap, not yet marked)
        self._in_progress: set[str] = set()

        # Dry-round counter: incremented when get_next_hypotheses returns empty
        # while no hypotheses are in-progress; reset when new hypotheses arrive.
        self._consecutive_dry_rounds: int = 0

        # Force-stop flag set by external callers
        self._force_stopped: bool = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_hypothesis(
        self,
        statement: str,
        priority: float,
        category: str = "general",
        evidence: Optional[list[str]] = None,
        parent_id: Optional[str] = None,
    ) -> QueuedHypothesis:
        """Create a hypothesis and add it to the priority queue.

        Parameters
        ----------
        statement:  Human-readable testable claim.
        priority:   Float 0.0–1.0. Higher = scheduled sooner.
        category:   Semantic type tag (injection, exposure, auth, cve, port, panel, recon, general).
        evidence:   Optional list of evidence strings carried from the parent finding.
        parent_id:  ID of the hypothesis that triggered this one (for lineage).

        Returns
        -------
        The newly created ``QueuedHypothesis`` (status PENDING).
        """
        priority = max(0.0, min(1.0, float(priority)))
        hyp = QueuedHypothesis(
            statement=statement,
            priority=priority,
            category=category,
            evidence=list(evidence) if evidence else [],
            parent_id=parent_id,
        )
        self._enqueue(hyp)
        logger.debug(
            "Hypothesis added [%s] pri=%.2f cat=%s: %s",
            hyp.id,
            priority,
            category,
            statement[:80],
        )
        return hyp

    def get_next_hypotheses(self, n: int = 3) -> list[QueuedHypothesis]:
        """Pop the top N pending hypotheses to test in the next round.

        Popped hypotheses are moved to IN_PROGRESS status.  Returns an empty
        list if the queue is exhausted.  The engine tracks consecutive empty
        returns to support ``is_exhausted()``.
        """
        results: list[QueuedHypothesis] = []
        while len(results) < n and self._heap:
            _, _, hyp = heapq.heappop(self._heap)
            # Guard against hypotheses that were marked while in the heap
            if hyp.status != HypothesisStatus.PENDING:
                continue
            hyp.status = HypothesisStatus.IN_PROGRESS
            self._in_progress.add(hyp.id)
            results.append(hyp)

        if not results and not self._in_progress:
            self._consecutive_dry_rounds += 1
            logger.debug(
                "Dry round %d/%d — no pending or in-progress hypotheses",
                self._consecutive_dry_rounds,
                self._dry_round_threshold,
            )
        else:
            # Any activity (either results returned OR hypotheses still in flight)
            # resets the dry-round streak
            self._consecutive_dry_rounds = 0

        return results

    def mark_tested(
        self,
        hypothesis_id: str,
        result: str,
        new_findings: Optional[list[dict]] = None,
    ) -> list[QueuedHypothesis]:
        """Record the outcome of testing a hypothesis.

        If the hypothesis is CONFIRMED and ``new_findings`` are provided,
        follow-up hypotheses are automatically generated and added to the
        queue.

        Parameters
        ----------
        hypothesis_id:  ID of the hypothesis being closed.
        result:         One of ``"confirmed"`` or ``"disproved"`` (case-insensitive).
        new_findings:   Raw finding dicts (may include ``type``, ``url``, ``port``, etc.)
                        used to generate follow-up hypotheses.

        Returns
        -------
        List of newly generated follow-up ``QueuedHypothesis`` objects
        (empty if none were generated).
        """
        hyp = self._registry.get(hypothesis_id)
        if hyp is None:
            logger.warning(
                "mark_tested called with unknown hypothesis id: %s", hypothesis_id
            )
            return []

        result_lower = result.strip().lower()
        if result_lower == "confirmed":
            hyp.status = HypothesisStatus.CONFIRMED
        else:
            hyp.status = HypothesisStatus.DISPROVED

        hyp.tested_at = time.time()
        hyp.result = result
        self._in_progress.discard(hypothesis_id)

        # Generate follow-up hypotheses when confirmed
        followups: list[QueuedHypothesis] = []
        if hyp.status == HypothesisStatus.CONFIRMED and new_findings:
            for finding in new_findings:
                generated = _generate_followups(hyp.id, finding)
                for fup in generated:
                    self._enqueue(fup)
                    followups.append(fup)
                    logger.info(
                        "Follow-up hypothesis queued [%s] from finding type=%s: %s",
                        fup.id,
                        finding.get("type", "?"),
                        fup.statement[:80],
                    )

        return followups

    def is_exhausted(self) -> bool:
        """Return True if the engine has no more work to schedule.

        Termination conditions (any one is sufficient):
        1. Queue empty AND no in-progress hypotheses AND dry rounds >= threshold.
        2. Wall-clock time exceeded (if ``max_wall_seconds`` is set).
        3. ``force_stop()`` was called.
        """
        if self._force_stopped:
            return True
        if self._max_wall_seconds is not None:
            if (time.time() - self._start_time) >= self._max_wall_seconds:
                logger.info(
                    "HypothesisEngine: wall-clock limit reached (%.0fs)",
                    self._max_wall_seconds,
                )
                return True
        if (
            not self._heap
            and not self._in_progress
            and self._consecutive_dry_rounds >= self._dry_round_threshold
        ):
            logger.info(
                "HypothesisEngine: exhausted after %d consecutive dry rounds",
                self._consecutive_dry_rounds,
            )
            return True
        return False

    def force_stop(self) -> None:
        """Signal the engine to halt at the next ``is_exhausted()`` check."""
        self._force_stopped = True
        logger.info("HypothesisEngine: force_stop requested")

    def to_prompt_summary(self, max_items: int = 5) -> str:
        """Return a compact string of top hypotheses for injection into the system prompt.

        Shows the highest-priority pending hypotheses plus a brief status
        line about confirmed/disproved counts.  Designed to fit within a
        limited token budget.
        """
        lines: list[str] = []

        # Pull top pending hypotheses without dequeuing them
        pending = [
            hyp
            for hyp in self._registry.values()
            if hyp.status == HypothesisStatus.PENDING
        ]
        # Sort by priority descending for display
        pending.sort(key=lambda h: -h.priority)

        in_progress = [
            h
            for h in self._registry.values()
            if h.status == HypothesisStatus.IN_PROGRESS
        ]
        confirmed = sum(
            1 for h in self._registry.values() if h.status == HypothesisStatus.CONFIRMED
        )
        disproved = sum(
            1 for h in self._registry.values() if h.status == HypothesisStatus.DISPROVED
        )

        total = len(self._registry)
        lines.append(
            f"Hypotheses: {total} total | {len(pending)} pending | "
            f"{len(in_progress)} in-progress | {confirmed} confirmed | {disproved} disproved"
        )

        if in_progress:
            lines.append("Testing now:")
            for h in in_progress[:3]:
                lines.append(
                    f"  [TESTING] [{h.id}] pri={h.priority:.2f} ({h.category}): {h.statement[:80]}"
                )

        top_pending = pending[:max_items]
        if top_pending:
            lines.append("Next to test:")
            for h in top_pending:
                lines.append(
                    f"  [PENDING] [{h.id}] pri={h.priority:.2f} ({h.category}): {h.statement[:80]}"
                )

        if not in_progress and not pending:
            lines.append("Queue exhausted — no pending hypotheses.")

        return "\n".join(lines)

    @classmethod
    def from_findings(cls, findings: list[dict]) -> list[QueuedHypothesis]:
        """Generate follow-up hypotheses from a list of raw finding dicts.

        This is a pure class-method factory — it does NOT add the hypotheses
        to any queue.  The caller is responsible for adding them.

        Parameters
        ----------
        findings: List of raw finding dicts (each with at least a ``type`` key).

        Returns
        -------
        Flat list of ``QueuedHypothesis`` objects derived from the findings.
        """
        results: list[QueuedHypothesis] = []
        seen_statements: set[str] = set()
        for finding in findings:
            generated = _generate_followups(parent_id="external", finding=finding)
            for h in generated:
                # Deduplicate by statement to avoid flooding identical hypotheses
                if h.statement not in seen_statements:
                    seen_statements.add(h.statement)
                    results.append(h)
        return results

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def all_hypotheses(self) -> list[QueuedHypothesis]:
        """Return all hypotheses ever registered, ordered by creation time."""
        return sorted(self._registry.values(), key=lambda h: h.created_at)

    def pending_count(self) -> int:
        """Number of hypotheses still in the priority queue (PENDING status)."""
        return sum(
            1 for h in self._registry.values() if h.status == HypothesisStatus.PENDING
        )

    def in_progress_count(self) -> int:
        """Number of hypotheses currently being tested."""
        return len(self._in_progress)

    def stats(self) -> dict:
        """Return a snapshot of engine statistics."""
        return {
            "total": len(self._registry),
            "pending": self.pending_count(),
            "in_progress": self.in_progress_count(),
            "confirmed": sum(
                1
                for h in self._registry.values()
                if h.status == HypothesisStatus.CONFIRMED
            ),
            "disproved": sum(
                1
                for h in self._registry.values()
                if h.status == HypothesisStatus.DISPROVED
            ),
            "consecutive_dry_rounds": self._consecutive_dry_rounds,
            "elapsed_seconds": time.time() - self._start_time,
            "force_stopped": self._force_stopped,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _enqueue(self, hyp: QueuedHypothesis) -> None:
        """Add a QueuedHypothesis to the heap and registry."""
        self._registry[hyp.id] = hyp
        # Negate priority so heapq (a min-heap) pops highest priority first.
        # Use insertion_counter as a tie-breaker to keep ordering stable (FIFO
        # among equal-priority items).
        heapq.heappush(self._heap, (-hyp.priority, self._insertion_counter, hyp))
        self._insertion_counter += 1
        # Any new hypothesis resets the dry-round streak
        self._consecutive_dry_rounds = 0
