"""Mission state machine: phases, valid transitions, and persistent state."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

import uuid


class MissionPhase(str, Enum):
    INIT = "init"
    RECON = "recon"
    ENUMERATE = "enumerate"
    EXPLOIT = "exploit"
    ESCALATE = "escalate"
    DEBRIEF = "debrief"
    COMPLETED = "completed"
    PAUSED = "paused"
    FAILED = "failed"
    ABORTED = "aborted"


_TERMINAL = {MissionPhase.COMPLETED, MissionPhase.FAILED, MissionPhase.ABORTED}

VALID_TRANSITIONS: set[tuple[MissionPhase, MissionPhase]] = {
    # Normal flow
    (MissionPhase.INIT, MissionPhase.RECON),
    (MissionPhase.RECON, MissionPhase.ENUMERATE),
    (MissionPhase.RECON, MissionPhase.DEBRIEF),
    (MissionPhase.ENUMERATE, MissionPhase.EXPLOIT),
    (MissionPhase.ENUMERATE, MissionPhase.DEBRIEF),
    (MissionPhase.EXPLOIT, MissionPhase.ESCALATE),
    (MissionPhase.EXPLOIT, MissionPhase.RECON),
    (MissionPhase.EXPLOIT, MissionPhase.DEBRIEF),
    (MissionPhase.ESCALATE, MissionPhase.RECON),
    (MissionPhase.ESCALATE, MissionPhase.DEBRIEF),
    (MissionPhase.DEBRIEF, MissionPhase.COMPLETED),
    # Any non-terminal phase can pause
    *((p, MissionPhase.PAUSED) for p in MissionPhase if p not in _TERMINAL),
    # Any non-terminal, non-completed phase can fail
    *(
        (p, MissionPhase.FAILED)
        for p in MissionPhase
        if p not in {MissionPhase.COMPLETED, MissionPhase.ABORTED}
    ),
    # Any non-terminal phase can abort
    *(
        (p, MissionPhase.ABORTED)
        for p in MissionPhase
        if p not in {MissionPhase.COMPLETED, MissionPhase.FAILED}
    ),
    # Resume from paused
    (MissionPhase.PAUSED, MissionPhase.RECON),
    (MissionPhase.PAUSED, MissionPhase.ENUMERATE),
    (MissionPhase.PAUSED, MissionPhase.EXPLOIT),
    (MissionPhase.PAUSED, MissionPhase.ESCALATE),
    (MissionPhase.PAUSED, MissionPhase.DEBRIEF),
}


class InvalidTransition(Exception):
    pass


class MissionState(BaseModel):
    """Persistent mission state -- serialized to SQLite after every transition."""

    mission_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    phase: MissionPhase = MissionPhase.INIT
    previous_phase: Optional[MissionPhase] = None
    turn: int = 0
    scope_hash: str = ""
    started_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    stealth_profile: str = "normal"
    stall_count: int = 0
    total_findings: int = 0
    current_target: Optional[str] = None
    error_message: Optional[str] = None

    def transition(self, to: MissionPhase) -> None:
        if (self.phase, to) not in VALID_TRANSITIONS:
            raise InvalidTransition(
                f"Cannot transition from {self.phase.value} to {to.value}"
            )
        self.previous_phase = self.phase
        self.phase = to
        self.updated_at = datetime.utcnow()

    def pause(self) -> None:
        self.transition(MissionPhase.PAUSED)

    def resume(self) -> None:
        if self.phase != MissionPhase.PAUSED:
            raise InvalidTransition("Can only resume from PAUSED state")
        if self.previous_phase is None:
            raise InvalidTransition("No previous phase recorded")
        target = self.previous_phase
        self.previous_phase = MissionPhase.PAUSED
        self.phase = target
        self.updated_at = datetime.utcnow()
