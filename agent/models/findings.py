"""Finding, action, hypothesis, and target models for mission memory."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Optional

import uuid


class HypothesisConfidence(str, Enum):
    SPECULATIVE = "speculative"
    PROBABLE = "probable"
    CONFIRMED = "confirmed"
    DISPROVED = "disproved"


@dataclass
class Finding:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    severity: str = "info"  # critical, high, medium, low, info
    category: str = ""  # cve, misconfig, credential, exposure, etc.
    title: str = ""
    target: str = ""
    evidence: str = ""
    tool_source: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    cvss: Optional[float] = None
    cve_id: Optional[str] = None
    remediation: Optional[str] = None
    screenshot_path: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d

    @classmethod
    def from_dict(cls, data: dict) -> Finding:
        data = dict(data)
        if isinstance(data.get("timestamp"), str):
            data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        return cls(**data)


@dataclass
class ActionRecord:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    tool: str = ""
    parameters: dict = field(default_factory=dict)
    result_summary: str = ""
    findings_produced: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    success: bool = True

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d

    @classmethod
    def from_dict(cls, data: dict) -> ActionRecord:
        data = dict(data)
        if isinstance(data.get("timestamp"), str):
            data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        return cls(**data)


@dataclass
class Hypothesis:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    statement: str = ""
    confidence: HypothesisConfidence = HypothesisConfidence.SPECULATIVE
    evidence_for: list[str] = field(default_factory=list)
    evidence_against: list[str] = field(default_factory=list)
    created_turn: int = 0
    last_updated_turn: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["confidence"] = self.confidence.value
        return d

    @classmethod
    def from_dict(cls, data: dict) -> Hypothesis:
        data = dict(data)
        if isinstance(data.get("confidence"), str):
            data["confidence"] = HypothesisConfidence(data["confidence"])
        return cls(**data)


@dataclass
class TargetInfo:
    host: str = ""
    ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)  # port -> service name
    technologies: list[str] = field(default_factory=list)
    os_guess: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        # JSON keys must be strings, convert int port keys
        d["services"] = {str(k): v for k, v in self.services.items()}
        return d

    @classmethod
    def from_dict(cls, data: dict) -> TargetInfo:
        data = dict(data)
        if data.get("services"):
            data["services"] = {int(k): v for k, v in data["services"].items()}
        return cls(**data)
