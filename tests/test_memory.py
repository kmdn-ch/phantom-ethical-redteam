"""Tests for agent.memory — MissionMemory, MissionDB persistence, TimelineBuilder."""

import os
import tempfile

import pytest

from agent.models.events import Event, EventType, Severity
from agent.models.findings import (
    ActionRecord,
    Finding,
    Hypothesis,
    HypothesisConfidence,
    TargetInfo,
)
from agent.models.state import MissionPhase, MissionState
from agent.memory.mission_memory import MissionMemory
from agent.memory.persistence import MissionDB
from agent.memory.timeline import TimelineBuilder

from datetime import datetime, timedelta


# ===========================================================================
# MissionMemory
# ===========================================================================


@pytest.fixture
def memory():
    return MissionMemory()


def test_add_finding(memory):
    f = Finding(id="f1", title="SQLi", severity="critical", target="10.0.0.1")
    memory.add_finding(f)
    assert "f1" in memory.findings
    assert memory.findings["f1"].title == "SQLi"


def test_add_finding_idempotent(memory):
    f = Finding(id="f1", title="v1")
    memory.add_finding(f)
    f2 = Finding(id="f1", title="v2")
    memory.add_finding(f2)
    assert memory.findings["f1"].title == "v2"
    assert len(memory.findings) == 1


def test_add_action(memory):
    a = ActionRecord(id="a1", tool="nmap", result_summary="3 ports")
    memory.add_action(a)
    assert "a1" in memory.actions


def test_add_hypothesis(memory):
    h = Hypothesis(id="h1", statement="Apache outdated")
    memory.add_hypothesis(h)
    assert "h1" in memory.hypotheses


def test_update_target_new(memory):
    t = TargetInfo(host="10.0.0.1", ports=[80, 443], services={80: "http"})
    memory.update_target(t)
    assert "10.0.0.1" in memory.target_map
    assert memory.target_map["10.0.0.1"].ports == [80, 443]


def test_update_target_merge(memory):
    t1 = TargetInfo(
        host="10.0.0.1", ports=[80], services={80: "http"}, technologies=["Apache"]
    )
    memory.update_target(t1)

    t2 = TargetInfo(
        host="10.0.0.1", ports=[443], services={443: "https"}, technologies=["PHP"]
    )
    memory.update_target(t2)

    merged = memory.target_map["10.0.0.1"]
    assert 80 in merged.ports
    assert 443 in merged.ports
    assert merged.services[80] == "http"
    assert merged.services[443] == "https"
    assert "Apache" in merged.technologies
    assert "PHP" in merged.technologies


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------


def test_unanswered_hypotheses(memory):
    memory.add_hypothesis(
        Hypothesis(id="h1", confidence=HypothesisConfidence.SPECULATIVE)
    )
    memory.add_hypothesis(
        Hypothesis(id="h2", confidence=HypothesisConfidence.CONFIRMED)
    )
    memory.add_hypothesis(Hypothesis(id="h3", confidence=HypothesisConfidence.PROBABLE))

    unanswered = memory.unanswered_hypotheses()
    ids = {h.id for h in unanswered}
    assert ids == {"h1", "h3"}


def test_unexplored_targets(memory):
    memory.update_target(TargetInfo(host="10.0.0.1"))
    memory.update_target(TargetInfo(host="10.0.0.2"))
    memory.add_finding(Finding(id="f1", target="10.0.0.1"))

    unexplored = memory.unexplored_targets()
    hosts = [t.host for t in unexplored]
    assert "10.0.0.2" in hosts
    assert "10.0.0.1" not in hosts


def test_findings_by_severity(memory):
    memory.add_finding(Finding(id="f1", severity="critical"))
    memory.add_finding(Finding(id="f2", severity="info"))
    memory.add_finding(Finding(id="f3", severity="critical"))

    by_sev = memory.findings_by_severity()
    assert "critical" in by_sev
    assert len(by_sev["critical"]) == 2
    # Critical should come before info in the dict ordering
    keys = list(by_sev.keys())
    assert keys.index("critical") < keys.index("info")


def test_findings_for_target(memory):
    memory.add_finding(Finding(id="f1", target="10.0.0.1"))
    memory.add_finding(Finding(id="f2", target="10.0.0.2"))
    memory.add_finding(Finding(id="f3", target="10.0.0.1"))

    results = memory.findings_for_target("10.0.0.1")
    assert len(results) == 2


# ---------------------------------------------------------------------------
# summary_for_context
# ---------------------------------------------------------------------------


def test_summary_for_context_basic(memory):
    memory.add_finding(
        Finding(id="f1", severity="high", title="XSS", target="10.0.0.1")
    )
    memory.update_target(TargetInfo(host="10.0.0.1", ports=[80], services={80: "http"}))
    memory.add_hypothesis(Hypothesis(id="h1", statement="Test hypothesis"))

    summary = memory.summary_for_context(max_tokens=4000)
    assert "XSS" in summary
    assert "10.0.0.1" in summary
    assert "Hypothesis" in summary or "hypothesis" in summary


def test_summary_for_context_truncation(memory):
    # Add many findings to exceed a very small budget
    for i in range(50):
        memory.add_finding(Finding(id=f"f{i}", severity="info", title=f"Finding {i}"))

    summary = memory.summary_for_context(max_tokens=100)
    assert "truncated" in summary


# ---------------------------------------------------------------------------
# Serialization roundtrip
# ---------------------------------------------------------------------------


def test_memory_to_dict_from_dict(memory):
    memory.add_finding(
        Finding(id="f1", severity="high", title="SQLi", target="10.0.0.1", cvss=8.5)
    )
    memory.add_action(ActionRecord(id="a1", tool="nmap"))
    memory.add_hypothesis(
        Hypothesis(id="h1", statement="test", confidence=HypothesisConfidence.PROBABLE)
    )
    memory.update_target(
        TargetInfo(host="10.0.0.1", ports=[80, 443], services={80: "http"})
    )

    d = memory.to_dict()
    restored = MissionMemory.from_dict(d)

    assert restored.findings["f1"].title == "SQLi"
    assert restored.actions["a1"].tool == "nmap"
    assert restored.hypotheses["h1"].confidence == HypothesisConfidence.PROBABLE
    assert restored.target_map["10.0.0.1"].services[80] == "http"


# ===========================================================================
# MissionDB — SQLite persistence
# ===========================================================================


@pytest.fixture
def db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    database = MissionDB(path)
    yield database
    database.close()
    os.unlink(path)


def test_save_and_load_state(db):
    state = MissionState(mission_id="m1", phase=MissionPhase.RECON, turn=5)
    db.save_state(state)

    data = db.load_mission("m1")
    loaded = data["state"]
    assert loaded.mission_id == "m1"
    assert loaded.phase == MissionPhase.RECON
    assert loaded.turn == 5


def test_save_and_load_finding(db):
    state = MissionState(mission_id="m1")
    db.save_state(state)

    f = Finding(id="f1", severity="critical", title="RCE", target="10.0.0.1", cvss=10.0)
    db.save_finding(f, "m1")

    data = db.load_mission("m1")
    findings = data["findings"]
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].cvss == 10.0


def test_save_and_load_action(db):
    state = MissionState(mission_id="m1")
    db.save_state(state)

    a = ActionRecord(
        id="a1", tool="nmap", parameters={"target": "10.0.0.1"}, success=True
    )
    db.save_action(a, "m1")

    data = db.load_mission("m1")
    actions = data["actions"]
    assert len(actions) == 1
    assert actions[0].tool == "nmap"


def test_save_and_load_hypothesis(db):
    state = MissionState(mission_id="m1")
    db.save_state(state)

    h = Hypothesis(
        id="h1",
        statement="Apache is outdated",
        confidence=HypothesisConfidence.PROBABLE,
        evidence_for=["Header: Apache/2.4.29"],
    )
    db.save_hypothesis(h, "m1")

    data = db.load_mission("m1")
    hyps = data["hypotheses"]
    assert len(hyps) == 1
    assert hyps[0].confidence == HypothesisConfidence.PROBABLE
    assert "Header: Apache/2.4.29" in hyps[0].evidence_for


def test_save_and_load_target(db):
    state = MissionState(mission_id="m1")
    db.save_state(state)

    t = TargetInfo(
        host="10.0.0.1", ports=[22, 80], services={80: "http"}, os_guess="Ubuntu"
    )
    db.save_target(t, "m1")

    data = db.load_mission("m1")
    targets = data["targets"]
    assert len(targets) == 1
    assert targets[0].host == "10.0.0.1"
    assert targets[0].services[80] == "http"


def test_save_and_load_event(db):
    state = MissionState(mission_id="m1")
    db.save_state(state)

    ev = Event(
        mission_id="m1",
        turn=1,
        event_type=EventType.TOOL_INVOKED,
        phase="recon",
        tool_name="nmap",
    )
    db.save_event(ev)

    events = db.load_events("m1")
    assert len(events) == 1
    assert events[0].tool_name == "nmap"
    assert events[0].event_type == EventType.TOOL_INVOKED


def test_load_mission_not_found(db):
    with pytest.raises(ValueError, match="not found"):
        db.load_mission("nonexistent")


def test_list_missions(db):
    s1 = MissionState(mission_id="m1", phase=MissionPhase.RECON)
    s2 = MissionState(mission_id="m2", phase=MissionPhase.EXPLOIT)
    db.save_state(s1)
    db.save_state(s2)

    missions = db.list_missions()
    ids = {m["id"] for m in missions}
    assert "m1" in ids
    assert "m2" in ids


def test_db_context_manager():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    with MissionDB(path) as database:
        state = MissionState(mission_id="ctx")
        database.save_state(state)
    os.unlink(path)


# ===========================================================================
# TimelineBuilder
# ===========================================================================


def _make_event(turn, event_type, phase="recon", delta_seconds=0, **kwargs):
    return Event(
        mission_id="m1",
        turn=turn,
        event_type=event_type,
        phase=phase,
        timestamp=datetime(2025, 1, 1) + timedelta(seconds=delta_seconds),
        **kwargs,
    )


def test_timeline_empty():
    tb = TimelineBuilder()
    result = tb.build_timeline([])
    assert result == []


def test_timeline_groups_by_phase():
    events = [
        _make_event(1, EventType.TOOL_INVOKED, phase="recon", delta_seconds=0),
        _make_event(2, EventType.TOOL_COMPLETED, phase="recon", delta_seconds=10),
        _make_event(3, EventType.TOOL_INVOKED, phase="enumerate", delta_seconds=20),
    ]
    tb = TimelineBuilder()
    phases = tb.build_timeline(events)

    assert len(phases) == 2
    assert phases[0]["phase"] == "recon"
    assert phases[0]["event_count"] == 2
    assert phases[1]["phase"] == "enumerate"


def test_timeline_counts_findings():
    events = [
        _make_event(1, EventType.FINDING_DISCOVERED, phase="recon", delta_seconds=0),
        _make_event(2, EventType.TOOL_INVOKED, phase="recon", delta_seconds=5),
        _make_event(3, EventType.FINDING_CONFIRMED, phase="recon", delta_seconds=10),
    ]
    tb = TimelineBuilder()
    phases = tb.build_timeline(events)
    assert phases[0]["findings_count"] == 2


def test_timeline_tracks_tools():
    events = [
        _make_event(
            1, EventType.TOOL_INVOKED, phase="recon", delta_seconds=0, tool_name="nmap"
        ),
        _make_event(
            2, EventType.TOOL_INVOKED, phase="recon", delta_seconds=5, tool_name="ffuf"
        ),
        _make_event(
            3, EventType.TOOL_INVOKED, phase="recon", delta_seconds=10, tool_name="nmap"
        ),
    ]
    tb = TimelineBuilder()
    phases = tb.build_timeline(events)
    assert phases[0]["tools_used"] == ["nmap", "ffuf"]


def test_timeline_to_markdown():
    events = [
        _make_event(
            1, EventType.TOOL_INVOKED, phase="recon", delta_seconds=0, tool_name="nmap"
        ),
        _make_event(
            2,
            EventType.FINDING_DISCOVERED,
            phase="recon",
            delta_seconds=30,
            severity=Severity.HIGH,
            title="Open admin panel",
        ),
    ]
    tb = TimelineBuilder()
    tb.build_timeline(events)
    md = tb.to_markdown()

    assert "# Mission Timeline" in md
    assert "RECON" in md
    assert "nmap" in md


def test_timeline_to_markdown_empty():
    tb = TimelineBuilder()
    tb.build_timeline([])
    md = tb.to_markdown()
    assert "No events" in md


def test_timeline_to_dict():
    events = [
        _make_event(1, EventType.TOOL_INVOKED, phase="recon", delta_seconds=0),
    ]
    tb = TimelineBuilder()
    tb.build_timeline(events)
    d = tb.to_dict()

    assert d["total_events"] == 1
    assert d["phase_count"] == 1
    assert len(d["phases"]) == 1
