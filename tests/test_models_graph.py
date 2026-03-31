"""Tests for agent.models.graph — AttackGraph, GraphNode, GraphEdge."""

import pytest

from agent.models.graph import (
    AttackGraph,
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_linear_graph():
    """Build: host -> service -> vuln -> access."""
    g = AttackGraph()
    host = g.add_node(GraphNode(id="h1", node_type=NodeType.HOST, label="10.0.0.1"))
    svc = g.add_node(GraphNode(id="s1", node_type=NodeType.SERVICE, label="http:80"))
    vuln = g.add_node(
        GraphNode(id="v1", node_type=NodeType.VULNERABILITY, label="SQLi")
    )
    acc = g.add_node(GraphNode(id="a1", node_type=NodeType.ACCESS, label="shell"))

    g.add_edge(GraphEdge(source_id="h1", target_id="s1", edge_type=EdgeType.RUNS_ON))
    g.add_edge(GraphEdge(source_id="s1", target_id="v1", edge_type=EdgeType.EXPOSES))
    g.add_edge(GraphEdge(source_id="v1", target_id="a1", edge_type=EdgeType.EXPLOITS))
    return g


# ---------------------------------------------------------------------------
# Node / edge basics
# ---------------------------------------------------------------------------


def test_add_node():
    g = AttackGraph()
    n = g.add_node(GraphNode(id="n1", label="test"))
    assert g.get_node("n1") is n
    assert len(g.nodes) == 1


def test_add_edge_valid():
    g = AttackGraph()
    g.add_node(GraphNode(id="a", label="A"))
    g.add_node(GraphNode(id="b", label="B"))
    e = g.add_edge(GraphEdge(source_id="a", target_id="b"))
    assert len(g.edges) == 1


def test_add_edge_missing_source():
    g = AttackGraph()
    g.add_node(GraphNode(id="b", label="B"))
    with pytest.raises(ValueError, match="Source node"):
        g.add_edge(GraphEdge(source_id="missing", target_id="b"))


def test_add_edge_missing_target():
    g = AttackGraph()
    g.add_node(GraphNode(id="a", label="A"))
    with pytest.raises(ValueError, match="Target node"):
        g.add_edge(GraphEdge(source_id="a", target_id="missing"))


def test_get_node_missing():
    g = AttackGraph()
    assert g.get_node("nope") is None


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------


def test_get_paths_linear():
    g = _build_linear_graph()
    paths = g.get_paths("h1", "a1")
    assert len(paths) == 1
    assert paths[0] == ["h1", "s1", "v1", "a1"]


def test_get_paths_no_path():
    g = AttackGraph()
    g.add_node(GraphNode(id="a", label="A"))
    g.add_node(GraphNode(id="b", label="B"))
    # No edge connecting them
    assert g.get_paths("a", "b") == []


def test_get_paths_missing_node():
    g = AttackGraph()
    g.add_node(GraphNode(id="a", label="A"))
    assert g.get_paths("a", "missing") == []
    assert g.get_paths("missing", "a") == []


def test_get_paths_diamond():
    """A -> B -> D, A -> C -> D — should find two paths."""
    g = AttackGraph()
    for nid in ["a", "b", "c", "d"]:
        g.add_node(GraphNode(id=nid, label=nid.upper()))
    g.add_edge(GraphEdge(source_id="a", target_id="b"))
    g.add_edge(GraphEdge(source_id="a", target_id="c"))
    g.add_edge(GraphEdge(source_id="b", target_id="d"))
    g.add_edge(GraphEdge(source_id="c", target_id="d"))

    paths = g.get_paths("a", "d")
    assert len(paths) == 2


# ---------------------------------------------------------------------------
# Chains
# ---------------------------------------------------------------------------


def test_get_chains_linear():
    g = _build_linear_graph()
    chains = g.get_chains()
    assert len(chains) >= 1
    # Longest chain should be h1 -> s1 -> v1 -> a1
    longest = chains[0]
    assert len(longest) == 4
    assert longest[0].id == "h1"


def test_get_chains_empty_graph():
    g = AttackGraph()
    assert g.get_chains() == []


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def test_to_dict_from_dict_roundtrip():
    g = _build_linear_graph()
    d = g.to_dict()

    assert len(d["nodes"]) == 4
    assert len(d["edges"]) == 3

    restored = AttackGraph.from_dict(d)
    assert len(restored.nodes) == 4
    assert len(restored.edges) == 3
    assert restored.get_node("h1").label == "10.0.0.1"


def test_node_roundtrip():
    n = GraphNode(id="x", node_type=NodeType.CREDENTIAL, label="admin:pass")
    d = n.to_dict()
    assert d["node_type"] == "credential"
    r = GraphNode.from_dict(d)
    assert r.node_type == NodeType.CREDENTIAL
    assert r.label == "admin:pass"


def test_edge_roundtrip():
    e = GraphEdge(
        source_id="a", target_id="b", edge_type=EdgeType.GRANTS, label="ssh key"
    )
    d = e.to_dict()
    assert d["edge_type"] == "grants"
    r = GraphEdge.from_dict(d)
    assert r.edge_type == EdgeType.GRANTS


# ---------------------------------------------------------------------------
# Mermaid export
# ---------------------------------------------------------------------------


def test_to_mermaid_basic():
    g = _build_linear_graph()
    md = g.to_mermaid()
    assert md.startswith("graph LR")
    assert "h1" in md
    assert "10.0.0.1" in md
    assert "-->" in md


def test_to_mermaid_empty():
    g = AttackGraph()
    md = g.to_mermaid()
    assert md == "graph LR"
