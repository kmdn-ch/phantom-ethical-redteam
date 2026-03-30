"""Attack graph: directed graph of nodes (discoveries) and edges (relationships)."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional

import uuid


class NodeType(str, Enum):
    HOST = "host"
    SERVICE = "service"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    ACCESS = "access"
    DATA = "data"


class EdgeType(str, Enum):
    RUNS_ON = "runs_on"
    EXPOSES = "exposes"
    EXPLOITS = "exploits"
    GRANTS = "grants"
    LEADS_TO = "leads_to"
    EXFILTRATES = "exfiltrates"


@dataclass
class GraphNode:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:10])
    node_type: NodeType = NodeType.HOST
    label: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    event_id: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["node_type"] = self.node_type.value
        return d

    @classmethod
    def from_dict(cls, data: dict) -> GraphNode:
        data = dict(data)
        if isinstance(data.get("node_type"), str):
            data["node_type"] = NodeType(data["node_type"])
        return cls(**data)


@dataclass
class GraphEdge:
    source_id: str = ""
    target_id: str = ""
    edge_type: EdgeType = EdgeType.LEADS_TO
    label: str = ""
    event_id: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["edge_type"] = self.edge_type.value
        return d

    @classmethod
    def from_dict(cls, data: dict) -> GraphEdge:
        data = dict(data)
        if isinstance(data.get("edge_type"), str):
            data["edge_type"] = EdgeType(data["edge_type"])
        return cls(**data)


class AttackGraph:
    """In-memory directed graph tracking the attack surface and exploitation paths."""

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._edges: list[GraphEdge] = []
        self._adjacency: dict[str, list[int]] = {}  # node_id -> [edge indices]

    def add_node(self, node: GraphNode) -> GraphNode:
        self._nodes[node.id] = node
        self._adjacency.setdefault(node.id, [])
        return node

    def add_edge(self, edge: GraphEdge) -> GraphEdge:
        if edge.source_id not in self._nodes:
            raise ValueError(f"Source node {edge.source_id} does not exist")
        if edge.target_id not in self._nodes:
            raise ValueError(f"Target node {edge.target_id} does not exist")
        idx = len(self._edges)
        self._edges.append(edge)
        self._adjacency.setdefault(edge.source_id, []).append(idx)
        return edge

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        return self._nodes.get(node_id)

    @property
    def nodes(self) -> list[GraphNode]:
        return list(self._nodes.values())

    @property
    def edges(self) -> list[GraphEdge]:
        return list(self._edges)

    def get_paths(
        self, from_id: str, to_id: str, max_depth: int = 10
    ) -> list[list[str]]:
        """Return all simple paths (as lists of node IDs) between two nodes."""
        if from_id not in self._nodes or to_id not in self._nodes:
            return []
        results: list[list[str]] = []
        self._dfs_paths(from_id, to_id, [from_id], set(), results, max_depth)
        return results

    def _dfs_paths(
        self,
        current: str,
        target: str,
        path: list[str],
        visited: set[str],
        results: list[list[str]],
        max_depth: int,
    ) -> None:
        if len(path) > max_depth:
            return
        if current == target and len(path) > 1:
            results.append(list(path))
            return
        visited.add(current)
        for edge_idx in self._adjacency.get(current, []):
            edge = self._edges[edge_idx]
            if edge.target_id not in visited:
                path.append(edge.target_id)
                self._dfs_paths(edge.target_id, target, path, visited, results, max_depth)
                path.pop()
        visited.discard(current)

    def get_chains(self) -> list[list[GraphNode]]:
        """Find all attack chains: paths from HOST nodes to terminal nodes.

        Terminal nodes are those with no outgoing edges (leaf nodes).
        Chains are sorted longest-first to surface deep exploitation paths.
        """
        terminal_ids = {
            nid for nid in self._nodes if not self._adjacency.get(nid)
        }
        host_nodes = [n for n in self._nodes.values() if n.node_type == NodeType.HOST]
        chains: list[list[GraphNode]] = []

        for root in host_nodes:
            for terminal_id in terminal_ids:
                if terminal_id == root.id:
                    continue
                for path_ids in self.get_paths(root.id, terminal_id):
                    chain = [self._nodes[nid] for nid in path_ids]
                    chains.append(chain)

        chains.sort(key=lambda c: -len(c))
        return chains

    def to_dict(self) -> dict:
        return {
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges],
        }

    @classmethod
    def from_dict(cls, data: dict) -> AttackGraph:
        graph = cls()
        for nd in data.get("nodes", []):
            graph.add_node(GraphNode.from_dict(nd))
        for ed in data.get("edges", []):
            graph.add_edge(GraphEdge.from_dict(ed))
        return graph

    def to_mermaid(self) -> str:
        """Render the graph as a Mermaid flowchart."""
        lines = ["graph LR"]

        shape_map = {
            NodeType.HOST: ('(["', '"])', "host"),
            NodeType.SERVICE: ('["', '"]', "service"),
            NodeType.VULNERABILITY: ('{"', '"}', "vuln"),
            NodeType.CREDENTIAL: ('(["', '"])', "cred"),
            NodeType.ACCESS: ('[["', '"]]', "access"),
            NodeType.DATA: ('(("', '"))', "data"),
        }

        for node in self._nodes.values():
            open_b, close_b, css_class = shape_map.get(
                node.node_type, ('["', '"]', "default")
            )
            safe_label = node.label.replace('"', "'")
            lines.append(f"    {node.id}{open_b}{safe_label}{close_b}")

        for edge in self._edges:
            edge_label = edge.label or edge.edge_type.value
            safe_label = edge_label.replace('"', "'")
            lines.append(f"    {edge.source_id} -->|{safe_label}| {edge.target_id}")

        return "\n".join(lines)
