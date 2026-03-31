"""Strategist -- higher-level reasoning about the attack surface.

Invoked periodically (every N turns) or on significant events such as
critical findings or plan completions.  The strategist looks at the full
picture: what attack chains are emerging, what high-value targets remain
unexplored, and what the agent should focus on next.

This module works with an ``attack_graph`` dict and ``mission_memory``
dict (both plain dicts to avoid coupling to modules that may not exist
yet).  It has **no** dependency on ``agent.tools`` or ``agent.providers``.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

from agent.reasoning.types import AttackState, PlanStatus

logger = logging.getLogger(__name__)

LLMCall = Callable[[list[dict]], str]

# Default: run strategic analysis every N turns.
_DEFAULT_STRATEGY_INTERVAL = 5


class Strategist:
    """High-level attack surface analysis and objective prioritisation.

    Parameters
    ----------
    llm_call:
        Provider-agnostic LLM callable ``(messages) -> str``.
    strategy_interval:
        Run strategic analysis every N turns (in addition to event triggers).
    """

    def __init__(
        self,
        llm_call: Optional[LLMCall] = None,
        strategy_interval: int = _DEFAULT_STRATEGY_INTERVAL,
    ) -> None:
        self.llm_call = llm_call
        self.strategy_interval = strategy_interval
        self._last_strategy_turn: int = 0

    # ------------------------------------------------------------------
    # Trigger check
    # ------------------------------------------------------------------

    def should_strategize(self, state: AttackState) -> bool:
        """Return True if a strategic review is warranted this turn."""
        turns_since = state.turn - self._last_strategy_turn

        if turns_since >= self.strategy_interval:
            return True

        # Trigger on critical finding
        if state.findings and state.findings[-1].get("severity") == "CRITICAL":
            return True

        # Trigger when a plan just completed (new chain may be possible)
        if any(
            p.status == PlanStatus.COMPLETED
            and p.created_turn > self._last_strategy_turn
            for p in state.plans
        ):
            return True

        return False

    # ------------------------------------------------------------------
    # Attack surface analysis
    # ------------------------------------------------------------------

    def analyze_attack_surface(
        self,
        attack_graph: dict[str, Any],
        mission_memory: dict[str, Any],
    ) -> dict[str, Any]:
        """Identify emerging attack chains from the graph.

        Performs algorithmic analysis on the attack graph (hosts, services,
        vulnerabilities, credentials, paths) to find multi-step exploitation
        opportunities without requiring an LLM call.

        Parameters
        ----------
        attack_graph:
            Dict with keys like ``hosts``, ``services``, ``vulnerabilities``,
            ``credentials``, ``edges``.  Structure is intentionally loose to
            accommodate the graph module that will be built later.
        mission_memory:
            Dict with ``findings``, ``actions``, ``hypotheses`` from the
            mission memory store.

        Returns
        -------
        dict with keys:
            - ``chains``: list of identified attack chain dicts
            - ``coverage``: dict mapping categories to coverage percentage
            - ``recommendations``: list of recommendation strings
        """
        chains = self._find_attack_chains(attack_graph)
        coverage = self._compute_coverage(attack_graph, mission_memory)
        recommendations = self._generate_recommendations(
            attack_graph, mission_memory, chains, coverage
        )

        self._last_strategy_turn = max(
            self._last_strategy_turn,
            # Accept state.turn via mission_memory if available
            mission_memory.get("current_turn", self._last_strategy_turn),
        )

        return {
            "chains": chains,
            "coverage": coverage,
            "recommendations": recommendations,
        }

    # ------------------------------------------------------------------
    # High-value target identification
    # ------------------------------------------------------------------

    def identify_high_value_targets(
        self,
        attack_graph: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Find unexplored or under-explored high-value targets.

        Returns a list of target dicts sorted by estimated value (highest
        first).  Each dict contains:
            - ``target``: host/service/endpoint identifier
            - ``reason``: why this is high-value
            - ``score``: numeric priority score (0-1)
            - ``explored``: bool, whether the target has been tested
        """
        targets: list[dict[str, Any]] = []

        hosts = attack_graph.get("hosts", {})
        for host, info in hosts.items():
            if not isinstance(info, dict):
                continue

            ports = info.get("ports", {})
            vulns = info.get("vulnerabilities", [])
            explored = info.get("explored", False)

            # Score based on exposed services and known vulns
            score = 0.0

            # High-value ports (management, databases, admin panels)
            high_value_ports = {
                21,
                22,
                23,
                25,
                53,
                80,
                110,
                135,
                139,
                443,
                445,
                1433,
                1521,
                3306,
                3389,
                5432,
                5900,
                6379,
                8080,
                8443,
                9090,
                27017,
            }
            matching_ports = (
                set(int(p) for p in ports if str(p).isdigit()) & high_value_ports
            )
            score += min(0.4, len(matching_ports) * 0.1)

            # Existing vulnerabilities raise the score
            score += min(0.3, len(vulns) * 0.1)

            # Unexplored targets are more valuable
            if not explored:
                score += 0.3

            reason_parts: list[str] = []
            if matching_ports:
                reason_parts.append(f"high-value ports: {sorted(matching_ports)}")
            if vulns:
                reason_parts.append(f"{len(vulns)} known vulnerabilities")
            if not explored:
                reason_parts.append("not yet explored")

            if score > 0.0:
                targets.append(
                    {
                        "target": host,
                        "reason": "; ".join(reason_parts)
                        if reason_parts
                        else "in scope",
                        "score": round(min(1.0, score), 2),
                        "explored": explored,
                    }
                )

        # Sort by score descending
        targets.sort(key=lambda t: -t["score"])
        return targets

    # ------------------------------------------------------------------
    # Next objective suggestion
    # ------------------------------------------------------------------

    def suggest_next_objective(
        self,
        state: AttackState,
        attack_graph: Optional[dict[str, Any]] = None,
        mission_memory: Optional[dict[str, Any]] = None,
    ) -> list[dict[str, Any]]:
        """Return prioritised objectives based on current state.

        Each objective is a dict with:
            - ``objective``: description string
            - ``priority``: float 0-1
            - ``rationale``: why this should be next
            - ``suggested_tools``: list of tool names

        If an ``llm_call`` is configured, the strategist will ask the LLM
        for deeper reasoning.  Otherwise it falls back to algorithmic
        prioritisation.
        """
        objectives: list[dict[str, Any]] = []

        # 1. Algorithmic suggestions based on state
        objectives.extend(self._algorithmic_objectives(state, attack_graph or {}))

        # 2. LLM-augmented suggestions (if available)
        if self.llm_call is not None and attack_graph:
            llm_objectives = self._llm_objectives(
                state, attack_graph, mission_memory or {}
            )
            objectives.extend(llm_objectives)

        # Deduplicate by objective text (keep highest priority)
        seen: dict[str, dict[str, Any]] = {}
        for obj in objectives:
            key = obj["objective"].lower()
            if key not in seen or obj["priority"] > seen[key]["priority"]:
                seen[key] = obj
        objectives = sorted(seen.values(), key=lambda o: -o["priority"])

        self._last_strategy_turn = state.turn
        return objectives

    # ------------------------------------------------------------------
    # Internal: algorithmic chain detection
    # ------------------------------------------------------------------

    def _find_attack_chains(
        self,
        attack_graph: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Find multi-step attack chains in the graph.

        A chain is a sequence of nodes (host/service/vuln/credential)
        connected by edges that could lead to deeper access.
        """
        chains: list[dict[str, Any]] = []
        edges = attack_graph.get("edges", [])
        hosts = attack_graph.get("hosts", {})
        credentials = attack_graph.get("credentials", [])

        if not edges:
            return chains

        # Build adjacency from edges
        adjacency: dict[str, list[str]] = {}
        for edge in edges:
            src = edge.get("from", "")
            dst = edge.get("to", "")
            if src and dst:
                adjacency.setdefault(src, []).append(dst)

        # Find paths of length >= 2 (simple DFS, bounded depth)
        for start in adjacency:
            self._dfs_chains(start, [start], adjacency, chains, max_depth=5)

        # Enrich chains with credential pivots
        if credentials:
            for cred in credentials:
                cred_host = cred.get("host", "")
                cred_user = cred.get("username", "")
                if cred_host and cred_user:
                    for host in hosts:
                        if host != cred_host:
                            chains.append(
                                {
                                    "path": [cred_host, f"cred:{cred_user}", host],
                                    "type": "credential_pivot",
                                    "description": (
                                        f"Credential {cred_user}@{cred_host} "
                                        f"may grant access to {host}"
                                    ),
                                }
                            )

        return chains

    def _dfs_chains(
        self,
        node: str,
        path: list[str],
        adjacency: dict[str, list[str]],
        chains: list[dict[str, Any]],
        max_depth: int,
    ) -> None:
        """Depth-first search for attack chains (bounded)."""
        if len(path) > max_depth:
            return
        if len(path) >= 2:
            chains.append(
                {
                    "path": list(path),
                    "type": "multi_step",
                    "description": " -> ".join(path),
                }
            )
        for neighbor in adjacency.get(node, []):
            if neighbor not in path:  # avoid cycles
                path.append(neighbor)
                self._dfs_chains(neighbor, path, adjacency, chains, max_depth)
                path.pop()

    # ------------------------------------------------------------------
    # Internal: coverage analysis
    # ------------------------------------------------------------------

    def _compute_coverage(
        self,
        attack_graph: dict[str, Any],
        mission_memory: dict[str, Any],
    ) -> dict[str, float]:
        """Compute coverage percentage across attack categories.

        Categories: recon, web, network, auth, injection, config.
        """
        categories = {
            "recon": ["nmap", "whatweb", "subfinder", "dnsrecon"],
            "web": ["ffuf", "nuclei", "nikto", "sqlmap", "xss"],
            "network": ["nmap", "masscan", "netcat"],
            "auth": ["hydra", "credential", "brute"],
            "injection": ["sqlmap", "ssti", "ssrf", "command_injection"],
            "config": ["nuclei", "ssl", "header", "misconfig"],
        }

        actions = mission_memory.get("actions", [])
        if isinstance(actions, dict):
            actions = list(actions.values())

        tools_used: set[str] = set()
        for action in actions:
            tool = ""
            if isinstance(action, dict):
                tool = action.get("tool", "")
            elif isinstance(action, str):
                tool = action
            tools_used.add(tool.lower())

        coverage: dict[str, float] = {}
        for cat, relevant_tools in categories.items():
            matched = sum(
                1 for t in relevant_tools if any(t in used for used in tools_used)
            )
            coverage[cat] = round(matched / max(len(relevant_tools), 1), 2)

        return coverage

    # ------------------------------------------------------------------
    # Internal: recommendation generation
    # ------------------------------------------------------------------

    def _generate_recommendations(
        self,
        attack_graph: dict[str, Any],
        mission_memory: dict[str, Any],
        chains: list[dict[str, Any]],
        coverage: dict[str, float],
    ) -> list[str]:
        """Generate actionable recommendations based on analysis."""
        recs: list[str] = []

        # Low coverage areas
        for cat, pct in coverage.items():
            if pct < 0.3:
                recs.append(
                    f"Low {cat} coverage ({pct:.0%}) -- consider expanding testing"
                )

        # Unexploited chains
        if chains:
            recs.append(
                f"{len(chains)} attack chain(s) identified -- "
                "evaluate for multi-step exploitation"
            )

        # Credentials found but not pivoted
        creds = attack_graph.get("credentials", [])
        if creds:
            recs.append(
                f"{len(creds)} credential(s) found -- test for password reuse "
                "and lateral movement"
            )

        # No findings yet
        findings = mission_memory.get("findings", [])
        if isinstance(findings, dict):
            findings = list(findings.values())
        if not findings:
            recs.append("No findings yet -- broaden reconnaissance scope")

        return recs

    # ------------------------------------------------------------------
    # Internal: algorithmic objectives
    # ------------------------------------------------------------------

    def _algorithmic_objectives(
        self,
        state: AttackState,
        attack_graph: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Generate objectives from state without LLM."""
        objectives: list[dict[str, Any]] = []

        # If no plans exist, start with recon
        if not state.plans:
            objectives.append(
                {
                    "objective": "Initial reconnaissance of target attack surface",
                    "priority": 0.9,
                    "rationale": "No plans exist yet -- recon is the first step",
                    "suggested_tools": ["run_nmap", "run_whatweb", "run_subfinder"],
                }
            )
            return objectives

        # Exploit critical/high findings
        critical_findings = [
            f for f in state.findings if f.get("severity") in ("CRITICAL", "HIGH")
        ]
        if critical_findings:
            latest = critical_findings[-1]
            objectives.append(
                {
                    "objective": f"Exploit {latest.get('title', 'critical finding')}",
                    "priority": 0.95,
                    "rationale": (
                        f"Critical/high finding detected: {latest.get('title', '')[:60]}"
                    ),
                    "suggested_tools": [
                        "run_sqlmap",
                        "run_metasploit",
                        "run_custom_script",
                    ],
                }
            )

        # Explore high-value targets
        hvt = self.identify_high_value_targets(attack_graph)
        for target in hvt[:3]:
            if not target["explored"]:
                objectives.append(
                    {
                        "objective": f"Investigate {target['target']}",
                        "priority": target["score"],
                        "rationale": target["reason"],
                        "suggested_tools": ["run_nmap", "run_nuclei"],
                    }
                )

        # If all plans are stalled, suggest pivoting
        active = state.active_plans()
        if active and all(
            all(a.status in ("failed", "skipped") for a in p.actions) for p in active
        ):
            objectives.append(
                {
                    "objective": "Pivot to alternative attack vector",
                    "priority": 0.85,
                    "rationale": "All active plan actions have failed or been skipped",
                    "suggested_tools": [],
                }
            )

        return objectives

    # ------------------------------------------------------------------
    # Internal: LLM-augmented objectives
    # ------------------------------------------------------------------

    def _llm_objectives(
        self,
        state: AttackState,
        attack_graph: dict[str, Any],
        mission_memory: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Ask the LLM for strategic objectives."""
        if self.llm_call is None:
            return []

        # Build a compact summary for the LLM
        hosts = attack_graph.get("hosts", {})
        findings_count = len(state.findings)
        plans_summary = ", ".join(
            f"[{p.id}] {p.objective[:40]} ({p.status.value})" for p in state.plans[-5:]
        )

        prompt = f"""\
You are Phantom's strategist.  Given the current attack state, suggest
1-3 high-priority objectives the agent should pursue next.

State:
- Turn: {state.turn}
- Hosts: {list(hosts.keys())[:10]}
- Findings: {findings_count} total
- Plans: {plans_summary or "none"}

For each objective, output one line in this format:
OBJECTIVE: <description> | PRIORITY: <0.0-1.0> | RATIONALE: <why> | TOOLS: <tool1,tool2>
"""
        messages = [
            {"role": "system", "content": "You are a penetration testing strategist."},
            {"role": "user", "content": prompt},
        ]

        try:
            response = self.llm_call(messages)
        except Exception:
            logger.warning("LLM strategy call failed", exc_info=True)
            return []

        return self._parse_objective_lines(response)

    @staticmethod
    def _parse_objective_lines(text: str) -> list[dict[str, Any]]:
        """Parse OBJECTIVE lines from LLM response."""
        objectives: list[dict[str, Any]] = []

        for line in text.splitlines():
            if "OBJECTIVE:" not in line:
                continue
            parts: dict[str, str] = {}
            for segment in line.split("|"):
                segment = segment.strip()
                if ":" in segment:
                    key, _, val = segment.partition(":")
                    parts[key.strip().upper()] = val.strip()

            if "OBJECTIVE" in parts:
                tools_str = parts.get("TOOLS", "")
                tools = [t.strip() for t in tools_str.split(",") if t.strip()]
                try:
                    priority = float(parts.get("PRIORITY", "0.5"))
                except ValueError:
                    priority = 0.5

                objectives.append(
                    {
                        "objective": parts["OBJECTIVE"],
                        "priority": priority,
                        "rationale": parts.get("RATIONALE", ""),
                        "suggested_tools": tools,
                    }
                )

        return objectives
