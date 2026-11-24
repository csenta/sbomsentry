"""
Dependency Graph Engine for SBOMsentry.
Constructs Directed Acyclic Graphs (DAG), traces reachability paths, and distinguishes direct vs transitive dependencies.
"""

from collections import deque
from sbomsentry.core.models import Component


class DependencyGraphEngine:
    """Manages the dependency graph and computes reachability and shortest paths."""

    def __init__(self, target_name: str, components: list[Component], raw_edges: dict[str, list[str]]):
        self.target_name = target_name
        self.components: dict[str, Component] = {c.name.lower(): c for c in components}
        self.adj: dict[str, list[str]] = {}
        self.pred: dict[str, list[str]] = {}
        self._build_graph(raw_edges)

    def _build_graph(self, raw_edges: dict[str, list[str]]):
        for name in self.components.keys():
            self.adj[name] = []
            self.pred[name] = []

        # Connect edges
        for src, targets in raw_edges.items():
            src_clean = self._clean_node_key(src)
            if src_clean not in self.adj:
                self.adj[src_clean] = []
            for tgt in targets:
                tgt_clean = self._clean_node_key(tgt)
                if tgt_clean not in self.adj:
                    self.adj[tgt_clean] = []
                if tgt_clean not in self.pred:
                    self.pred[tgt_clean] = []
                self.adj[src_clean].append(tgt_clean)
                self.pred[tgt_clean].append(src_clean)

        # Distinguish direct vs transitive dependencies
        for name, comp in self.components.items():
            incoming = self.pred.get(name, [])
            # If has incoming edges and none of them is root/target, marked as transitive
            if incoming and not any(inc == self.target_name.lower() or inc == "root" for inc in incoming):
                comp.is_direct = False

    def _clean_node_key(self, raw_key: str) -> str:
        """Strips purl prefixes or versions to match component name."""
        if "@" in raw_key:
            raw_key = raw_key.split("@")[0]
        if "/" in raw_key:
            raw_key = raw_key.split("/")[-1]
        return raw_key.lower().strip()

    def get_shortest_path_from_root(self, target_component: str) -> list[str]:
        """Returns shortest path from root/direct dependency to target_component using BFS."""
        target_clean = self._clean_node_key(target_component)
        if target_clean not in self.components and target_clean not in self.pred:
            return [target_component]

        # BFS backwards from target to any root/direct dependency
        queue: deque[list[str]] = deque([[target_clean]])
        visited: set[str] = {target_clean}

        while queue:
            path = queue.popleft()
            curr = path[-1]

            parents = self.pred.get(curr, [])
            if not parents:
                # Reached a root/direct node
                rev = list(reversed(path))
                if rev and rev[0] == self.target_name.lower():
                    return [self.target_name] + rev[1:]
                return [self.target_name] + rev

            for parent in parents:
                if parent not in visited:
                    visited.add(parent)
                    queue.append(path + [parent])

        return [self.target_name, target_clean]

    def get_statistics(self) -> tuple[int, int]:
        """Returns (direct_count, transitive_count)."""
        direct = sum(1 for c in self.components.values() if c.is_direct)
        transitive = len(self.components) - direct
        return direct, transitive
