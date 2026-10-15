"""IDA-independent CFG algorithms and structural counterexample witnesses.

Paths describe recovered CFG reachability, never path feasibility, request
controllability, or a security verdict. Missing blocks remain explicit gaps.
"""
from collections import deque


class ControlFlowGraph:
    def __init__(self, blocks, entry):
        self.blocks = {b["start"]: b for b in blocks}
        self.entry = entry
        self.successors = {a: tuple(b.get("successors", ())) for a, b in self.blocks.items()}
        self.gaps = sorted({s for values in self.successors.values() for s in values if s not in self.blocks})
        self.predecessors = {a: set() for a in self.blocks}
        for source, targets in self.successors.items():
            for target in targets:
                if target in self.predecessors:
                    self.predecessors[target].add(source)

    def reachable(self, start=None, forbidden_edges=(), forbidden_nodes=()):
        start = self.entry if start is None else start
        blocked_edges, blocked_nodes = set(forbidden_edges), set(forbidden_nodes)
        seen, pending = set(), [start]
        while pending:
            node = pending.pop()
            if node in seen or node in blocked_nodes or node not in self.blocks:
                continue
            seen.add(node)
            pending.extend(s for s in self.successors[node] if (node, s) not in blocked_edges)
        return seen

    def path(self, target, start=None, forbidden_edges=(), forbidden_nodes=()):
        start = self.entry if start is None else start
        blocked_edges, blocked_nodes = set(forbidden_edges), set(forbidden_nodes)
        if start not in self.blocks or start in blocked_nodes:
            return None
        parents, pending = {start: None}, deque([start])
        while pending:
            node = pending.popleft()
            if node == target:
                result = []
                while node is not None:
                    result.append(node)
                    node = parents[node]
                return result[::-1]
            for successor in self.successors[node]:
                if (successor in self.blocks and successor not in parents and successor not in blocked_nodes
                        and (node, successor) not in blocked_edges):
                    parents[successor] = node
                    pending.append(successor)
        return None

    def dominators(self):
        reachable = self.reachable()
        if not reachable:
            return {}
        dom = {a: ({a} if a == self.entry else set(reachable)) for a in reachable}
        changed = True
        while changed:
            changed = False
            for node in sorted(reachable - {self.entry}):
                preds = self.predecessors[node] & reachable
                common = set.intersection(*(dom[p] for p in preds)) if preds else set()
                new = {node} | common
                if new != dom[node]:
                    dom[node] = new
                    changed = True
        return dom

    def immediate_dominators(self):
        dom = self.dominators()
        result = {}
        for node, ancestors in dom.items():
            strict = ancestors - {node}
            result[node] = max(strict, key=lambda a: len(dom[a])) if strict else node
        return result

    def guard_coverage(self, target):
        """Find candidate branch guards even when TIS is low or symmetric.

        A candidate must dominate the target and have exactly one successor
        that reaches it without revisiting the check. This establishes branch
        dependence, not that the predicate enforces authentication.
        """
        dom = self.dominators()
        result = {"target": target, "reachable": target in dom, "gaps": self.gaps,
                  "entry_path": self.path(target), "guards": [],
                  "interpretation": "structural CFG evidence; feasibility and security semantics unverified"}
        for node in sorted(dom.get(target, set()) - {target}):
            successors = self.successors[node]
            if len(successors) != 2:
                continue
            paths = {s: self.path(target, start=s, forbidden_nodes={node}) for s in successors}
            reaching = [s for s, path in paths.items() if path is not None]
            if len(reaching) == 1:
                accepted = reaching[0]
                result["guards"].append({"block": node, "continuation": accepted,
                                         "other_successor": next(s for s in successors if s != accepted),
                                         "target_path": paths[accepted],
                                         "bypass_path": self.path(target, forbidden_nodes={node})})
        return result
