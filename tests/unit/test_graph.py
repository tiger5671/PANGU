import random
from core.graph_analysis import ControlFlowGraph


def graph(edges, entry="a"):
    nodes = set(edges) | {v for values in edges.values() for v in values}
    return ControlFlowGraph([{"start": n, "successors": edges.get(n, [])} for n in nodes], entry)


def test_diamond_loop_and_unreachable_predecessor():
    cfg = graph({"a": ["b", "c"], "b": ["d"], "c": ["d"],
                 "d": ["e"], "e": ["d", "f"], "dead": ["e"]})
    assert cfg.immediate_dominators() == {"a": "a", "b": "a", "c": "a", "d": "a", "e": "d", "f": "e"}
    assert "dead" not in cfg.dominators()
    assert cfg.path("f", forbidden_nodes={"d"}) is None


def test_symmetric_guard_and_bypass_witness():
    cfg = graph({"a": ["check"], "check": ["reject", "work"], "work": ["sink"]})
    guards = cfg.guard_coverage("sink")["guards"]
    assert len(guards) == 1
    assert guards[0]["block"] == "check"
    assert guards[0]["target_path"] == ["work", "sink"]
    assert guards[0]["bypass_path"] is None
    bypass = graph({"a": ["check", "sink"], "check": ["reject", "sink"]})
    assert not any(g["block"] == "check" for g in bypass.guard_coverage("sink")["guards"])
    assert bypass.path("sink", forbidden_nodes={"check"}) == ["a", "sink"]


def test_cfg_gaps_are_reported():
    cfg = ControlFlowGraph([{"start": "a", "successors": ["missing"]}], "a")
    assert cfg.guard_coverage("missing")["gaps"] == ["missing"]
    assert not cfg.guard_coverage("missing")["reachable"]


def test_dominance_matches_exhaustive_simple_paths():
    # Independent oracle includes cycles and irreducible graphs. Every reachable
    # path has a simple counterpart, so dominance is their vertex intersection.
    rng = random.Random(41)
    nodes = list("abcdef")
    for _ in range(80):
        edges = {n: [v for v in nodes if rng.random() < 0.25] for n in nodes}
        cfg = graph(edges)
        paths = {}
        def visit(path):
            paths.setdefault(path[-1], []).append(set(path))
            for target in edges[path[-1]]:
                if target not in path:
                    visit(path + [target])
        visit(["a"])
        expected = {n: set.intersection(*values) for n, values in paths.items()}
        assert cfg.dominators() == expected
