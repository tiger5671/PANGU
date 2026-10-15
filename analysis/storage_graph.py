"""Cross-binary persistent-storage joins, with explicit evidence and limits.

A matching constant NVRAM key establishes a possible communication channel.
It does not establish user controllability, temporal feasibility, or taint flow.
"""
import json
from collections import defaultdict
from pathlib import Path


class StorageGraph:
    def __init__(self, firmware_id, edges=(), gaps=()):
        self.firmware_id = firmware_id
        self.edges, self.gaps = list(edges), list(gaps)

    @classmethod
    def from_snapshots(cls, paths, firmware_id, max_edges=10000):
        if not firmware_id or max_edges < 1:
            raise ValueError("A firmware scope and positive edge budget are required")
        accesses, gaps = {}, []
        for path in paths:
            snapshot = json.loads(Path(path).read_text(encoding="utf-8"))
            if snapshot.get("schema_version") != 1:
                raise ValueError("Unsupported snapshot schema")
            observed = False
            for query in snapshot.get("queries", []):
                if query.get("command") != "get_storage_accesses":
                    continue
                observed = True
                result = query.get("result", {})
                if result.get("status") != "ok":
                    gaps.append(f"Storage query failed in {Path(path).name}")
                    continue
                data = result.get("data", {})
                gaps.extend(data.get("gaps", []))
                for access in data.get("accesses", []):
                    if (not isinstance(access, dict) or access.get("mode") not in {"read", "write"}
                            or not all(isinstance(access.get(k), str) and access[k] for k in
                                       ("binary_id", "namespace", "key", "function", "callsite"))):
                        gaps.append("Incomplete storage-access evidence omitted")
                        continue
                    accesses[json.dumps(access, sort_keys=True)] = access
            if not observed:
                gaps.append(f"No storage-access query in {Path(path).name}")
        readers, writers = defaultdict(list), defaultdict(list)
        for access in accesses.values():
            (readers if access["mode"] == "read" else writers)[(access["namespace"], access["key"])].append(access)
        edges = []
        for namespace, key in sorted(writers):
            for writer in writers[(namespace, key)]:
                for reader in readers[(namespace, key)]:
                    if writer["binary_id"] == reader["binary_id"]:
                        continue
                    if len(edges) >= max_edges:
                        gaps.append("Storage edge budget exhausted")
                        return cls(firmware_id, edges, list(dict.fromkeys(gaps)))
                    edges.append({"namespace": namespace, "key": key, "writer": writer, "reader": reader,
                                  "status": "CANDIDATE_CHANNEL", "taint_verified": False})
        return cls(firmware_id, edges, list(dict.fromkeys(gaps)))

    def query(self, binary_id, function):
        return {"status": "ok", "data": {"firmware_id": self.firmware_id, "gaps": self.gaps,
                "links": [edge for edge in self.edges if any(
                    edge[side]["binary_id"] == binary_id and function in {
                        edge[side]["function"], edge[side].get("function_address")}
                    for side in ("writer", "reader"))],
                "interpretation": "Candidate storage channel only; taint, timing and control unverified"}}

    def to_dict(self):
        return {"schema_version": 1, "firmware_id": self.firmware_id, "edges": self.edges, "gaps": self.gaps}

    @classmethod
    def load(cls, path):
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if data.get("schema_version") != 1 or not isinstance(data.get("edges"), list) or not data.get("firmware_id"):
            raise ValueError("Unsupported storage graph")
        return cls(data["firmware_id"], data["edges"], data.get("gaps", []))
