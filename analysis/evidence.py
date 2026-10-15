"""Bounded, reusable binary evidence and route prioritization.

Shared callees are explored once per run. Every result has a content-derived
receipt; partial coverage and failed queries are preserved instead of being
silently treated as absence of sensitive operations or authentication.
"""
import hashlib
import json
import re
from collections import deque

from analysis.models import AuthState


def function_name(value):
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return value.get("name") or value.get("func_name") or value.get("address") or ""
    return ""


class EvidenceCollector:
    ALLOWED = {"decompile", "decompile_page", "get_callees", "get_xrefs", "scan_args",
               "find_blocking_checks", "scan_auth_patterns", "get_basic_blocks",
               "analyze_guard_coverage", "get_storage_links"}

    def __init__(self, ida, max_records=4096, storage_graph=None, binary_id=""):
        self.ida = ida
        self.max_records = max_records
        self.cache = {}
        self.records = {}
        self.query_count = 0
        self.cache_hits = 0
        self.storage_graph, self.binary_id = storage_graph, binary_id

    def query(self, tool, **args):
        if tool not in self.ALLOWED:
            raise ValueError(f"Unsupported evidence tool: {tool}")
        key = json.dumps([tool, args], sort_keys=True, ensure_ascii=False)
        if key in self.cache:
            self.cache_hits += 1
            return self.cache[key]
        if len(self.records) >= self.max_records:
            return {"status": "error", "error": "Evidence query budget exhausted", "evidence_id": ""}
        try:
            if tool == "get_storage_links":
                if self.storage_graph is None or not self.binary_id:
                    result = {"status": "error", "error": "Storage graph or current binary identity unavailable"}
                else:
                    result = self.storage_graph.query(self.binary_id, args.get("address", ""))
            else:
                method = getattr(self.ida, tool)
                result = method(**args)
            if not isinstance(result, dict) or result.get("status") not in {"ok", "error"}:
                result = {"status": "error", "error": "Malformed analysis response"}
        except Exception as exc:
            result = {"status": "error", "error": f"{type(exc).__name__}: {exc}"}
        self.query_count += 1
        digest = hashlib.sha256(json.dumps([tool, args, result], sort_keys=True,
                                          ensure_ascii=False).encode("utf-8")).hexdigest()
        receipt = "E_" + digest[:16]
        record = {"id": receipt, "tool": tool, "args": args, "result": result, "sha256": digest}
        self.records[receipt] = record
        wrapped = dict(result, evidence_id=receipt)
        self.cache[key] = wrapped
        return wrapped

    def valid_refs(self, refs, require_code=False):
        if not isinstance(refs, list) or not refs or not all(isinstance(r, str) for r in refs):
            return False
        records = [self.records.get(r) for r in refs]
        if any(r is None or r["result"].get("status") != "ok" for r in records):
            return False
        if require_code:
            return any(r["tool"] in {"decompile", "decompile_page"}
                       and isinstance(r["result"].get("data"), dict)
                       and bool(r["result"]["data"].get("code", "").strip()) for r in records)
        return True

    def export(self, refs):
        return [self.records[r] for r in dict.fromkeys(refs) if r in self.records]

    def has_code_quote(self, refs, quote):
        if not isinstance(quote, str) or len(quote.strip()) < 8:
            return False
        return any(record["tool"] in {"decompile", "decompile_page"}
                   and isinstance(record["result"].get("data"), dict)
                   and quote in record["result"]["data"].get("code", "")
                   for record in self.export(refs))

    @staticmethod
    def display(result, max_chars=14000):
        text = json.dumps(result, ensure_ascii=False, indent=2)
        if len(text) <= max_chars:
            return text
        # Never present a clipped result as a complete function.
        return ("Evidence receipt: " + str(result.get("evidence_id", "")) + "\n" + text[:max_chars]
                + "\n[TRUNCATED: request decompile_page(address, start_line, max_lines) for omitted code]")

    def collect_context(self, address, max_depth=2, max_nodes=32):
        pending, seen, functions, gaps = deque([(address, 0)]), set(), [], []
        while pending and len(seen) < max_nodes:
            name, depth = pending.popleft()
            if not name or name in seen:
                continue
            seen.add(name)
            result = self.query("get_callees", address=name)
            values = result.get("data", [])
            if result.get("status") != "ok" or not isinstance(values, list):
                gaps.append(f"Cannot resolve callees of {name}")
                continue
            callees = sorted({function_name(c) for c in values} - {""})
            functions.append({"function": name, "depth": depth, "callees": callees,
                              "evidence_id": result["evidence_id"]})
            if depth < max_depth:
                pending.extend((callee, depth + 1) for callee in callees if callee not in seen)
            elif callees:
                gaps.append(f"Call depth limit reached at {name}")
        if pending:
            gaps.append("Call graph node budget exhausted")
        return {"functions": functions, "gaps": gaps}


# Exact import/function matching avoids treating 'execute', 'admin_check', or
# 'log_system_status' as system() calls. Stripped unknown wrappers are traversed.
SINKS = {
    "rce": {"system", "popen", "execve", "execl", "execvp", "doSystemCmd", "twsystem", "run_cmd"},
    "config_mod": {"nvram_set", "cfm_set", "setcfg", "CommitCfm", "save_config"},
    "file_write": {"fwrite", "fputs", "fprintf", "unlink", "rename"},
    "file_read": {"fread", "fgets", "fopen", "nvram_get", "load_config"},
}


def classify_sink(name):
    normalized = name.split("@", 1)[0].lstrip("._")
    if normalized.startswith("imp_"):
        normalized = normalized[4:]
    return [f"{category}:{normalized}" for category, names in SINKS.items() if normalized in names]


def prioritize_routes(routes, evidence=None, max_depth=2, max_nodes=32):
    """Rank every distinct request context; never prune a route as 'safe'."""
    ranked, contexts = [], {}
    for position, route in enumerate(routes):
        gaps = []
        if evidence is not None and route.handler and not route.handler.startswith("("):
            if route.handler not in contexts:
                contexts[route.handler] = evidence.collect_context(route.handler, max_depth, max_nodes)
            context = contexts[route.handler]
            gaps.extend(context["gaps"])
            sinks = set(route.sensitive_sinks)
            for function in context["functions"]:
                for callee in function["callees"]:
                    sinks.update(classify_sink(callee))
            route.sensitive_sinks = sorted(sinks)
            route.has_sensitive_sink = bool(sinks)
        elif not route.handler or route.handler.startswith("("):
            gaps.append("Handler unresolved")
        route.analysis_gaps = list(dict.fromkeys(route.analysis_gaps + gaps))
        score = 100 if route.has_sensitive_sink else 0
        score += {AuthState.AUTH_FREE: 30, AuthState.UNKNOWN: 25, AuthState.AUTH_REQUIRED: 10}[route.auth_state]
        score += 15 if re.search(r"config|backup|password|firmware|upload|reboot|command", route.path, re.I) else 0
        # Keep stable order for equally ranked routes to make comparisons repeatable.
        ranked.append((-score, position, route))
    return [route for _, _, route in sorted(ranked)]
