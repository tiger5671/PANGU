import json
import re
from collections import Counter
import pytest
from analysis.models import ACDG, RouteNode, AuthState, VulnerabilityFinding
from analysis.evidence import EvidenceCollector, prioritize_routes, classify_sink
from analysis.detective_agent import DetectiveAgent
from analysis.reviewer_agent import ReviewerAgent
from analysis.dual_agent_detector import DualAgentDetector


class Binary:
    def __init__(self, code="int handler(char *request) { system(request); return 0; }"):
        self.calls, self.code = Counter(), code
    def connect(self): return True
    def get_status(self): return {"status": "ok", "data": {"binary_name": "fixture"}}
    def decompile(self, address):
        self.calls[("decompile", address)] += 1
        return {"status": "ok", "data": {"code": self.code, "func_name": address}}
    def get_callees(self, address):
        self.calls[("get_callees", address)] += 1
        return {"status": "ok", "data": {"handler": ["wrapper"], "wrapper": ["system"]}.get(address, [])}
    def get_xrefs(self, address, direction="to"): return {"status": "ok", "data": []}
    def scan_args(self, address): return {"status": "ok", "data": []}


def route(path="/config", state=AuthState.UNKNOWN, handler="handler", **kwargs):
    return RouteNode(path, "", handler, "hub", auth_state=state, **kwargs)


def finding():
    return VulnerabilityFinding(route(), "Unauthorized command execution", "CWE-78", evidence="system(request)")


def receipts(messages):
    # Only select real code-query receipts from the independently collected
    # results, rather than accepting a made-up citation in model output.
    collector_text = messages[-1]["content"]
    return list(dict.fromkeys(re.findall(r'E_[0-9a-f]{16}', collector_text)))


class Respond:
    def __init__(self, function): self.function, self.count = function, 0
    def chat(self, messages, **kwargs):
        self.count += 1
        return self.function(messages)


def supported(messages):
    refs = receipts(messages)
    return {"status": "SUPPORTED", "analysis": {
        **{name: {"verified": True, "reasoning": "Fixture code evidence", "evidence_refs": refs}
           for name in ReviewerAgent.COUNTERFACTUAL_CHECKS[:4]},
        "alternative_path": {"found": False, "description": "No additional path in fixture"}},
        "verdict": {"is_valid": True, "adjusted_confidence": "HIGH", "cwe_id": "CWE-78",
                    "severity": "HIGH", "attack_vector": "POST fixture input", "final_reasoning": "Fixture evidence supports hypothesis",
                    "evidence_refs": refs}}


def test_deep_sink_discovery_and_shared_callee_cache():
    binary, evidence = Binary(), EvidenceCollector(Binary())
    evidence.ida = binary
    routes = [route("/one", AuthState.AUTH_REQUIRED), route("/two", AuthState.AUTH_FREE), route("/three")]
    ranked = prioritize_routes(routes, evidence)
    assert len(ranked) == 3 and all(r.has_sensitive_sink for r in ranked)
    assert {r.auth_state for r in ranked} == set(AuthState)
    assert binary.calls[("get_callees", "wrapper")] == 1
    assert binary.calls[("get_callees", "handler")] == 1
    assert classify_sink(".system") == ["rce:system"]
    assert classify_sink("log_system_status") == []


def test_call_graph_budget_and_unresolved_handler_preserved():
    evidence = EvidenceCollector(Binary())
    result = evidence.collect_context("handler", max_depth=0)
    assert result["gaps"] and len(result["functions"]) == 1
    unresolved = route(handler="")
    assert prioritize_routes([unresolved], evidence) == [unresolved]
    assert "Handler unresolved" in unresolved.analysis_gaps


def test_receipts_reject_unknown_failed_or_non_code_evidence():
    evidence = EvidenceCollector(Binary())
    reference = evidence.query("decompile", address="handler")["evidence_id"]
    assert evidence.valid_refs([reference], require_code=True)
    assert not evidence.valid_refs(["E_invented"])
    assert not evidence.valid_refs([{}])
    assert not evidence.valid_refs([])
    calls = evidence.query("get_callees", address="handler")["evidence_id"]
    assert not evidence.valid_refs([calls], require_code=True)
    assert "E_receipt" in evidence.display({"data": "x" * 500, "evidence_id": "E_receipt"}, 20)


@pytest.mark.parametrize("response", [None, "not JSON", [], {"verdict": {"is_valid": "true"}}])
def test_review_failure_never_confirms(response):
    reviewer = ReviewerAgent(Binary(), Respond(lambda _: response), ACDG())
    candidate = finding()
    assert reviewer.review_finding(candidate) is None
    assert candidate.review_status == "UNRESOLVED"
    assert reviewer.unresolved_findings == [candidate]


def test_supported_review_requires_all_checks_and_independent_receipts():
    binary = Binary()
    reviewer = ReviewerAgent(binary, Respond(supported), ACDG())
    candidate = finding()
    assert reviewer.review_finding(candidate) is candidate
    assert candidate.review_status == "SUPPORTED" and candidate.evidence_records
    assert binary.calls[("decompile", "handler")] == 1


@pytest.mark.parametrize("mutation", ["false_check", "string_boolean", "invented_receipt", "missing_reason"])
def test_contradictory_or_unreferenced_review_remains_unresolved(mutation):
    def response(messages):
        value = supported(messages)
        if mutation == "false_check": value["analysis"]["reachability"]["verified"] = False
        if mutation == "string_boolean": value["verdict"]["is_valid"] = "true"
        if mutation == "invented_receipt": value["verdict"]["evidence_refs"] = ["E_fabricated"]
        if mutation == "missing_reason": value["analysis"]["auth_bypass"]["reasoning"] = ""
        return value
    llm = Respond(response)
    reviewer = ReviewerAgent(Binary(), llm, ACDG())
    assert reviewer.review_finding(finding()) is None
    assert llm.count == reviewer.max_steps


def test_reviewer_can_gather_additional_tools_before_verdict():
    llm = Respond(lambda messages: {"action": {"tool": "decompile", "args": {"address": "wrapper"}}}
                  if len(messages) == 3 else supported(messages))
    reviewer = ReviewerAgent(Binary(), llm, ACDG())
    assert reviewer.review_finding(finding()).review_status == "SUPPORTED"
    assert llm.count == 2


def test_detective_rejects_uncollected_claims_and_accepts_cited_candidate():
    def response(messages):
        return {"status": "CANDIDATE", "finding": {"vuln_type": "Authentication bypass",
                "confidence": "HIGH", "reasoning": "Fixture check is missing", "evidence": "system(request)",
                "evidence_refs": receipts(messages)}}
    detective = DetectiveAgent(Binary(), Respond(response), ACDG())
    assert detective.investigate_route(route()).review_status == "UNRESOLVED"
    invalid = DetectiveAgent(Binary(), Respond(lambda _: {"finding": {"confidence": "HIGH"}}), ACDG())
    assert invalid.investigate_route(route()) is None
    assert invalid.diagnostics[-1]["status"] == "INSUFFICIENT_EVIDENCE"


def test_detector_covers_protected_unknown_and_free_routes_and_reports_budget(tmp_path):
    routes = [route("/a", AuthState.AUTH_REQUIRED), route("/b", AuthState.UNKNOWN), route("/c", AuthState.AUTH_FREE)]
    detector = DualAgentDetector(ida_client=Binary(), llm=Respond(lambda _: {"status": "NO_FINDING"}))
    detector.set_acdg(ACDG(routes=routes, firmware_name="fixture"))
    detector.verbose = False
    detector.max_routes_per_session = 0
    report = detector.run(str(tmp_path))
    assert report.coverage["attempted_routes"] == 3
    assert report.coverage["auth_states_attempted"] == {"Auth-Free": 1, "Auth-Required": 1, "Unknown": 1}
    assert report.auth_required_routes == 1 and not report.findings
    detector.max_routes_per_session = 1
    report = detector.run(str(tmp_path))
    assert report.coverage["attempted_routes"] == 1
    assert len(report.coverage["deferred_routes"]) == 2
    saved = json.loads(next(tmp_path.glob('*vulnerability_report*')).read_text())
    assert saved["coverage"]["route_budget"] == 1
