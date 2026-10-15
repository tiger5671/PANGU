import json
from analysis.logic_decoupler import LogicDecoupler, GatekeeperInfo, GatekeeperAnalyzer, LocalConstraintAnalyzer
from analysis.models import ACDG, RouteNode, AuthState, AuthMechanism
from analysis.route_extractor import RouteExtractor
from analysis.security_semantics import verify_security_check


class Binary:
    def decompile(self, address):
        return {"status": "ok", "data": {"code": "if (!valid_session(request)) return -1; sensitive();"}}
    def get_callees(self, address): return {"status": "ok", "data": []}
    def calculate_tis(self, address): return {"status": "ok", "data": [{"tis": 90, "terminates": True}]}


class Model:
    def __init__(self, value): self.value = value
    def chat(self, *args, **kwargs): return self.value


def test_tis_alone_never_proves_security():
    llm = Model({"classification": "NON_SECURITY", "code_evidence": "return -1;", "reasoning": "I/O error"})
    assert LocalConstraintAnalyzer(Binary(), llm)._analyze_handler("handler") is None
    assert not LocalConstraintAnalyzer(Binary(), llm)._verify_shared_utility("helper", [{"tis": 100}])


def test_semantic_verification_requires_a_real_quote():
    valid = {"classification": "AUTHENTICATION", "code_evidence": "valid_session(request)", "reasoning": "Checks session identity"}
    assert verify_security_check(Binary(), Model(valid), "handler")["effectiveness"] == "unverified"
    invalid = dict(valid, code_evidence="fake_code_not_in_binary")
    assert verify_security_check(Binary(), Model(invalid), "handler") is None


def test_unknown_static_and_out_of_scope_routes_never_assumed_protected():
    decoupler = LogicDecoupler(Binary(), Model({}))
    decoupler._build_acdg_conservative([
        {"path": "/api/config", "source_type": "static_analysis", "auth_state": "Auth-Required"},
        {"path": "/outside", "handler": "unknown"}], [GatekeeperInfo("auth", protected_prefixes=["/admin"])], {})
    assert all(r.auth_state == AuthState.UNKNOWN for r in decoupler.acdg.routes)
    assert all(r.analysis_gaps for r in decoupler.acdg.routes)


def test_local_check_survives_upstream_whitelist():
    decoupler = LogicDecoupler(Binary(), Model({}))
    protection = AuthMechanism("handler", "check", "inline", description="Session check present")
    decoupler._build_acdg_conservative([{"path": "/public", "handler": "handler"}],
                                     [GatekeeperInfo("auth", whitelist_paths=["/public"])], {"handler": protection})
    result = decoupler.acdg.routes[0]
    assert result.auth_state == AuthState.AUTH_REQUIRED and result.auth_refs


def test_whitelist_exact_matching_and_prefix_boundaries():
    analyzer = GatekeeperAnalyzer(Binary(), Model({}))
    analyzer.gatekeepers = [GatekeeperInfo("auth", protected_prefixes=["/admin"], whitelist_paths=["/login"])]
    assert analyzer.is_path_whitelisted("/login")[0]
    assert not analyzer.is_path_whitelisted("/private/login")[0]
    assert not analyzer.is_path_protected("/administrator")[0]
    assert analyzer.is_path_protected("/admin/config")[0]


def test_acdg_round_trip_preserves_evidence_context_and_legacy_defaults(tmp_path):
    route = RouteNode("/api", "api", "handler", "hub", auth_refs=[{"address": "0x123"}],
                      selector={"action": "set"}, analysis_gaps=["Missing caller"], binary_id="binary",
                      dispatch_function="dispatcher", dispatch_address="0x321")
    graph = ACDG(routes=[route], routing_edges=[{"parent": "root", "child": "hub", "evidence": "callsite"}])
    path = tmp_path / "graph.json"
    graph.save_json(path)
    restored = ACDG.load_json(path)
    assert restored.to_dict() == graph.to_dict()
    legacy = RouteNode.from_dict({"full_path": "/legacy"})
    assert legacy.path == "/legacy" and not legacy.auth_refs


def test_dedup_preserves_case_method_selector_binary_and_mount_context():
    routes = [RouteNode("/API", "", "same", "hub"), RouteNode("/api", "", "same", "hub"),
              RouteNode("/api", "", "same", "hub", http_method="POST"),
              RouteNode("/api", "", "same", "hub", selector={"action": "set"}),
              RouteNode("/api", "", "same", "hub", binary_id="other")]
    extractor = RouteExtractor(Binary(), Model({}))
    assert len(extractor.deduplicate_routes(routes + routes)) == 5


def test_all_table_batches_are_classified_without_invented_mounts():
    class Classifier:
        calls = 0
        def chat(self, messages, **kwargs):
            self.calls += 1
            text = messages[-1]["content"]
            data = json.loads(text.split('INPUT:\n', 1)[1].split('\nOUTPUT FORMAT', 1)[0])
            return {"decisions": [{"id": t["id"], "verdict": "KEEP", "class": "ACTION_MAP", "parent_hint": "/invented"} for t in data]}
    model = Classifier()
    extractor = RouteExtractor(Binary(), model)
    extractor.verbose = False
    extractor.static_tables = [{"address": hex(n), "type": "STATIC_ADAPTIVE", "all_entries": [{"url": "GetConfig", "handler": hex(n + 1000)}]} for n in range(65)]
    routes = extractor.extract_from_static_tables()
    assert len(routes) == 65 and model.calls == 3
    assert all(r.path == "GetConfig" and not r.route_resolved for r in routes)
    assert all("Mount context unresolved" in r.analysis_gaps for r in routes)


def test_invented_ids_and_contradictory_classes_are_rejected():
    tables = [{"address": "0x1", "all_entries": [{"url": "/api", "handler": "h"}]}]
    response = {"decisions": [{"id": "invented", "verdict": "KEEP", "class": "ACTION_MAP"},
                              {"id": "0x1", "verdict": "KEEP", "class": "RESOURCE_MAP"}]}
    assert RouteExtractor(Binary(), Model(response)).filter_tables_with_llm(tables) == {}
