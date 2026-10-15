from analysis.models import RouteNode
from analysis.route_hierarchy import reconstruct_routes, MountResolver


def route():
    return RouteNode("addUser", "addUser", "handler", "local", selector={"kind": "action", "value": "addUser"})


def mount(child, parent, prefix, root=False):
    return {"child": child, "parent": parent, "prefix": prefix, "evidence": "registration callsite", "registration_root": root}


def test_three_level_reconstruction_keeps_multiple_mounts():
    contexts = {"local": [mount("local", "forms", "/goform")],
                "forms": [mount("forms", "api", "/v1"), mount("forms", "legacy", "/legacy", True)],
                "api": [mount("api", "global", "/api", True)]}
    result = reconstruct_routes([route()], lambda scope: contexts.get(scope, []))
    assert {r.path for r in result} == {"/api/v1/goform/addUser", "/legacy/goform/addUser"}
    assert all(r.route_resolved for r in result)
    assert {len(r.mount_chain) for r in result} == {2, 3}
    assert all(r.selector['value'] == 'addUser' for r in result)


def test_unresolved_parent_retains_last_evidenced_context():
    result = reconstruct_routes([route()], lambda scope: [mount("local", "unknown", "/goform")] if scope == "local" else [])
    assert result[0].path == "/goform/addUser" and not result[0].route_resolved
    assert "Parent registration unresolved" in result[0].analysis_gaps


def test_cycles_budgets_and_unsupported_proposals_never_claim_resolution():
    contexts = {"local": [mount("local", "forms", "/goform")], "forms": [mount("forms", "local", "/api")]}
    result = reconstruct_routes([route()], lambda scope: contexts[scope])
    assert "Registration cycle" in result[0].analysis_gaps and not result[0].route_resolved
    capped = reconstruct_routes([route()], lambda scope: contexts[scope], max_depth=1)
    assert "Hierarchy traversal budget exhausted" in capped[0].analysis_gaps
    unsupported = reconstruct_routes([route()], lambda _: [{"prefix": "/invented", "child": "local"}])
    assert unsupported[0].path == "addUser"


def test_mount_resolver_rejects_fabricated_prefix():
    class Binary:
        def get_xrefs(self, *args): return {"status": "ok", "data": [{"func_name": "parent"}]}
        def decompile(self, *args): return {"status": "ok", "data": {"code": 'register_mount("/actual", local);'}}
    class Model:
        def chat(self, *args, **kwargs): return {"mounts": [{"prefix": "/fabricated", "code_evidence": 'register_mount("/actual", local);'}]}
    assert MountResolver(Binary(), Model())("local") == []


def test_root_resolution_requires_actual_registration_arguments():
    class Binary:
        def get_xrefs(self, *args): return {"status": "ok", "data": [{"func_name": "parent"}]}
        def decompile(self, *args): return {"status": "ok", "data": {"code": 'websUrlHandlerDefine("/api", local);'}}
        def scan_registration_args(self, *args): return {"status": "ok", "data": [{"args": ["/api", "local"]}]}
    class Model:
        def chat(self, *args, **kwargs): return {"mounts": [{"prefix": "/api", "code_evidence": 'websUrlHandlerDefine("/api", local);'}]}
    binary = Binary()
    assert MountResolver(binary, Model())("local")[0]['registration_root'] is True
    binary.scan_registration_args = lambda *args: {"status": "ok", "data": [{"args": ["/api", "other_child"]}]}
    assert MountResolver(binary, Model())("local")[0]['registration_root'] is False
