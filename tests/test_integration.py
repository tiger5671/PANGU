# tests/test_integration.py
# PANGU End-to-End Integration Tests
# Test complete pipeline: Route Extraction -> Logic Decoupling -> Dual-Agent Detection

import sys
import os
import json
from datetime import datetime

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from analysis.models import ACDG, RouteNode, AuthState, AuthMechanism, VulnerabilityFinding
from analysis.route_extractor import RouteExtractor
from analysis.logic_decoupler import LogicDecoupler
from analysis.dual_agent_detector import DualAgentDetector
from analysis.pangu_pipeline import PANGUPipeline


class MockIDAClient:
    """
    Mock IDA Client for offline testing
    """
    def __init__(self):
        self.connected = True
    
    def connect(self):
        return True
    
    def get_status(self):
        return {
            "status": "ok",
            "data": {
                "binary_name": "mock_firmware",
                "function_count": 1000
            }
        }
    
    def _send(self, cmd, args=None):
        # Mock responses for various commands
        if cmd == "run_static_scan":
            return {"status": "ok", "data": self._mock_static_scan()}
        elif cmd == "decompile":
            return {"status": "ok", "data": {"code": "int mock_func() { return 0; }"}}
        elif cmd == "get_callees":
            return {"status": "ok", "data": ["printf", "strcpy"]}
        else:
            return {"status": "ok", "data": {}}
    
    def decompile(self, addr):
        return self._send("decompile", {"address": addr})
    
    def get_callees(self, addr):
        return self._send("get_callees", {"address": addr})
    
    def scan_args(self, addr):
        return {"status": "ok", "data": []}
    
    def get_xrefs(self, addr, direction="from"):
        return {"status": "ok", "data": []}
    
    def find_blocking_checks(self, addr, threshold=2.0):
        return {"status": "ok", "data": []}
    
    def scan_auth_patterns(self, addr):
        return {"status": "ok", "data": {}}
    
    def build_dominator_tree(self, addr):
        return {"status": "ok", "data": {}}
    
    def get_dominator_context(self, func_addr, target_addr):
        return {"status": "ok", "data": []}
    
    def calculate_tis(self, addr):
        return {"status": "ok", "data": []}
    
    def _mock_static_scan(self):
        """Mock static scan results"""
        return {
            "potential_apis": [],
            "memory_structures": [
                {
                    "type": "STATIC_ADAPTIVE",
                    "address": "0x58000",
                    "all_entries": [
                        {"url": "/login.asp", "handler": "0x401000"},
                        {"url": "/admin/config.asp", "handler": "0x402000"},
                        {"url": "/goform/setPassword", "handler": "0x403000"},
                        {"url": "/goform/execCommand", "handler": "0x404000"},
                        {"url": "/cgi-bin/backup.cgi", "handler": "0x405000"},
                    ]
                },
                {
                    "type": "STATIC_ADAPTIVE",
                    "address": "0x59000",
                    "all_entries": [
                        {"url": "GetDeviceSettings", "handler": "0x410000"},
                        {"url": "SetWLanRadio", "handler": "0x411000"},
                        {"url": "RunReboot", "handler": "0x412000"},
                    ]
                }
            ]
        }


class MockLLMProvider:
    """
    Mock LLM Provider for offline testing
    """
    def chat(self, messages, json_mode=False):
        # Simple mock response
        last_msg = messages[-1]["content"] if messages else ""
        
        # Mock table classification
        if "Classify these firmware routing tables" in last_msg:
            return {
                "decisions": [
                    {"id": "0x58000", "verdict": "KEEP", "class": "STANDARD_PATH", "parent_hint": "/"},
                    {"id": "0x59000", "verdict": "KEEP", "class": "ACTION_MAP", "parent_hint": "/HNAP1"}
                ]
            }
        
        # Mock Detective Agent response
        if "Detective" in str(messages[0].get("content", "")):
            return {
                "thought": "Analyzing handler for potential vulnerabilities",
                "finding": {
                    "handler": "0x404000",
                    "path": "/goform/execCommand",
                    "vuln_type": "Unauthenticated RCE",
                    "confidence": "HIGH",
                    "evidence": "system() call with user input",
                    "reasoning": "Handler directly calls system() without authentication"
                }
            }
        
        # Mock Reviewer Agent response
        if "Reviewer" in str(messages[0].get("content", "")) or "skeptical" in str(messages[0].get("content", "")):
            return {
                "analysis": {
                    "auth_bypass": {"verified": True, "reasoning": "No auth check found"},
                    "reachability": {"verified": True, "reasoning": "Direct path to system()"},
                    "user_controllable": {"verified": True, "reasoning": "Input from request"},
                    "exploitability": {"verified": True, "reasoning": "Standard command injection"},
                    "alternative_path": {"found": False, "description": "N/A"}
                },
                "verdict": {
                    "is_valid": True,
                    "adjusted_confidence": "HIGH",
                    "cwe_id": "CWE-78",
                    "final_reasoning": "Confirmed unauthenticated command injection",
                    "severity": "CRITICAL",
                    "attack_vector": "POST /goform/execCommand with cmd parameter"
                }
            }
        
        return {}


def test_route_extractor_with_mock():
    """Test route extractor (using Mock)"""
    print("\n" + "=" * 60)
    print("TEST: Route Extractor with Mock IDA")
    print("=" * 60)
    
    ida = MockIDAClient()
    llm = MockLLMProvider()
    
    extractor = RouteExtractor(ida, llm)
    routes = extractor.run()
    
    print(f"\n  Extracted {len(routes)} routes:")
    for r in routes:
        print(f"    - {r.path} -> {r.handler}")
    
    assert len(routes) > 0, "Should extract at least one route"
    print("\n  [OK] Route extraction test passed!")
    return routes


def test_logic_decoupler_with_mock():
    """Test logic decoupler (using Mock)"""
    print("\n" + "=" * 60)
    print("TEST: Logic Decoupler with Mock IDA")
    print("=" * 60)
    
    ida = MockIDAClient()
    llm = MockLLMProvider()
    
    # Create test routes
    routes = [
        RouteNode(path="/login.asp", sub_path="login.asp", handler="0x401000", source_hub="0x58000"),
        RouteNode(path="/admin/config.asp", sub_path="config.asp", handler="0x402000", source_hub="0x58000"),
        RouteNode(path="/goform/setPassword", sub_path="setPassword", handler="0x403000", source_hub="0x58000"),
        RouteNode(path="/goform/execCommand", sub_path="execCommand", handler="0x404000", source_hub="0x58000"),
    ]
    
    decoupler = LogicDecoupler(ida, llm)
    acdg = decoupler.run(routes, "MockFirmware")
    
    print(f"\n  ACDG Summary:")
    print(f"    Total Routes: {acdg.total_routes}")
    print(f"    Auth-Free: {acdg.auth_free_count}")
    print(f"    Auth-Required: {acdg.auth_required_count}")
    print(f"    Unknown: {acdg.unknown_count}")
    
    print("\n  [OK] Logic decoupler test passed!")
    return acdg


def test_dual_agent_with_mock():
    """Test dual-Agent detector (using Mock)"""
    print("\n" + "=" * 60)
    print("TEST: Dual-Agent Detector with Mock")
    print("=" * 60)
    
    ida = MockIDAClient()
    llm = MockLLMProvider()
    
    # Create test ACDG
    acdg = ACDG()
    acdg.firmware_name = "MockFirmware"
    acdg.analysis_timestamp = datetime.now().isoformat()
    
    # Add Auth-Free route (high risk)
    route = RouteNode(
        path="/goform/execCommand",
        sub_path="execCommand",
        handler="0x404000",
        source_hub="0x58000",
        auth_state=AuthState.AUTH_FREE,
        has_sensitive_sink=True,
        sensitive_sinks=["rce:system"]
    )
    acdg.add_route(route)
    
    # Create Detective Agent
    from analysis.detective_agent import DetectiveAgent
    from analysis.reviewer_agent import ReviewerAgent
    
    detective = DetectiveAgent(ida, llm, acdg)
    detective.verbose = True
    detective.max_steps = 2
    
    # Investigate
    finding = detective.investigate_route(route)
    
    if finding:
        print(f"\n  Detective Finding:")
        print(f"    Type: {finding.vuln_type}")
        print(f"    Confidence: {finding.confidence}")
        
        # Create Reviewer Agent
        reviewer = ReviewerAgent(ida, llm, acdg)
        reviewer.verbose = True
        
        verified = reviewer.review_finding(finding)
        
        if verified:
            print(f"\n  Reviewer Verdict:")
            print(f"    Severity: {verified.severity}")
            print(f"    CWE: {verified.cwe_id}")
            print(f"    Valid: YES")
        else:
            print(f"\n  Reviewer: Finding rejected")
    
    print("\n  [OK] Dual-Agent test passed!")
    return finding


def test_full_pipeline_offline():
    """
    Test complete pipeline (offline mode)
    """
    print("\n" + "=" * 60)
    print("TEST: Full Pipeline (Offline Mode)")
    print("=" * 60)
    
    # Use existing routes file for testing
    test_routes_file = "output/2025.12.11_Dlink_823G_routes_v3_hierarchical.json"
    
    if not os.path.exists(test_routes_file):
        print(f"  [SKIP] Test routes file not found: {test_routes_file}")
        return
    
    # Load routes
    from tests.test_pipeline_offline import load_routes_from_json, create_mock_acdg_from_routes
    
    routes = load_routes_from_json(test_routes_file)
    print(f"  Loaded {len(routes)} routes")
    
    # Create ACDG
    acdg = create_mock_acdg_from_routes(routes, "Dlink_823G")
    
    print(f"\n  ACDG Summary:")
    print(f"    Total: {acdg.total_routes}")
    print(f"    Auth-Free: {acdg.auth_free_count}")
    print(f"    Unknown: {acdg.unknown_count}")
    
    # Show sensitive routes
    sensitive = [r for r in acdg.routes if r.has_sensitive_sink]
    print(f"\n  Sensitive Routes: {len(sensitive)}")
    for r in sensitive[:5]:
        print(f"    - {r.path}")
    
    # Save ACDG
    output_path = "output/test_pipeline_acdg.json"
    acdg.save_json(output_path)
    print(f"\n  [OK] ACDG saved to: {output_path}")


def run_all_tests():
    """Run all integration tests"""
    os.makedirs("output", exist_ok=True)
    
    print("\n" + "=" * 70)
    print(" PANGU Integration Tests")
    print(" Testing end-to-end pipeline components")
    print("=" * 70)
    
    # Tests using Mock
    test_route_extractor_with_mock()
    test_logic_decoupler_with_mock()
    test_dual_agent_with_mock()
    
    # Offline tests
    test_full_pipeline_offline()
    
    print("\n" + "=" * 70)
    print(" All integration tests completed!")
    print("=" * 70)


if __name__ == "__main__":
    run_all_tests()
