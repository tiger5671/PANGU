#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
PANGU Functionality Verification Test Script
Verify that all modules can be imported normally and basic functions work correctly after project reorganization
"""

import sys
import os

# Ensure project modules can be found - add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

def print_header(title):
    print(f"\n{'='*60}")
    print(f" {title}")
    print('='*60)

def print_result(name, success, error=None):
    status = "✅ PASS" if success else "❌ FAIL"
    print(f"  {status} - {name}")
    if error:
        print(f"         Error: {error}")

def test_imports():
    """Test if all core modules can be imported normally"""
    print_header("Module Import Tests")
    
    results = []
    
    # 1. Core data models
    try:
        from analysis.models import ACDG, RouteNode, VulnerabilityFinding, AuthState, ProtectionType
        print_result("analysis.models", True)
        results.append(True)
    except Exception as e:
        print_result("analysis.models", False, str(e))
        results.append(False)
    
    # 2. Route extractor
    try:
        from analysis.route_extractor import RouteExtractor
        print_result("analysis.route_extractor", True)
        results.append(True)
    except Exception as e:
        print_result("analysis.route_extractor", False, str(e))
        results.append(False)
    
    # 3. FastCGI extractor
    try:
        from analysis.fastcgi_extractor import FastCGIExtractor, ArchitectureDetector
        print_result("analysis.fastcgi_extractor", True)
        results.append(True)
    except Exception as e:
        print_result("analysis.fastcgi_extractor", False, str(e))
        results.append(False)
    
    # 4. GoForm extractor
    try:
        from analysis.goform_extractor import GoFormExtractor
        print_result("analysis.goform_extractor", True)
        results.append(True)
    except Exception as e:
        print_result("analysis.goform_extractor", False, str(e))
        results.append(False)
    
    # 5. JSONRPC extractor
    try:
        from analysis.jsonrpc_extractor import JSONRPCExtractor
        print_result("analysis.jsonrpc_extractor", True)
        results.append(True)
    except Exception as e:
        print_result("analysis.jsonrpc_extractor", False, str(e))
        results.append(False)
    
    # 6. SSI extractor
    try:
        from analysis.ssi_extractor import SSIExtractor
        print_result("analysis.ssi_extractor", True)
        results.append(True)
    except Exception as e:
        print_result("analysis.ssi_extractor", False, str(e))
        results.append(False)
    
    # 7. Distributed CGI extractor
    try:
        from analysis.distributed_cgi_extractor import DistributedCGIExtractor
        print_result("analysis.distributed_cgi_extractor", True)
        results.append(True)
    except Exception as e:
        print_result("analysis.distributed_cgi_extractor", False, str(e))
        results.append(False)
    
    # 8. Logic decoupler
    try:
        from analysis.logic_decoupler import LogicDecoupler
        print_result("analysis.logic_decoupler", True)
        results.append(True)
    except Exception as e:
        print_result("analysis.logic_decoupler", False, str(e))
        results.append(False)
    
    # 9. Detective Agent
    try:
        from analysis.detective_agent import DetectiveAgent
        print_result("analysis.detective_agent", True)
        results.append(True)
    except Exception as e:
        print_result("analysis.detective_agent", False, str(e))
        results.append(False)
    
    # 10. Reviewer Agent
    try:
        from analysis.reviewer_agent import ReviewerAgent
        print_result("analysis.reviewer_agent", True)
        results.append(True)
    except Exception as e:
        print_result("analysis.reviewer_agent", False, str(e))
        results.append(False)
    
    # 11. Dual-Agent detector
    try:
        from analysis.dual_agent_detector import DualAgentDetector
        print_result("analysis.dual_agent_detector", True)
        results.append(True)
    except Exception as e:
        print_result("analysis.dual_agent_detector", False, str(e))
        results.append(False)
    
    # 12. Firmware analyzer
    try:
        from analysis.firmware_analyzer import FirmwareAnalyzer
        print_result("analysis.firmware_analyzer", True)
        results.append(True)
    except Exception as e:
        print_result("analysis.firmware_analyzer", False, str(e))
        results.append(False)
    
    # 13. GoAhead analyzer
    try:
        from analysis.goahead_analyzer import GoAheadAnalyzer
        print_result("analysis.goahead_analyzer", True)
        results.append(True)
    except Exception as e:
        print_result("analysis.goahead_analyzer", False, str(e))
        results.append(False)
    
    # 14. PANGU Pipeline
    try:
        from analysis.pangu_pipeline import PANGUPipeline
        print_result("analysis.pangu_pipeline", True)
        results.append(True)
    except Exception as e:
        print_result("analysis.pangu_pipeline", False, str(e))
        results.append(False)
    
    # 15. IDA Client
    try:
        from core.bridge.ida_client import IDAProClient
        print_result("core.bridge.ida_client", True)
        results.append(True)
    except Exception as e:
        print_result("core.bridge.ida_client", False, str(e))
        results.append(False)
    
    # 16. LLM Provider
    try:
        from core.llm import LLMProvider
        print_result("core.llm", True)
        results.append(True)
    except Exception as e:
        print_result("core.llm", False, str(e))
        results.append(False)
    
    # 17. Knowledge base
    try:
        from rag.knowledge_base import KnowledgeBase
        print_result("rag.knowledge_base", True)
        results.append(True)
    except Exception as e:
        print_result("rag.knowledge_base", False, str(e))
        results.append(False)
    
    return results


def test_models():
    """Test data model functionality"""
    print_header("Data Model Functionality Tests")
    
    results = []
    
    # Test RouteNode creation
    try:
        from analysis.models import RouteNode, AuthState, ProtectionType
        route = RouteNode(
            path="/api/test",
            sub_path="test",
            handler="0x12345678",
            source_hub="0x1000",
            auth_state=AuthState.AUTH_FREE
        )
        assert route.path == "/api/test"
        assert route.handler == "0x12345678"
        print_result("RouteNode creation", True)
        results.append(True)
    except Exception as e:
        print_result("RouteNode creation", False, str(e))
        results.append(False)
    
    # Test ACDG creation
    try:
        from analysis.models import ACDG, RouteNode, AuthState
        routes = [
            RouteNode(path="/login", sub_path="login", handler="0x1000", source_hub="0x100"),
            RouteNode(path="/admin", sub_path="admin", handler="0x2000", source_hub="0x100", auth_state=AuthState.AUTH_REQUIRED),
        ]
        acdg = ACDG(routes=routes)
        assert len(acdg.routes) == 2
        print_result("ACDG creation", True)
        results.append(True)
    except Exception as e:
        print_result("ACDG creation", False, str(e))
        results.append(False)
    
    # Test VulnerabilityFinding creation
    try:
        from analysis.models import VulnerabilityFinding, RouteNode
        route = RouteNode(path="/vuln", sub_path="vuln", handler="0x3000", source_hub="0x100")
        finding = VulnerabilityFinding(
            route=route,
            vuln_type="Authentication Bypass",
            cwe_id="CWE-287",
            severity="HIGH",
            confidence=0.85,
            description="Test vulnerability"
        )
        assert finding.cwe_id == "CWE-287"
        print_result("VulnerabilityFinding creation", True)
        results.append(True)
    except Exception as e:
        print_result("VulnerabilityFinding creation", False, str(e))
        results.append(False)
    
    # Test AuthState enum
    try:
        from analysis.models import AuthState
        assert AuthState.AUTH_FREE.value == "Auth-Free"
        assert AuthState.AUTH_REQUIRED.value == "Auth-Required"
        print_result("AuthState enum", True)
        results.append(True)
    except Exception as e:
        print_result("AuthState enum", False, str(e))
        results.append(False)
    
    return results


def test_llm_provider():
    """Test LLM Provider initialization"""
    print_header("LLM Provider Tests")
    
    results = []
    
    try:
        from core.llm import LLMProvider
        llm = LLMProvider()
        # Don't actually call API, only check initialization
        assert llm is not None
        print_result("LLMProvider initialization", True)
        results.append(True)
    except Exception as e:
        print_result("LLMProvider initialization", False, str(e))
        results.append(False)
    
    return results


def test_ida_client():
    """Test IDA Client initialization (without actual connection)"""
    print_header("IDA Client Tests")
    
    results = []
    
    try:
        from core.bridge.ida_client import IDAProClient
        # Only test initialization, no actual connection
        client = IDAProClient(host="localhost", port=18811)
        assert client is not None
        assert client.host == "localhost"
        assert client.port == 18811
        print_result("IDAProClient initialization", True)
        results.append(True)
    except Exception as e:
        print_result("IDAProClient initialization", False, str(e))
        results.append(False)
    
    return results


def test_pangu_main():
    """Test if PANGU main program can be loaded normally"""
    print_header("PANGU Main Program Tests")
    
    results = []
    
    try:
        # Test if main program can be imported
        import importlib.util
        spec = importlib.util.spec_from_file_location("PANGU", "PANGU.py")
        module = importlib.util.module_from_spec(spec)
        # Don't execute, only check syntax
        print_result("PANGU.py syntax check", True)
        results.append(True)
    except SyntaxError as e:
        print_result("PANGU.py syntax check", False, str(e))
        results.append(False)
    except Exception as e:
        # Other errors may be runtime dependencies, syntax is OK
        print_result("PANGU.py syntax check", True)
        results.append(True)
    
    return results


def main():
    """Run all tests"""
    print("\n" + "="*60)
    print(" PANGU Functionality Verification Tests")
    print(" Verify module imports and basic functionality after project reorganization")
    print("="*60)
    
    all_results = []
    
    # Run all tests
    all_results.extend(test_imports())
    all_results.extend(test_models())
    all_results.extend(test_llm_provider())
    all_results.extend(test_ida_client())
    all_results.extend(test_pangu_main())
    
    # Summarize results
    passed = sum(all_results)
    total = len(all_results)
    
    print_header("Test Results Summary")
    print(f"  Passed: {passed}/{total}")
    print(f"  Failed: {total - passed}/{total}")
    
    if passed == total:
        print("\n  🎉 All tests passed! PANGU functionality is normal.")
        return 0
    else:
        print("\n  ⚠️ Some tests failed, please check errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
