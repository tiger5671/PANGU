#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
PANGU Dual-Agent Vulnerability Detection System Test
Testing Paper Section 3.4: Dual-Agent BAC Detection
- 3.4.1 Detective Agent: Hypothesis Generation & Evidence Collection
- 3.4.2 Reviewer Agent: Counterfactual Verification & Confidence Assessment
"""

import sys
sys.path.insert(0, '.')
import json
import os
from datetime import datetime
from core.bridge.ida_client import IDAProClient
from core.llm import LLMProvider
from analysis.models import ACDG, AuthState

def banner(text):
    print("\n" + "=" * 70)
    print(f"    {text}")
    print("=" * 70)

def test_environment():
    """Test environment preparation"""
    banner("Environment Check")
    
    # 1. IDA connection
    print("[1] IDA Pro connection...")
    ida = IDAProClient()
    if not ida.connect():
        print("    [FAIL] IDA connection failed!")
        return None, None, None
    print("    [OK] IDA connection successful")
    
    # 2. LLM connection
    print("\n[2] LLM connection...")
    llm = LLMProvider()
    test_resp = llm.chat([{"role": "user", "content": "Reply with just 'OK'"}])
    if test_resp:
        print(f"    [OK] LLM response normal")
    else:
        print("    [WARN] LLM may have issues")
    
    # 3. ACDG loading
    print("\n[3] ACDG loading...")
    acdg_file = "output/acdg_conservative.json"
    if not os.path.exists(acdg_file):
        print(f"    [FAIL] ACDG file does not exist: {acdg_file}")
        return None, None, None
    
    acdg = ACDG.load_json(acdg_file)
    print(f"    [OK] Loaded ACDG: {acdg.firmware_name}")
    print(f"    Total routes: {acdg.total_routes}")
    
    auth_free = acdg.get_auth_free_routes()
    print(f"    Auth-Free routes: {len(auth_free)}")
    
    return ida, llm, acdg


def test_detective_tools(ida, llm, acdg):
    """Test Detective Agent tool set"""
    banner("Test 1: Detective Tool Set")
    
    from analysis.detective_agent import DetectiveAgent
    
    detective = DetectiveAgent(ida, llm, acdg)
    
    # Select an Auth-Free route for testing
    auth_free = acdg.get_auth_free_routes()
    if not auth_free:
        print("[WARN] No Auth-Free routes available for testing")
        return False
    
    test_route = auth_free[0]
    print(f"\nTest route: {test_route.path} -> {test_route.handler}")
    
    # 1. Test decompile
    print("\n[Tool 1] decompile...")
    code = detective._tool_decompile(test_route.handler)
    if code and "error" not in code.lower():
        print(f"    [OK] Decompilation successful ({len(code)} chars)")
        print(f"    Preview: {code[:200]}...")
    else:
        print(f"    [FAIL] Decompilation failed: {code[:100]}")
    
    # 2. Test get_callees
    print("\n[Tool 2] get_callees...")
    callees = detective._tool_get_callees(test_route.handler)
    if callees:
        print(f"    [OK] Retrieved called functions: {callees[:200]}...")
    else:
        print("    [FAIL] Cannot retrieve called functions")
    
    # 3. Test scan_args
    print("\n[Tool 3] scan_args...")
    args = detective._tool_scan_args(test_route.handler)
    if args:
        print(f"    [OK] Scanned parameters: {args[:200]}...")
    else:
        print("    [WARN] No parameter information")
    
    # 4. Test analyze_blocking
    print("\n[Tool 4] analyze_blocking...")
    blocking = detective._tool_analyze_blocking(test_route.handler)
    if blocking:
        print(f"    [OK] Blocking analysis: {blocking[:200]}...")
    else:
        print("    [WARN] No blocking information")
    
    return True


def test_quick_triage(ida, llm, acdg):
    """Test quick triage functionality"""
    banner("Test 2: Quick Triage")
    
    from analysis.detective_agent import DetectiveAgent
    
    detective = DetectiveAgent(ida, llm, acdg)
    
    # Run quick triage
    print("\nRunning quick triage to identify high-risk routes...")
    high_risk = detective.quick_triage()
    
    print(f"\nHigh-risk route count: {len(high_risk)}")
    
    if high_risk:
        print("\nHigh-risk route list:")
        for route in high_risk[:10]:
            print(f"  - {route.path} -> {route.handler}")
            print(f"    Sensitive operations: {route.sensitive_sinks}")
    
    return high_risk


def test_gatekeeper_audit(ida, llm, acdg):
    """Test gatekeeper audit functionality - Critical security review!"""
    banner("Test 2.5: Global Gatekeeper Security Audit (CRITICAL)")
    
    from analysis.detective_agent import DetectiveAgent
    
    detective = DetectiveAgent(ida, llm, acdg)
    detective.verbose = True
    
    # Get global gatekeepers
    gatekeepers = acdg.global_auth_mechanisms
    
    if not gatekeepers:
        print("[WARN] No global gatekeeper identified!")
        print("       This may mean all routes are unprotected!")
        return []
    
    print(f"\nFound {len(gatekeepers)} global gatekeepers:")
    for gk in gatekeepers:
        print(f"  - {gk.name} @ {gk.address}")
        print(f"    Type: {gk.mechanism_type}")
        print(f"    Confidence: {gk.confidence:.2f}")
    
    all_findings = []
    
    for gk in gatekeepers:
        print(f"\n{'='*50}")
        print(f"Auditing gatekeeper: {gk.name}")
        print(f"{'='*50}")
        
        findings = detective.investigate_gatekeeper(gk.name, gk.address)
        all_findings.extend(findings)
        
        if findings:
            print(f"\n[!] Found {len(findings)} potential bypass vulnerabilities:")
            for f in findings:
                print(f"    - {f.vuln_type}")
                print(f"      Confidence: {f.confidence}")
                print(f"      Description: {f.description[:100]}...")
        else:
            print(f"\n[OK] Gatekeeper {gk.name} has no obvious bypass vulnerabilities")
    
    return all_findings


def test_detective_investigation(ida, llm, acdg, target_route=None):
    """Test Detective investigation functionality"""
    banner("Test 3: Detective Investigation (ReAct Loop)")
    
    from analysis.detective_agent import DetectiveAgent
    
    detective = DetectiveAgent(ida, llm, acdg)
    detective.verbose = True
    detective.max_steps = 8  # Allow more steps
    
    # Select target route
    if target_route is None:
        auth_free = acdg.get_auth_free_routes()
        if not auth_free:
            print("[WARN] No Auth-Free routes available for testing")
            return None
        target_route = auth_free[0]
    
    print(f"\nTarget route: {target_route.path} -> {target_route.handler}")
    print(f"Auth state: {target_route.auth_state.value if hasattr(target_route.auth_state, 'value') else target_route.auth_state}")
    
    # Display sensitive operations (if any)
    if hasattr(target_route, 'sensitive_sinks') and target_route.sensitive_sinks:
        print(f"Sensitive operations: {target_route.sensitive_sinks}")
    
    # Execute investigation
    print("\nStarting ReAct investigation loop...")
    print("-" * 50)
    finding = detective.investigate_route(target_route)
    print("-" * 50)
    
    if finding:
        print("\n[Vulnerability Found!]")
        print(f"  Type: {finding.vuln_type}")
        print(f"  Confidence: {finding.confidence}")
        print(f"  CWE: {finding.cwe_id}")
        print(f"  Reasoning: {finding.detective_reasoning[:300]}..." if len(finding.detective_reasoning) > 300 else f"  Reasoning: {finding.detective_reasoning}")
        if finding.evidence:
            print(f"  Evidence length: {len(finding.evidence)} chars")
        return finding
    else:
        print("\n[No Vulnerability Found]")
        return None


def test_reviewer_verification(ida, llm, acdg, finding):
    """Test Reviewer verification functionality"""
    banner("Test 4: Reviewer Verification")
    
    from analysis.reviewer_agent import ReviewerAgent
    
    if not finding:
        print("[SKIP] No Finding to verify")
        return None
    
    reviewer = ReviewerAgent(ida, llm, acdg)
    reviewer.verbose = True
    
    print(f"\nVerifying Finding: {finding.vuln_type}")
    print(f"Route: {finding.route.path}")
    
    # Execute verification
    print("\nStarting counterfactual verification...")
    verified = reviewer.review_finding(finding)
    
    if verified:
        print("\n[Verification Passed!]")
        print(f"  Final type: {verified.vuln_type}")
        print(f"  Severity: {verified.severity}")
        print(f"  CWE: {verified.cwe_id}")
        print(f"  Verification verdict: {verified.reviewer_verdict}")
        return verified
    else:
        print("\n[Verification Failed] Finding rejected by Reviewer")
        return None


def test_full_dual_agent(ida, llm, acdg):
    """Test complete dual-Agent flow"""
    banner("Test 5: Complete Dual-Agent Detection Flow")
    
    from analysis.dual_agent_detector import DualAgentDetector
    
    # Create detector
    detector = DualAgentDetector()
    detector.ida = ida
    detector.llm = llm
    detector.set_acdg(acdg)
    
    # Configuration
    detector.verbose = True
    detector.max_routes_per_session = 3  # Limit test count
    detector.enable_quick_triage = True
    
    print("\nConfiguration:")
    print(f"  Max routes: {detector.max_routes_per_session}")
    print(f"  Quick triage: {detector.enable_quick_triage}")
    
    # Run
    print("\nStarting dual-Agent detection...")
    
    try:
        report = detector.run(output_dir="output")
        
        print("\nDetection complete!")
        print(f"  Vulnerabilities found: {len(report.findings)}")
        print(f"  Duration: {report.duration_seconds:.2f} seconds")
        
        return report
    except Exception as e:
        import traceback
        print(f"\n[ERROR] Detection failed: {e}")
        traceback.print_exc()
        return None


def main():
    print("=" * 70)
    print("    PANGU Dual-Agent Vulnerability Detection System Test")
    print("    Dual-Agent BAC Detection Test")
    print("=" * 70)
    print(f"Test time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Environment check
    ida, llm, acdg = test_environment()
    if not ida or not acdg:
        print("\n[ABORT] Environment check failed!")
        return
    
    # Test 1: Detective tool set
    test_detective_tools(ida, llm, acdg)
    
    # Test 2: Quick triage
    high_risk = test_quick_triage(ida, llm, acdg)
    
    # Test 2.5: Gatekeeper audit (Critical!)
    gatekeeper_findings = test_gatekeeper_audit(ida, llm, acdg)
    
    # Test 3: Detective investigation (select a high-risk route)
    target = high_risk[0] if high_risk else None
    finding = test_detective_investigation(ida, llm, acdg, target)
    
    # Test 4: Reviewer verification
    all_findings = gatekeeper_findings.copy() if gatekeeper_findings else []
    if finding:
        all_findings.append(finding)
    
    if all_findings:
        verified = test_reviewer_verification(ida, llm, acdg, all_findings[0])
    
    # Test 5: Complete flow
    # test_full_dual_agent(ida, llm, acdg)  # Uncomment to run complete test
    
    # Summary
    banner("Test Summary")
    print(f"""
Dual-Agent Vulnerability Detection System Test Complete!

Test Results:
  - Gatekeeper audit found: {len(gatekeeper_findings)} potential bypass vulnerabilities
  - Auth-Free route found: {1 if finding else 0} vulnerabilities
  - Total findings: {len(all_findings)}

Test Items:
  1. Detective tool set - Decompilation, call analysis, parameter scanning, etc.
  2. Quick triage - Identify high-risk routes containing sensitive operations
  2.5 Gatekeeper audit - Analyze bypass vulnerabilities in global authentication mechanisms (Critical!)
  3. Detective investigation - ReAct loop for hypothesis generation and evidence collection
  4. Reviewer verification - Counterfactual verification and confidence assessment

Note: Complete dual-Agent flow test is commented out. Uncomment to run.
""")


if __name__ == "__main__":
    main()
