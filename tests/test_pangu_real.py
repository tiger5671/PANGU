# tests/test_pangu_real.py
# Test PANGU complete pipeline on real firmware
# Verify module functionality and discover areas for optimization

import sys
import os
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.bridge.ida_client import IDAProClient
from core.llm import LLMProvider
from analysis.models import RouteNode, ACDG, AuthState
from analysis.route_extractor import RouteExtractor
from analysis.logic_decoupler import LogicDecoupler
from analysis.dual_agent_detector import DualAgentDetector


def banner(text):
    print("\n" + "=" * 70)
    print(f" {text}")
    print("=" * 70)


def test_phase1_route_extraction(ida, llm, dispatch_func=None, root_path="/goform"):
    """Phase 1: Test route extraction module"""
    banner("Phase 1: Route Extraction (RouteExtractor)")
    
    extractor = RouteExtractor(ida, llm)
    extractor.verbose = True
    
    # If dispatch function specified, use dispatch function mode
    if dispatch_func:
        print(f"\n[1.1] Using dispatch function mode: {dispatch_func}")
        routes = extractor.run_with_dispatch(dispatch_func, root_path)
        print(f"\n[Result] Dispatch function mode extracted: {len(routes)} routes")
    else:
        # Test standard scan
        print("\n[1.1] Testing standard static scan...")
        routes = extractor.run()
        
        print(f"\n[Result] Standard scan extracted: {len(routes)} routes")
        
        if routes:
            print("\n[Sample routes]:")
            for r in routes[:10]:
                print(f"  - {r.path} -> {r.handler}")
        
        # Test enhanced scan
        print("\n[1.2] Testing enhanced scan...")
        extractor2 = RouteExtractor(ida, llm)
        extractor2.verbose = True
        routes2 = extractor2.run_enhanced()
        
        print(f"\n[Result] Enhanced scan extracted: {len(routes2)} routes")
        
        routes = routes if len(routes) > len(routes2) else routes2
    
    if routes:
        print("\n[Extracted route samples]:")
        for r in routes[:15]:
            print(f"  - {r.path} -> {r.handler}")
        if len(routes) > 15:
            print(f"  ... and {len(routes) - 15} more routes")
    
    return routes


def test_phase2_logic_decoupling(ida, llm, routes):
    """Phase 2: Test logic decoupling module"""
    banner("Phase 2: Logic Decoupling (LogicDecoupler)")
    
    if not routes:
        print("[!] No routes to analyze")
        return None
    
    decoupler = LogicDecoupler(ida, llm)
    decoupler.verbose = True
    
    print(f"\n[2.1] Analyzing authentication status of {len(routes)} routes...")
    
    # Run logic decoupling
    acdg = decoupler.run(routes, "Tenda_httpd")
    
    # Summarize results
    auth_free = [r for r in acdg.routes if r.auth_state == AuthState.AUTH_FREE]
    auth_required = [r for r in acdg.routes if r.auth_state == AuthState.AUTH_REQUIRED]
    unknown = [r for r in acdg.routes if r.auth_state == AuthState.UNKNOWN]
    
    print(f"\n[Result] Authentication analysis complete:")
    print(f"  - Auth-Free (no auth required): {len(auth_free)}")
    print(f"  - Auth-Required (auth required): {len(auth_required)}")
    print(f"  - Unknown: {len(unknown)}")
    
    if auth_free:
        print("\n[Auth-Free route samples]:")
        for r in auth_free[:10]:
            print(f"  - {r.path} -> {r.handler}")
    
    return acdg


def test_phase3_dual_agent(ida, llm, acdg):
    """Phase 3: Test dual-Agent vulnerability detection"""
    banner("Phase 3: Dual-Agent Vulnerability Detection (DualAgentDetector)")
    
    if not acdg:
        print("[!] No ACDG to analyze")
        return []
    
    detector = DualAgentDetector(ida, llm)
    detector.verbose = True
    
    # Set ACDG
    detector.set_acdg(acdg)
    
    # Only detect Auth-Free routes
    auth_free = [r for r in acdg.routes if r.auth_state == AuthState.AUTH_FREE]
    
    if not auth_free:
        print("[!] No Auth-Free routes to detect")
        # Also detect Unknown routes
        auth_free = [r for r in acdg.routes if r.auth_state == AuthState.UNKNOWN][:20]
        print(f"[*] Switching to detect {len(auth_free)} Unknown routes")
    
    # Filter out invalid routes (e.g., /0H- garbage data)
    valid_routes = [r for r in auth_free if r.path and not r.path.endswith('H-')]
    print(f"\n[3.1] Performing vulnerability detection on {len(valid_routes)} valid routes...")
    
    findings = []
    for i, route in enumerate(valid_routes[:10]):  # Limit count to avoid slowness
        print(f"\n[{i+1}/{min(len(valid_routes), 10)}] Detecting: {route.path}")
        
        # Use run_interactive method
        result = detector.run_interactive(route.path)
        if result and result.valid:
            findings.append({
                "route": route.path,
                "handler": route.handler,
                "vuln_type": result.vuln_type.value if result.vuln_type else "unknown",
                "severity": result.severity.value if result.severity else "unknown",
                "confidence": result.confidence,
                "cwe": result.cwe_id
            })
            print(f"  [!] Vulnerability found: {result.vuln_type} ({result.severity})")
    
    print(f"\n[Result] Found {len(findings)} potential vulnerabilities")
    
    return findings


def main():
    import argparse
    parser = argparse.ArgumentParser(description="PANGU Real Firmware Test")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=4455)
    parser.add_argument("--phase", type=int, help="Test specific phase only (1/2/3)")
    parser.add_argument("--routes-file", help="Load routes from file (skip phase 1)")
    parser.add_argument("--dispatch", help="Dispatch function address (e.g., 0x42378)")
    parser.add_argument("--root-path", default="/goform", help="Route root path")
    args = parser.parse_args()
    
    banner("PANGU Real Firmware Test")
    print(f"Target: {args.host}:{args.port}")
    
    # Initialize
    ida = IDAProClient(args.host, args.port)
    if not ida.connect():
        print("[!] Cannot connect to IDA Pro")
        return
    
    llm = LLMProvider()
    
    # Get firmware information
    status = ida.get_status()
    if status.get("status") == "ok":
        data = status.get("data", {})
        print(f"Firmware: {data.get('binary_name')}")
        print(f"Function count: {data.get('function_count')}")
    
    routes = []
    acdg = None
    findings = []
    
    # Phase 1: Route extraction
    if args.phase is None or args.phase == 1:
        if args.routes_file:
            print(f"\n[*] Loading routes from file: {args.routes_file}")
            extractor = RouteExtractor(ida, llm)
            routes = extractor.load_routes_from_file(args.routes_file)
        else:
            routes = test_phase1_route_extraction(ida, llm, args.dispatch, args.root_path)
    
    # Phase 2: Logic decoupling
    if args.phase is None or args.phase == 2:
        if routes:
            acdg = test_phase2_logic_decoupling(ida, llm, routes)
    
    # Phase 3: Dual-Agent detection
    if args.phase is None or args.phase == 3:
        if acdg:
            findings = test_phase3_dual_agent(ida, llm, acdg)
    
    # Save results
    banner("Test Complete - Result Summary")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if routes:
        routes_path = f"output/pangu_test_routes_{timestamp}.json"
        os.makedirs("output", exist_ok=True)
        with open(routes_path, 'w') as f:
            json.dump([r.to_dict() for r in routes], f, indent=2)
        print(f"Routes saved to: {routes_path}")
    
    if acdg:
        acdg_path = f"output/pangu_test_acdg_{timestamp}.json"
        acdg.save_json(acdg_path)
        print(f"ACDG saved to: {acdg_path}")
    
    if findings:
        findings_path = f"output/pangu_test_findings_{timestamp}.json"
        with open(findings_path, 'w') as f:
            json.dump(findings, f, indent=2)
        print(f"Vulnerabilities saved to: {findings_path}")
    
    print("\n[Evaluation]")
    print(f"  Route extraction: {'OK' if routes else 'FAIL'} ({len(routes)} items)")
    print(f"  Logic decoupling: {'OK' if acdg else 'FAIL'}")
    print(f"  Vulnerability detection: {'OK' if findings else 'FAIL'} ({len(findings)} items)")


if __name__ == "__main__":
    main()
