#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
PANGU Generalization Test - D-Link 823G (goahead)
Test PANGU analysis effectiveness on different vendor firmware
"""

import sys
sys.path.insert(0, '.')
import json
import os
from datetime import datetime
from core.bridge.ida_client import IDAProClient
from core.llm import LLMProvider

def banner(text):
    print("\n" + "=" * 70)
    print(f"    {text}")
    print("=" * 70)

def test_step1_route_extraction(ida, llm):
    """Step 1: Route extraction test"""
    banner("Step 1: Route Extraction")
    
    from analysis.route_extractor import RouteExtractor
    
    extractor = RouteExtractor(ida, llm)
    extractor.verbose = True
    
    print("\n[1.1] Executing static scan...")
    scan_data = extractor.run_static_scan()
    
    print(f"\nStatic scan results:")
    print(f"  Static tables: {len(extractor.static_tables)}")
    print(f"  Registration hubs: {len(extractor.registration_hubs)}")
    
    if extractor.registration_hubs:
        print("\nDiscovered route hubs:")
        for hub in extractor.registration_hubs[:10]:
            print(f"  - {hub.get('name', 'unknown')} @ {hub.get('address', 'N/A')}")
    
    print("\n[1.2] Extracting routes...")
    routes = extractor.run(use_llm_filter=False)  # Test pure static capability without LLM filtering
    
    print(f"\nExtracted {len(routes)} routes:")
    for route in routes[:20]:
        print(f"  {route.path} -> {route.handler}")
    
    if len(routes) > 20:
        print(f"  ... {len(routes) - 20} more routes")
    
    return routes, extractor


def test_step2_hierarchical_reconstruction(ida, llm, routes):
    """Step 2: Hierarchical route tree reconstruction"""
    banner("Step 2: Hierarchical Route Tree Reconstruction")
    
    print("\n[2.1] Analyzing route hierarchy...")
    
    # Group by root path
    tree = {}
    for route in routes:
        root = route.root or "/"
        if root not in tree:
            tree[root] = []
        tree[root].append(route)
    
    print(f"\nDiscovered {len(tree)} root paths:")
    for root, items in sorted(tree.items(), key=lambda x: -len(x[1])):
        print(f"  {root}/ ({len(items)} routes)")
    
    print(f"\n[2.2] Route tree structure preview:")
    for root, items in sorted(tree.items(), key=lambda x: -len(x[1]))[:5]:
        print(f"\n  {root}/")
        for item in items[:8]:
            sub = item.sub_path or item.path.replace(root, '', 1)
            print(f"    └─ {sub} -> {item.handler}")
        if len(items) > 8:
            print(f"    └─ ... ({len(items) - 8} more)")
    
    return tree


def test_step3_logic_decoupling(ida, llm, routes):
    """Step 3: Logic decoupling and state identification"""
    banner("Step 3: Logic Decoupling and ACDG Construction")
    
    from analysis.logic_decoupler import LogicDecoupler
    from analysis.models import ACDG, RouteNode
    
    decoupler = LogicDecoupler(ida, llm)
    decoupler.verbose = True
    
    print("\n[3.1] Discovering global gatekeeper...")
    
    # D-Link 823G init function is sub_423F90
    # It contains registration of gatekeeper sub_4110F4
    result = decoupler.run(routes, 
                          firmware_name="DLink_823G_goahead",
                          init_func="sub_423F90")  # Explicitly specify init function
    
    if result:
        print(f"\n[3.2] ACDG construction results:")
        print(f"  Total routes: {result.total_routes}")
        
        auth_free = result.get_auth_free_routes()
        auth_required_count = result.total_routes - len(auth_free)
        
        print(f"  Auth-Free: {len(auth_free)}")
        print(f"  Auth-Required: {auth_required_count}")
        
        print(f"\nGlobal authentication mechanisms:")
        for mech in result.global_auth_mechanisms:
            print(f"  - {mech.name} (confidence: {mech.confidence:.2f})")
        
        # Save ACDG
        output_file = "output/dlink_823g_acdg.json"
        result.save_json(output_file)
        print(f"\n[OK] ACDG saved: {output_file}")
        
        return result
    else:
        print("[FAIL] ACDG construction failed")
        return None


def test_step4_dual_agent(ida, llm, acdg):
    """Step 4: Dual-Agent vulnerability detection"""
    banner("Step 4: Dual-Agent Vulnerability Detection")
    
    from analysis.detective_agent import DetectiveAgent
    
    detective = DetectiveAgent(ida, llm, acdg)
    detective.verbose = True
    
    findings = []
    
    # 4.1 Gatekeeper review
    print("\n[4.1] Global gatekeeper review...")
    for mech in acdg.global_auth_mechanisms:
        print(f"\nReviewing gatekeeper: {mech.name}")
        gk_findings = detective.investigate_gatekeeper(mech.name, mech.address)
        findings.extend(gk_findings)
    
    # 4.2 Quick triage
    print("\n[4.2] Quick triage...")
    high_risk = detective.quick_triage()
    print(f"  High-risk routes: {len(high_risk)}")
    
    # 4.3 Auth-Free route investigation
    print("\n[4.3] Auth-Free route investigation...")
    auth_free = acdg.get_auth_free_routes()
    
    for route in auth_free[:3]:  # Limit count
        print(f"\nInvestigating: {route.path}")
        finding = detective.investigate_route(route)
        if finding:
            findings.append(finding)
    
    print(f"\n[Result] Found {len(findings)} potential vulnerabilities")
    for f in findings:
        print(f"  - {f.vuln_type} @ {f.route.path}")
        print(f"    Confidence: {f.confidence}, CWE: {f.cwe_id}")
    
    return findings


def main():
    print("=" * 70)
    print("    PANGU Generalization Test - D-Link 823G")
    print("    Generalization Test on D-Link goahead")
    print("=" * 70)
    print(f"Test time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Environment setup
    banner("Environment Setup")
    
    print("[1] IDA connection...")
    ida = IDAProClient()
    if not ida.connect():
        print("[FAIL] IDA connection failed!")
        return
    
    status = ida.get_status()
    if status.get("status") == "ok":
        info = status["data"]
        print(f"    Firmware: {info['binary_name']}")
        print(f"    Architecture: {info['processor']} {info['architecture']}")
        print(f"    Function count: {info['function_count']}")
    
    print("\n[2] LLM connection...")
    llm = LLMProvider()
    test_resp = llm.chat([{"role": "user", "content": "Reply OK"}])
    if test_resp:
        print("    [OK] LLM connection normal")
    else:
        print("    [WARN] LLM may be unstable")
    
    # Step 1: Route extraction
    routes, extractor = test_step1_route_extraction(ida, llm)
    
    if not routes:
        print("\n[WARN] No routes extracted, trying fallback approach...")
        # Special handling for goahead can be added here
        return
    
    # Step 2: Hierarchical reconstruction
    tree = test_step2_hierarchical_reconstruction(ida, llm, routes)
    
    # Step 3: Logic decoupling
    acdg = test_step3_logic_decoupling(ida, llm, routes)
    
    if not acdg:
        print("\n[ABORT] ACDG construction failed, cannot continue")
        return
    
    # Step 4: Dual-Agent detection
    findings = test_step4_dual_agent(ida, llm, acdg)
    
    # Summary
    banner("Test Summary")
    
    auth_free = acdg.get_auth_free_routes()
    auth_required_count = acdg.total_routes - len(auth_free)
    
    print(f"""
D-Link 823G (goahead) Analysis Complete!

Result Statistics:
  - Extracted routes: {len(routes)}
  - Auth-Free routes: {len(auth_free)}
  - Auth-Required routes: {auth_required_count}
  - Vulnerabilities found: {len(findings)}

Generalization Capability Evaluation:
  - Route extraction: {'PASS' if len(routes) > 0 else 'Needs adaptation'}
  - Gatekeeper identification: {'PASS' if acdg.global_auth_mechanisms else 'Needs adaptation'}
  - Vulnerability detection: {'PASS' if findings else 'Not found/Needs adaptation'}
""")


if __name__ == "__main__":
    main()
