#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
PANGU Logic Decoupling and State Identification Test
Testing functionality from Paper Section 3.3:
- 3.3.1 Global Authentication Mechanism Identification
- 3.3.2 Local Constraint Analysis
- 3.3.3 ACDG Construction (Access Control Dependency Graph)
"""

import sys
sys.path.insert(0, '.')
import os
import json
from datetime import datetime
from core.bridge.ida_client import IDAProClient
from core.llm import LLMProvider

def test_ida_auth_apis():
    """Test availability of IDA authentication-related APIs"""
    print("=" * 70)
    print("[Test 1] IDA Authentication API Test")
    print("=" * 70)
    
    ida = IDAProClient()
    if not ida.connect():
        print("[FAIL] IDA connection failed!")
        return False
    print("[OK] IDA connection successful")
    
    # Test main dispatch hub: 0x42378
    hub_addr = "0x42378"
    print(f"\nTarget Hub: {hub_addr}")
    
    # 1. Test get_basic_blocks
    print("\n[1.1] Testing get_basic_blocks...")
    res = ida.get_basic_blocks(hub_addr)
    if res.get("status") == "ok":
        blocks = res.get("data", [])
        print(f"    [OK] Retrieved {len(blocks)} basic blocks")
    else:
        print(f"    [WARN] get_basic_blocks: {res.get('error', 'unknown error')}")
    
    # 2. Test build_dominator_tree
    print("\n[1.2] Testing build_dominator_tree...")
    res = ida.build_dominator_tree(hub_addr)
    if res.get("status") == "ok":
        dom_tree = res.get("data", {})
        print(f"    [OK] Dominator tree built successfully, {len(dom_tree)} dominance relations")
    else:
        print(f"    [WARN] build_dominator_tree: {res.get('error', 'unknown error')}")
    
    # 3. Test scan_auth_patterns
    print("\n[1.3] Testing scan_auth_patterns...")
    res = ida.scan_auth_patterns(hub_addr)
    if res.get("status") == "ok":
        auth_data = res.get("data", {})
        auth_calls = auth_data.get("auth_calls", [])
        blocking_checks = auth_data.get("blocking_checks", [])
        print(f"    [OK] Scanned {len(auth_calls)} auth calls, {len(blocking_checks)} blocking checks")
        if auth_calls:
            print(f"    Sample auth call: {auth_calls[0]}")
    else:
        print(f"    [WARN] scan_auth_patterns: {res.get('error', 'unknown error')}")
    
    # 4. Test get_callees
    print("\n[1.4] Testing get_callees (get called functions)...")
    test_handler = "formSetPPTPServer"
    res = ida.get_callees(test_handler)
    if res.get("status") == "ok":
        callees = res.get("data", [])
        print(f"    [OK] {test_handler} calls {len(callees)} functions")
        if callees:
            print(f"    First 5: {callees[:5]}")
    else:
        print(f"    [WARN] get_callees: {res.get('error', 'unknown error')}")
    
    # 5. Test calculate_tis (Terminating Imbalance Score)
    print("\n[1.5] Testing calculate_tis (TIS calculation)...")
    res = ida.calculate_tis(test_handler)
    if res.get("status") == "ok":
        tis_data = res.get("data", [])
        print(f"    [OK] Calculated TIS for {len(tis_data)} branches")
        high_tis = [t for t in tis_data if t.get("tis", 0) >= 2.0]
        if high_tis:
            print(f"    High TIS branches (>=2.0): {len(high_tis)}")
            for t in high_tis[:3]:
                print(f"        TIS={t.get('tis'):.2f}, terminates={t.get('terminates')}")
    else:
        print(f"    [WARN] calculate_tis: {res.get('error', 'unknown error')}")
    
    return True


def test_global_auth_identification():
    """Test global authentication mechanism identification"""
    print("\n" + "=" * 70)
    print("[Test 2] Global Authentication Mechanism Identification")
    print("=" * 70)
    
    ida = IDAProClient()
    if not ida.connect():
        return False
    
    # Analyze registration function sub_2E9EC (initWebs)
    init_func = "sub_2E9EC"
    print(f"\nAnalyzing web initialization function: {init_func}")
    
    # Get decompiled code
    res = ida.decompile(init_func)
    if res.get("status") != "ok":
        print(f"[FAIL] Decompilation failed")
        return False
    
    code = res.get("data", {}).get("code", "")
    
    # Search for key authentication patterns
    print("\n[2.1] Searching for global authentication patterns...")
    
    auth_patterns = [
        "R7WebsSecurityHandler",  # Tenda security handler
        "SecurityHandler",
        "AuthHandler",
        "checkLogin",
        "session",
    ]
    
    found_patterns = []
    for line in code.split('\n'):
        for pattern in auth_patterns:
            if pattern.lower() in line.lower():
                found_patterns.append((pattern, line.strip()))
    
    if found_patterns:
        print(f"    [OK] Found {len(found_patterns)} authentication-related patterns:")
        for pattern, line in found_patterns[:5]:
            print(f"        [{pattern}] {line[:60]}...")
    else:
        print("    [INFO] No explicit authentication patterns found in initialization code")
    
    # Analyze dominator tree
    print("\n[2.2] Analyzing Hub function dominance context...")
    hub_addr = "sub_42378"
    
    res = ida.build_dominator_tree(hub_addr)
    if res.get("status") == "ok":
        dom_tree = res.get("data", {})
        print(f"    [OK] Dominator tree contains {len(dom_tree)} nodes")
        
        # Display first few dominance relations
        for i, (dominated, dominator) in enumerate(list(dom_tree.items())[:3]):
            print(f"        {dominator} dominates {dominated}")
    else:
        print(f"    [WARN] Dominator tree construction: {res.get('error')}")
    
    return True


def test_local_constraint_analysis():
    """Test local constraint analysis"""
    print("\n" + "=" * 70)
    print("[Test 3] Local Constraint Analysis")
    print("=" * 70)
    
    ida = IDAProClient()
    if not ida.connect():
        return False
    
    # Select several representative handlers for analysis
    test_handlers = [
        "formSetPPTPServer",      # Configuration interface
        "formGetSysInfo",         # Information retrieval interface
        "formSetFirewallCfg",     # Firewall configuration
        "formSetWifiBasicCfg",    # WiFi configuration
        "formSetClientState",     # Client state
    ]
    
    print("\n[3.1] Analyzing handler call patterns (identifying shared authentication utilities)...")
    
    from collections import Counter
    callee_counter = Counter()
    handler_details = {}
    
    for handler in test_handlers:
        res = ida.get_callees(handler)
        if res.get("status") == "ok":
            callees = res.get("data", [])
            handler_details[handler] = callees
            for callee in callees:
                callee_counter[callee] += 1
            print(f"    {handler}: calls {len(callees)} functions")
    
    # Find shared function calls
    print("\n[3.2] Identifying shared utility functions (called by multiple handlers)...")
    shared_funcs = [(func, count) for func, count in callee_counter.most_common(10) if count >= 2]
    
    if shared_funcs:
        print(f"    [OK] Found {len(shared_funcs)} shared functions:")
        for func, count in shared_funcs:
            print(f"        {func}: called by {count}/{len(test_handlers)} handlers")
    
    # Analyze TIS (Terminating Imbalance Score)
    print("\n[3.3] TIS analysis (identifying blocking behavior)...")
    
    for handler in test_handlers[:3]:
        res = ida.calculate_tis(handler)
        if res.get("status") == "ok":
            tis_data = res.get("data", [])
            high_tis = [t for t in tis_data if t.get("tis", 0) >= 2.0 and t.get("terminates")]
            if high_tis:
                max_tis = max(t.get("tis", 0) for t in high_tis)
                print(f"    {handler}: {len(high_tis)} high TIS branches, max={max_tis:.2f}")
            else:
                print(f"    {handler}: No high TIS blocking branches")
        else:
            print(f"    {handler}: TIS calculation failed - {res.get('error', 'unknown')}")
    
    return True


def test_acdg_construction():
    """Test ACDG construction"""
    print("\n" + "=" * 70)
    print("[Test 4] ACDG Construction (Access Control Dependency Graph)")
    print("=" * 70)
    
    # Check routes file
    routes_file = "output/routes_v3_hierarchical.json"
    if not os.path.exists(routes_file):
        print(f"[WARN] Routes file does not exist: {routes_file}")
        routes_file = "output/routes_v3_latest.json"
    
    if not os.path.exists(routes_file):
        print("[FAIL] No available routes file!")
        return False
    
    print(f"\n[4.1] Loading route data: {routes_file}")
    
    with open(routes_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Flatten routes
    flat_routes = []
    if isinstance(data, dict):
        for root_path, routes in data.items():
            for r in routes:
                r['root'] = root_path
                flat_routes.append(r)
    else:
        flat_routes = data
    
    print(f"    [OK] Loaded {len(flat_routes)} routes")
    
    # Import and run LogicDecoupler
    print("\n[4.2] Running LogicDecoupler...")
    
    try:
        from analysis.logic_decoupler import LogicDecoupler
        from analysis.models import ACDG, AuthState, ProtectionType
        
        decoupler = LogicDecoupler()
        acdg = decoupler.run_from_file(routes_file, firmware_name="Tenda_AC15_httpd")
        
        print(f"\n[4.3] ACDG construction results:")
        print(f"    Total routes: {acdg.total_routes}")
        print(f"    Auth-Required: {acdg.auth_required_count}")
        print(f"    Auth-Free: {acdg.auth_free_count}")
        print(f"    Unknown: {acdg.unknown_count}")
        
        # Display global authentication mechanisms
        if acdg.global_auth_mechanisms:
            print(f"\n    Global authentication mechanisms ({len(acdg.global_auth_mechanisms)}):")
            for mech in acdg.global_auth_mechanisms[:5]:
                print(f"        - {mech.name} ({mech.mechanism_type})")
        
        # Display shared authentication utilities
        if acdg.shared_auth_utilities:
            print(f"\n    Shared authentication utilities ({len(acdg.shared_auth_utilities)}):")
            for util in acdg.shared_auth_utilities[:5]:
                print(f"        - {util.name} (TIS={util.tis_score})")
        
        # Display Auth-Free route examples
        auth_free = [r for r in acdg.routes if r.auth_state == AuthState.AUTH_FREE]
        if auth_free:
            print(f"\n    Auth-Free route examples ({len(auth_free)} total):")
            for r in auth_free[:5]:
                print(f"        - {r.path} -> {r.handler}")
        
        # Save ACDG
        output_file = "output/acdg_test.json"
        acdg.save_json(output_file)
        print(f"\n    [OK] ACDG saved: {output_file}")
        
        return True
        
    except Exception as e:
        import traceback
        print(f"[FAIL] LogicDecoupler execution failed: {e}")
        traceback.print_exc()
        return False


def main():
    print("=" * 70)
    print("    PANGU Logic Decoupling and State Identification Test")
    print("    Logic Decoupling & State Identification Test")
    print("=" * 70)
    print(f"Test time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    results = {}
    
    # Test 1: IDA API
    results["IDA Auth API"] = test_ida_auth_apis()
    
    # Test 2: Global authentication mechanism identification
    results["Global Auth Identification"] = test_global_auth_identification()
    
    # Test 3: Local constraint analysis
    results["Local Constraint Analysis"] = test_local_constraint_analysis()
    
    # Test 4: ACDG construction
    results["ACDG Construction"] = test_acdg_construction()
    
    # Summary
    print("\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)
    
    for test_name, passed in results.items():
        status = "[OK]" if passed else "[FAIL]"
        print(f"    {status} {test_name}")
    
    passed_count = sum(1 for v in results.values() if v)
    print(f"\n    Passed: {passed_count}/{len(results)}")


if __name__ == "__main__":
    main()
