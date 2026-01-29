# tests/test_cfg_analysis.py
# Test CFG Analysis Interface
# Usage: Run this script in Python environment (ensure IDA Server is started)

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.bridge.ida_client import IDAProClient


def test_basic_blocks(client, func_addr):
    """Test basic block retrieval"""
    print(f"\n=== Test get_basic_blocks({func_addr}) ===")
    result = client.get_basic_blocks(func_addr)
    
    if result.get("status") == "ok":
        blocks = result.get("data", [])
        print(f"[+] Found {len(blocks)} basic blocks")
        for block in blocks[:5]:  # Only show first 5
            print(f"    Block {block['id']}: {block['start']} - {block['end']}")
            print(f"        Successors: {block['successors']}")
            print(f"        Predecessors: {block['predecessors']}")
    else:
        print(f"[-] Error: {result.get('error')}")
    
    return result


def test_dominator_tree(client, func_addr):
    """Test dominator tree construction"""
    print(f"\n=== Test build_dominator_tree({func_addr}) ===")
    result = client.build_dominator_tree(func_addr)
    
    if result.get("status") == "ok":
        dom_tree = result.get("data", {})
        print(f"[+] Dominator tree node count: {len(dom_tree)}")
        for block, idom in list(dom_tree.items())[:10]:  # Only show first 10
            print(f"    {block} <- (dominated by) {idom}")
    else:
        print(f"[-] Error: {result.get('error')}")
    
    return result


def test_tis_calculation(client, func_addr):
    """Test TIS calculation"""
    print(f"\n=== Test calculate_tis({func_addr}) ===")
    result = client.calculate_tis(func_addr)
    
    if result.get("status") == "ok":
        tis_results = result.get("data", [])
        print(f"[+] Found {len(tis_results)} if statements")
        
        # Sort by TIS score, show high scores
        sorted_results = sorted(tis_results, key=lambda x: x['tis'], reverse=True)
        for item in sorted_results[:10]:
            print(f"    [{item['pattern']}] TIS={item['tis']:.2f} @ {item['address']}")
            print(f"        Then: {item['weight_then']}, Else: {item['weight_else']}, Terminates: {item['terminates']}")
    else:
        print(f"[-] Error: {result.get('error')}")
    
    return result


def test_blocking_checks(client, func_addr, threshold=2.0):
    """Test blocking check identification"""
    print(f"\n=== Test find_blocking_checks({func_addr}, threshold={threshold}) ===")
    result = client.find_blocking_checks(func_addr, threshold)
    
    if result.get("status") == "ok":
        checks = result.get("data", [])
        print(f"[+] Found {len(checks)} blocking checks")
        for check in checks:
            print(f"    [{check['pattern']}] TIS={check['tis']:.2f} @ {check['address']}")
    else:
        print(f"[-] Error: {result.get('error')}")
    
    return result


def test_auth_patterns(client, func_addr):
    """Test authentication pattern scanning"""
    print(f"\n=== Test scan_auth_patterns({func_addr}) ===")
    result = client.scan_auth_patterns(func_addr)
    
    if result.get("status") == "ok":
        data = result.get("data", {})
        print(f"[+] Function: {data.get('func_name')} @ {data.get('func_addr')}")
        
        auth_calls = data.get("auth_calls", [])
        if auth_calls:
            print(f"    Authentication-related calls ({len(auth_calls)}):")
            for call in auth_calls[:5]:
                print(f"        {call['callee']} @ {call['address']}")
        
        auth_strings = data.get("auth_strings", [])
        if auth_strings:
            print(f"    Authentication-related strings ({len(auth_strings)}):")
            for s in auth_strings[:5]:
                print(f"        \"{s['string']}\" @ {s['address']}")
        
        blocking = data.get("blocking_checks", [])
        if blocking:
            print(f"    Blocking checks ({len(blocking)}):")
            for check in blocking[:5]:
                print(f"        [{check['pattern']}] TIS={check['tis']:.2f} @ {check['address']}")
    else:
        print(f"[-] Error: {result.get('error')}")
    
    return result


def run_all_tests(func_addr):
    """Run all tests"""
    print("=" * 60)
    print("PANGU CFG Analysis Interface Test")
    print("=" * 60)
    
    client = IDAProClient()
    
    if not client.connect():
        print("[-] Cannot connect to IDA Server, please ensure service is started in IDA")
        return
    
    print(f"[+] Connected to IDA Server")
    print(f"[*] Test target function: {func_addr}")
    
    # Run all tests
    test_basic_blocks(client, func_addr)
    test_dominator_tree(client, func_addr)
    test_tis_calculation(client, func_addr)
    test_blocking_checks(client, func_addr)
    test_auth_patterns(client, func_addr)
    
    print("\n" + "=" * 60)
    print("Tests completed!")
    print("=" * 60)
    
    client.close()


if __name__ == "__main__":
    # Default test address (modify according to actual firmware)
    # Can be passed via command line: python test_cfg_analysis.py 0x401000
    if len(sys.argv) > 1:
        test_addr = sys.argv[1]
    else:
        test_addr = "main"  # Default test main function
        print(f"[*] Using default address: {test_addr}")
        print("[*] Can specify via command line: python test_cfg_analysis.py 0x401000")
    
    run_all_tests(test_addr)
