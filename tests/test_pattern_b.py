#!/usr/bin/env python3
"""
Test Pattern B (Dynamic Registration Hub) detection on Tenda firmware.

According to paper Section 3.2.1:
- Pattern B: Dynamic Registration Hub
- Characteristic: High call frequency to a registration function
- Example: goform_dispatch() calls register("route", handler) many times
"""

import sys
sys.path.insert(0, '.')

from core.bridge.ida_client import IDAProClient

def test_static_scan():
    """Test run_static_scan to see what registration hubs are found"""
    print("="*60)
    print("Testing Pattern B: Dynamic Registration Hub Detection")
    print("="*60)
    
    ida = IDAProClient('localhost', 4455)
    ida.connect()
    
    # Run static scan
    print("\n[1] Running static scan...")
    result = ida.run_static_scan()
    
    if result.get('status') != 'success':
        print(f"  ERROR: {result.get('error')}")
        return
    
    data = result.get('data', {})
    structures = data.get('memory_structures', [])
    
    print(f"\n[2] Found {len(structures)} memory structures:")
    
    # Count by type
    by_type = {}
    for s in structures:
        t = s.get('type', 'unknown')
        if t not in by_type:
            by_type[t] = []
        by_type[t].append(s)
    
    for t, items in by_type.items():
        print(f"  - {t}: {len(items)} items")
    
    # Check for REGISTRATION_HUB
    hubs = by_type.get('REGISTRATION_HUB', [])
    if hubs:
        print(f"\n[3] Found {len(hubs)} registration hubs:")
        for hub in hubs:
            addr = hub.get('address', 'unknown')
            traces = hub.get('raw_call_traces', [])
            print(f"  - Hub at {addr}, {len(traces)} call traces")
            # Show first few traces
            for trace in traces[:3]:
                print(f"    Call: {trace}")
    else:
        print("\n[3] No registration hubs found!")
        print("    This is the problem - Pattern B detection is not working")
    
    return data


def test_dynamic_hub_scan_direct():
    """Directly test scan_dynamic_hubs on IDA server"""
    print("\n" + "="*60)
    print("Testing scan_dynamic_hubs directly")
    print("="*60)
    
    ida = IDAProClient('localhost', 4455)
    ida.connect()
    
    # Execute scan_dynamic_hubs directly
    script = '''
import idautils
import idc
import ida_funcs

# Count how many times each function is called
call_counts = {}
for seg_ea in idautils.Segments():
    for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
        for ref in idautils.CodeRefsTo(func_ea, 0):
            if func_ea not in call_counts:
                call_counts[func_ea] = 0
            call_counts[func_ea] += 1

# Find functions called most frequently
sorted_funcs = sorted(call_counts.items(), key=lambda x: x[1], reverse=True)

print("Top 20 most called functions:")
for func_ea, count in sorted_funcs[:20]:
    name = idc.get_func_name(func_ea)
    print(f"  {hex(func_ea)}: {name} - called {count} times")
'''
    
    print("\n[1] Finding most called functions...")
    result = ida.execute_script(script)
    
    if result.get('status') == 'success':
        print(result.get('data', {}).get('output', ''))
    else:
        print(f"  ERROR: {result.get('error')}")


def test_find_registration_function():
    """Find the registration function by looking for functions that take (string, handler) args"""
    print("\n" + "="*60)
    print("Looking for registration function patterns")
    print("="*60)
    
    ida = IDAProClient('localhost', 4455)
    ida.connect()
    
    # Look for sub_171EC (the known registration function)
    script = '''
import idautils
import idc

# The known registration function in Tenda
reg_func = 0x171EC

print(f"Analyzing registration function at {hex(reg_func)}...")

# Find all cross-references to this function
xrefs = list(idautils.CodeRefsTo(reg_func, 0))
print(f"Found {len(xrefs)} calls to this function")

# Find the parent functions (callers)
caller_funcs = {}
for xref in xrefs:
    func = idc.get_func_attr(xref, idc.FUNCATTR_START)
    if func != idc.BADADDR:
        if func not in caller_funcs:
            caller_funcs[func] = 0
        caller_funcs[func] += 1

print(f"\\nCaller functions ({len(caller_funcs)} unique):")
for func_ea, call_count in sorted(caller_funcs.items(), key=lambda x: x[1], reverse=True)[:10]:
    name = idc.get_func_name(func_ea)
    print(f"  {hex(func_ea)}: {name} - calls reg_func {call_count} times")
'''
    
    print("\n[1] Finding callers of registration function (0x171EC)...")
    result = ida.execute_script(script)
    
    if result.get('status') == 'success':
        print(result.get('data', {}).get('output', ''))
    else:
        print(f"  ERROR: {result.get('error')}")


def test_analyze_hub_function():
    """Analyze the known hub function (sub_42378) to understand the pattern"""
    print("\n" + "="*60)
    print("Analyzing known hub function (sub_42378)")
    print("="*60)
    
    ida = IDAProClient('localhost', 4455)
    ida.connect()
    
    # Decompile the hub function
    print("\n[1] Decompiling sub_42378...")
    result = ida.decompile_function(0x42378)
    
    if result.get('status') == 'success':
        code = result.get('data', {}).get('code', '')
        lines = code.split('\n')
        print(f"  Function has {len(lines)} lines")
        
        # Count calls to sub_171EC
        calls = [l for l in lines if 'sub_171EC' in l or '0x171EC' in l.lower()]
        print(f"  Found {len(calls)} calls to sub_171EC")
        
        # Show first few calls
        print("\n  First 5 calls:")
        for call in calls[:5]:
            print(f"    {call.strip()}")
        
        return code
    else:
        print(f"  ERROR: {result.get('error')}")
        return None


def test_extract_routes_from_hub():
    """Extract routes by parsing the hub function's calls"""
    print("\n" + "="*60)
    print("Extracting routes from hub function")
    print("="*60)
    
    ida = IDAProClient('localhost', 4455)
    ida.connect()
    
    # Use get_ast_calls to extract calls from hub function
    script = '''
import ida_hexrays
import idc
import idaapi

hub_ea = 0x42378

# Decompile the function
cfunc = ida_hexrays.decompile(hub_ea)
if cfunc:
    code = str(cfunc)
    
    # Parse for sub_171EC calls
    import re
    # Pattern: sub_171EC("route_name", handler_func)
    pattern = r'sub_171EC\s*\(\s*"([^"]+)"\s*,\s*([a-zA-Z_][a-zA-Z0-9_]*|\(\w+\))\s*\)'
    matches = re.findall(pattern, code)
    
    print(f"Found {len(matches)} route registrations:")
    for route, handler in matches[:20]:
        print(f"  Route: {route} -> Handler: {handler}")
    
    if len(matches) > 20:
        print(f"  ... and {len(matches) - 20} more")
else:
    print("Failed to decompile function")
'''
    
    print("\n[1] Extracting routes using regex on decompiled code...")
    result = ida.execute_script(script)
    
    if result.get('status') == 'success':
        print(result.get('data', {}).get('output', ''))
    else:
        print(f"  ERROR: {result.get('error')}")


if __name__ == '__main__':
    # Test 1: Check static scan results
    test_static_scan()
    
    # Test 2: Find most called functions
    test_dynamic_hub_scan_direct()
    
    # Test 3: Find registration function callers
    test_find_registration_function()
    
    # Test 4: Analyze the known hub function
    test_analyze_hub_function()
    
    # Test 5: Extract routes from hub
    test_extract_routes_from_hub()
