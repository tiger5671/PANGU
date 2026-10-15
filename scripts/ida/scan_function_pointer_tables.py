# scan_function_pointer_tables.py
# IDA Pro 9.0 Compatible Script: Scan and Identify Function Pointer Tables
# Purpose: Discover function pointer arrays that may be used for route dispatch in firmware

import idc
import idaapi
import idautils
import ida_bytes
import ida_segment
import ida_funcs
import ida_name
import ida_ida

# ================= Configuration Parameters =================
MIN_TABLE_SIZE = 3          # Minimum consecutive pointers (values below this are not considered tables)
MAX_TABLE_SIZE = 200        # Maximum table size (to prevent false positives)
PTR_SIZE = 4                # Pointer size, auto-detected
IS_64BIT = False            # Whether 64-bit architecture

# ================= Initialization =================
def init_config():
    """Auto-detect architecture and configure parameters"""
    global PTR_SIZE, IS_64BIT
    try:
        IS_64BIT = ida_ida.inf_is_64bit()
        PTR_SIZE = 8 if IS_64BIT else 4
        print(f"[*] Architecture detected: {'64-bit' if IS_64BIT else '32-bit'}")
        print(f"[*] Pointer size: {PTR_SIZE} bytes")
    except:
        print("[!] Warning: Could not detect architecture, assuming 32-bit")
        PTR_SIZE = 4

# ================= Utility Functions =================
def read_pointer(ea):
    """Read pointer value (32-bit or 64-bit)"""
    try:
        if IS_64BIT:
            return ida_bytes.get_qword(ea)
        else:
            return ida_bytes.get_wide_dword(ea)
    except:
        return None

def is_valid_code_address(ea):
    """Check if address points to valid code"""
    if ea is None or ea == 0 or ea == idc.BADADDR:
        return False
    
    # For ARM architecture, clear Thumb bit
    if ida_ida.inf_get_procname().lower().startswith("arm") and not IS_64BIT:
        ea = ea & ~1
    
    # Check if within valid address range
    if ea < 0 or ea == idc.BADADDR:
        return False
    
    # Check if points to a function
    if ida_funcs.get_func(ea):
        return True
    
    # Check if within executable segment
    seg = ida_segment.getseg(ea)
    if seg and (seg.perm & ida_segment.SEGPERM_EXEC):
        return True
    
    return False

def get_function_name(ea):
    """Get function name (with address info)"""
    if ida_ida.inf_get_procname().lower().startswith("arm") and not IS_64BIT:
        ea = ea & ~1
    
    # Try to get function name
    name = idc.get_func_name(ea)
    if name and not name.startswith("sub_"):
        return name
    
    # Try to get symbol name
    name = ida_name.get_name(ea)
    if name:
        return name
    
    # Return address representation
    return f"sub_{ea:X}"

def is_data_segment(seg):
    """Check if segment is a data segment"""
    if not seg:
        return False
    
    # Exclude code segments
    if seg.perm & ida_segment.SEGPERM_EXEC:
        return False
    
    # Common data segment names
    seg_name = idc.get_segm_name(seg.start_ea).lower()
    data_seg_names = ['.data', '.rodata', '.bss', 'data', 'rodata', 'bss']
    
    return any(name in seg_name for name in data_seg_names)

# ================= Core Scanning Logic =================
def scan_segment_for_function_pointer_tables(seg):
    """
    Scan a single segment for function pointer tables
    Returns: List of {address, size, entries}
    """
    tables = []
    current_ea = seg.start_ea
    end_ea = seg.end_ea
    
    # Iterate through each pointer position in the segment
    while current_ea < end_ea - PTR_SIZE:
        ptr_array = []  # Store consecutive code pointers
        start_addr = current_ea
        
        # Try to read consecutive pointers
        while current_ea < end_ea:
            ptr_val = read_pointer(current_ea)
            
            if ptr_val is None:
                break
            
            # Check if valid code pointer
            if is_valid_code_address(ptr_val):
                ptr_array.append({
                    'address': current_ea,
                    'target': ptr_val,
                    'func_name': get_function_name(ptr_val)
                })
                current_ea += PTR_SIZE
            else:
                # Encountered non-code pointer, end current sequence
                break
        
        # Determine if this is a valid function pointer table
        if MIN_TABLE_SIZE <= len(ptr_array) <= MAX_TABLE_SIZE:
            tables.append({
                'start_address': start_addr,
                'size': len(ptr_array),
                'entries': ptr_array
            })
            print(f"[+] Found table at 0x{start_addr:X} with {len(ptr_array)} entries")
        
        # If current position didn't move, skip one pointer size to avoid infinite loop
        if current_ea == start_addr:
            current_ea += PTR_SIZE
    
    return tables

def scan_all_segments():
    """Scan all data segments"""
    all_tables = []
    
    print("\n" + "="*70)
    print("Starting Function Pointer Table Scan...")
    print("="*70 + "\n")
    
    # Iterate through all segments
    for n in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(n)
        if not seg:
            continue
        
        # Only scan data segments
        if not is_data_segment(seg):
            continue
        
        seg_name = idc.get_segm_name(seg.start_ea)
        print(f"[*] Scanning segment: {seg_name} (0x{seg.start_ea:X} - 0x{seg.end_ea:X})")
        
        # Scan this segment
        tables = scan_segment_for_function_pointer_tables(seg)
        all_tables.extend(tables)
    
    return all_tables

# ================= Result Output =================
def print_table_details(table, index):
    """Print detailed information for a single table"""
    print(f"\n{'='*70}")
    print(f"Table #{index + 1}")
    print(f"{'='*70}")
    print(f"Address:       0x{table['start_address']:X}")
    print(f"Size:          {table['size']} entries ({table['size'] * PTR_SIZE} bytes)")
    print(f"Segment:       {idc.get_segm_name(table['start_address'])}")
    
    # Check for cross-references (usage)
    xrefs = list(idautils.DataRefsTo(table['start_address']))
    if xrefs:
        print(f"Xrefs:         {len(xrefs)} reference(s) found")
        for xref in xrefs[:3]:  # Only show first 3
            xref_func = ida_funcs.get_func(xref)
            if xref_func:
                print(f"               ↳ 0x{xref:X} in {idc.get_func_name(xref_func.start_ea)}")
    else:
        print(f"Xrefs:         No references found (might be unused)")
    
    print(f"\nEntries:")
    print(f"{'Index':<8} {'Pointer Addr':<16} {'Target Addr':<16} {'Function Name'}")
    print("-" * 70)
    
    for i, entry in enumerate(table['entries']):
        print(f"{i:<8} 0x{entry['address']:08X}     0x{entry['target']:08X}     {entry['func_name']}")
    
    # Try to identify usage (heuristic)
    unique_funcs = set(e['func_name'] for e in table['entries'])
    print(f"\n[Analysis]")
    print(f"  - Unique functions: {len(unique_funcs)}/{table['size']}")
    
    if len(unique_funcs) == table['size']:
        print(f"  - Type: Likely a dispatch table (all unique handlers)")
    else:
        print(f"  - Type: Might contain duplicate entries or function families")

def export_results_to_json(tables, output_file):
    """Export results to JSON file"""
    import json
    from datetime import datetime
    
    result = {
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "binary": idc.get_input_file_path(),
        "architecture": "64-bit" if IS_64BIT else "32-bit",
        "tables_found": len(tables),
        "tables": []
    }
    
    for table in tables:
        table_data = {
            "address": f"0x{table['start_address']:X}",
            "size": table['size'],
            "entries": [
                {
                    "index": i,
                    "pointer_addr": f"0x{e['address']:X}",
                    "target_addr": f"0x{e['target']:X}",
                    "function": e['func_name']
                }
                for i, e in enumerate(table['entries'])
            ]
        }
        result["tables"].append(table_data)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=4, ensure_ascii=False)
    
    print(f"\n[+] Results exported to: {output_file}")

# ================= Main Function =================
def main():
    """Main scanning workflow"""
    print("\n" + "*"*70)
    print("*" + " "*20 + "Function Pointer Table Scanner" + " "*19 + "*")
    print("*" + " "*25 + "IDA Pro 9.0 Compatible" + " "*22 + "*")
    print("*"*70 + "\n")
    
    # Initialize
    init_config()
    
    # Scan
    tables = scan_all_segments()
    
    # Output statistics
    print("\n" + "="*70)
    print("SCAN COMPLETE")
    print("="*70)
    print(f"Total tables found: {len(tables)}")
    
    if not tables:
        print("\n[!] No function pointer tables detected.")
        print("[*] Possible reasons:")
        print("    1. This binary doesn't use function pointer dispatch")
        print("    2. Tables are dynamically constructed (malloc'd arrays)")
        print("    3. Tables are smaller than MIN_TABLE_SIZE threshold")
        print("    4. Tables contain mixed data (not purely code pointers)")
        return
    
    # Output detailed information
    for i, table in enumerate(tables):
        print_table_details(table, i)
    
    # Export results
    output_path = idc.get_idb_path().replace('.i64', '_function_pointer_tables.json').replace('.idb', '_function_pointer_tables.json')
    export_results_to_json(tables, output_path)
    
    # Summary recommendations
    print("\n" + "="*70)
    print("RECOMMENDATIONS")
    print("="*70)
    print("[*] Next steps:")
    print("    1. Review tables with Xrefs to find dispatcher functions")
    print("    2. Check if entries follow URL/Action naming patterns")
    print("    3. Decompile dispatcher functions to see usage context")
    print("    4. Look for array index calculations (e.g., handlers[id]())")
    
    if tables:
        print(f"\n[*] Example: To analyze the first table, decompile functions that reference:")
        print(f"    Address: 0x{tables[0]['start_address']:X}")

# ================= Execution Entry =================
if __name__ == "__main__":
    main()
