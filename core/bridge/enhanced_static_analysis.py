# Copyright (c) 2026 The Pangu Project Authors. All rights reserved.
# core/bridge/enhanced_static_analysis.py
# PANGU Enhanced Static Analysis Module
# Improved function pointer table identification and route backtracing algorithms
# Corresponds to Paper Section 3.2.2: Hub Identification via Backward Slicing

"""
This module must run inside IDA Pro environment.
Provides the following enhanced features:
1. Smart function pointer table identification (distinguish route tables from normal data)
2. String-Handler pairing identification
3. Backward slicing for route registration tracing
"""

try:
    import idc
    import idaapi
    import idautils
    import ida_bytes
    import ida_segment
    import ida_funcs
    import ida_name
    import ida_xref
    import ida_ida
    IN_IDA = True
except ImportError:
    IN_IDA = False

import json
from typing import List, Dict, Optional, Tuple, Set


class EnhancedTableScanner:
    """
    Enhanced function pointer table scanner
    Improvements:
    1. Identify [String, Handler] pairing pattern
    2. Support mixed tables (resources + multiple Handlers)
    3. Filter noise data
    """
    
    # Route-related keywords
    ROUTE_KEYWORDS = [
        "goform", "cgi", "hnap", "soap", "upnp", "json", "api",
        "get", "set", "run", "action", "cmd", "exec", "config",
        ".asp", ".htm", ".cgi", ".php", ".do"
    ]
    
    # Noise keywords
    NOISE_KEYWORDS = [
        "nvram_", "gpio_", "mfcp_", "debug_", "log_", "trace_",
        "text/", "image/", "application/", "error:", "warning:"
    ]
    
    def __init__(self):
        if not IN_IDA:
            raise RuntimeError("This module must run inside IDA Pro")
        
        # Architecture detection - IDA 9.0 compatible
        self.is_64bit = ida_ida.inf_is_64bit()
        self.arm_thumb = ida_ida.inf_get_procname().lower().startswith("arm") and not self.is_64bit
        
        self.ptr_size = 8 if self.is_64bit else 4
        
        # Configuration
        self.min_table_size = 3
        self.max_table_size = 500
        self.max_string_len = 256
    
    def read_pointer(self, ea: int) -> Optional[int]:
        """Read pointer value"""
        try:
            if self.is_64bit:
                return ida_bytes.get_qword(ea)
            else:
                return ida_bytes.get_wide_dword(ea)
        except:
            return None
    
    def read_string(self, ea: int) -> Optional[str]:
        """Read string"""
        try:
            s = idc.get_strlit_contents(ea, -1, idc.STRTYPE_C)
            if s:
                return s.decode('utf-8', errors='ignore')
            
            # Try direct read
            result = []
            for i in range(self.max_string_len):
                byte = ida_bytes.get_byte(ea + i)
                if byte == 0:
                    break
                if 32 <= byte < 127:
                    result.append(chr(byte))
                else:
                    return None  # Non-ASCII, may not be string
            
            return ''.join(result) if len(result) >= 2 else None
        except:
            return None
    
    def is_string_pointer(self, ea: int) -> Tuple[bool, Optional[str]]:
        """Check if it's a string pointer"""
        ptr = self.read_pointer(ea)
        if not ptr or ptr == 0 or ptr == idc.BADADDR:
            return False, None
        
        # Check if pointing to valid data segment
        seg = ida_segment.getseg(ptr)
        if not seg:
            return False, None
        
        # [FIX] If target is a function, it's not a string pointer
        # Avoid misinterpreting the first bytes of function code as strings (e.g., "pH-", "0H-")
        if ida_funcs.get_func(ptr):
            return False, None
        
        # Try to read string
        s = self.read_string(ptr)
        if s and len(s) >= 2:
            return True, s
        
        return False, None
    
    def is_code_pointer(self, ea: int) -> Tuple[bool, Optional[int]]:
        """Check if it's a code pointer"""
        ptr = self.read_pointer(ea)
        if not ptr or ptr == 0 or ptr == idc.BADADDR:
            return False, None
        
        # ARM Thumb bit handling
        target = ptr & ~1 if self.arm_thumb else ptr
        
        # Check if it's a function
        if ida_funcs.get_func(target):
            return True, ptr
        
        # Check if in executable segment
        seg = ida_segment.getseg(target)
        if seg and (seg.perm & ida_segment.SEGPERM_EXEC):
            return True, ptr
        
        return False, None
    
    def classify_string(self, s: str) -> str:
        """Classify string"""
        s_lower = s.lower()
        
        # Check noise
        for noise in self.NOISE_KEYWORDS:
            if noise in s_lower:
                return "NOISE"
        
        # Check route related
        for route in self.ROUTE_KEYWORDS:
            if route in s_lower:
                return "ROUTE"
        
        # Check path features
        if '/' in s or '.' in s[-5:]:
            return "PATH"
        
        # CamelCase detection
        import re
        if re.match(r'^[A-Z][a-z]+[A-Z]', s):
            return "ACTION"
        
        # snake_case detection
        if '_' in s and s.replace('_', '').isalnum():
            return "CONFIG"
        
        return "UNKNOWN"
    
    def scan_string_handler_table(self, start_ea: int, seg_end: int) -> Optional[Dict]:
        """
        Scan [String, Handler] pairing table
        Format: [str_ptr, handler_ptr, str_ptr, handler_ptr, ...]
        """
        entries = []
        ea = start_ea
        
        while ea < seg_end - 2 * self.ptr_size:
            # Try to read pairing
            is_str, str_val = self.is_string_pointer(ea)
            is_code, code_ptr = self.is_code_pointer(ea + self.ptr_size)
            
            if is_str and is_code:
                entry = {
                    "url": str_val,
                    "url_addr": hex(self.read_pointer(ea)),
                    "handler": hex(code_ptr),
                    "handler_addr": hex(ea + self.ptr_size),
                    "string_class": self.classify_string(str_val)
                }
                entries.append(entry)
                ea += 2 * self.ptr_size
            else:
                break
        
        if len(entries) >= self.min_table_size:
            # Statistics classification
            classes = [e["string_class"] for e in entries]
            noise_ratio = classes.count("NOISE") / len(classes)
            
            if noise_ratio < 0.5:  # Valid only if noise < 50%
                return {
                    "type": "STATIC_ADAPTIVE",
                    "address": hex(start_ea),
                    "entry_count": len(entries),
                    "all_entries": entries,
                    "dominant_class": max(set(classes), key=classes.count)
                }
        
        return None
    
    def scan_mixed_handler_table(self, start_ea: int, seg_end: int) -> Optional[Dict]:
        """
        Scan mixed Handler table
        Format: [str_ptr, handler1, handler2, handler3, str_ptr, handler1, ...]
        Common in resource CRUD operation tables
        """
        # Detect pattern: first calculate how many handlers per "entry"
        handlers_per_entry = self._detect_handler_count(start_ea, seg_end)
        if handlers_per_entry < 2:
            return None
        
        entries = []
        ea = start_ea
        entry_size = self.ptr_size * (1 + handlers_per_entry)
        
        while ea < seg_end - entry_size:
            is_str, str_val = self.is_string_pointer(ea)
            if not is_str:
                break
            
            handlers = []
            valid = True
            for i in range(handlers_per_entry):
                is_code, code_ptr = self.is_code_pointer(ea + (i + 1) * self.ptr_size)
                if is_code:
                    handlers.append({"address": hex(code_ptr), "index": i})
                else:
                    # Allow NULL handler
                    ptr = self.read_pointer(ea + (i + 1) * self.ptr_size)
                    if ptr == 0:
                        handlers.append({"address": "NULL", "index": i})
                    else:
                        valid = False
                        break
            
            if valid and handlers:
                entries.append({
                    "key": str_val,
                    "key_addr": hex(self.read_pointer(ea)),
                    "handlers": handlers
                })
                ea += entry_size
            else:
                break
        
        if len(entries) >= self.min_table_size:
            return {
                "type": "MIXED_TABLE",
                "address": hex(start_ea),
                "entry_count": len(entries),
                "handlers_per_entry": handlers_per_entry,
                "pattern": f"[str + {handlers_per_entry} handlers]",
                "entries": entries
            }
        
        return None
    
    def _detect_handler_count(self, start_ea: int, seg_end: int) -> int:
        """Detect how many handlers per entry"""
        # Simplified detection: assume first is string, count consecutive code pointers
        is_str, _ = self.is_string_pointer(start_ea)
        if not is_str:
            return 0
        
        count = 0
        ea = start_ea + self.ptr_size
        
        while ea < seg_end:
            is_code, _ = self.is_code_pointer(ea)
            if is_code or self.read_pointer(ea) == 0:  # NULL also counts
                count += 1
                ea += self.ptr_size
            else:
                break
            
            if count > 10:  # Limit max handler count
                break
        
        return count
    
    def scan_all_tables(self) -> List[Dict]:
        """Scan all data segments for routing tables"""
        tables = []
        
        print("[EnhancedScanner] Starting comprehensive table scan...")
        
        for n in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(n)
            if not seg:
                continue
            
            # Only scan data segments
            if seg.perm & ida_segment.SEGPERM_EXEC:
                continue
            
            seg_name = idc.get_segm_name(seg.start_ea)
            print(f"  Scanning: {seg_name}")
            
            ea = seg.start_ea
            while ea < seg.end_ea - 2 * self.ptr_size:
                # Try to identify table
                table = self.scan_string_handler_table(ea, seg.end_ea)
                if table:
                    tables.append(table)
                    # Skip identified region
                    ea += table["entry_count"] * 2 * self.ptr_size
                    continue
                
                # Try mixed table
                mixed = self.scan_mixed_handler_table(ea, seg.end_ea)
                if mixed:
                    tables.append(mixed)
                    ea += mixed["entry_count"] * self.ptr_size * (1 + mixed["handlers_per_entry"])
                    continue
                
                ea += self.ptr_size
        
        print(f"[EnhancedScanner] Found {len(tables)} potential routing tables")
        return tables
    
    def scan_string_handler_tables(self, start_addr: int = None, end_addr: int = None, 
                                    min_entries: int = 3) -> List[Dict]:
        """
        Scan all String-Handler pairing tables
        
        Args:
            start_addr: Start address (optional)
            end_addr: End address (optional)
            min_entries: Minimum number of table entries
        
        Returns:
            List of detected tables
        """
        tables = []
        self.min_table_size = min_entries
        
        for n in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(n)
            if not seg:
                continue
            
            # Only scan data segments
            if seg.perm & ida_segment.SEGPERM_EXEC:
                continue
            
            # Apply address filter
            scan_start = max(seg.start_ea, start_addr) if start_addr else seg.start_ea
            scan_end = min(seg.end_ea, end_addr) if end_addr else seg.end_ea
            
            if scan_start >= scan_end:
                continue
            
            ea = scan_start
            while ea < scan_end - 2 * self.ptr_size:
                table = self.scan_string_handler_table(ea, scan_end)
                if table:
                    tables.append(table)
                    ea += table["entry_count"] * 2 * self.ptr_size
                else:
                    ea += self.ptr_size
        
        return tables
    
    def scan_mixed_handler_tables(self, start_addr: int = None, end_addr: int = None,
                                   min_entries: int = 3) -> List[Dict]:
        """
        Scan all mixed Handler tables
        
        Args:
            start_addr: Start address (optional)
            end_addr: End address (optional)
            min_entries: Minimum number of table entries
        
        Returns:
            List of detected tables
        """
        tables = []
        self.min_table_size = min_entries
        
        for n in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(n)
            if not seg:
                continue
            
            if seg.perm & ida_segment.SEGPERM_EXEC:
                continue
            
            scan_start = max(seg.start_ea, start_addr) if start_addr else seg.start_ea
            scan_end = min(seg.end_ea, end_addr) if end_addr else seg.end_ea
            
            if scan_start >= scan_end:
                continue
            
            ea = scan_start
            while ea < scan_end - 2 * self.ptr_size:
                table = self.scan_mixed_handler_table(ea, scan_end)
                if table:
                    tables.append(table)
                    ea += table["entry_count"] * self.ptr_size * (1 + table["handlers_per_entry"])
                else:
                    ea += self.ptr_size
        
        return tables
    
    def analyze_dispatch_function(self, func_addr: int, extract_routes: bool = True) -> Dict:
        """
        Analyze dispatch function, extract route mappings
        
        Args:
            func_addr: Dispatch function address
            extract_routes: Whether to extract route information
        
        Returns:
            Dispatch logic analysis result
        """
        func = ida_funcs.get_func(func_addr)
        if not func:
            return {"error": "Not a function"}
        
        result = {
            "address": hex(func_addr),
            "name": idc.get_func_name(func_addr),
            "size": func.size(),
            "switch_tables": [],
            "string_comparisons": [],
            "dispatch_targets": [],
            "routes": []
        }
        
        # Find switch tables in function
        for head in idautils.Heads(func.start_ea, func.end_ea):
            si = idaapi.get_switch_info(head)
            if si:
                switch_info = {
                    "addr": hex(head),
                    "cases": si.get_jtable_size(),
                    "targets": []
                }
                # Get jump targets
                for i in range(si.get_jtable_size()):
                    target = idc.get_wide_dword(si.jumps + i * 4)
                    if target:
                        switch_info["targets"].append(hex(target))
                result["switch_tables"].append(switch_info)
        
        # Find string comparisons (strcmp/strncmp calls)
        strcmp_funcs = ["strcmp", "strncmp", "strcasecmp", "strncasecmp"]
        for head in idautils.Heads(func.start_ea, func.end_ea):
            if idc.is_code(idc.get_full_flags(head)):
                for xref in idautils.CodeRefsFrom(head, 0):
                    name = idc.get_func_name(xref)
                    if name and any(s in name.lower() for s in strcmp_funcs):
                        # Try to get compared string
                        strings = self._get_strings_near_call(head)
                        if strings:
                            result["string_comparisons"].append({
                                "call_addr": hex(head),
                                "func": name,
                                "strings": strings
                            })
        
        # Find dispatch targets (indirect calls)
        for head in idautils.Heads(func.start_ea, func.end_ea):
            if idc.is_code(idc.get_full_flags(head)):
                for xref in idautils.CodeRefsFrom(head, 0):
                    if ida_funcs.get_func(xref):
                        target_name = idc.get_func_name(xref)
                        if target_name and target_name not in result["dispatch_targets"]:
                            result["dispatch_targets"].append(target_name)
        
        # If need to extract routes
        if extract_routes:
            for cmp in result["string_comparisons"]:
                for s in cmp.get("strings", []):
                    if s and ('/' in s or '.' in s or len(s) > 3):
                        result["routes"].append({
                            "path": s,
                            "detection_point": cmp["call_addr"],
                            "type": "string_compare"
                        })
        
        return result
    
    def _get_strings_near_call(self, call_addr: int, look_back: int = 10) -> List[str]:
        """Get string arguments near call site"""
        strings = []
        func = ida_funcs.get_func(call_addr)
        if not func:
            return strings
        
        # Search data references backward
        ea = call_addr
        for _ in range(look_back):
            ea = idc.prev_head(ea, func.start_ea)
            if ea == idc.BADADDR:
                break
            
            for dref in idautils.DataRefsFrom(ea):
                s = self.read_string(dref)
                if s and len(s) >= 2:
                    strings.append(s)
        
        return strings


class BackwardSlicer:
    """
    Backward Slicing Analyzer
    Implements paper Section 3.2.2 backward slicing algorithm
    Used for tracing route registration calls
    """
    
    def __init__(self):
        if not IN_IDA:
            raise RuntimeError("This module must run inside IDA Pro")
    
    def find_registration_sites(self, api_addresses: List[str]) -> List[Dict]:
        """
        Find all locations that call specified APIs
        
        Args:
            api_addresses: List of route registration API addresses
        
        Returns:
            List of call site information
        """
        sites = []
        
        for api_addr in api_addresses:
            try:
                addr = int(api_addr, 16) if isinstance(api_addr, str) else api_addr
            except:
                continue
            
            # Get all locations calling this API
            for xref in idautils.XrefsTo(addr):
                if xref.type in [ida_xref.fl_CN, ida_xref.fl_CF]:  # Call type
                    site = self._analyze_call_site(xref.frm, addr)
                    if site:
                        sites.append(site)
        
        return sites
    
    def _analyze_call_site(self, call_addr: int, target_addr: int) -> Optional[Dict]:
        """Analyze single call site, extract arguments"""
        func = ida_funcs.get_func(call_addr)
        if not func:
            return None
        
        # Get decompile result to extract arguments
        try:
            import ida_hexrays
            cfunc = ida_hexrays.decompile(func.start_ea)
            if cfunc:
                # Find call in pseudocode
                return self._extract_call_args_from_ctree(cfunc, call_addr, target_addr)
        except:
            pass
        
        # Fallback to assembly-based analysis
        return self._extract_call_args_from_asm(call_addr, func)
    
    def _extract_call_args_from_ctree(self, cfunc, call_addr: int, target_addr: int) -> Optional[Dict]:
        """Extract call arguments from Hex-Rays ctree"""
        # Simplified implementation: return basic info
        return {
            "call_addr": hex(call_addr),
            "target_addr": hex(target_addr),
            "caller_func": idc.get_func_name(cfunc.entry_ea),
            "args": [],  # TODO: Implement argument extraction
            "method": "ctree"
        }
    
    def _extract_call_args_from_asm(self, call_addr: int, func) -> Optional[Dict]:
        """Extract call arguments from assembly code"""
        # Simplified implementation
        return {
            "call_addr": hex(call_addr),
            "caller_func": idc.get_func_name(func.start_ea),
            "args": [],
            "method": "asm"
        }
    
    def trace_hub_structure(self, hub_addr: int) -> Dict:
        """
        Trace Hub structure
        Analyze how Hub function dispatches to various Handlers
        """
        func = ida_funcs.get_func(hub_addr)
        if not func:
            return {"error": "Not a function"}
        
        result = {
            "hub_addr": hex(hub_addr),
            "hub_name": idc.get_func_name(hub_addr),
            "dispatches": [],
            "dispatch_tables": []
        }
        
        # Find data referenced by this function (possible dispatch tables)
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for xref in idautils.DataRefsFrom(head):
                seg = ida_segment.getseg(xref)
                if seg and not (seg.perm & ida_segment.SEGPERM_EXEC):
                    # Possibly a dispatch table
                    result["dispatch_tables"].append({
                        "ref_addr": hex(head),
                        "table_addr": hex(xref)
                    })
        
        return result
    
    def trace_table_registrations(self, table_addr: int, max_depth: int = 5) -> Dict:
        """
        Backward trace from table address to registration sites
        
        Args:
            table_addr: Function pointer table start address
            max_depth: Maximum trace depth
        
        Returns:
            Registration site information
        """
        result = {
            "table_addr": hex(table_addr),
            "references": [],
            "registration_sites": [],
            "call_chains": []
        }
        
        # Find all references to this table
        for xref in idautils.XrefsTo(table_addr):
            ref_addr = xref.frm
            func = ida_funcs.get_func(ref_addr)
            
            ref_info = {
                "address": hex(ref_addr),
                "type": self._xref_type_name(xref.type),
                "in_function": idc.get_func_name(func.start_ea) if func else "N/A"
            }
            result["references"].append(ref_info)
            
            # If in function, trace call chain
            if func:
                chain = self._trace_call_chain(func.start_ea, max_depth)
                if chain:
                    result["call_chains"].append({
                        "start_func": idc.get_func_name(func.start_ea),
                        "chain": chain
                    })
        
        return result
    
    def _xref_type_name(self, xref_type: int) -> str:
        """Get cross-reference type name"""
        type_names = {
            ida_xref.fl_CF: "CALL_FAR",
            ida_xref.fl_CN: "CALL_NEAR",
            ida_xref.fl_JF: "JUMP_FAR",
            ida_xref.fl_JN: "JUMP_NEAR",
            ida_xref.dr_O: "DATA_OFFSET",
            ida_xref.dr_R: "DATA_READ",
            ida_xref.dr_W: "DATA_WRITE"
        }
        return type_names.get(xref_type, f"UNKNOWN_{xref_type}")
    
    def _trace_call_chain(self, func_addr: int, max_depth: int, 
                           visited: Set[int] = None) -> List[str]:
        """Trace function's call chain"""
        if visited is None:
            visited = set()
        
        if func_addr in visited or len(visited) >= max_depth:
            return []
        
        visited.add(func_addr)
        chain = [idc.get_func_name(func_addr) or hex(func_addr)]
        
        # Find locations calling this function
        for xref in idautils.XrefsTo(func_addr):
            if xref.type in [ida_xref.fl_CN, ida_xref.fl_CF]:
                caller_func = ida_funcs.get_func(xref.frm)
                if caller_func and caller_func.start_ea not in visited:
                    sub_chain = self._trace_call_chain(caller_func.start_ea, 
                                                       max_depth, visited)
                    if sub_chain:
                        chain.extend(sub_chain)
                        break  # Only trace one path
        
        return chain


# Exported main functions
def run_enhanced_scan() -> Dict:
    """Run enhanced scan"""
    scanner = EnhancedTableScanner()
    tables = scanner.scan_all_tables()
    
    return {
        "status": "ok",
        "tables": tables,
        "count": len(tables)
    }


def run_backward_slice(api_addresses: List[str]) -> Dict:
    """Run backward slicing analysis"""
    slicer = BackwardSlicer()
    sites = slicer.find_registration_sites(api_addresses)
    
    return {
        "status": "ok",
        "registration_sites": sites,
        "count": len(sites)
    }


if __name__ == "__main__" and IN_IDA:
    result = run_enhanced_scan()
    print(json.dumps(result, indent=2))
