# Copyright (c) 2026 The Pangu Project Authors. All rights reserved.
# core/bridge/static_analysis_v3.py
# [Version 3.3: Adaptive Stride + LLM Sampling (Greedy Engine 1)]
import idaapi
import idautils
import ida_funcs
import idc
import ida_segment
import ida_bytes
import ida_nalt
import ida_ua
import ida_ida 
import json
import os
import re
import traceback
import random

# Try importing Hex-Rays
HAS_HEXRAYS = False
try:
    import ida_hexrays
    if ida_hexrays.init_hexrays_plugin():
        HAS_HEXRAYS = True
except:
    pass

# ================= CONFIGURATION =================
IS_64 = False
try:
    IS_64 = ida_ida.inf_is_64bit()
except:
    pass
PTR_SIZE = 8 if IS_64 else 4
IS_ARM_THUMB = ida_ida.inf_get_procname().lower().startswith("arm") and not IS_64

# NOISE FILTER (Used mainly for Engine 3 API pruning)
BLACKLIST = {
    # Standard C Library
    "memset", "memcpy", "memmove", "strcpy", "strncpy", "strcat", "strlen","memcmp",
    "malloc", "free", "realloc", "sprintf", "printf", "fprintf", "doSystemCmd",
    "tolower", "toupper", "atoi", "atol", "strchr", "strstr", "strrchr",
    "vsnprintf", "snprintf", "puts", "inet_ntoa", "inet_aton","strcmp", "strncmp","sscanf",
    "fclose", "fopen", "fread", "fwrite", "fseek", "ftell", "rewind","close", "read", "write", "open",
    "fgets", "fputs", "feof", "fileno", "fflush", "system","perror","exit","abort",
    "strdup", "calloc","strcspn","strpbrk","strspn","strtok","vprintf","vfprintf",
    "strsep","sleep",
    
    # Common Tenda/Broadcom Utility Noise
    "GetValue", "SetValue", "GetVal", "SetVal", 
    "nvram_get", "nvram_set", "nvram_match",
    "websWrite", "websDone", "websError", "websHeader", "websFooter","CommitCfm",
    "send_msg_to_netctrl", "recv_msg_from_netctrl","inet_addr", "nvram_unset","remove_from_list",
    "add_to_list"
}

# [Global Storage for Hub-Local APIs]
# Used to pass discovered "companion functions" between Engine 2 (Hubs) and Engine 3 (APIs)
g_hub_local_high_freq = set() # Stores func_ea

# ================= BASIC HELPERS =================
def log(msg):
    print(f"[RouteScanner] {msg}")

def clean_addr(ea):
    if ea is None or ea == idc.BADADDR: return idc.BADADDR
    return ea & ~1 if IS_ARM_THUMB else ea

def read_ptr(ea):
    if IS_64: return ida_bytes.get_qword(ea)
    return ida_bytes.get_wide_dword(ea)

def is_code_ptr(ea):
    if ea == 0 or ea == idc.BADADDR: return False
    aligned_ea = clean_addr(ea)
    if ida_funcs.get_func(aligned_ea): return True
    seg = ida_segment.getseg(aligned_ea)
    if seg and (seg.perm & ida_segment.SEGPERM_EXEC): return True
    return False

def get_string_content(ea):
    try:
        s_bytes = ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C)
        if s_bytes:
            s = s_bytes.decode('utf-8', 'ignore')
            if _is_valid_str(s): return s
    except: pass
    try:
        raw_s = b""
        curr = ea
        for _ in range(128):
            b = ida_bytes.get_byte(curr)
            if b == 0: break
            raw_s += bytes([b])
            curr += 1
        if raw_s:
            s = raw_s.decode('utf-8', 'ignore')
            if _is_valid_str(s): return s
    except: pass
    return None

def _is_valid_str(s):
    if len(s) < 3: return False
    # Relaxed regex to allow more potential keys (Supports D-Link CamelCase & TrendNet paths)
    if not re.match(r'^[a-zA-Z0-9_/.\-%]+$', s): return False
    return True

# ================= ENGINE 1: STATIC TABLES (Adaptive & Greedy) =================
# [Modified for V3.3]: Implements Adaptive Stride Detection + LLM Sampling
def scan_static_tables():
    log("Engine 1: Scanning for Static Tables (Adaptive Stride + Greedy)...")
    found_tables = []
    processed_eas = set()

    for n in range(ida_segment.get_segm_qty()):
        seg_t = ida_segment.getnseg(n)
        if not seg_t: continue
        if seg_t.perm & ida_segment.SEGPERM_EXEC: continue
        
        curr = seg_t.start_ea
        end_ea = seg_t.end_ea
        
        while curr < end_ea - (PTR_SIZE * 4):
            if curr in processed_eas:
                curr += PTR_SIZE
                continue
            
            ptr_val = read_ptr(curr)
            root_str = get_string_content(ptr_val)
            
            if not root_str:
                curr += PTR_SIZE
                continue
                
            match_found = False
            
            # Probe for Function Pointer Offset
            for offset in range(PTR_SIZE, 64, PTR_SIZE):
                possible_func_ptr = read_ptr(curr + offset)
                
                if is_code_ptr(possible_func_ptr):
                    # Probe for Array Stride
                    for stride in range(offset + PTR_SIZE, 128, PTR_SIZE):
                        e1_addr = curr + stride
                        e2_addr = curr + stride * 2
                        
                        if e2_addr >= end_ea: break
                        
                        s1 = get_string_content(read_ptr(e1_addr))
                        f1 = is_code_ptr(read_ptr(e1_addr + offset))
                        s2 = get_string_content(read_ptr(e2_addr))
                        f2 = is_code_ptr(read_ptr(e2_addr + offset))
                        
                        if s1 and f1 and s2 and f2:
                            # Hit! Found a table. Extract everything greedily.
                            entries = []
                            entries.append({"url": root_str, "handler": idc.get_func_name(possible_func_ptr) or hex(possible_func_ptr)})
                            entries.append({"url": s1, "handler": idc.get_func_name(read_ptr(e1_addr + offset)) or hex(read_ptr(e1_addr + offset))})
                            entries.append({"url": s2, "handler": idc.get_func_name(read_ptr(e2_addr + offset)) or hex(read_ptr(e2_addr + offset))})
                            
                            temp_curr = curr + stride * 3
                            while temp_curr < end_ea:
                                s_next = get_string_content(read_ptr(temp_curr))
                                f_next_val = read_ptr(temp_curr + offset)
                                if s_next and is_code_ptr(f_next_val):
                                    entries.append({
                                        "url": s_next, 
                                        "handler": idc.get_func_name(f_next_val) or hex(f_next_val)
                                    })
                                    temp_curr += stride
                                else:
                                    break
                            
                            # Create the table object
                            # Note: We include 'sample_entries' here temporarily. 
                            # 'run_analysis' will strip it out and move it to the separate LLM file.
                            found_tables.append({
                                "type": "STATIC_ADAPTIVE",
                                "address": hex(curr), # This serves as the ID
                                "count": len(entries),
                                "stride": stride,
                                "member_offset": offset,
                                "sample_entries": entries[:5], # Temp field for LLM
                                "all_entries": entries
                            })
                            
                            log(f" -> Found Table at {hex(curr)}: {len(entries)} entries. Stride={stride}")
                            
                            table_byte_size = len(entries) * stride
                            for i in range(0, table_byte_size, 4):
                                processed_eas.add(curr + i)
                            match_found = True
                            break 
                    if match_found: break
            
            if not match_found:
                curr += PTR_SIZE
                
    return found_tables

# ================= ENGINE 2: DYNAMIC HUBS (Blind AST) =================
# ... (Optimized Blind AST Visitor from v2) ...
def get_ast_calls_blind(cfunc):
    class BlindCallVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
            self.calls = []
            self.local_stats = {} # {callee_ea: count} for counting Hub internal frequency

        def visit_expr(self, e):
            try:
                if e.op == ida_hexrays.cot_call:
                    parsed_args = []
                    raw_args_text = []
                    callee_name = "Unknown"
                    callee_ea = idc.BADADDR
                    
                    if e.x.op == ida_hexrays.cot_obj:
                        callee_ea = e.x.obj_ea
                        callee_name = idc.get_name(callee_ea)
                    elif e.x.op == ida_hexrays.cot_helper:
                        callee_name = e.x.helper

                    # Skip blacklist in Hub scanning to reduce noise
                    for bad in BLACKLIST:
                        if callee_name and bad in callee_name: return 0 
                    
                    # [Strategy A] Count Hub internal frequency
                    if callee_ea != idc.BADADDR:
                        self.local_stats[callee_ea] = self.local_stats.get(callee_ea, 0) + 1

                    for i, arg in enumerate(e.a):
                        if i > 4: break 
                        try: p_arg = self.resolve_arg_node(arg, i)
                        except: p_arg = {"type": "err"}
                        parsed_args.append(p_arg)
                        try: raw_args_text.append(self.get_raw_repr(arg))
                        except: raw_args_text.append("err")

                    self.calls.append({
                        "ea": hex(e.ea),
                        "callee": callee_name,
                        "callee_addr": hex(callee_ea) if callee_ea != idc.BADADDR else None,
                        "args": parsed_args,
                        "raw_args": raw_args_text
                    })
            except: pass 
            return 0
        
        def get_raw_repr(self, arg):
            try:
                while arg.op == ida_hexrays.cot_cast: arg = arg.x
                if arg.op == ida_hexrays.cot_str: return f"\"{arg.string}\""
                if arg.op == ida_hexrays.cot_obj:
                    name = idc.get_name(arg.obj_ea)
                    return f"&{name}" if name else f"OBJ_{hex(arg.obj_ea)}"
                if arg.op == ida_hexrays.cot_num: 
                    try: return f"{hex(arg.n.value(arg.type))}"
                    except: return "num_err"
                if arg.op == ida_hexrays.cot_var: return f"var_{arg.v.idx}"
            except: pass
            return "unknown"

        def resolve_arg_node(self, arg, index):
            # [Fix Bug C] Fix argument parsing: prioritize extracting Content over Name
            while arg.op == ida_hexrays.cot_cast: arg = arg.x
            if arg.op == ida_hexrays.cot_str:
                return {"type": "string", "val": arg.string}
            
            if arg.op == ida_hexrays.cot_obj:
                obj_ea = arg.obj_ea
                name = idc.get_name(obj_ea)
                
                # [Fix for Pattern B] First check if it's a function
                # If address is a function, return obj type directly, don't try to read string
                if ida_funcs.get_func(obj_ea):
                    return {"type": "obj", "val": name or hex(obj_ea)}
                
                # Try to get string content
                s = get_string_content(obj_ea)
                if s: 
                    # Only return string type if actual string was retrieved
                    return {"type": "string", "val": s}
                
                # If no content, fall back to returning Name (Symbol)
                if name and name.startswith("a") and index == 0:
                     return {"type": "string", "val": name, "origin": "symbol_name_fallback"}
                     
                return {"type": "obj", "val": name or hex(obj_ea)}
                
            if arg.op == ida_hexrays.cot_num:
                try: return {"type": "num", "val": hex(arg.n.value(arg.type))}
                except: return {"type": "num", "val": "num_err"}
            return {"type": "unknown"}

    visitor = BlindCallVisitor()
    try: visitor.apply_to(cfunc.body, None)
    except: pass
    return visitor.calls, visitor.local_stats

def scan_dynamic_hubs():
    log("Engine 2: Scanning for Dynamic Hubs (Unlimited Scope + Parent Index + Hub-Local Frequency)...")
    global g_hub_local_high_freq
    g_hub_local_high_freq = set() # Clear previous
    
    candidates = []
    # 1. Identify Busy Functions
    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func: continue
        
        call_count = 0
        for head in idautils.Heads(func.start_ea, func.end_ea):
            try:
                if len(list(idautils.CodeRefsFrom(head, 0))) > 0: call_count += 1
            except: pass
        
        if call_count > 10:
            candidates.append((func_ea, call_count))
            
    candidates.sort(key=lambda x: x[1], reverse=True)
    log(f"Processing {len(candidates)} candidate hubs...")
    
    hubs = []
    
    for func_ea, count in candidates:
        if HAS_HEXRAYS:
            try:
                cfunc = ida_hexrays.decompile(func_ea)
                if cfunc:
                    extracted_calls, local_stats = get_ast_calls_blind(cfunc)
                    
                    if len(extracted_calls) > 2:
                        # === [Improvement B]: Robust Parent Discovery ===
                        # Cover both CodeRefsTo (direct calls) and DataRefsTo (pointer references/thread entry)
                        parent_addrs = []
                        try:
                            # 1. Code Xrefs
                            for ref in idautils.CodeRefsTo(func_ea, 0):
                                parent_func = ida_funcs.get_func(ref)
                                if parent_func:
                                    parent_addrs.append(hex(parent_func.start_ea))
                            # 2. Data Xrefs (New)
                            for ref in idautils.DataRefsTo(func_ea):
                                parent_func = ida_funcs.get_func(ref)
                                if parent_func:
                                    parent_addrs.append(hex(parent_func.start_ea))
                        except:
                            pass
                        parent_addrs = list(set(parent_addrs))
                        # =================================================

                        # === [Strategy A]: Analyze Hub-Local Stats ===
                        # If a function is called > 5 times in current Hub and ratio is significant, consider it "companion function"
                        # E.g., sub_10120 is heavily called in sub_171EC
                        total_calls_in_hub = len(extracted_calls)
                        for callee_ea, freq in local_stats.items():
                            # Threshold: at least 5 times, and ratio > 10% (or absolute count very high > 20)
                            if (freq >= 5 and (freq / total_calls_in_hub > 0.1)) or freq > 20:
                                g_hub_local_high_freq.add(callee_ea)
                        # ============================================
                        
                        hubs.append({
                            "type": "REGISTRATION_HUB",
                            "address": hex(func_ea),
                            "count": len(extracted_calls),
                            "callers": parent_addrs, 
                            "raw_call_traces": extracted_calls 
                        })
            except:
                pass
    
    log(f"Engine 2 discovered {len(g_hub_local_high_freq)} unique Hub-Local High-Freq APIs.")
    return hubs

# ================= ENGINE 3: POTENTIAL API SCANNER (New) =================
def extract_snippet(func_ea, call_ea):
    """ Decompile func_ea and extract lines around call_ea """
    if not HAS_HEXRAYS: return "No Hex-Rays"
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc: return "Decompile Failed"
        
        lines = str(cfunc).split("\n")
        return "\n".join(lines[:40]) 
        
    except Exception as e:
        return f"Snippet Error: {str(e)}"

def scan_potential_apis(limit=30):
    log("Engine 3: Scanning for High-Frequency APIs (Global + Hub-Local Mixed)...")
    global g_hub_local_high_freq
    
    api_counts = {} # {func_ea: {"count": int, "refs": list}}
    
    # 1. Iterate all functions, count reference counts
    for func_ea in idautils.Functions():
        flags = ida_bytes.get_flags(func_ea)
        if not ida_funcs.get_func(func_ea): continue
        
        # [Filter 1] Blacklist filter
        func_name = idc.get_func_name(func_ea)
        clean_name = func_name
        
        is_noise = False
        for bad in BLACKLIST:
            if bad.lower() in clean_name.lower():
                is_noise = True
                break
        if is_noise: continue

        # Count callers
        refs = list(idautils.CodeRefsTo(func_ea, 0))
        count = len(refs)
        
        # [Filter 2] Threshold filter (High Freq OR Hub-Local Special)
        # As long as it's a high-frequency companion discovered by Hub scan, forcibly include even if global refs are few
        is_hub_local = func_ea in g_hub_local_high_freq
        
        if count > 5 or is_hub_local: 
            api_counts[func_ea] = {
                "count": count, 
                "refs": refs, 
                "name": func_name,
                "is_hub_local": is_hub_local
            }
            
    # 2. Sort (Sort by frequency)
    # Prioritize Hub-Local first since they have very high confidence
    sorted_apis = sorted(api_counts.items(), key=lambda x: (x[1]["is_hub_local"], x[1]["count"]), reverse=True)
    
    # The Limit here needs to be slightly relaxed, or always keep Hub-Local regardless
    final_apis = []
    
    # First add all Hub-Local
    for func_ea, data in sorted_apis:
        if data["is_hub_local"]:
            final_apis.append((func_ea, data))
            
    # Then fill remaining Global High Freq up to Limit
    remaining_slots = limit - len(final_apis)
    if remaining_slots > 0:
        for func_ea, data in sorted_apis:
            if not data["is_hub_local"]:
                final_apis.append((func_ea, data))
                remaining_slots -= 1
                if remaining_slots <= 0: break
    
    results = []
    
    for func_ea, data in final_apis:
        func_name = data["name"]
        raw_refs = data["refs"]
        
        # 3. Smart sampling
        parent_map = {} 
        for call_ea in raw_refs:
            parent_func = ida_funcs.get_func(call_ea)
            if parent_func:
                if parent_func.start_ea not in parent_map:
                    parent_map[parent_func.start_ea] = []
                parent_map[parent_func.start_ea].append(call_ea)
        
        unique_parents = list(parent_map.keys())
        # Sample 2
        selected_parents = random.sample(unique_parents, min(len(unique_parents), 2))
        
        snippets = []
        for p_ea in selected_parents:
            call_site = parent_map[p_ea][0] 
            snippet_text = extract_snippet(p_ea, call_site)
            snippets.append({
                "caller": hex(p_ea),
                "call_site": hex(call_site),
                "code": snippet_text
            })
        
        results.append({
            "address": hex(func_ea),
            "name": func_name,
            "count": data["count"],
            "source": "HUB_LOCAL" if data["is_hub_local"] else "GLOBAL_FREQ", # Add source marker
            "usage_snippets": snippets
        })
        
        log(f" -> Potential API {func_name} ({hex(func_ea)}): {data['count']} refs. Source: {results[-1]['source']}")
        
    return results

# ================= ENGINE 4: LOGIC DISPATCHERS (AST-Based) =================
# [New Module: Scans for if (strcmp(path, "/url") == 0) { handler(); } patterns]

class StringDispatchVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.entries = [] # List of {url, handler}
        
    def get_string_from_arg(self, arg):
        """ Helper to extract string literal from a function argument """
        # Handle Casts
        while arg.op == ida_hexrays.cot_cast:
            arg = arg.x
        # Handle Direct String
        if arg.op == ida_hexrays.cot_str:
            return arg.string
        # Handle Global Obj pointer (char *g_str = "value")
        if arg.op == ida_hexrays.cot_obj:
            return get_string_content(arg.obj_ea)
        return None

    def is_strcmp_call(self, expr):
        """ Check if expression is a call to strcmp/strncmp/strcasecmp """
        if expr.op != ida_hexrays.cot_call:
            return None
        
        func_name = ""
        if expr.x.op == ida_hexrays.cot_obj:
            func_name = idc.get_name(expr.x.obj_ea)
        elif expr.x.op == ida_hexrays.cot_helper:
            func_name = expr.x.helper
            
        if "cmp" in func_name and ("str" in func_name or "mem" in func_name):
            # Try to find the constant string argument
            # Usually strcmp(var, "const") -> arg 1 is const
            if len(expr.a) >= 2:
                s = self.get_string_from_arg(expr.a[1])
                if not s: # Try arg 0
                     s = self.get_string_from_arg(expr.a[0])
                return s
        return None

    def find_handler_in_block(self, stmt):
        """ Find the first meaningful function call OR assignment in a block """
        
        # Helper internal function to check an expression
        def check_expr(expr):
            # Pattern A: Direct Call -> Handler(...)
            if expr.op == ida_hexrays.cot_call:
                if expr.x.op == ida_hexrays.cot_obj:
                    return idc.get_name(expr.x.obj_ea)
                elif expr.x.op == ida_hexrays.cot_helper:
                    return expr.x.helper
            
            # Pattern B: Assignment -> v8 = Handler;
            # This handles: v8 = (__int64 (*)())addUserBookmark;
            elif expr.op == ida_hexrays.cot_asg:
                # Check Right-Hand Side (y)
                if expr.y.op == ida_hexrays.cot_obj:
                    # Make sure it looks like a function
                    name = idc.get_name(expr.y.obj_ea)
                    # Simple heuristic: Valid name and looks like code
                    if name and is_code_ptr(expr.y.obj_ea):
                        return name
                # Handle Casts: v8 = (type)Handler;
                elif expr.y.op == ida_hexrays.cot_cast:
                    if expr.y.x.op == ida_hexrays.cot_obj:
                        name = idc.get_name(expr.y.x.obj_ea)
                        if name and is_code_ptr(expr.y.x.obj_ea):
                            return name
            return None

        # --- Main Logic ---

        # Case 1: Block { stmt1; stmt2; ... }
        if stmt.op == ida_hexrays.cit_block:
            for s in stmt.cblock:
                res = self.find_handler_in_block(s) 
                if res: return res
                
        # Case 2: Expression Statement (Call or Assignment)
        elif stmt.op == ida_hexrays.cit_expr:
            res = check_expr(stmt.cexpr)
            # Check Blacklist
            if res:
                is_noise = False
                for bad in BLACKLIST:
                    if bad in res:
                        is_noise = True
                        break
                if not is_noise:
                    return res

        # Case 3: Return Statement
        elif stmt.op == ida_hexrays.cit_return:
            # Pattern: return Handler;
            if stmt.creturn.expr:
                if stmt.creturn.expr.op == ida_hexrays.cot_obj:
                     return idc.get_name(stmt.creturn.expr.obj_ea)
                # Pattern: return Handler(...);
                elif stmt.creturn.expr.op == ida_hexrays.cot_call:
                    res = check_expr(stmt.creturn.expr)
                    if res: return res

        return None

    def visit_insn(self, i):
        # We look for IF statements
        if i.op == ida_hexrays.cit_if:
            condition = i.cif.expr
            matched_string = None
            
            # Pattern 1: if ( !strcmp(v, "str") ) ...
            if condition.op == ida_hexrays.cot_lnot:
                matched_string = self.is_strcmp_call(condition.x)
                
            # Pattern 2: if ( strcmp(v, "str") == 0 ) ...
            elif condition.op == ida_hexrays.cot_eq:
                # check x == 0 or 0 == x
                if condition.y.op == ida_hexrays.cot_num and condition.y.n.value(condition.y.type) == 0:
                    matched_string = self.is_strcmp_call(condition.x)
                elif condition.x.op == ida_hexrays.cot_num and condition.x.n.value(condition.x.type) == 0:
                    matched_string = self.is_strcmp_call(condition.y)

            if matched_string and _is_valid_str(matched_string):
                # We found a routing check! Now look for the handler in the THEN block
                handler_name = self.find_handler_in_block(i.cif.ithen)
                
                if handler_name:
                    self.entries.append({
                        "url": matched_string,
                        "handler": handler_name,
                        "match_type": "logic_strcmp"
                    })
                    
        return 0

def scan_logic_dispatchers():
    log("Engine 4: Scanning for Logic-Based Dispatchers (if-strcmp-call)...")
    if not HAS_HEXRAYS:
        log("Skipping Engine 4 (Hex-Rays not available)")
        return []

    found_tables = []
    
    # 1. Quick Filter: Find functions that use strcmp heavily
    candidates = []
    import idautils
    
    # Common strcmp variants to look for
    target_names = {"strcmp", "strncmp", "strcasecmp", "memcmp", "_strcmp", "_strncmp"}
    
    for func_ea in idautils.Functions():
        flags = ida_bytes.get_flags(func_ea)
        if not ida_funcs.get_func(func_ea): continue
        
        # Check Cross-References FROM this function
        cmp_score = 0
        for head in idautils.Heads(func_ea, idc.get_func_attr(func_ea, idc.FUNCATTR_END)):
            refs = idautils.CodeRefsFrom(head, 0)
            for ref in refs:
                name = idc.get_name(ref)
                # Check against target names
                for t in target_names:
                    if t in name:
                        cmp_score += 1
                        break
        
        # Threshold: If a function calls cmp functions >= 3 times, scan it.
        if cmp_score >= 3:
            candidates.append(func_ea)

    log(f" -> Found {len(candidates)} candidate dispatcher functions.")

    # 2. Deep Scan with AST
    for func_ea in candidates:
        try:
            cfunc = ida_hexrays.decompile(func_ea)
            if not cfunc: continue
            
            visitor = StringDispatchVisitor()
            visitor.apply_to(cfunc.body, None)
            
            if len(visitor.entries) > 0:
                # Format compatible with previous Engines
                table_obj = {
                    "type": "LOGIC_DISPATCH",
                    "address": hex(func_ea),
                    "count": len(visitor.entries),
                    "all_entries": visitor.entries
                }
                found_tables.append(table_obj)
                log(f" -> Found Logic Table at {hex(func_ea)}: {len(visitor.entries)} entries.")
                
        except Exception as e:
            # log(f"Error scanning {hex(func_ea)}: {e}")
            pass

    return found_tables

# ================= ENGINE 6: MIXED FUNCTION POINTER TABLES (New) =================
# [New Module: Scans for String + Function pointer mixed tables (e.g., Tenda route tables)]
# Detects patterns like: ["ipgroup", clear_handler, set_handler, show_handler]

def is_string_pointer(ea):
    """Check if address points to a string"""
    try:
        ptr_val = read_ptr(ea)
        if ptr_val == 0 or ptr_val == idc.BADADDR:
            return False, None
        
        # Try to read string content
        s_bytes = ida_bytes.get_strlit_contents(ptr_val, -1, ida_nalt.STRTYPE_C)
        if s_bytes:
            try:
                s = s_bytes.decode('utf-8', errors='ignore')
                # Verify if it's a valid route key
                if 3 <= len(s) <= 50 and s.isprintable():
                    return True, s
            except:
                pass
        return False, None
    except:
        return False, None

def detect_mixed_table_pattern(start_ea, max_entries=50):
    """
    Detect mixed table pattern, return table structure info
    Supported patterns:
    - SF: String + Function (simplest, like Netgear)
    - SFFF: String + 3 Functions (Tenda case)
    - SFF: String + 2 Functions
    - SFFFF+: String + 4+ Functions
    """
    patterns_found = []
    
    # Try different repeat patterns
    for stride in [2, 3, 4, 5, 6]:  # SF, SFF, SFFF, SFFFF, SFFFFF
        entries = []
        valid = True
        ea = start_ea
        
        for i in range(max_entries):
            # Check if it's a string pointer
            is_str, str_val = is_string_pointer(ea)
            if not is_str:
                if i < 3:  # At least need 3 valid entries
                    valid = False
                break
            
            entry = {"key": str_val, "key_addr": hex(ea), "handlers": []}
            
            # Read subsequent function pointers
            for j in range(1, stride):
                func_ea = ea + j * PTR_SIZE
                ptr_val = read_ptr(func_ea)
                
                if not is_code_ptr(ptr_val):
                    valid = False
                    break
                
                func_name = idc.get_func_name(ptr_val)
                if not func_name:
                    func_name = f"sub_{ptr_val:X}"
                
                entry["handlers"].append({
                    "address": hex(ptr_val),
                    "name": func_name
                })
            
            if not valid:
                break
            
            entries.append(entry)
            ea += stride * PTR_SIZE
        
        # Check if it's a valid pattern
        if valid and len(entries) >= 3:
            patterns_found.append({
                "stride": stride,
                "count": len(entries),
                "entries": entries,
                "confidence": 0.9 if len(entries) >= 5 else 0.7
            })
    
    # Return the longest valid pattern
    if patterns_found:
        return max(patterns_found, key=lambda x: x['count'])
    return None

def scan_mixed_function_pointer_tables():
    """
    Engine 6: Scan mixed function pointer tables (String + Function)
    Specifically handles route dispatch tables like those in Tenda AC15
    """
    log("Engine 6: Scanning for Mixed Function Pointer Tables (String + Handler)...")
    
    found_tables = []
    processed_addrs = set()  # Prevent duplicate detection
    
    # Iterate all data segments
    for n in range(ida_segment.get_segm_qty()):
        seg_t = ida_segment.getnseg(n)
        if not seg_t:
            continue
        
        # Only scan data segments (.data, .rodata, .data.rel.ro)
        if seg_t.perm & ida_segment.SEGPERM_EXEC:
            continue
        
        seg_name = idc.get_segm_name(seg_t.start_ea)
        log(f" -> Scanning segment: {seg_name}")
        
        curr = seg_t.start_ea
        end_ea = seg_t.end_ea
        
        while curr < end_ea - (PTR_SIZE * 4):  # At least need SF structure (2 pointers)
            # Skip already processed addresses
            if curr in processed_addrs:
                curr += PTR_SIZE
                continue
            
            # Check if it's a string pointer
            is_str, str_val = is_string_pointer(curr)
            if not is_str:
                curr += PTR_SIZE
                continue
            
            # Check if next is function pointer
            next_ptr = read_ptr(curr + PTR_SIZE)
            if not is_code_ptr(next_ptr):
                curr += PTR_SIZE
                continue
            
            # Try to detect complete mixed table pattern
            pattern = detect_mixed_table_pattern(curr)
            
            if pattern and pattern['count'] >= 3:
                # Mark processed address range
                table_size = pattern['stride'] * pattern['count'] * PTR_SIZE
                for addr in range(curr, curr + table_size, PTR_SIZE):
                    processed_addrs.add(addr)
                
                # Construct table structure
                table_entry = {
                    "type": "MIXED_TABLE",
                    "address": hex(curr),
                    "count": pattern['count'],
                    "stride": pattern['stride'],
                    "pattern": f"S{'F' * (pattern['stride'] - 1)}",  # SF, SFF, SFFF
                    "segment": seg_name,
                    "entries": pattern['entries'],
                    "confidence": pattern['confidence']
                }
                
                # Try to find function referencing this table (dispatcher)
                # IDA 9.0 API: DataRefsTo only takes 1 argument
                xrefs = list(idautils.DataRefsTo(curr))
                if xrefs:
                    dispatcher_funcs = []
                    for xref in xrefs[:5]:  # Record max 5 references
                        func_ea = idc.get_func_attr(xref, idc.FUNCATTR_START)
                        if func_ea != idc.BADADDR:
                            dispatcher_funcs.append({
                                "address": hex(func_ea),
                                "name": idc.get_func_name(func_ea)
                            })
                    table_entry["dispatcher_candidates"] = dispatcher_funcs
                
                # Generate LLM sampling
                sample_entries = []
                for i, entry in enumerate(pattern['entries'][:5]):  # Sample max 5
                    sample = {
                        "index": i,
                        "key": entry['key'],
                        "handlers": [h['name'] for h in entry['handlers']]
                    }
                    sample_entries.append(sample)
                table_entry["sample_entries"] = sample_entries
                
                found_tables.append(table_entry)
                
                log(f" -> Found Mixed Table at {hex(curr)}: {pattern['count']} entries, pattern {table_entry['pattern']}")
                log(f"    Example: {pattern['entries'][0]['key']} → [{', '.join([h['name'] for h in pattern['entries'][0]['handlers']])}]")
                
                # Skip entire table
                curr += table_size
            else:
                curr += PTR_SIZE
    
    log(f"Engine 6 found {len(found_tables)} mixed function pointer tables.")
    return found_tables

# ================= ENGINE 5: SYMBOLIC SWITCH DISPATCHER (New) =================
# [New Module: Scans for switch(id) { case 1: handler_A(); case 2: handler_B(); }]

class SwitchSymbolicVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.switch_tables = [] # List of {address, entries: []}
        
        # Route feature whitelist (if function name contains these words, consider it potential Handler)
        # Optimized for Zyxel case: struct, urn, zyxel, authentication
        self.KEYWORDS = {
            "struct", "create", "handler", "cgi", "http", "auth", "login", 
            "wan", "lan", "wlan", "set", "get", "add", "del", "sys", "admin",
            "adv", "chk", "proc", "form", "asp", "html", "json", "xml", "soap",
            "action", "service", "mgmt", "sso", "dns", "pin"
        }

    def get_callee_name(self, expr):
        """ Extract function name from a call expression """
        if expr.op == ida_hexrays.cot_call:
            if expr.x.op == ida_hexrays.cot_obj:
                return idc.get_name(expr.x.obj_ea), expr.x.obj_ea
            elif expr.x.op == ida_hexrays.cot_helper:
                return expr.x.helper, idc.BADADDR
        return None, idc.BADADDR

    def find_inner_call(self, stmt):
        """ Find the most relevant function call in a case block """
        # Case 1: Block { call(); ... }
        if stmt.op == ida_hexrays.cit_block:
            for s in stmt.cblock:
                # Recursively check sub-blocks or expressions
                res_name, res_addr = self.find_inner_call(s)
                if res_name: return res_name, res_addr
        
        # Case 2: Expression call(); or return call();
        elif stmt.op == ida_hexrays.cit_expr:
            return self.get_callee_name(stmt.cexpr)
        elif stmt.op == ida_hexrays.cit_return:
            if stmt.creturn.expr:
                return self.get_callee_name(stmt.creturn.expr)
                
        return None, idc.BADADDR

    def clean_symbol_name(self, name):
        """ 
        Extract readable route hint from function name 
        Example: j_create_struct_wan -> wan
        """
        # Remove prefix
        name = re.sub(r'^(sub_|j_|ws_|f_|create_|struct_|do_)', '', name)
        # Remove hex suffix
        name = re.sub(r'_?[0-9A-Fa-f]{6,}$', '', name)
        return name

    def visit_insn(self, i):
        if i.op == ida_hexrays.cit_switch:
            cswitch = i.cswitch
            cases_found = []
            valid_handler_count = 0
            
            # Iterate all Cases
            for case_idx in range(cswitch.cases.size()):
                case_block = cswitch.cases[case_idx]
                
                # Extract Case value (Integer ID)
                # Note: Hex-Rays Case value may be a range, take start value as ID here
                case_vals = []
                for v in case_block.values:
                    case_vals.append(v)
                case_id = case_vals[0] if case_vals else -1
                
                # Analyze Case code block, look for Handler call
                func_name, func_addr = self.find_inner_call(case_block.body)
                
                if func_name:
                    # Filter out system functions (memset, printf, etc.)
                    is_noise = False
                    for bad in BLACKLIST:
                        if bad in func_name:
                            is_noise = True; break
                    if is_noise: continue

                    # Scoring mechanism: check if contains feature words
                    score = 0
                    clean_name = func_name.lower()
                    for kw in self.KEYWORDS:
                        if kw in clean_name:
                            score += 1
                    
                    inferred_url = self.clean_symbol_name(func_name)
                    
                    entry = {
                        "case_id": case_id,
                        "handler": func_name,
                        "handler_addr": hex(func_addr) if func_addr != idc.BADADDR else None,
                        "inferred_url": inferred_url, # Key point: URL inferred from symbol name
                        "score": score
                    }
                    cases_found.append(entry)
                    if score > 0: valid_handler_count += 1

            # === Judgment Logic ===
            # If a Switch has more than 3 Cases that look like Handlers,
            # or total Cases are few but hit rate is very high (>50%), consider it route table
            total_cases = cswitch.cases.size()
            if total_cases > 0:
                hit_rate = valid_handler_count / total_cases
                if (valid_handler_count >= 3) or (total_cases >= 2 and hit_rate > 0.5):
                    self.switch_tables.append({
                        "type": "SYMBOLIC_SWITCH",
                        "address": hex(i.ea),
                        "count": len(cases_found),
                        "all_entries": cases_found
                    })
                    
        return 0

def scan_symbolic_dispatchers():
    log("Engine 5: Scanning for Symbolic Switch Dispatchers (Integer -> Handler Name)...")
    if not HAS_HEXRAYS:
        log("Skipping Engine 5 (Hex-Rays not available)")
        return []

    found_tables = []
    
    # 1. Filter functions containing Switch
    # Iterate all functions, if function is large and contains switch instruction, analyze deeply
    candidates = []
    for func_ea in idautils.Functions():
        # Simple filter: function too small may just be simple getter
        if idc.get_func_attr(func_ea, idc.FUNCATTR_END) - func_ea < 50: continue
        candidates.append(func_ea)

    # 2. Deep AST analysis
    # For performance, could optimize with idautils.CodeRefsTo(switch_jump_table),
    # but decompiling large functions directly is usually fast enough.
    
    count = 0
    for func_ea in candidates:
        try:
            cfunc = ida_hexrays.decompile(func_ea)
            if not cfunc: continue
            
            visitor = SwitchSymbolicVisitor()
            visitor.apply_to(cfunc.body, None)
            
            if len(visitor.switch_tables) > 0:
                found_tables.extend(visitor.switch_tables)
                for tbl in visitor.switch_tables:
                    log(f" -> Found Switch Dispatcher at {tbl['address']} with {tbl['count']} entries.")
                
        except Exception as e:
            pass
        
        count += 1
        if count % 500 == 0: print(f"...scanned {count} functions...")

    return found_tables

# ================= ORCHESTRATOR =================
def run_analysis(output_dir="logs"):
    log("Starting Full Analysis (V3.4: Split Output)...")
    if not os.path.isabs(output_dir):
        idb_dir = os.path.dirname(idc.get_input_file_path())
        output_dir = os.path.join(idb_dir, output_dir)
    try: os.makedirs(output_dir)
    except: pass
        
    # Container for the full, heavy static analysis result
    full_result = {
        "memory_structures": [],
        "potential_apis": []
    }
    
    # Container specifically for the LLM
    llm_payload = {
        "description": "Candidates for HTTP Route Tables. Please identify valid ones.",
        "candidates": []
    }
    
    try:
        # 1. Static Tables
        static_tables = scan_static_tables()
        
        # [SEPARATION LOGIC]
        # Iterate through tables, extract samples for LLM, and clean up the main record
        for table in static_tables:
            # Check if this table has samples (it should)
            if "sample_entries" in table:
                # 1. Create LLM Task Item
                # We use 'address' as the unique key to link back later
                llm_item = {
                    "id": table["address"], 
                    "type": table["type"],
                    "entry_count": table["count"],
                    "samples": table["sample_entries"]
                }
                llm_payload["candidates"].append(llm_item)
                
                # 2. Remove sample_entries from main object to keep it clean
                del table["sample_entries"]
        
        full_result["memory_structures"].extend(static_tables)
        
        # 2. Dynamic Hubs
        dynamic_hubs = scan_dynamic_hubs()
        full_result["memory_structures"].extend(dynamic_hubs)
        
        # 3. Potential APIs
        potential_apis = scan_potential_apis()
        
        # Optional: You could also split API snippets here if you want LLM to filter APIs too
        # For now, we only process Static Tables as requested.
        full_result["potential_apis"] = potential_apis
        
        # 4. Logic Dispatchers (New Engine 4)
        logic_tables = scan_logic_dispatchers()
        
        full_result["memory_structures"].extend(logic_tables)
        
        # 5. Symbolic Switch Dispatchers (Engine 5) - [NEW]
        symbolic_switches = scan_symbolic_dispatchers()
        full_result["memory_structures"].extend(symbolic_switches)
        
        # 6. Mixed Function Pointer Tables (Engine 6) - [NEW]
        mixed_tables = scan_mixed_function_pointer_tables()
        
        # Process mixed table samples for LLM
        for table in mixed_tables:
            if "sample_entries" in table:
                llm_item = {
                    "id": table["address"],
                    "type": table["type"],
                    "pattern": table["pattern"],
                    "entry_count": table["count"],
                    "samples": table["sample_entries"],
                    "dispatcher_candidates": table.get("dispatcher_candidates", [])
                }
                llm_payload["candidates"].append(llm_item)
                del table["sample_entries"]
        
        full_result["memory_structures"].extend(mixed_tables)

        # --- Save Files ---
        import datetime
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # File 1: Full Static Analysis Result (Clean Structure)
        main_filename = f"static_scan_v3_4_{ts}.json"
        main_path = os.path.join(output_dir, main_filename)
        with open(main_path, "w", encoding='utf-8') as f:
            json.dump(full_result, f, indent=2)
            
        # File 2: LLM Samples Only (Lightweight)
        llm_filename = f"llm_samples_v3_4_{ts}.json"
        llm_path = os.path.join(output_dir, llm_filename)
        with open(llm_path, "w", encoding='utf-8') as f:
            json.dump(llm_payload, f, indent=2)
            
        log(f"Scan Complete.")
        log(f" [1] Full Result: {main_path}")
        log(f" [2] LLM Samples: {llm_path}")
        
        return full_result
        
    except Exception as e:
        log(f"Error: {str(e)}")
        traceback.print_exc()
        return {"error": str(e)}

if __name__ == "__main__":
    run_analysis(output_dir=".")
