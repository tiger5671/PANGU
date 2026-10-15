# Copyright (c) 2026 The Pangu Project Authors. All rights reserved.
# core/bridge/ida_server_v6.py
import socket
import json
import threading
import sys
import os
import idc
import idautils
import idaapi
import ida_hexrays
import ida_bytes
import ida_name
import ida_segment
import ida_funcs
import ida_ida
import ida_nalt
import ida_ua
import ida_idp
from core.bridge.protocol import receive_json, send_json
from core.graph_analysis import ControlFlowGraph

# --- Import sibling modules ---
# Since static_analysis.py is in the same folder, direct import is possible
try:
    # Try to reload modules so changes take effect without restarting IDA
    import static_analysis
    import cfg_analysis  # CFG analysis module
    import enhanced_static_analysis  # Enhanced static analysis module
    import importlib
    importlib.reload(static_analysis)
    importlib.reload(cfg_analysis)
    importlib.reload(enhanced_static_analysis)
    print("[+] Loaded 'static_analysis' module.")
    print("[+] Loaded 'cfg_analysis' module.")
    print("[+] Loaded 'enhanced_static_analysis' module.")
except ImportError as e:
    print(f"[-] Error importing modules: {e}")
    # If error occurs here, it means file is not in the right place or filename is wrong

# ================= CONFIGURATION =================
HOST = '127.0.0.1'
PORT = 4455
BUFFER_SIZE = 4096000

class IDAServerAgent:
    def __init__(self):
        self.sock = None
        self.running = False
        self.thread = None
        self._clients = set()
        self._clients_lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(8)

    # --- Startup and Network Layer (maintained unchanged, reusing V3 stable logic) ---
    def start(self):
        if self.running: return
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind((HOST, PORT))
            self.sock.listen(5)
            print(f"[+] IDA RPC Server V6 (Modular) listening on {HOST}:{PORT}")
        except Exception as e:
            print(f"[-] Bind failed: {e}")
            self.running = False
            return
        self.thread = threading.Thread(target=self.server_loop)
        self.thread.daemon = True
        self.thread.start()

    def server_loop(self):
        while self.running:
            try:
                self.sock.settimeout(1.0)
                try:
                    conn, addr = self.sock.accept()
                except socket.timeout: continue
                except OSError: break
                if not self._slots.acquire(blocking=False):
                    conn.close()
                    continue
                with self._clients_lock:
                    self._clients.add(conn)
                threading.Thread(target=self.handle_client_persistent, args=(conn, addr), daemon=True).start()
            except Exception as e: print(f"[-] Server loop error: {e}")

    def handle_client_persistent(self, conn, addr):
        conn.settimeout(120)
        try:
            while self.running:
                try:
                    request = receive_json(conn, timeout=600)
                    response = self.safe_dispatch(request)
                except (ValueError, UnicodeError) as exc:
                    send_json(conn, {"status": "error", "error": str(exc)})
                    break  # Invalid framing must never be reused.
                send_json(conn, response)
        except (OSError, ConnectionError):
            pass
        finally:
            with self._clients_lock:
                self._clients.discard(conn)
            conn.close()
            self._slots.release()

    def safe_dispatch(self, request):
        class Context: result = None
        ctx = Context()
        def main_thread_task():
            ctx.result = self._dispatch_logic(request)
            return 1
        idaapi.execute_sync(main_thread_task, idaapi.MFF_READ)
        return ctx.result

    # --- Core Dispatch Logic (Modular Dispatcher) ---
    def _dispatch_logic(self, request):
        if not isinstance(request, dict) or not isinstance(request.get("params", {}), dict):
            return {"status": "error", "error": "Expected command object and params object"}
        cmd = request.get("command")
        if not isinstance(cmd, str):
            return {"status": "error", "error": "Expected command string"}
        params = request.get("params", {})
        
        # Dynamically find worker_xxx methods
        method_name = f"worker_{cmd}"
        if hasattr(self, method_name):
            try:
                handler = getattr(self, method_name)
                return handler(params)
            except Exception as e:
                # Print stack trace for debugging
                import traceback
                traceback.print_exc()
                return {"status": "error", "error": f"Internal Logic Error: {str(e)}"}
        else:
            return {"status": "error", "error": f"Unknown command: {cmd}"}

    # ================= Helper Functions =================

    def _resolve_addr(self, addr_val):
        """ 
        Smart address resolution:
        - If integer, return directly
        - If hex string "0x4000", convert
        - If function name "main", lookup address
        """
        if isinstance(addr_val, int):
            return addr_val
        if isinstance(addr_val, str):
            if addr_val.startswith("0x") or addr_val.startswith("0X"):
                return int(addr_val, 16)
            # Try to parse as function name
            addr = idc.get_name_ea_simple(addr_val)
            if addr != idc.BADADDR:
                return addr
            # Try to parse as decimal string
            if addr_val.isdigit():
                return int(addr_val)
        return idc.BADADDR

    # ================= Business Logic Workers =================

    # 1. Basic Controls
    def worker_ping(self, params):
        return {"status": "ok", "data": "pong"}

    def worker_batch(self, params):
        requests = params.get("requests")
        if not isinstance(requests, list) or not 1 <= len(requests) <= 32:
            return {"status": "error", "error": "batch requires 1-32 requests"}
        allowed = {"decompile", "get_callees", "get_xrefs", "scan_args", "get_basic_blocks",
                   "build_dominator_tree", "get_dominator_context", "calculate_tis",
                   "find_blocking_checks", "scan_auth_patterns", "analyze_guard_coverage"}
        results = []
        for request in requests:
            if not isinstance(request, dict) or request.get("command") not in allowed:
                results.append({"status": "error", "error": "Command not allowed in read batch"})
            else:
                results.append(self._dispatch_logic(request))
        return {"status": "ok", "data": results}

    def worker_get_storage_accesses(self, params):
        """Extract constant NVRAM keys at real C-tree call sites, not string hits."""
        specs = params.get("apis", [
            {"name": "nvram_set", "mode": "write", "key_arg": 0, "namespace": "nvram"},
            {"name": "nvram_get", "mode": "read", "key_arg": 0, "namespace": "nvram"},
            {"name": "nvram_safe_get", "mode": "read", "key_arg": 0, "namespace": "nvram"}])
        limit = int(params.get("max_callers", 256))
        if not isinstance(specs, list) or len(specs) > 16 or not 1 <= limit <= 2048:
            return {"status": "error", "error": "Invalid storage scan budget"}
        targets, gaps = {}, []
        for spec in specs:
            if (not isinstance(spec, dict) or spec.get("mode") not in {"read", "write"}
                    or not isinstance(spec.get("name"), str) or not isinstance(spec.get("namespace"), str)
                    or type(spec.get("key_arg")) is not int or not 0 <= spec["key_arg"] < 16):
                return {"status": "error", "error": "Invalid storage API specification"}
            address = self._resolve_addr(spec["name"])
            if address == idc.BADADDR:
                gaps.append("Storage API unresolved: " + spec["name"])
            else:
                targets[address] = spec
        callers = set()
        for address in targets:
            for xref in idautils.CodeRefsTo(address, 0):
                func = ida_funcs.get_func(xref)
                if func:
                    callers.add(func.start_ea)
        if len(callers) > limit:
            gaps.append("Storage caller budget exhausted")
        binary_md5 = ida_nalt.retrieve_input_file_md5()
        binary_id = binary_md5.hex() if binary_md5 else ""
        accesses = []

        class StorageVisitor(ida_hexrays.ctree_visitor_t):
            def __init__(self, function):
                super().__init__(ida_hexrays.CV_FAST)
                self.function = function

            def visit_expr(self, expr):
                if expr.op != ida_hexrays.cot_call or expr.x.op != ida_hexrays.cot_obj:
                    return 0
                spec = targets.get(expr.x.obj_ea)
                if spec is None or len(expr.a) <= spec["key_arg"]:
                    return 0
                arg = expr.a[spec["key_arg"]]
                for _ in range(4):
                    if arg.op in (ida_hexrays.cot_cast, ida_hexrays.cot_ref):
                        arg = arg.x
                    else:
                        break
                key = None
                if arg.op == ida_hexrays.cot_str:
                    key = arg.string
                elif arg.op == ida_hexrays.cot_obj:
                    value = idc.get_strlit_contents(arg.obj_ea, -1, idc.STRTYPE_C)
                    if value:
                        key = value.decode("utf-8", errors="replace")
                if not key or len(key) > 512:
                    gaps.append("Dynamic/unresolved storage key at " + hex(expr.ea))
                    return 0
                accesses.append({"binary_id": binary_id, "namespace": spec["namespace"],
                                 "key": key, "mode": spec["mode"], "api": spec["name"],
                                 "function": idc.get_func_name(self.function),
                                 "function_address": hex(self.function), "callsite": hex(expr.ea)})
                return 0

        for caller in sorted(callers)[:limit]:
            try:
                cfunc = ida_hexrays.decompile(caller)
                if cfunc is None:
                    raise ValueError("Decompilation unavailable")
                StorageVisitor(caller).apply_to(cfunc.body, None)
            except Exception:
                gaps.append("Storage caller decompilation failed: " + hex(caller))
        return {"status": "ok", "data": {"accesses": accesses, "gaps": list(dict.fromkeys(gaps)),
                "binary_id": binary_id, "interpretation": "Constant-key access evidence, not taint proof"}}

    def worker_analyze_guard_coverage(self, params):
        address = self._resolve_addr(params.get("address"))
        target = self._resolve_addr(params.get("target_address"))
        func = ida_funcs.get_func(address)
        if not func or target == idc.BADADDR:
            return {"status": "error", "error": "Invalid function or target"}
        blocks = cfg_analysis.get_basic_blocks(func.start_ea)
        block = next((b for b in blocks if int(b["start"], 16) <= target < int(b["end"], 16)), None)
        if block is None:
            return {"status": "error", "error": "Target not in function CFG"}
        return {"status": "ok", "data": ControlFlowGraph(blocks, hex(func.start_ea)).guard_coverage(block["start"])}
    
    def worker_get_status(self, params):
        """Get IDA server status information"""
        try:
            # Basic information
            binary_path = idaapi.get_input_file_path()
            binary_name = os.path.basename(binary_path) if binary_path else "Unknown"
            
            # Statistics information
            func_count = len(list(idautils.Functions()))
            seg_count = len(list(idautils.Segments()))
            
            # Architecture information - IDA 9.0 compatible
            arch = "64-bit" if ida_ida.inf_is_64bit() else "32-bit"
            proc = ida_ida.inf_get_procname()
            input_md5 = ida_nalt.retrieve_input_file_md5()
            
            return {
                "status": "ok",
                "data": {
                    "binary_name": binary_name,
                    "binary_path": binary_path,
                    "function_count": func_count,
                    "segment_count": seg_count,
                    "architecture": arch,
                    "processor": proc,
                    "server_version": "V7",
                    "binary_id": input_md5.hex() if input_md5 else "",
                    "capabilities": ["batch", "decompile_page", "analyze_guard_coverage"]
                }
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    # 2. Global Information Retrieval (Segments, Functions, Strings)
    def worker_get_segments(self, params):
        """ Get memory segment information (.text, .data, .bss) """
        segs = []
        for seg in idautils.Segments():
            segs.append({
                "name": idc.get_segm_name(seg),
                "start": hex(seg),
                "end": hex(idc.get_segm_end(seg)),
                "perm": idc.get_segm_attr(seg, idc.SEGATTR_PERM)
            })
        return {"status": "ok", "data": segs}

    def worker_get_functions(self, params):
        """ 
        Get all function list
        params: {"search": "http", "limit": 100}
        """
        search = params.get("search", "").lower()
        limit = params.get("limit", 1000) # Default limit to prevent token overflow
        funcs = []
        
        for ea in idautils.Functions():
            name = idc.get_func_name(ea)
            if search and search not in name.lower():
                continue
                
            funcs.append({
                "name": name,
                "addr": hex(ea),
                "size": idc.get_func_attr(ea, idc.FUNCATTR_END) - ea
            })
            if len(funcs) >= limit: break
            
        return {"status": "ok", "data": funcs}

    def worker_search_strings(self, params):
        """ 
        Search for strings
        params: {"content": "/admin"}
        """
        target = params.get("content", "")
        results = []
        for s in idautils.Strings():
            s_str = str(s)
            if target in s_str:
                results.append({
                    "val": s_str,
                    "addr": hex(s.ea),
                    "length": s.length
                })
        return {"status": "ok", "data": results}

    # 3. Decompilation and Code Analysis
    def worker_decompile(self, params):
        """ 
        Decompile specified function 
        params: {"address": "main" or 0x401000}
        """
        addr = self._resolve_addr(params.get("address"))
        if addr == idc.BADADDR:
            return {"status": "error", "error": "Invalid address/name"}

        if not ida_hexrays.init_hexrays_plugin():
            return {"status": "error", "error": "No Hex-Rays"}

        func = idaapi.get_func(addr)
        if not func:
            return {"status": "error", "error": "Not a function"}

        try:
            cfunc = ida_hexrays.decompile(func)
            if not cfunc: return {"status": "error", "error": "Decompile failed"}
            
            lines = [idaapi.tag_remove(line.line) for line in cfunc.get_pseudocode()]
            start = int(params.get("start_line", 0))
            count = int(params.get("max_lines", len(lines)))
            if start < 0 or count < 1:
                return {"status": "error", "error": "Invalid decompile page bounds"}
            selected = lines[start:start + min(count, 2000)]
            return {
                "status": "ok", 
                "data": {
                    "func_name": idc.get_func_name(func.start_ea),
                    "address": hex(func.start_ea),
                    "code": "\n".join(selected),
                    "start_line": start, "total_lines": len(lines),
                    "truncated": start + len(selected) < len(lines)
                }
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    # 4. Cross-Reference Analysis (Callers/Callees)
    def worker_get_xrefs(self, params):
        """
        Get reference relationships
        params: {
            "address": "0x...", 
            "direction": "to" (who called me) | "from" (what I call/use)
        }
        """
        addr = self._resolve_addr(params.get("address"))
        if addr == idc.BADADDR: return {"status": "error", "error": "Invalid address"}
        
        direction = params.get("direction", "to")
        refs = []

        if direction == "to":
            # Who called addr (Code Xref)
            for xref in idautils.CodeRefsTo(addr, 0):
                refs.append({
                    "type": "code_call",
                    "from": hex(xref),
                    "func_name": idc.get_func_name(xref)
                })
            # Who uses addr's pointer (Data Xref)
            for xref in idautils.DataRefsTo(addr):
                refs.append({
                    "type": "data_ref",
                    "from": hex(xref),
                    "func_name": idc.get_func_name(xref)
                })

        elif direction == "from":
            # Who does addr call
            func = idaapi.get_func(addr)
            if func:
                # Iterate through each instruction in the function
                for head in idautils.Heads(func.start_ea, func.end_ea):
                    # Check Code Ref
                    for xref in idautils.CodeRefsFrom(head, 0):
                        refs.append({
                            "type": "call",
                            "addr": hex(head), # Which line called from
                            "target": hex(xref),
                            "target_name": idc.get_func_name(xref)
                        })
                    # Check Data Ref (what global variables/strings are used)
                    for xref in idautils.DataRefsFrom(head):
                        refs.append({
                            "type": "use_data",
                            "addr": hex(head),
                            "target": hex(xref),
                            # Try to get string content or variable name
                            "target_val": str(idc.get_strlit_contents(xref) or idc.get_name(xref))
                        })

        return {"status": "ok", "data": refs}

    # 5. Raw Memory Read
    def worker_read_bytes(self, params):
        """
        Read raw memory (for analyzing non-string struct data)
        params: {"address": 0x..., "length": 16}
        """
        addr = self._resolve_addr(params.get("address"))
        length = params.get("length", 16)
        if addr == idc.BADADDR: return {"status": "error", "error": "Invalid address"}

        data = ida_bytes.get_bytes(addr, length)
        if data:
            return {"status": "ok", "data": data.hex()} # Return Hex string
        else:
            return {"status": "error", "error": "Read failed"}
            
    # 6. Get Imports/Exports (for backward compatibility)
    def worker_get_imports(self, params):
        # ... (Reusing V5 code logic) ...
        # Omitted for brevity, copy worker_get_imports from V5
        # Remember to keep cb function internal
        import_list = []
        def cb(ea, name, ord):
            if not name: name = f"ORD_{ord}"
            import_list.append({"name": name, "addr": hex(ea)})
            return True
        nimps = idaapi.get_import_module_qty()
        for i in range(nimps): idaapi.enum_import_names(i, cb)
        return {"status": "ok", "data": import_list}

    def stop(self):
        self.running = False
        if self.sock: self.sock.close()
        with self._clients_lock:
            for conn in self._clients:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    # 7. Smart Data Parsing (String or Pointer)
    def worker_resolve_data(self, params):
        """
        Auto-detect data type at address:
        1. If it's a string, return the content directly.
        2. If it's a pointer, return the target address.
        """
        addr = self._resolve_addr(params.get("address"))
        if addr == idc.BADADDR: return {"status": "error", "error": "Invalid address"}

        # 1. Try reading as string
        content = idc.get_strlit_contents(addr)
        if content:
            return {"status": "ok", "type": "string", "value": content.decode('utf-8', 'ignore')}
        
        # 2. Try reading as pointer (32-bit or 64-bit)
        # Assuming 32-bit IoT (use get_qword for 64-bit)
        ptr_val = ida_bytes.get_wide_dword(addr) 
        
        # Check if pointer points to a string
        deep_content = idc.get_strlit_contents(ptr_val)
        if deep_content:
            return {
                "status": "ok", 
                "type": "pointer_to_string", 
                "ptr_value": hex(ptr_val), 
                "target_string": deep_content.decode('utf-8', 'ignore')
            }

        return {"status": "ok", "type": "unknown_data", "hex": hex(ptr_val)}
    
    # 8. Scan function call arguments
    # [In ida_server_v6.py] Replacement for worker_scan_args

    def worker_scan_args(self, params):
        """
        AST-Based Argument Extractor (High Precision)
        """
        target_addr = self._resolve_addr(params.get("address"))
        if target_addr == idc.BADADDR:
            return {"status": "error", "error": "Invalid address"}

        results = []
        # Find all callers (Xrefs)
        refs = list(idautils.CodeRefsTo(target_addr, 0))
        
        # Cache processed functions to avoid duplicates
        processed_funcs = set()

        for caller_addr in refs:
            caller_func = idaapi.get_func(caller_addr)
            if not caller_func or caller_func.start_ea in processed_funcs:
                continue
            processed_funcs.add(caller_func.start_ea)

            try:
                # Decompile the caller
                cfunc = ida_hexrays.decompile(caller_func)
                if not cfunc: continue

                # Create a tree visitor to find calls
                class CallVisitor(ida_hexrays.ctree_visitor_t):
                    def __init__(self, target_ea):
                        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                        self.target_ea = target_ea
                        self.calls_found = []

                    def visit_expr(self, e):
                        # We are looking for a function call (cot_call)
                        if e.op == ida_hexrays.cot_call:
                            # Check if the called object is our target address
                            # usually x.op == cot_obj (direct call) or cot_helper (imported)
                            func_expr = e.x
                            if func_expr.op == ida_hexrays.cot_obj and func_expr.obj_ea == self.target_ea:
                                # Found a call! Extract args.
                                args_list = []
                                for arg in e.a:
                                    arg_val = "unknown"
                                    # Case 1: Literal String ("string")
                                    if arg.op == ida_hexrays.cot_str:
                                        arg_val = arg.string
                                    # Case 2: Global Object/Pointer (&off_XXXX or sub_XXXX)
                                    elif arg.op == ida_hexrays.cot_obj:
                                        # Check if it's a string pointer
                                        str_content = idc.get_strlit_contents(arg.obj_ea)
                                        if str_content:
                                            arg_val = str_content.decode('utf-8', 'ignore')
                                        else:
                                            # Likely a function pointer (Handler)
                                            name = idc.get_name(arg.obj_ea)
                                            arg_val = f"&{name}"
                                    # Case 3: Number (Flags, etc.)
                                    elif arg.op == ida_hexrays.cot_num:
                                        arg_val = arg.n.value(arg.type)
                                    # Case 4: Cast (skip the cast wrapper)
                                    elif arg.op == ida_hexrays.cot_cast:
                                        # Simple unwrap for now
                                        if arg.x.op == ida_hexrays.cot_obj:
                                            name = idc.get_name(arg.x.obj_ea)
                                            arg_val = f"&{name}"
                                    
                                    args_list.append(str(arg_val))
                                
                                self.calls_found.append({
                                    "caller": idc.get_func_name(caller_func.start_ea),
                                    "args": args_list,
                                    "ea": hex(e.ea) # Address of the call instruction
                                })
                            return 0 # Continue visiting
                        return 0

                # Execute Visitor
                cv = CallVisitor(target_addr)
                cv.apply_to(cfunc.body, None)
                
                results.extend(cv.calls_found)

            except Exception as e:
                # print(f"Error scanning {hex(caller_addr)}: {e}") 
                continue

        return {"status": "ok", "data": results}
    
    # 9. Static Routing Table Scan
    def worker_scan_static_table(self, params):
        """
        [Powerful Tool] Try to parse static routing table.
        params: {
            "address": "0x588D80",  # Table start address
            "layout": "sf",         # Layout mode: 's' for string pointer, 'f' for function pointer, 'x' for skip 4 bytes
                                    # e.g., "sf" = StringPtr, FuncPtr (most common)
                                    # "fs" = FuncPtr, StringPtr
            "count": 20             # How many entries to try reading (stops early on failure)
        }
        """
        start_addr = self._resolve_addr(params.get("address"))
        layout = params.get("layout", "sf") 
        count = params.get("limit", 20)
        
        ptr_size = 4  # Assuming 32-bit system, change to 8 for 64-bit
        stride = len(layout) * ptr_size 
        
        results = []
        current_addr = start_addr
        
        for i in range(count):
            entry = {"offset": hex(current_addr)}
            valid_entry = True
            
            # Parse each column of this row
            for idx, char in enumerate(layout):
                field_addr = current_addr + (idx * ptr_size)
                # Read pointer value
                ptr_val = ida_bytes.get_wide_dword(field_addr)  # 32-bit
                
                if char == 's': # String Pointer
                    content = idc.get_strlit_contents(ptr_val)
                    if content:
                        entry["url"] = content.decode('utf-8', 'ignore')
                    else:
                        valid_entry = False  # Expected string but got none, table ends
                        
                elif char == 'f': # Function Pointer
                    func_name = idc.get_name(ptr_val)
                    # Verify if it points to valid code segment
                    if ida_bytes.is_code(ida_bytes.get_flags(ptr_val)):
                        entry["handler"] = func_name
                        entry["handler_addr"] = hex(ptr_val)
                    else:
                        # Sometimes IDA hasn't analyzed it as code yet, or it's NULL terminator
                        if ptr_val == 0: valid_entry = False
                        entry["handler_ptr"] = hex(ptr_val)

            if not valid_entry:
                break
                
            results.append(entry)
            current_addr += stride
            
        return {"status": "ok", "data": results}

# ================= 10. Full Static Scan =================
    def worker_run_static_scan(self, params):
        """
        Trigger server-side full static analysis
        """
        # Get the directory of the IDA database as default log output directory
        # This is more robust than hardcoding a relative path
        idb_dir = os.path.dirname(idc.get_input_file_path())
        out_dir = os.path.join(idb_dir, "logs")

        # Can also accept parameter override
        if params.get("output_dir"):
            out_dir = params.get("output_dir")

        print(f"[*] Executing Static Scan... (Target Log Dir: {out_dir})")
        
        try:
            # Directly call sibling module method
            scan_result = static_analysis.run_analysis(output_dir=out_dir)
            return {"status": "ok", "data": scan_result}
        except Exception as e:
            traceback.print_exc()
            return {"status": "error", "error": f"Scan failed: {str(e)}"}
        
    # ================= 11. Authentication Analysis Helper Tools =================
    
    def worker_get_callees(self, params):
        """
        [Efficient] Get list of all callees of specified function (for clustering analysis)
        params: {"address": "sub_401000"}
        """
        func_addr = self._resolve_addr(params.get("address"))
        if func_addr == idc.BADADDR: 
            return {"status": "error", "error": "Invalid address"}

        callees = set()
        func = idaapi.get_func(func_addr)
        if not func: 
            return {"status": "error", "error": "Not a function"}

        # Iterate through all instructions in function, looking for Code References
        for head in idautils.Heads(func.start_ea, func.end_ea):
            insn = ida_ua.insn_t()
            if not ida_ua.decode_insn(insn, head) or not ida_idp.is_call_insn(insn):
                continue
            for xref in idautils.CodeRefsFrom(head, 0):
                # Exclude self recursion
                if xref == func.start_ea: continue
                
                # Get callee function name
                name = idc.get_func_name(xref)
                if name:
                    callees.add(name)
        
        return {"status": "ok", "data": list(callees)}

    def worker_get_func_head(self, params):
        """
        [Concise] Only decompile and extract first N lines of function (for gatekeeper identification)
        params: {"address": "sub_401000", "lines": 20}
        """
        addr = self._resolve_addr(params.get("address"))
        limit = params.get("lines", 30)
        
        if not ida_hexrays.init_hexrays_plugin():
            return {"status": "error", "error": "No Hex-Rays"}

        try:
            cfunc = ida_hexrays.decompile(addr)
            if not cfunc: return {"status": "error", "error": "Decompile failed"}
            
            # Extract first N lines
            all_lines = [idaapi.tag_remove(line.line) for line in cfunc.get_pseudocode()]
            head_lines = all_lines[:limit]
            
            return {
                "status": "ok", 
                "data": {
                    "func_name": idc.get_func_name(addr),
                    "code_snippet": "\n".join(head_lines),
                    "total_lines": len(all_lines)
                }
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def worker_scan_caller_context(self, params):
        """
        [Tenda Specific] Context scanner
        1. Find callers of target_addr (registration function) (webinit)
        2. Scan all calls to target_addr within webinit
        3. Return all call argument lists (looking for Flag=1)
        """
        target_addr = self._resolve_addr(params.get("address"))
        if target_addr == idc.BADADDR: return {"status": "error", "error": "Invalid address"}

        # 1. Find callers (usually only one main init function)
        callers = list(idautils.CodeRefsTo(target_addr, 0))
        if not callers:
            return {"status": "error", "error": "No callers found"}
        
        # Get first caller (webinit)
        webinit_ea = idc.get_func_attr(callers[0], idc.FUNCATTR_START)
        if webinit_ea == idc.BADADDR:
             return {"status": "error", "error": "Caller is not a function"}
             
        webinit_name = idc.get_func_name(webinit_ea)
        print(f"[*] Scanning context in {webinit_name} for calls to {hex(target_addr)}")

        # 2. Decompile webinit
        if not ida_hexrays.init_hexrays_plugin():
            return {"status": "error", "error": "No Hex-Rays"}
            
        try:
            cfunc = ida_hexrays.decompile(webinit_ea)
            if not cfunc: return {"status": "error", "error": "Decompile failed"}
        except:
            return {"status": "error", "error": "Decompile exception"}

        results = []

        # 3. AST visitor: Find all calls to target_addr
        class ContextVisitor(ida_hexrays.ctree_visitor_t):
            def __init__(self, target):
                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                self.target = target
                self.calls = []

            def visit_expr(self, e):
                if e.op == ida_hexrays.cot_call:
                    # Check if the called function is target
                    is_target = False
                    if e.x.op == ida_hexrays.cot_obj and e.x.obj_ea == self.target:
                        is_target = True
                    
                    if is_target:
                        args = []
                        for arg in e.a:
                            val = "unknown"
                            # Try to resolve Handler (function pointer)
                            if arg.op == ida_hexrays.cot_obj:
                                name = idc.get_name(arg.obj_ea)
                                if name: val = name # R7WebsSecurityHandler
                                else: val = hex(arg.obj_ea)
                            # Try to resolve Flag (number)
                            elif arg.op == ida_hexrays.cot_num:
                                val = arg.n.value(arg.type)
                            # Try to resolve String
                            elif arg.op == ida_hexrays.cot_str:
                                val = arg.string
                            
                            args.append(val)
                        
                        self.calls.append(args)
                return 0

        cv = ContextVisitor(target_addr)
        cv.apply_to(cfunc.body, None)
        
        return {
            "status": "ok", 
            "caller": webinit_name,
            "calls": cv.calls  # [[url, 0, 0, handler, flag], ...]
        }
    
    # [Add/Replace the following methods in ida_server_v6.py]

    # ================= 12. Powerful AST Rule Analysis (New) =================

    def worker_analyze_blocking_behavior(self, params):
        """
        [Rule Engine Core] Analyze whether a function's calls exhibit "blocking" or "wrapping" characteristics.
        Replaces LLM for CFG analysis.
        
        Principle: Branch Weight Imbalance Analysis
        """
        target_addr = self._resolve_addr(params.get("address"))
        if target_addr == idc.BADADDR: return {"status": "error"}

        if not ida_hexrays.init_hexrays_plugin():
            return {"status": "error", "error": "No Hex-Rays"}

        # Statistics data
        stats = {
            "total_calls": 0,
            "blocking_calls": 0,  # Number of times satisfying "blocking" characteristics
            "patterns": []        # Record specific blocking patterns
        }

        # 1. Find all callers
        refs = list(idautils.CodeRefsTo(target_addr, 0))
        unique_callers = set()
        
        for caller_addr in refs:
            func = idaapi.get_func(caller_addr)
            if not func or func.start_ea in unique_callers: continue
            unique_callers.add(func.start_ea)
            
            # Limit sampling count to avoid slow analysis
            if len(unique_callers) > 10: break

            try:
                cfunc = ida_hexrays.decompile(func)
                if not cfunc: continue
            except: continue

            # 2. AST visitor: Find call site and analyze context
            class BlockingVisitor(ida_hexrays.ctree_visitor_t):
                def __init__(self, target_ea):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                    self.target_ea = target_ea
                    self.is_blocking = False
                    self.pattern = "None"

                def visit_expr(self, e):
                    # Find call site
                    if e.op == ida_hexrays.cot_call and \
                       e.x.op == ida_hexrays.cot_obj and \
                       e.x.obj_ea == self.target_ea:
                        
                        # Backtrack parent node, looking for if statement
                        parent = self.get_parent_if(e)
                        if parent:
                            self.analyze_if_stmt(parent)
                        return 0  # Found, don't continue into this branch
                    return 0

                def get_parent_if(self, expr):
                    # This is a simplified parent node lookup, actual implementation may need parent stack
                    # Here we simply assume the call is in the if condition
                    # In actual hexrays visitor, we need to record the path ourselves
                    # But for simplicity, we assume the ctree structure.
                    # *Note: Standard visitor doesn't directly provide parent, typically need to maintain a stack*
                    # Here to make code work, we use "logical parent" judgment, or simplify to:
                    # If this call is a condition member of some cit_if
                    return None  # Placeholder, using more robust stack method below

                def analyze_if_stmt(self, if_stmt):
                    # Count then and else statement weights
                    w_then = self.calc_weight(if_stmt.ithen)
                    w_else = self.calc_weight(if_stmt.ielse)
                    
                    has_return_then = self.has_return(if_stmt.ithen)
                    has_return_else = self.has_return(if_stmt.ielse) or (if_stmt.ielse is None)
                    
                    # Pattern A: if (fail) return; (Then is very light and has return)
                    if w_then < 5 and has_return_then and w_else > 10:
                        self.is_blocking = True
                        self.pattern = "Fail-Fast"
                    
                    # Pattern B: if (success) { heavy } else return; (Else is very light and has return)
                    elif w_else < 5 and has_return_else and w_then > 10:
                        self.is_blocking = True
                        self.pattern = "Wrap-Logic"
                        
                def calc_weight(self, stmt):
                    if not stmt: return 0
                    if stmt.op == ida_hexrays.cit_block:
                        return len(stmt.cblock) # Number of statements in block
                    return 1 # Single statement
                
                def has_return(self, stmt):
                    if not stmt: return False
                    # Simple recursive search for return
                    if stmt.op == ida_hexrays.cit_return: return True
                    if stmt.op == ida_hexrays.cit_block:
                        for s in stmt.cblock:
                            if self.has_return(s): return True
                    return False

            # *Fix: Since HexRays Visitor by default doesn't have Parent pointer, we need to maintain Parent Stack manually*
            # Below is a more practical Stack Visitor implementation
            class StackVisitor(ida_hexrays.ctree_visitor_t):
                def __init__(self, target_ea):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                    self.target_ea = target_ea
                    self.parents = [] # Stack
                    self.found_blocking = False
                    self.pattern = ""

                def visit_insn(self, i):
                    self.parents.append(i)
                    ret = ida_hexrays.ctree_visitor_t.visit_insn(self, i)
                    self.parents.pop()
                    return ret

                def visit_expr(self, e):
                    if e.op == ida_hexrays.cot_call and \
                       e.x.op == ida_hexrays.cot_obj and \
                       e.x.obj_ea == self.target_ea:
                        
                        # Check if stack top (nearest statement) is IF
                        # Note: Call is Expr, which is contained in Insn (Statement)
                        # We look back to see if it's wrapped in cit_if's condition
                        for p in reversed(self.parents):
                            if p.op == ida_hexrays.cit_if:
                                self.check_imbalance(p)
                                break
                    return 0

                def check_imbalance(self, if_stmt):
                    # Calculate weights
                    w_then = self.get_stmt_count(if_stmt.ithen)
                    w_else = self.get_stmt_count(if_stmt.ielse)
                    
                    # Check if contains return/goto
                    term_then = self.is_terminating(if_stmt.ithen)
                    term_else = self.is_terminating(if_stmt.ielse)
                    
                    # Case 1: Forward blocking (Then is very short and terminates)
                    # if (check < 0) return;
                    if w_then <= 3 and term_then and (w_else > 5 or if_stmt.ielse is None):
                        self.found_blocking = True
                        self.pattern = "Blocking(If)"

                    # Case 2: Reverse wrapping (Else is very short and terminates, or Else is empty but Then is very long)
                    # if (check == 0) { ...long... } else return;
                    # Or if (check == 0) { ...long... } (implicit Else Fallthrough, this case is harder to judge, being conservative for now)
                    elif w_else <= 3 and term_else and w_then > 5:
                        self.found_blocking = True
                        self.pattern = "Blocking(Else)"
                
                def get_stmt_count(self, stmt):
                    if not stmt: return 0
                    if stmt.op == ida_hexrays.cit_block: return len(stmt.cblock)
                    return 1

                def is_terminating(self, stmt):
                    if not stmt: return False
                    if stmt.op in [ida_hexrays.cit_return, ida_hexrays.cit_goto, ida_hexrays.cit_break]:
                        return True
                    if stmt.op == ida_hexrays.cit_block:
                        for s in stmt.cblock:
                            if self.is_terminating(s): return True
                    return False

            # Execute analysis
            sv = StackVisitor(target_addr)
            sv.apply_to(cfunc.body, None)
            
            stats["total_calls"] += 1
            if sv.found_blocking:
                stats["blocking_calls"] += 1
                stats["patterns"].append(sv.pattern)

        return {"status": "ok", "data": stats}

    def worker_scan_registration_args(self, params):
        """
        [Rule Engine Core] Find specific registration function calls in source_hub and extract arguments.
        Used to solve the gatekeeper's diverse registration problem.
        """
        source_hub = self._resolve_addr(params.get("source_hub"))
        reg_funcs = params.get("reg_funcs", []) # list of names or addrs
        
        # Convert reg_funcs to address set
        reg_addrs = set()
        for f in reg_funcs:
            addr = self._resolve_addr(f)
            if addr != idc.BADADDR: reg_addrs.add(addr)
            
        if not ida_hexrays.init_hexrays_plugin():
            return {"status": "error", "error": "No Hex-Rays"}

        try:
            cfunc = ida_hexrays.decompile(source_hub)
        except:
            return {"status": "error", "error": "Decompile failed"}

        results = []

        class RegVisitor(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                self.calls = []

            def visit_expr(self, e):
                if e.op == ida_hexrays.cot_call and e.x.op == ida_hexrays.cot_obj:
                    callee = e.x.obj_ea
                    if callee in reg_addrs:
                        # Extract arguments
                        args = []
                        for arg in e.a:
                            val = "unknown"
                            if arg.op == ida_hexrays.cot_str: val = arg.string
                            elif arg.op == ida_hexrays.cot_num: val = arg.n.value(arg.type)
                            elif arg.op == ida_hexrays.cot_obj: 
                                name = idc.get_name(arg.obj_ea)
                                val = name if name else hex(arg.obj_ea)
                            args.append(val)
                        
                        self.calls.append({
                            "reg_func": hex(callee),
                            "reg_func_name": idc.get_name(callee),
                            "args": args
                        })
                return 0

        rv = RegVisitor()
        rv.apply_to(cfunc.body, None)
        return {"status": "ok", "data": rv.calls}

    def worker_analyze_inline_check(self, params):
        """
        [Engine 3 Core] Inline sensitive check detection.
        Analyzes whether a function references sensitive strings (e.g., "admin", "auth")
        and whether the reference is within an if branch with blocking characteristics.
        """
        target_addr = self._resolve_addr(params.get("address"))
        # Default sensitive word list (lowercase)
        keywords = params.get("keywords", [
            "uid", "user", "admin", "login", "auth", "password", 
            "token", "session", "cookie", "level", "group", "root"
        ])
        
        if target_addr == idc.BADADDR: return {"status": "error"}
        if not ida_hexrays.init_hexrays_plugin(): return {"status": "error", "error": "No Hex-Rays"}

        try:
            cfunc = ida_hexrays.decompile(target_addr)
            if not cfunc: return {"status": "error", "error": "Decompile failed"}
        except:
            return {"status": "error", "error": "Decompile exception"}

        # Result container
        result = {
            "found": False,
            "keyword": "",
            "pattern": "",
            "line_num": 0
        }

        # --- AST Visitor ---
        class InlineAuthVisitor(ida_hexrays.ctree_visitor_t):
            def __init__(self, target_keywords):
                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                self.keywords = target_keywords
                self.parents = []  # Maintain parent stack
                self.detected = False
                self.detected_kw = ""
                self.detected_pattern = ""

            def visit_insn(self, i):
                self.parents.append(i)
                ret = ida_hexrays.ctree_visitor_t.visit_insn(self, i)
                self.parents.pop()
                return ret

            def visit_expr(self, e):
                if self.detected: return 0 # Found one is enough

                found_kw = None
                
                # 1. Check if it's a string literal (cot_str)
                if e.op == ida_hexrays.cot_str:
                    s = e.string
                    if any(k in s.lower() for k in self.keywords):
                        found_kw = s

                # 2. Check if it's a global object reference (cot_obj -> pointing to string)
                elif e.op == ida_hexrays.cot_obj:
                    name = idc.get_name(e.obj_ea)
                    # Try to read content
                    content = idc.get_strlit_contents(e.obj_ea)
                    if content:
                        s = content.decode('utf-8', 'ignore')
                        if any(k in s.lower() for k in self.keywords):
                            found_kw = s
                    elif name and any(k in name.lower() for k in self.keywords):
                        found_kw = name

                # If found sensitive word, check if it's in blocking control flow
                if found_kw:
                    # Backtrack stack, find nearest if
                    for p in reversed(self.parents):
                        if p.op == ida_hexrays.cit_if:
                            if self.is_blocking(p):
                                self.detected = True
                                self.detected_kw = found_kw
                                self.detected_pattern = "Keyword inside Blocking IF"
                            break
                return 0

            def is_blocking(self, if_stmt):
                # Check if Then or Else is blocking (Return/Goto/Break)
                # Simple version: as long as one side is short and has return, consider it blocking
                then_blk = self.is_term_block(if_stmt.ithen)
                else_blk = self.is_term_block(if_stmt.ielse)
                return then_blk or else_blk

            def is_term_block(self, stmt):
                if not stmt: return False
                # If single return
                if stmt.op == ida_hexrays.cit_return: return True
                # If Block
                if stmt.op == ida_hexrays.cit_block:
                    # Only a few lines of code, and contains return
                    if len(stmt.cblock) > 5: return False # Too long is usually business logic
                    for s in stmt.cblock:
                        if s.op == ida_hexrays.cit_return: return True
                return False

        visitor = InlineAuthVisitor(keywords)
        visitor.apply_to(cfunc.body, None)

        if visitor.detected:
            result["found"] = True
            result["keyword"] = visitor.detected_kw
            result["pattern"] = visitor.detected_pattern
            
        return {"status": "ok", "data": result}
    
    def worker_scan_global_writes(self, params):
        """
        [Engine 4 Core] Global variable write scan.
        Analyzes a function to find which global variables it writes (assigns) to.
        Used to extract potential Auth Flags from Login interfaces.
        """
        func_addr = self._resolve_addr(params.get("address"))
        if func_addr == idc.BADADDR: return {"status": "error"}
        
        if not ida_hexrays.init_hexrays_plugin(): return {"status": "error", "error": "No Hex-Rays"}
        try:
            cfunc = ida_hexrays.decompile(func_addr)
            if not cfunc: return {"status": "error", "error": "Decompile failed"}
        except: return {"status": "error", "error": "Exception"}

        written_globals = set()

        class WriteVisitor(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
            
            def visit_expr(self, e):
                # Find assignment statement (cot_asg)
                if e.op == ida_hexrays.cot_asg:
                    # Check if LHS is global object (cot_obj)
                    lhs = e.x
                    if lhs.op == ida_hexrays.cot_obj:
                        # Record address and name
                        written_globals.add(lhs.obj_ea)
                    # Can also extend to support array/pointer assignment, omitted for now
                return 0

        wv = WriteVisitor()
        wv.apply_to(cfunc.body, None)
        
        # Format output
        results = []
        for ea in written_globals:
            results.append({
                "addr": hex(ea),
                "name": idc.get_name(ea)
            })
            
        return {"status": "ok", "data": results}

    def worker_scan_global_blocking_usage(self, params):
        """
        [Engine 4 Core] Global variable blocking usage scan.
        Checks if the specified function reads variables from candidate_globals,
        and whether the read occurs in an IF condition that causes function return (blocking).
        """
        target_addr = self._resolve_addr(params.get("address"))
        # Candidate global variable address list (extracted from Login interface)
        candidates = set()
        for x in params.get("candidates", []):
            val = self._resolve_addr(x)
            if val != idc.BADADDR: candidates.add(val)
            
        if not candidates: return {"status": "ok", "data": {"found": False}}
        
        if not ida_hexrays.init_hexrays_plugin(): return {"status": "error"}
        try:
            cfunc = ida_hexrays.decompile(target_addr)
            if not cfunc: return {"status": "error"}
        except: return {"status": "error"}

        result = {"found": False, "global_used": None}

        class GlobalBlockingVisitor(ida_hexrays.ctree_visitor_t):
            def __init__(self, target_globals):
                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_PARENTS)
                self.targets = target_globals
                self.found_addr = None

            def visit_expr(self, e):
                if self.found_addr: return 0
                
                # Check if target global variable is used
                if e.op == ida_hexrays.cot_obj and e.obj_ea in self.targets:
                    # Found reference, check context
                    if self.check_blocking_context(e):
                        self.found_addr = e.obj_ea
                return 0

            def check_blocking_context(self, expression):
                # Backtrack parent nodes to find IF
                for p in reversed(self.parents):
                    if p.op == ida_hexrays.cit_if:
                        if not p.cinsn.cif.expr.contains_expr(expression):
                            continue
                        # Check if IF is blocking
                        if self.is_term_block(p.cinsn.cif.ithen) or self.is_term_block(p.cinsn.cif.ielse):
                            return True
                return False
                
            def is_term_block(self, stmt):
                if not stmt: return False
                if stmt.op == ida_hexrays.cit_return: return True
                if stmt.op == ida_hexrays.cit_block:
                    # Allow few statements (e.g., print error log before exit)
                    if len(stmt.cblock) > 5: return False
                    for s in stmt.cblock:
                        if s.op == ida_hexrays.cit_return: return True
                return False

        gbv = GlobalBlockingVisitor(candidates)
        gbv.apply_to(cfunc.body, None)

        if gbv.found_addr:
            result["found"] = True
            result["global_used"] = hex(gbv.found_addr)
            result["global_name"] = idc.get_name(gbv.found_addr)
            
        return {"status": "ok", "data": result}

    # ================= 13. CFG Analysis Interface (New - PANGU Core) =================
    
    def worker_get_basic_blocks(self, params):
        """
        Get all basic blocks of a function
        params: {"address": "0x..."}
        """
        addr = self._resolve_addr(params.get("address"))
        if addr == idc.BADADDR:
            return {"status": "error", "error": "Invalid address"}
        
        try:
            blocks = cfg_analysis.get_basic_blocks(addr)
            return {"status": "ok", "data": blocks}
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def worker_build_dominator_tree(self, params):
        """
        Build function's dominator tree
        params: {"address": "0x..."}
        Returns: {block_addr: immediate_dominator_addr}
        """
        addr = self._resolve_addr(params.get("address"))
        if addr == idc.BADADDR:
            return {"status": "error", "error": "Invalid address"}
        
        try:
            dom_tree = cfg_analysis.build_dominator_tree(addr)
            return {"status": "ok", "data": dom_tree}
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def worker_get_dominator_context(self, params):
        """
        Get dominator context of target address (all blocks that dominate the address)
        params: {"func_address": "0x...", "target_address": "0x..."}
        """
        func_addr = self._resolve_addr(params.get("func_address"))
        target_addr = self._resolve_addr(params.get("target_address"))
        
        if func_addr == idc.BADADDR or target_addr == idc.BADADDR:
            return {"status": "error", "error": "Invalid address"}
        
        try:
            dominators = cfg_analysis.get_dominator_context(func_addr, target_addr)
            return {"status": "ok", "data": dominators}
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def worker_calculate_tis(self, params):
        """
        Calculate TIS (Terminating Imbalance Score) for all if statements in a function
        params: {"address": "0x..."}
        """
        addr = self._resolve_addr(params.get("address"))
        if addr == idc.BADADDR:
            return {"status": "error", "error": "Invalid address"}
        
        try:
            tis_results = cfg_analysis.calculate_tis(addr)
            return {"status": "ok", "data": tis_results}
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def worker_find_blocking_checks(self, params):
        """
        Find blocking checks in function (conditions with high TIS scores)
        params: {"address": "0x...", "threshold": 2.0}
        """
        addr = self._resolve_addr(params.get("address"))
        threshold = params.get("threshold", 5.0)
        
        if addr == idc.BADADDR:
            return {"status": "error", "error": "Invalid address"}
        
        try:
            checks = cfg_analysis.find_blocking_checks(addr, threshold)
            return {"status": "ok", "data": checks}
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def worker_scan_auth_patterns(self, params):
        """
        Scan authentication patterns in function (combining TIS and keywords)
        params: {"address": "0x..."}
        """
        addr = self._resolve_addr(params.get("address"))
        if addr == idc.BADADDR:
            return {"status": "error", "error": "Invalid address"}
        
        try:
            patterns = cfg_analysis.scan_auth_patterns(addr)
            return {"status": "ok", "data": patterns}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    # ================= 14. Enhanced Static Analysis Interface (Enhanced Static Analysis) =================
    
    def worker_run_enhanced_scan(self, params):
        """
        Run enhanced function pointer table scan
        params: {
            "start_addr": "0x..." (optional, default scan from beginning),
            "end_addr": "0x..." (optional),
            "scan_type": "string_handler" | "mixed" | "all" (default "all"),
            "min_entries": 3 (minimum number of table entries)
        }
        Returns: List of detected tables and their handler functions
        """
        start_addr = self._resolve_addr(params.get("start_addr")) if params.get("start_addr") else None
        end_addr = self._resolve_addr(params.get("end_addr")) if params.get("end_addr") else None
        scan_type = params.get("scan_type", "all")
        min_entries = params.get("min_entries", 3)
        
        try:
            scanner = enhanced_static_analysis.EnhancedTableScanner()
            results = {
                "string_handler_tables": [],
                "mixed_tables": [],
                "total_routes": 0
            }
            
            if scan_type in ["string_handler", "all"]:
                sh_tables = scanner.scan_string_handler_tables(
                    start_addr=start_addr,
                    end_addr=end_addr,
                    min_entries=min_entries
                )
                results["string_handler_tables"] = sh_tables
                for t in sh_tables:
                    results["total_routes"] += len(t.get("entries", []))
            
            if scan_type in ["mixed", "all"]:
                mixed_tables = scanner.scan_mixed_handler_tables(
                    start_addr=start_addr,
                    end_addr=end_addr,
                    min_entries=min_entries
                )
                results["mixed_tables"] = mixed_tables
                for t in mixed_tables:
                    results["total_routes"] += len(t.get("entries", []))
            
            return {"status": "ok", "data": results}
        except Exception as e:
            import traceback
            return {"status": "error", "error": str(e), "traceback": traceback.format_exc()}
    
    def worker_backward_slice(self, params):
        """
        Backward trace from function pointer table to route registration point
        params: {
            "table_address": "0x..." (table start address),
            "handler_address": "0x..." (optional, specific handler function address),
            "max_depth": 5 (maximum trace depth)
        }
        Returns: List of registration sites and their call chains
        """
        table_addr = self._resolve_addr(params.get("table_address"))
        handler_addr = self._resolve_addr(params.get("handler_address")) if params.get("handler_address") else None
        max_depth = params.get("max_depth", 5)
        
        if table_addr == idc.BADADDR:
            return {"status": "error", "error": "Invalid table address"}
        
        try:
            slicer = enhanced_static_analysis.BackwardSlicer()
            
            if handler_addr:
                # Trace specific handler function
                sites = slicer.find_registration_sites(handler_addr, max_depth)
            else:
                # Trace entire table
                sites = slicer.trace_table_registrations(table_addr, max_depth)
            
            return {"status": "ok", "data": sites}
        except Exception as e:
            import traceback
            return {"status": "error", "error": str(e), "traceback": traceback.format_exc()}
    
    def worker_analyze_dispatch_hub(self, params):
        """
        Analyze route dispatch hub function
        params: {
            "address": "0x..." (dispatch function address),
            "extract_routes": true (whether to extract route information)
        }
        Returns: Dispatch logic analysis result
        """
        addr = self._resolve_addr(params.get("address"))
        extract_routes = params.get("extract_routes", True)
        
        if addr == idc.BADADDR:
            return {"status": "error", "error": "Invalid address"}
        
        try:
            scanner = enhanced_static_analysis.EnhancedTableScanner()
            analysis = scanner.analyze_dispatch_function(addr, extract_routes)
            return {"status": "ok", "data": analysis}
        except Exception as e:
            import traceback
            return {"status": "error", "error": str(e), "traceback": traceback.format_exc()}
    
    def worker_get_handler_info(self, params):
        """
        Get detailed information about handler function (for route classification)
        params: {
            "address": "0x..." (handler function address)
        }
        Returns: Function characteristic information (parameters, calls, strings, etc.)
        """
        addr = self._resolve_addr(params.get("address"))
        if addr == idc.BADADDR:
            return {"status": "error", "error": "Invalid address"}
        
        try:
            func = idaapi.get_func(addr)
            if not func:
                return {"status": "error", "error": "Not a function"}
            
            info = {
                "address": hex(addr),
                "name": idc.get_func_name(addr),
                "size": func.size(),
                "calls": [],
                "strings": [],
                "dangerous_calls": [],
                "auth_related": []
            }
            
            # Collect called functions
            for head in idautils.Heads(func.start_ea, func.end_ea):
                if idc.is_code(idc.get_full_flags(head)):
                    for xref in idautils.CodeRefsFrom(head, 0):
                        called_name = idc.get_func_name(xref)
                        if called_name and called_name not in info["calls"]:
                            info["calls"].append(called_name)
                            
                            # Check dangerous functions
                            dangerous = ["system", "popen", "exec", "sprintf", "strcpy", "gets"]
                            if any(d in called_name.lower() for d in dangerous):
                                info["dangerous_calls"].append(called_name)
                            
                            # Check authentication related
                            auth_keywords = ["auth", "login", "session", "check", "verify", "password"]
                            if any(k in called_name.lower() for k in auth_keywords):
                                info["auth_related"].append(called_name)
            
            # Collect string references
            for head in idautils.Heads(func.start_ea, func.end_ea):
                for dref in idautils.DataRefsFrom(head):
                    str_val = idc.get_strlit_contents(dref, -1, idc.STRTYPE_C)
                    if str_val:
                        try:
                            decoded = str_val.decode('utf-8', errors='ignore')
                            if len(decoded) > 2 and decoded not in info["strings"]:
                                info["strings"].append(decoded)
                        except:
                            pass
            
            return {"status": "ok", "data": info}
        except Exception as e:
            import traceback
            return {"status": "error", "error": str(e), "traceback": traceback.format_exc()}

# Startup entry point
if 'server_agent' in globals():
    try: globals()['server_agent'].stop()
    except: pass
    del globals()['server_agent']


if os.environ.get("PANGU_NO_AUTOSTART") != "1":
    print("[*] Starting IDA RPC Server V7...")
    server_agent = IDAServerAgent()
    server_agent.start()
