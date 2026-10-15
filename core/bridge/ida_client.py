# Copyright (c) 2026 The Pangu Project Authors. All rights reserved.
# core/bridge/ida_client.py
import socket
import json
import threading
from core.bridge.protocol import receive_json, send_json

class IDAProClient:
    def __init__(self, host='127.0.0.1', port=4455, timeout=120, connect_timeout=5):
        self.host = host
        self.port = port
        self.sock = None
        if timeout <= 0 or connect_timeout <= 0:
            raise ValueError("IDA timeouts must be positive")
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self._lock = threading.RLock()
        self.last_error = None

    def connect(self):
        with self._lock:
            if self.sock is not None:
                return True
            try:
                self.sock = socket.create_connection((self.host, self.port), self.connect_timeout)
                self.sock.settimeout(self.timeout)
                self.last_error = None
                print(f"[+] Connected to IDA at {self.host}:{self.port}")
                return True
            except OSError as exc:
                self.close()
                self.last_error = str(exc)
                return False

    def close(self):
        with self._lock:
            if self.sock is not None:
                self.sock.close()
                self.sock = None

    def __enter__(self):
        if not self.connect():
            raise ConnectionError(self.last_error or "Cannot connect to IDA")
        return self

    def __exit__(self, *args):
        self.close()

    def _send(self, cmd, params=None):
        # One request/response pair owns the connection. Do not automatically
        # replay a failed request: the server may already have executed it.
        with self._lock:
            if self.sock is None:
                return {"status": "error", "error": "Not connected"}
            try:
                send_json(self.sock, {"command": cmd, "params": params or {}})
                response = receive_json(self.sock, self.timeout)
                if not isinstance(response, dict) or response.get("status") not in {"ok", "error"}:
                    raise ValueError("Malformed IDA response")
                return response
            except (OSError, ValueError, ConnectionError) as exc:
                self.last_error = str(exc)
                self.close()
                return {"status": "error", "error": str(exc)}

    def batch(self, requests):
        """Execute up to 32 bounded read requests in one RPC round trip."""
        if not isinstance(requests, list) or not 1 <= len(requests) <= 32:
            raise ValueError("batch requires 1-32 requests")
        return self._send("batch", {"requests": requests})

    def decompile_page(self, address, start_line=0, max_lines=100):
        return self._send("decompile", {"address": address, "start_line": start_line,
                                        "max_lines": max_lines})

    def analyze_guard_coverage(self, address, target_address):
        return self._send("analyze_guard_coverage", {"address": address, "target_address": target_address})

    # --- Standard Server Interface Methods ---

    def get_status(self):
        """Get IDA server status information"""
        return self._send("get_status")

    def ping(self):
        return self._send("ping")

    def get_segments(self):
        return self._send("get_segments")

    def get_functions(self, search="", limit=1000):
        return self._send("get_functions", {"search": search, "limit": limit})

    def search_strings(self, content):
        return self._send("search_strings", {"content": content})

    def decompile(self, address):
        """ address can be 'sub_401000', 'main', or 0x401000 """
        return self._send("decompile", {"address": address})

    def get_xrefs(self, address, direction="to"):
        """ direction: 'to' (Callers) or 'from' (Callees/Data use) """
        return self._send("get_xrefs", {"address": address, "direction": direction})

    def read_bytes(self, address, length=16):
        return self._send("read_bytes", {"address": address, "length": length})

    def get_imports(self):
        return self._send("get_imports")
    
    def resolve_data(self, address, length=4):
        return self._send("resolve_data", {"address": address, "length": length})
    
    def scan_args(self, address=None, function_name=None):
        target = address if address else function_name
        return self._send("scan_args", {"address": target})
    
    def scan_static_table(self, address, layout="sf", limit=20):
        return self._send("scan_static_table", {
            "address": address,
            "layout": layout,
            "limit": limit
        })

    def get_callees(self, address):
        """ Get all callees of the specified function (for Engine 3/4) """
        return self._send("get_callees", {"address": address})

    def get_func_head(self, address, lines=30):
        """ Get the function header code snippet (for LLM analysis) """
        return self._send("get_func_head", {"address": address, "lines": lines})

    def scan_caller_context(self, address):
        """ Scan caller context (for Engine 2 Tenda) """
        return self._send("scan_caller_context", {"address": address})

    def run_static_scan(self, output_dir=None):
        """ Trigger server-side full scan """
        return self._send("run_static_scan", {"output_dir": output_dir})
    
    def analyze_blocking_behavior(self, address):
        """
        Call server-side AST branch weight imbalance analysis.
        Used to determine if a function has blocking characteristics like 'if(fail) return'.
        """
        return self._send("analyze_blocking_behavior", {"address": address})

    def scan_registration_args(self, source_hub, reg_funcs):
        """
        Call server-side to scan registration function call arguments within specified Source Hub.
        :param source_hub: Address or name of the routing source function (Source Hub)
        :param reg_funcs: List of known registration functions (List[str])
        """
        return self._send("scan_registration_args", {
            "source_hub": source_hub, 
            "reg_funcs": reg_funcs
        })
    
    def analyze_inline_check(self, address, keywords=None):
        """
        [Engine 3] Request server-side inline sensitive check analysis.
        """
        params = {"address": address}
        if keywords: params["keywords"] = keywords
        return self._send("analyze_inline_check", params)
    
    def scan_global_writes(self, address):
        """ [Engine 4] Scan which global variables the function writes to """
        return self._send("scan_global_writes", {"address": address})

    def scan_global_blocking_usage(self, address, candidates):
        """ [Engine 4] Scan whether the function uses candidate global variables in a blocking manner """
        # candidates: list of address strings or ints
        return self._send("scan_global_blocking_usage", {
            "address": address, 
            "candidates": candidates
        })

    # ================= PANGU Core: CFG Analysis Interface =================
    
    def get_basic_blocks(self, address):
        """
        Get all basic blocks of a function.
        Returns: [{"id": int, "start": hex, "end": hex, "successors": [], "predecessors": []}]
        """
        return self._send("get_basic_blocks", {"address": address})
    
    def build_dominator_tree(self, address):
        """
        Build the dominator tree of a function.
        Returns: {block_addr: immediate_dominator_addr}
        """
        return self._send("build_dominator_tree", {"address": address})
    
    def get_dominator_context(self, func_address, target_address):
        """
        Get the dominator context of a target address (all blocks that dominate the address).
        Used to identify global authentication logic before dispatch points.
        """
        return self._send("get_dominator_context", {
            "func_address": func_address,
            "target_address": target_address
        })
    
    def calculate_tis(self, address):
        """
        Calculate TIS (Terminating Imbalance Score) for all if statements in a function.
        Returns: [{"address": hex, "tis": float, "pattern": str, ...}]
        """
        return self._send("calculate_tis", {"address": address})
    
    def find_blocking_checks(self, address, threshold=5.0):
        """
        Find blocking checks in a function (conditions with high TIS scores).
        threshold: TIS threshold, default 2.0
        """
        return self._send("find_blocking_checks", {
            "address": address,
            "threshold": threshold
        })
    
    def scan_auth_patterns(self, address):
        """
        Scan authentication patterns in a function (combining TIS and keywords).
        Returns authentication calls, authentication strings, blocking checks, etc.
        """
        return self._send("scan_auth_patterns", {"address": address})

    # ================= PANGU Core: Enhanced Static Analysis Interface =================
    
    def run_enhanced_scan(self, start_addr=None, end_addr=None, scan_type="all", min_entries=3):
        """
        Run enhanced function pointer table scanning.
        
        Args:
            start_addr: Scan start address (optional)
            end_addr: Scan end address (optional)
            scan_type: "string_handler" | "mixed" | "all"
            min_entries: Minimum number of table entries
        
        Returns:
            {
                "string_handler_tables": [...],
                "mixed_tables": [...],
                "total_routes": int
            }
        """
        params = {
            "scan_type": scan_type,
            "min_entries": min_entries
        }
        if start_addr:
            params["start_addr"] = start_addr
        if end_addr:
            params["end_addr"] = end_addr
        return self._send("run_enhanced_scan", params)
    
    def backward_slice(self, table_address, handler_address=None, max_depth=5):
        """
        Backward slice from function pointer table to route registration point.
        
        Args:
            table_address: Start address of the table
            handler_address: Specific handler function address (optional)
            max_depth: Maximum trace depth
        
        Returns:
            List of registration sites and their call chains
        """
        params = {
            "table_address": table_address,
            "max_depth": max_depth
        }
        if handler_address:
            params["handler_address"] = handler_address
        return self._send("backward_slice", params)
    
    def analyze_dispatch_hub(self, address, extract_routes=True):
        """
        Analyze route dispatch hub function.
        
        Args:
            address: Dispatch function address
            extract_routes: Whether to extract route information
        
        Returns:
            Dispatch logic analysis result
        """
        return self._send("analyze_dispatch_hub", {
            "address": address,
            "extract_routes": extract_routes
        })
    
    def get_handler_info(self, address):
        """
        Get detailed information about a handler function (for route classification).
        
        Args:
            address: Handler function address
        
        Returns:
            Function characteristic information (parameters, calls, strings, etc.)
        """
        return self._send("get_handler_info", {"address": address})
