# Copyright (c) 2026 The Pangu Project Authors. All rights reserved.
# analysis/goahead_analyzer.py
# GoAhead Web Server Specialized Analyzer
# Enhanced Features:
# 1. Parse websUrlHandlerDefine calls to identify global authentication functions (flag=1)
# 2. Trace static table hierarchy relationships with ASP/Form handler functions

import sys
import os
import re
import json
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, field

sys.path.append(os.getcwd())

from core.bridge.ida_client import IDAProClient


@dataclass
class GoAheadHandlerInfo:
    """GoAhead Handler Information"""
    url_prefix: str              # URL prefix
    handler_func: str            # Handler function
    handler_addr: str = ""       # Handler function address
    priority: int = 0            # Priority (flag)
    is_global_auth: bool = False # Whether global authentication handler
    registration_site: str = ""  # Registration location
    description: str = ""


@dataclass
class StaticTableContext:
    """Static Table Context Information"""
    table_addr: str                 # Static table address
    using_func: str                 # Function using this table
    using_func_addr: str = ""       # Using function address
    parent_path: str = ""           # Parent path (e.g., aspGetInfo)
    registration_api: str = ""      # Registration API (e.g., websAspDefine)
    registration_site: str = ""     # Registration call location


class GoAheadAnalyzer:
    """
    GoAhead Web Server Analyzer
    
    Features:
    1. Parse websUrlHandlerDefine calls in initialization function
    2. Identify global authentication handlers (flag=1)
    3. Trace static table hierarchy relationships
    
    Key GoAhead APIs:
    - websUrlHandlerDefine(prefix, webDir, arg, handler, flags)
      - flags=0: Normal handler
      - flags=1: Priority handler (usually authentication)
      - flags=2: Post handler
    
    - websFormDefine(name, handler) - Register /goform/xxx
    - websAspDefine(name, handler)  - Register ASP tags
    """
    
    # GoAhead route registration API signatures
    REGISTRATION_APIS = {
        "websUrlHandlerDefine": {
            "args": ["prefix", "webDir", "arg", "handler", "flags"],
            "prefix_idx": 0,
            "handler_idx": 3,
            "flag_idx": 4,
            "type": "url_handler"
        },
        "websFormDefine": {
            "args": ["name", "handler"],
            "prefix_idx": 0,
            "handler_idx": 1,
            "flag_idx": -1,  # No flag
            "type": "form_handler",
            "base_path": "/goform"
        },
        "websAspDefine": {
            "args": ["name", "handler"],
            "prefix_idx": 0,
            "handler_idx": 1,
            "flag_idx": -1,
            "type": "asp_handler",
            "base_path": ""  # ASP is a tag, not a path
        }
    }
    
    # Common GoAhead function name patterns (for identification)
    GOAHEAD_PATTERNS = {
        "websUrlHandlerDefine": ["websUrlHandler", "sub_4CC6A4"],
        "websFormDefine": ["websFormDefine", "sub_40D484"],
        "websAspDefine": ["websAspDefine", "sub_405930"]
    }
    
    def __init__(self, ida_client: IDAProClient = None):
        self.ida = ida_client if ida_client else IDAProClient()
        
        # Analysis results
        self.handlers: List[GoAheadHandlerInfo] = []
        self.global_auth_handlers: List[GoAheadHandlerInfo] = []
        self.static_table_contexts: Dict[str, StaticTableContext] = {}
        
        # API address mapping (actual address -> API name)
        self.api_address_map: Dict[str, str] = {}
        
        # Cache
        self._init_func_code: str = ""
    
    def log(self, msg: str):
        print(f"[GoAhead] {msg}")
    
    def connect(self) -> bool:
        """Connect to IDA"""
        return self.ida.connect()
    
    def discover_api_addresses(self) -> Dict[str, str]:
        """
        Discover actual addresses of GoAhead APIs
        Because functions may be renamed to sub_XXXX
        """
        self.log("Discovering GoAhead API addresses...")
        
        # Search for known API names
        for api_name, patterns in self.GOAHEAD_PATTERNS.items():
            for pattern in patterns:
                res = self.ida.decompile(pattern)
                if res.get("status") == "ok":
                    addr = res.get("data", {}).get("address", "")
                    if addr:
                        self.api_address_map[addr] = api_name
                        self.api_address_map[pattern] = api_name
                        self.log(f"  Found {api_name} at {addr} (name: {pattern})")
                        break
        
        return self.api_address_map
    
    def analyze_init_function(self, init_func: str) -> List[GoAheadHandlerInfo]:
        """
        Analyze initialization function, extract all Handler registrations
        
        Args:
            init_func: Initialization function name or address
        
        Returns:
            List of registered Handlers
        """
        self.log(f"Analyzing init function: {init_func}")
        
        # Decompile initialization function
        res = self.ida.decompile(init_func)
        if res.get("status") != "ok":
            self.log(f"Failed to decompile {init_func}")
            return []
        
        code = res.get("data", {}).get("code", "")
        self._init_func_code = code
        
        # Parse all websUrlHandlerDefine calls
        self._parse_url_handler_defines(code)
        
        # Parse all websFormDefine calls
        self._parse_form_defines(code)
        
        # Parse all websAspDefine calls
        self._parse_asp_defines(code)
        
        self.log(f"Found {len(self.handlers)} handler registrations")
        self.log(f"Found {len(self.global_auth_handlers)} global auth handlers")
        
        return self.handlers
    
    def _parse_url_handler_defines(self, code: str):
        """
        Parse websUrlHandlerDefine calls
        
        Format: websUrlHandlerDefine(prefix, webDir, arg, handler, flags)
        Or:     sub_4CC6A4(prefix, webDir, arg, handler, flags)
        
        flags:
        - 0: Normal handler
        - 1: Priority handler (usually global authentication)
        - 2: Post handler
        """
        # Build matching pattern: support multiple function names
        func_names = self.GOAHEAD_PATTERNS.get("websUrlHandlerDefine", [])
        pattern = r'(' + '|'.join(re.escape(f) for f in func_names) + r')\s*\(\s*([^;]+)\s*\)\s*;'
        
        matches = re.finditer(pattern, code)
        
        for match in matches:
            func_name = match.group(1)
            args_str = match.group(2)
            
            # Parse arguments
            args = self._parse_function_args(args_str)
            
            if len(args) >= 5:
                prefix = args[0].strip('"').strip("&")
                handler = args[3].strip()
                flag_str = args[4].strip()
                
                try:
                    flag = int(flag_str)
                except ValueError:
                    flag = 0
                
                # If prefix is a variable name (like unk_XXXX), try to resolve it
                if prefix.startswith("unk_") or prefix.startswith("off_"):
                    prefix = self._resolve_string_variable(prefix)
                
                # Empty prefix means handle all requests
                is_global = (prefix == "" or prefix == "/")
                display_prefix = prefix if prefix else "(all requests)"
                
                handler_info = GoAheadHandlerInfo(
                    url_prefix=prefix if prefix else "",  # Keep empty string to indicate global
                    handler_func=handler,
                    priority=flag,
                    is_global_auth=(flag == 1),
                    registration_site=match.group(0)
                )
                
                self.handlers.append(handler_info)
                
                if flag == 1:
                    self.global_auth_handlers.append(handler_info)
                    self.log(f"  [AUTH] {handler} registered with flag=1 for prefix '{display_prefix}' (GLOBAL AUTH)")
                else:
                    self.log(f"  [ROUTE] {handler} registered for prefix '{display_prefix}' (flag={flag})")
    
    def _parse_form_defines(self, code: str):
        """Parse websFormDefine calls"""
        func_names = self.GOAHEAD_PATTERNS.get("websFormDefine", [])
        pattern = r'(' + '|'.join(re.escape(f) for f in func_names) + r')\s*\(\s*"([^"]+)"\s*,\s*(\w+)\s*\)'
        
        matches = re.finditer(pattern, code)
        
        for match in matches:
            name = match.group(2)
            handler = match.group(3)
            
            handler_info = GoAheadHandlerInfo(
                url_prefix=f"/goform/{name}",
                handler_func=handler,
                priority=0,
                is_global_auth=False,
                registration_site=match.group(0),
                description="Form handler"
            )
            
            self.handlers.append(handler_info)
    
    def _parse_asp_defines(self, code: str):
        """Parse websAspDefine calls"""
        func_names = self.GOAHEAD_PATTERNS.get("websAspDefine", [])
        pattern = r'(' + '|'.join(re.escape(f) for f in func_names) + r')\s*\(\s*"([^"]+)"\s*,\s*(\w+)\s*\)'
        
        matches = re.finditer(pattern, code)
        
        for match in matches:
            name = match.group(2)
            handler = match.group(3)
            
            handler_info = GoAheadHandlerInfo(
                url_prefix=name,  # ASP is a tag name, not a path
                handler_func=handler,
                priority=0,
                is_global_auth=False,
                registration_site=match.group(0),
                description="ASP tag handler"
            )
            
            self.handlers.append(handler_info)
    
    def _parse_function_args(self, args_str: str) -> List[str]:
        """Parse function argument string"""
        args = []
        depth = 0
        current_arg = ""
        
        for char in args_str:
            if char == '(':
                depth += 1
                current_arg += char
            elif char == ')':
                depth -= 1
                current_arg += char
            elif char == ',' and depth == 0:
                args.append(current_arg.strip())
                current_arg = ""
            else:
                current_arg += char
        
        if current_arg.strip():
            args.append(current_arg.strip())
        
        return args
    
    def _resolve_string_variable(self, var_name: str) -> str:
        """
        Resolve string variable value
        
        Note: If the first byte is 0 (empty string), return empty string ""
        This is important for GoAhead's websUrlHandlerDefine:
        - Empty string prefix means the handler handles all requests
        - flag=1 + empty prefix = global auth handler
        """
        try:
            # Extract address
            addr_match = re.search(r'[0-9A-Fa-f]+', var_name)
            if not addr_match:
                return ""
            
            addr = "0x" + addr_match.group()
            
            # Read memory
            res = self.ida._send('read_bytes', {'address': addr, 'size': 64})
            if res.get("status") == "ok":
                hex_data = res.get("data", "")
                # Convert to string
                try:
                    bytes_data = bytes.fromhex(hex_data)
                    # If the first byte is 0, it means empty string (global handler)
                    if len(bytes_data) > 0 and bytes_data[0] == 0:
                        return ""  # Empty string, meaning handle all requests
                    # Otherwise find the end of the string
                    end = bytes_data.find(b'\x00')
                    if end == -1:
                        end = len(bytes_data)
                    return bytes_data[:end].decode('utf-8', errors='ignore')
                except:
                    pass
        except:
            pass
        
        return ""
    
    def trace_static_table_hierarchy(self, table_addr: str) -> Optional[StaticTableContext]:
        """
        Trace static table hierarchy relationships
        
        Approach:
        1. Find functions that reference this table (e.g., sub_409240)
        2. Check how that function is registered (e.g., websAspDefine("aspGetInfo", sub_409240))
        3. Establish static_table -> function -> ASP_tag relationship
        
        Args:
            table_addr: Static table address (e.g., "0x5182C0")
        
        Returns:
            StaticTableContext containing hierarchy information
        """
        self.log(f"Tracing hierarchy for static table: {table_addr}")
        
        # Step 1: Find functions that reference this table
        refs_res = self.ida.get_xrefs(table_addr, direction="to")
        if refs_res.get("status") != "ok":
            return None
        
        refs = refs_res.get("data", [])
        if not refs:
            self.log(f"  No references found for {table_addr}")
            return None
        
        # Collect all functions that reference this table
        using_funcs = set()
        for ref in refs:
            func_name = ref.get("func_name", "")
            if func_name and func_name != "None":
                using_funcs.add(func_name)
        
        self.log(f"  Table {table_addr} is used by: {using_funcs}")
        
        # Step 2: For each using function, check how it was registered
        for using_func in using_funcs:
            context = self._find_registration_for_function(using_func, table_addr)
            if context:
                self.static_table_contexts[table_addr] = context
                return context
        
        return None
    
    def _find_registration_for_function(self, func_name: str, table_addr: str) -> Optional[StaticTableContext]:
        """
        Find how a function is registered
        
        Check if the function is registered via:
        - websAspDefine("aspXxx", func)
        - websFormDefine("formXxx", func)
        - sub_4BD16C("aspGetInfo", func)  (actual websAspDefine)
        """
        self.log(f"  Looking for registration of {func_name}...")
        
        # Method 1: Search directly in initialization function code
        if self._init_func_code:
            context = self._search_registration_in_code(self._init_func_code, func_name, table_addr)
            if context:
                return context
        
        # Method 2: Get function address and find references
        func_addr = self._get_function_address(func_name)
        
        # If function name didn't return address, try to extract from function name
        if not func_addr and func_name.startswith("sub_"):
            func_addr = "0x" + func_name[4:]
        
        if func_addr:
            # Find references to this function (who passes it as an argument)
            refs_res = self.ida.get_xrefs(func_addr, direction="to")
            if refs_res.get("status") == "ok":
                refs = refs_res.get("data", [])
                
                for ref in refs:
                    caller_func = ref.get("func_name", "")
                    if not caller_func:
                        continue
                    
                    # Check the caller function's code
                    decompile_res = self.ida.decompile(caller_func)
                    if decompile_res.get("status") != "ok":
                        continue
                    
                    code = decompile_res.get("data", {}).get("code", "")
                    
                    context = self._search_registration_in_code(code, func_name, table_addr)
                    if context:
                        return context
        
        return None
    
    def _search_registration_in_code(self, code: str, func_name: str, table_addr: str) -> Optional[StaticTableContext]:
        """
        Search for function registration pattern in code
        """
        # Find registration pattern: websAspDefine("xxx", func_name) or sub_XXXX("xxx", func_name)
        # Support multiple formats
        patterns = [
            rf'(\w+)\s*\(\s*"([^"]+)"\s*,\s*{re.escape(func_name)}\s*\)',
            rf'(\w+)\s*\(\s*"([^"]+)"\s*,\s*&?{re.escape(func_name)}\s*\)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, code)
            if match:
                api_func = match.group(1)
                tag_name = match.group(2)
                
                # Determine if it's ASP or Form registration
                # sub_4BD16C is the actual implementation of websAspDefine
                # sub_4CBDAC is the websFormDefine implementation (or other forms)
                if "asp" in api_func.lower() or api_func in ["sub_4BD16C"]:
                    parent_path = tag_name  # ASP tag name as path identifier
                    reg_api = "websAspDefine"
                elif "form" in api_func.lower() or api_func in ["sub_4CBDAC"]:
                    parent_path = f"/goform/{tag_name}"
                    reg_api = "websFormDefine"
                else:
                    # Check if tag name starts with asp
                    if tag_name.lower().startswith("asp"):
                        parent_path = tag_name
                        reg_api = "websAspDefine"
                    else:
                        parent_path = f"/{tag_name}"
                        reg_api = api_func
                
                func_addr = self._get_function_address(func_name)
                if not func_addr and func_name.startswith("sub_"):
                    func_addr = "0x" + func_name[4:]
                
                context = StaticTableContext(
                    table_addr=table_addr,
                    using_func=func_name,
                    using_func_addr=func_addr or "",
                    parent_path=parent_path,
                    registration_api=reg_api,
                    registration_site=match.group(0)
                )
                
                self.log(f"    Found: {func_name} registered as '{tag_name}' via {reg_api}")
                self.log(f"    Parent path: {parent_path}")
                
                return context
        
        return None
    
    def _get_function_address(self, func_name: str) -> Optional[str]:
        """Get function address"""
        res = self.ida.decompile(func_name)
        if res.get("status") == "ok":
            return res.get("data", {}).get("address", "")
        return None
    
    def trace_all_static_tables(self, table_addrs: List[str]) -> Dict[str, StaticTableContext]:
        """
        Trace hierarchy relationships for all static tables
        
        Args:
            table_addrs: List of static table addresses
        
        Returns:
            {table_addr: StaticTableContext} mapping
        """
        self.log(f"Tracing hierarchy for {len(table_addrs)} static tables...")
        
        for addr in table_addrs:
            self.trace_static_table_hierarchy(addr)
        
        self.log(f"Resolved hierarchy for {len(self.static_table_contexts)} tables")
        
        return self.static_table_contexts
    
    def get_global_auth_function(self) -> Optional[GoAheadHandlerInfo]:
        """Get global authentication function"""
        if self.global_auth_handlers:
            return self.global_auth_handlers[0]
        return None
    
    def get_parent_path_for_table(self, table_addr: str) -> str:
        """Get parent path for static table"""
        ctx = self.static_table_contexts.get(table_addr)
        if ctx:
            return ctx.parent_path
        return "/"


def test_goahead_analyzer():
    """Test GoAhead analyzer"""
    analyzer = GoAheadAnalyzer()
    
    if not analyzer.connect():
        print("Failed to connect to IDA")
        return
    
    # Discover API addresses
    analyzer.discover_api_addresses()
    
    # Analyze initialization function
    handlers = analyzer.analyze_init_function("sub_406408")
    
    print("\n=== Global Auth Handlers ===")
    for h in analyzer.global_auth_handlers:
        print(f"  {h.handler_func} -> {h.url_prefix} (flag={h.priority})")
    
    print("\n=== All Handlers ===")
    for h in handlers[:10]:
        print(f"  {h.handler_func} -> {h.url_prefix}")
    
    # Trace static table hierarchy
    print("\n=== Static Table Hierarchy ===")
    ctx = analyzer.trace_static_table_hierarchy("0x5182C0")
    if ctx:
        print(f"  Table 0x5182C0 -> used by {ctx.using_func} -> parent path: {ctx.parent_path}")


if __name__ == "__main__":
    test_goahead_analyzer()
