# Copyright (c) 2026 The Pangu Project Authors. All rights reserved.
# analysis/fastcgi_extractor.py
# PANGU FastCGI Architecture Adapter
# Specialized for Lighttpd + FastCGI + strncmp dispatch pattern route extraction
# Target Devices: H3C NX15 and other devices using similar architectures

"""
FastCGI Architecture Characteristics:
1. Uses FCGI_Accept() as the request loop entry point
2. Retrieves request path via getenv("PATH_INFO")
3. Uses strncmp() for route dispatch
4. Authentication typically centralized in a single function (e.g., FCGI_UserAuth)

Route Extraction Strategy:
1. Locate the FCGI_Accept main loop
2. Search for all strncmp calls within the loop body
3. Extract the second argument as the route path
4. Analyze authentication function call positions to determine Auth-Free/Auth-Required
"""

import sys
import os
import json
import re
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

sys.path.append(os.getcwd())

from core.bridge.ida_client import IDAProClient
from core.llm import LLMProvider
from analysis.models import RouteNode, AuthState, ProtectionType


class FastCGIArchitecture(Enum):
    """FastCGI Architecture Subtypes"""
    STANDARD = "standard"           # Standard FCGI (strncmp dispatch)
    LUA_BRIDGE = "lua_bridge"       # FCGI + Lua bridge (e.g., H3C)
    UBUS_BACKEND = "ubus_backend"   # FCGI + UBUS backend


@dataclass
class FCGIRouteInfo:
    """FastCGI Route Information"""
    path: str                           # Route path (e.g., /login, /esps)
    handler: str                        # Handler function name or address
    handler_addr: str                   # Handler function address
    compare_length: int                 # strncmp comparison length
    is_before_auth: bool = False        # Whether before authentication check (Auth-Free)
    is_after_auth: bool = False         # Whether after authentication check (Auth-Required)
    source_location: str = ""           # strncmp call location
    
    def to_route_node(self) -> RouteNode:
        """Convert to standard RouteNode"""
        if self.is_before_auth:
            auth_state = AuthState.AUTH_FREE
            protection = ProtectionType.NONE
            detail = "Route dispatched before authentication check"
        elif self.is_after_auth:
            auth_state = AuthState.AUTH_REQUIRED
            protection = ProtectionType.GATEKEEPER
            detail = "Route protected by FCGI authentication gatekeeper"
        else:
            auth_state = AuthState.UNKNOWN
            protection = ProtectionType.NONE
            detail = None
        
        return RouteNode(
            path=self.path,
            sub_path=self.path.lstrip('/'),
            handler=self.handler,
            source_hub=self.source_location,
            source_type="fastcgi_strncmp",
            root="/",
            auth_state=auth_state,
            protection_type=protection,
            protection_detail=detail
        )


class FastCGIExtractor:
    """
    FastCGI Route Extractor
    
    Specialized for FastCGI applications that use strncmp for dispatch
    """
    
    # FastCGI characteristic functions
    FCGI_MARKERS = {
        "accept_functions": [
            "FCGI_Accept", "FCGX_Accept", "FCGI_Accept_r", 
            "accept", "FCGX_Accept_r"
        ],
        "auth_functions": [
            "FCGI_UserAuth", "fcgi_auth", "check_auth", 
            "verify_session", "session_check", "auth_check",
            "checkAuth", "CheckAuth", "UserAuth"
        ],
        "env_functions": [
            "getenv", "FCGX_GetParam", "get_env"
        ],
        "compare_functions": [
            "strncmp", "strcmp", "strncasecmp", "strcasecmp"
        ]
    }
    
    # Common Auth-Free routes (usually login-related)
    COMMON_AUTH_FREE_PATTERNS = [
        r"/login", r"/logout", r"/wizard", r"/setup",
        r"/public", r"/static", r"/css", r"/js", r"/images",
        r"/captcha", r"/init", r"/reset"
    ]
    
    def __init__(self, ida_client: IDAProClient, llm: Optional[LLMProvider] = None):
        self.ida = ida_client
        self.llm = llm
        
        # Extraction results
        self.routes: List[FCGIRouteInfo] = []
        self.main_loop_func: Optional[str] = None
        self.auth_function: Optional[str] = None
        self.auth_function_addr: Optional[str] = None
        
        # Architecture information
        self.architecture: FastCGIArchitecture = FastCGIArchitecture.STANDARD
        
        # Configuration
        self.output_dir = "output"
        self.verbose = True
    
    def log(self, msg: str):
        """Log output"""
        if self.verbose:
            print(msg)
    
    @staticmethod
    def _extract_data(result: Dict, key: str, default=None):
        """
        Extract data from IDA return result, compatible with multiple formats:
        1. {"status": "ok", "data": {"key": value}}
        2. {"status": "ok", "data": value}
        3. {"status": "ok", "data": {"code": "..."}} (decompile)
        """
        if result.get("status") != "ok":
            return default if default is not None else []
        
        data = result.get("data")
        if data is None:
            return default if default is not None else []
        
        # If data is a dict, try to get key
        if isinstance(data, dict):
            value = data.get(key)
            if value is not None:
                return value
            # Special handling: if key is "code" but doesn't exist, try "decompiled" or other variants
            if key == "code":
                for alt_key in ["decompiled", "source", "pseudocode"]:
                    if alt_key in data:
                        return data[alt_key]
            return default if default is not None else []
        
        # If data is a string and code is requested, return directly
        if isinstance(data, str) and key == "code":
            return data
        
        # If data is not a dict, return directly (assume it's the data we want)
        return data if data else (default if default is not None else [])
    
    def detect_architecture(self) -> bool:
        """
        Detect whether this is a FastCGI architecture
        
        Returns:
            True if FastCGI architecture is detected
        """
        self.log("\n[FastCGI] Detecting architecture...")
        
        # 1. Search for FCGI_Accept or similar functions
        for func_name in self.FCGI_MARKERS["accept_functions"]:
            result = self.ida.get_functions(search=func_name, limit=10)
            functions = self._extract_data(result, "functions", [])
            if functions:
                self.log(f"  [+] Found FastCGI marker: {func_name}")
                return True
        
        # 2. Search for characteristic strings
        fcgi_strings = ["FCGI_Accept", "PATH_INFO", "HTTP_AUTHENTICATION", "FCGI_printf"]
        for s in fcgi_strings:
            result = self.ida.search_strings(s)
            strings = self._extract_data(result, "strings", [])
            if strings:
                self.log(f"  [+] Found FastCGI string: {s}")
                return True
        
        self.log("  [-] No FastCGI markers found")
        return False
    
    def find_main_loop(self) -> Optional[str]:
        """
        Locate the FastCGI main loop function
        
        Usually the function that calls FCGI_Accept, such as main or ftext
        """
        self.log("\n[FastCGI] Finding main loop function...")
        
        # Method 1: Find callers of FCGI_Accept
        for func_name in self.FCGI_MARKERS["accept_functions"]:
            result = self.ida.get_functions(search=func_name, limit=5)
            if result.get("status") != "ok":
                continue
            
            functions = self._extract_data(result, "functions", [])
            for func in functions:
                addr = func.get("address", "")
                # Get callers
                xrefs = self.ida.get_xrefs(addr, direction="to")
                callers = self._extract_data(xrefs, "xrefs", [])
                if callers:
                    for caller in callers:
                        caller_addr = caller.get("from", "")
                        caller_name = caller.get("from_name", "")
                        if caller_name and caller_name not in ["", "None"]:
                            self.log(f"  [+] Found main loop candidate: {caller_name} @ {caller_addr}")
                            self.main_loop_func = caller_name
                            return caller_addr
        
        # Method 2: Common entry function names - prefer exact match
        common_names = ["ftext", "main", "fastcgi_main", "fcgi_main", "handle_request"]
        for name in common_names:
            result = self.ida.get_functions(search=name, limit=10)
            functions = self._extract_data(result, "functions", [])
            # If functions returned is the list itself
            if not functions and isinstance(result.get("data"), list):
                functions = result.get("data", [])
            
            # Debug output
            if functions:
                self.log(f"  [DEBUG] Found {len(functions)} functions for '{name}'")
                for func in functions[:3]:  # Only print first 3
                    self.log(f"  [DEBUG]   Function data: {func}")
            
            if functions:
                for func in functions:
                    # Handle different key name formats
                    func_name = func.get("name", func.get("func_name", ""))
                    func_addr = func.get("address", func.get("ea", func.get("start", func.get("addr", ""))))
                    
                    # If func itself is string format "name @ address"
                    if isinstance(func, str) and "@" in func:
                        parts = func.split("@")
                        func_name = parts[0].strip()
                        func_addr = parts[1].strip() if len(parts) > 1 else ""
                    
                    # Exact match takes priority (exclude __uClibc_main etc.)
                    if func_name == name or func_name == f"_{name}":
                        self.log(f"  [+] Found main loop by exact name: {func_name} @ {func_addr}")
                        self.main_loop_func = func_name
                        if func_addr:
                            return func_addr
                        # If no address, try to decompile by name
                        self.log(f"  [*] No address found, will use name: {func_name}")
                        return func_name
                    # Partial match but exclude uClibc and other library functions
                    elif name.lower() in func_name.lower() and "uClibc" not in func_name and "__" not in func_name:
                        self.log(f"  [+] Found main loop by name: {func_name} @ {func_addr}")
                        self.main_loop_func = func_name
                        if func_addr:
                            return func_addr
                        return func_name
        
        self.log("  [-] Could not find main loop function")
        return None
    
    def _find_main_loop_fallback(self) -> Optional[str]:
        """
        Fallback method: search for functions containing strncmp + route strings
        """
        self.log("\n[FastCGI] Trying fallback: searching for functions with route patterns...")
        
        # Search for functions containing typical route strings
        route_markers = ["/login", "/esps", "/wizard", "/upload", "/api"]
        
        for marker in route_markers:
            result = self.ida.search_strings(marker)
            strings = self._extract_data(result, "strings", [])
            if not strings and isinstance(result.get("data"), list):
                strings = result.get("data", [])
            
            for s in strings:
                # Get string references
                addr = s.get("address", s.get("ea", ""))
                if addr:
                    xrefs = self.ida.get_xrefs(addr, direction="to")
                    refs = self._extract_data(xrefs, "xrefs", [])
                    if not refs and isinstance(xrefs.get("data"), list):
                        refs = xrefs.get("data", [])
                    
                    for ref in refs:
                        func_addr = ref.get("from", ref.get("func", ""))
                        func_name = ref.get("from_name", ref.get("func_name", ""))
                        if func_addr:
                            self.log(f"  [+] Found function referencing '{marker}': {func_name} @ {func_addr}")
                            self.main_loop_func = func_name if func_name else f"sub_{func_addr}"
                            return func_addr
        
        return None
    
    def find_auth_function(self, main_loop_addr: str) -> Optional[Tuple[str, str]]:
        """
        Locate authentication function
        
        Args:
            main_loop_addr: Main loop function address
        
        Returns:
            (function_name, function_address) or None
        """
        self.log("\n[FastCGI] Finding authentication function...")
        
        # Method 1: Search for auth function in main loop's callees
        result = self.ida.get_callees(main_loop_addr)
        callees = self._extract_data(result, "callees", [])
        
        if callees:
            for callee in callees:
                # Handle different return formats
                if isinstance(callee, str):
                    # Format might be "func_name" or "func_name @ 0xaddr"
                    if "@" in callee:
                        parts = callee.split("@")
                        callee_name = parts[0].strip()
                        callee_addr = parts[1].strip() if len(parts) > 1 else ""
                    else:
                        callee_name = callee
                        callee_addr = ""
                elif isinstance(callee, dict):
                    callee_name = callee.get("name", callee.get("func_name", ""))
                    callee_addr = callee.get("address", callee.get("addr", ""))
                else:
                    continue
                
                for auth_pattern in self.FCGI_MARKERS["auth_functions"]:
                    if auth_pattern.lower() in callee_name.lower():
                        self.log(f"  [+] Found auth function: {callee_name} @ {callee_addr}")
                        self.auth_function = callee_name
                        self.auth_function_addr = callee_addr
                        return (callee_name, callee_addr)
        
        # Method 2: Global search for auth function
        for auth_name in self.FCGI_MARKERS["auth_functions"]:
            result = self.ida.get_functions(search=auth_name, limit=10)
            functions = self._extract_data(result, "functions", [])
            if not functions and isinstance(result.get("data"), list):
                functions = result.get("data", [])
                
            if functions:
                for func in functions:
                    if isinstance(func, dict):
                        func_name = func.get("name", func.get("func_name", ""))
                        func_addr = func.get("address", func.get("addr", ""))
                    elif isinstance(func, str):
                        if "@" in func:
                            parts = func.split("@")
                            func_name = parts[0].strip()
                            func_addr = parts[1].strip() if len(parts) > 1 else ""
                        else:
                            func_name = func
                            func_addr = ""
                    else:
                        continue
                    
                    self.log(f"  [+] Found auth function by search: {func_name}")
                    self.auth_function = func_name
                    self.auth_function_addr = func_addr
                    return (func_name, func_addr)
        
        self.log("  [-] Could not find authentication function")
        return None
    
    def extract_strncmp_routes(self, func_addr: str) -> List[Dict]:
        """
        Extract route info from strncmp calls in a function
        
        Analyze strncmp calls via decompiled code
        """
        self.log(f"\n[FastCGI] Extracting strncmp routes from {func_addr}...")
        
        # Decompile function
        result = self.ida.decompile(func_addr)
        if result.get("status") != "ok":
            self.log(f"  [-] Failed to decompile: {result.get('error')}")
            return []
        
        code = self._extract_data(result, "code", "")
        
        # Debug output
        if not code:
            self.log(f"  [-] No code returned, raw data type: {type(result.get('data'))}")
            # Try to use data directly
            if isinstance(result.get("data"), str):
                code = result.get("data")
            elif isinstance(result.get("data"), dict):
                # Print all keys for debugging
                self.log(f"  [DEBUG] Data keys: {result.get('data', {}).keys()}")
        
        if not code:
            self.log("  [-] Could not extract decompiled code")
            return []
        
        self.log(f"  [*] Decompiled code length: {len(code)} chars")
        
        routes = []
        
        # Parse strncmp calls - multiple patterns
        # Pattern 1: strncmp(var, "string", length)
        # Pattern 2: !strncmp(var, "string", length)
        # Pattern 3: strncmp(var, "/path", 5) (IDA sometimes uses numbers)
        strncmp_patterns = [
            r'strncmp\s*\(\s*\w+\s*,\s*["\']([^"\']+)["\']\s*,\s*(\d+)\s*\)',
            r'strncmp\s*\(\s*\w+\s*,\s*["\']([^"\']+)["\']\s*,\s*(\d+)\w*\s*\)',
            r'strncmp\s*\([^,]+,\s*["\']([^"\']+)["\']\s*,\s*(\d+)',
        ]
        
        for pattern in strncmp_patterns:
            for match in re.finditer(pattern, code):
                route_str = match.group(1)
                length = int(match.group(2))
                
                # Filter non-route strings
                if not route_str.startswith('/'):
                    continue
                
                # Avoid duplicates
                if any(r["path"] == route_str for r in routes):
                    continue
                
                routes.append({
                    "path": route_str,
                    "length": length,
                    "position": match.start()
                })
                self.log(f"    [+] Found route: {route_str} (len={length})")
        
        # Also check strcmp (exact match)
        strcmp_pattern = r'strcmp\s*\(\s*\w+\s*,\s*["\']([^"\']+)["\']\s*\)'
        for match in re.finditer(strcmp_pattern, code):
            route_str = match.group(1)
            if route_str.startswith('/') and not any(r["path"] == route_str for r in routes):
                routes.append({
                    "path": route_str,
                    "length": len(route_str),
                    "position": match.start()
                })
                self.log(f"    [+] Found route (strcmp): {route_str}")
        
        return routes
    
    def analyze_auth_boundary(self, func_addr: str, routes: List[Dict]) -> List[FCGIRouteInfo]:
        """
        Analyze authentication boundary, determine if each route is Auth-Free or Auth-Required
        
        Core logic:
        - Routes dispatched before auth function call = Auth-Free
        - Routes dispatched after auth function call = Auth-Required
        """
        self.log("\n[FastCGI] Analyzing authentication boundary...")
        
        if not self.auth_function:
            self.log("  [-] No auth function found, all routes marked as Unknown")
            return [
                FCGIRouteInfo(
                    path=r["path"],
                    handler=f"handler_{r['path'].replace('/', '_')}",
                    handler_addr="",
                    compare_length=r["length"],
                    source_location=func_addr
                )
                for r in routes
            ]
        
        # Decompile to get code
        result = self.ida.decompile(func_addr)
        if result.get("status") != "ok":
            return []
        
        code = self._extract_data(result, "code", "")
        
        # Find auth function call position
        auth_patterns = [
            rf'{self.auth_function}\s*\(',
            rf'{self.auth_function_addr}\s*\('
        ]
        
        auth_position = -1
        for pattern in auth_patterns:
            match = re.search(pattern, code)
            if match:
                auth_position = match.start()
                self.log(f"  [+] Auth function call at position {auth_position}")
                break
        
        if auth_position == -1:
            self.log("  [-] Could not locate auth function call in code")
            auth_position = len(code)  # Assume auth at end
        
        # Classify routes
        route_infos = []
        for r in routes:
            is_before = r["position"] < auth_position
            
            # Try to find corresponding handler function
            handler_name = self._find_handler_for_route(code, r["path"], r["position"])
            
            info = FCGIRouteInfo(
                path=r["path"],
                handler=handler_name,
                handler_addr="",
                compare_length=r["length"],
                is_before_auth=is_before,
                is_after_auth=not is_before,
                source_location=func_addr
            )
            route_infos.append(info)
            
            auth_status = "Auth-Free" if is_before else "Auth-Required"
            self.log(f"    [{auth_status}] {r['path']} -> {handler_name}")
        
        return route_infos
    
    def _find_handler_for_route(self, code: str, route_path: str, route_position: int) -> str:
        """
        Find the handler function for a route in the code
        
        Search for function calls after strncmp
        """
        # Search for function calls in a small window after route_position
        # Expand search range to 800 chars to ensure nested handler calls are found
        search_window = code[route_position:route_position + 800]
        
        # Extract route name for matching
        route_name = route_path.strip('/').split('/')[0]  # e.g., /esps -> esps
        
        # Try to find handler related to route name
        # Pattern 1: Function call containing route name (e.g., FCGI_EspsProcess)
        specific_patterns = [
            rf'(\w*{route_name}\w*Process)\s*\(',
            rf'(\w*{route_name}\w*Handler)\s*\(',
            rf'(handle_{route_name}\w*)\s*\(',
            rf'({route_name}_\w+)\s*\(',
        ]
        
        for pattern in specific_patterns:
            match = re.search(pattern, search_window, re.IGNORECASE)
            if match:
                return match.group(1)
        
        # Pattern 2: Generic pattern - first occurring Process/Handler function
        handler_patterns = [
            r'(FCGI_\w+Process)\s*\(',
            r'(FCIG_\w+Process)\s*\(',  # Note: IDA sometimes has spelling variations
            r'(\w+Process)\s*\(',
            r'(\w+_handler)\s*\(',
            r'(handle_\w+)\s*\(',
            r'(\w+Handler)\s*\(',
            r'(do_\w+)\s*\(',
        ]
        
        for pattern in handler_patterns:
            match = re.search(pattern, search_window)
            if match:
                handler = match.group(1)
                # Avoid duplicate matching to the same handler (if already found)
                return handler
        
        # Fallback: Generate from route name
        clean_name = route_path.replace('/', '_').strip('_')
        return f"FCGI_{clean_name.title()}Process"
    
    def extract_routes_with_llm(self, func_addr: str) -> List[FCGIRouteInfo]:
        """
        Use LLM to assist route extraction (for complex cases)
        """
        if not self.llm:
            self.log("  [-] LLM not available, using pattern-based extraction")
            return []
        
        self.log("\n[FastCGI] Using LLM for route extraction...")
        
        # Decompile function
        result = self.ida.decompile(func_addr)
        if result.get("status") != "ok":
            return []
        
        code = self._extract_data(result, "code", "")
        if not code:
            return []
        
        # If code is too long, truncate key parts
        if len(code) > 8000:
            code = code[:8000] + "\n... (truncated)"
        
        prompt = f"""Analyze this FastCGI main loop function and extract HTTP route information.

DECOMPILED CODE:
```c
{code}
```

TASK:
1. Find all HTTP routes dispatched via strncmp/strcmp
2. Identify the authentication check function (usually named *Auth*, *auth*, *session*)
3. Determine which routes are checked BEFORE authentication (Auth-Free) and which are AFTER (Auth-Required)

OUTPUT FORMAT (JSON):
{{
    "auth_function": "function_name_or_null",
    "routes": [
        {{
            "path": "/route_path",
            "handler": "handler_function_name",
            "auth_state": "Auth-Free" or "Auth-Required",
            "reason": "brief explanation"
        }}
    ]
}}

Important:
- Routes like /login, /wizard are typically Auth-Free (before auth check)
- Routes like /esps, /config, /upload are typically Auth-Required (after auth check)
- Look for the if(auth_function()) pattern to find the authentication boundary
"""
        
        try:
            response = self.llm.chat([{"role": "user", "content": prompt}], json_mode=True)
            
            if isinstance(response, str):
                response = json.loads(response)
            
            route_infos = []
            
            # Update auth function info
            if response.get("auth_function") and not self.auth_function:
                self.auth_function = response["auth_function"]
            
            for r in response.get("routes", []):
                is_auth_free = r.get("auth_state") == "Auth-Free"
                info = FCGIRouteInfo(
                    path=r.get("path", ""),
                    handler=r.get("handler", ""),
                    handler_addr="",
                    compare_length=len(r.get("path", "")),
                    is_before_auth=is_auth_free,
                    is_after_auth=not is_auth_free,
                    source_location=func_addr
                )
                route_infos.append(info)
            
            return route_infos
            
        except Exception as e:
            self.log(f"  [-] LLM extraction failed: {e}")
            return []
    
    def run(self, use_llm: bool = True) -> List[RouteNode]:
        """
        Run FastCGI route extraction
        
        Args:
            use_llm: Whether to use LLM-assisted analysis
        
        Returns:
            List of extracted route nodes
        """
        self.log("\n" + "=" * 60)
        self.log("[FastCGI Extractor] Starting route extraction")
        self.log("=" * 60)
        
        # 1. Detect architecture
        if not self.detect_architecture():
            self.log("[!] Not a FastCGI architecture, aborting")
            return []
        
        # 2. Find main loop
        main_loop_addr = self.find_main_loop()
        if not main_loop_addr:
            self.log("[!] Could not find main loop, trying alternative methods...")
            # Try direct search for ftext function
            main_loop_addr = self._find_main_loop_fallback()
            if not main_loop_addr:
                self.log("[!] All methods failed, aborting")
                return []
        
        self.log(f"  [+] Main loop address: {main_loop_addr}")
        
        # 3. Find authentication function
        self.find_auth_function(main_loop_addr)
        
        # 4. Extract routes - try pattern matching first, then enhance with LLM
        self.log("\n[FastCGI] Extracting routes...")
        raw_routes = self.extract_strncmp_routes(main_loop_addr)
        self.log(f"  [*] Pattern matching found {len(raw_routes)} routes")
        
        if not raw_routes and use_llm and self.llm:
            # Pattern matching failed, try LLM
            self.log("  [*] Trying LLM extraction...")
            route_infos = self.extract_routes_with_llm(main_loop_addr)
        elif raw_routes:
            # Pattern matching succeeded, analyze auth boundary
            route_infos = self.analyze_auth_boundary(main_loop_addr, raw_routes)
        else:
            route_infos = []
        
        self.routes = route_infos
        
        # 5. Convert to standard RouteNode
        route_nodes = [r.to_route_node() for r in route_infos]
        
        self.log(f"\n[FastCGI] Extraction complete: {len(route_nodes)} routes found")
        for node in route_nodes:
            self.log(f"  - {node.path} [{node.auth_state.value}] -> {node.handler}")
        
        return route_nodes
    
    def save_routes(self, firmware_name: str) -> str:
        """Save routes to JSON file"""
        os.makedirs(self.output_dir, exist_ok=True)
        
        output_path = os.path.join(self.output_dir, f"{firmware_name}_routes.json")
        
        routes_data = [r.to_route_node().to_dict() for r in self.routes]
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(routes_data, f, indent=2, ensure_ascii=False)
        
        self.log(f"\n[FastCGI] Routes saved to: {output_path}")
        return output_path


# ============== Architecture Detector ==============

class ArchitectureDetector:
    """
    Firmware Architecture Detector
    
    Automatically identify the web server architecture used by firmware to select appropriate route extractor
    """
    
    # Architecture signature definitions
    # Each architecture requires:
    #   - functions: List of characteristic functions
    #   - strings: List of characteristic strings
    #   - priority: Priority (lower number = higher priority)
    #   - min_confidence: Minimum confidence threshold, below which architecture is not recognized
    ARCHITECTURE_SIGNATURES = {
        "GoAhead": {
            "functions": ["websUrlHandlerDefine", "websFormDefine", "goahead", "websGetVar"],
            "strings": ["GoAhead", "goform", "websUrlHandlerDefine"],
            "priority": 1,
            "min_confidence": 0.3
        },
        "FastCGI": {
            "functions": ["FCGI_Accept", "FCGX_Accept", "FCGI_printf", "FCGI_fopen"],
            "strings": ["FCGI_Accept", "PATH_INFO", "HTTP_AUTHENTICATION", "fastcgi"],
            "priority": 2,
            "min_confidence": 0.3
        },
        # Distributed CGI architecture - multiple independent CGI programs, each with its own auth logic
        # Features: Independent executables with .cgi suffix, dispatch via POST/GET parameters
        "DistributedCGI": {
            "functions": ["web_get", "check_valid_user", "check_csrf_referer", "nvram_bufget", 
                          "initCgi", "freeCgi", "gcgiSetLimits", "gcgiOut", "gcgiFetchCookies"],
            "strings": ["REQUEST_METHOD", "QUERY_STRING", "CONTENT_LENGTH", "check_valid_user", 
                       "page", "initCgi", "authtok", "checking session"],
            "priority": 2,  # High priority
            "min_confidence": 0.3
        },
        "JSONRPC": {
            # JSONRPC characteristic functions - must have JSON-RPC protocol-specific processing logic
            # Note: json-c library functions (json_tokener_parse etc.) are too generic to serve as sole criteria for JSONRPC
            "functions": ["jsonrpc_dispatch", "jsonrpc_handler", "rpc_method_call"],
            # JSON-RPC protocol-specific strings
            "strings": ["jsonrpc", "2.0", "/tmp/jsonrpcLogLevel", "JSON-RPC"],
            "priority": 5,  # Lower priority, let more specific architectures match first
            "min_confidence": 0.4  # Higher minimum confidence requirement
        },
        # SSI/CGI architecture (uHTTPd + SSI combination, common in Trendnet, D-Link etc.)
        # Features: Uses CGI environment variables, dispatches actions via static table
        "SSI_CGI": {
            "functions": ["ssi_func", "ssc_action_register", "ssi_get_method_register", "register_mime_handler", "do_apply_cgi"],
            "strings": ["ssi_cgi", "REQUEST_METHOD", "PATH_TRANSLATED", "SCRIPT_FILENAME", "ssc_action"],
            "priority": 2,  # High priority
            "min_confidence": 0.3
        },
        # TP-Link proprietary architecture (SSI + Rpm.htm style)
        # Features: Static .htm files + Server Side Includes, routes like xxxRpm.htm
        "TPLink": {
            "functions": ["httpRpmInit", "httpRpmConfGet", "httpGetEnv", "httpPrintf"],
            "strings": ["Rpm.htm", "/userRpm/", "httpd", "TP-LINK"],
            "priority": 2,
            "min_confidence": 0.3
        },
        # GoForm: Lighttpd mod_form.so module (if-else strcmp dispatch)
        "GoForm": {
            "functions": ["mod_form_plugin_init", "buffer_init_string", "config_insert_values_global"],
            "strings": ["form.path", "/goform/", "mod_form"],
            "priority": 3,
            "min_confidence": 0.3
        },
        "Lighttpd": {
            "functions": ["mod_fastcgi", "lighttpd"],
            "strings": ["lighttpd", "mod_fastcgi", "server.modules"],
            "priority": 4,
            "min_confidence": 0.3
        },
        "MiniHTTPD": {
            "functions": ["mini_httpd", "httpd_main"],
            "strings": ["mini_httpd", "thttpd"],
            "priority": 5,
            "min_confidence": 0.3
        },
        "BOA": {
            "functions": ["boa_main", "process_requests"],
            "strings": ["Boa/", "boa.conf"],
            "priority": 6,
            "min_confidence": 0.3
        },
        "uHTTPd": {
            "functions": ["uhttpd_main", "uh_"],
            "strings": ["uhttpd", "uHTTPd"],
            "priority": 7,
            "min_confidence": 0.3
        },
        # Lighttpd server itself - does not contain application routes
        "LighttpdServer": {
            "functions": ["http_response_prepare", "connection_state_machine", "network_init"],
            "strings": ["lighttpd", "server.modules", "server.document-root"],
            "priority": 10,
            "min_confidence": 0.3,
            "is_webserver_only": True  # Mark as pure web server
        },
        # Apache httpd server - does not contain application routes, routes are in independent CGIs
        # Features: apr_* functions, ap_hook_* hooks, application logic in CGI/modules
        "ApacheServer": {
            "functions": ["apr_pool_create", "ap_hook_handler", "ap_run_handler", "apr_table_get", "ap_rputs"],
            "strings": ["Apache", "apr_hook", "ap_hack_", "mod_cgi", "mod_auth"],
            "priority": 1,  # Highest priority, Apache signatures are very distinctive
            "min_confidence": 0.4,
            "is_webserver_only": True  # Mark as pure web server
        }
    }
    
    # Pure web server list (does not contain application routes)
    WEBSERVER_ONLY_ARCHS = ["LighttpdServer", "ApacheServer"]
    
    def __init__(self, ida_client: IDAProClient):
        self.ida = ida_client
        self.detected_arch: Optional[str] = None
        self.confidence: float = 0.0
        self.is_webserver_only: bool = False  # Whether it's a pure web server
    
    def detect(self) -> Tuple[str, float]:
        """
        Detect firmware architecture
        
        Returns:
            (architecture_name, confidence)
        """
        print("\n[Architecture Detector] Scanning binary...")
        
        scores = {}
        matched_features = {}  # Record matched features for debugging
        
        for arch_name, signatures in self.ARCHITECTURE_SIGNATURES.items():
            score = 0
            max_score = len(signatures["functions"]) + len(signatures["strings"])
            features = []
            
            # Check functions
            for func_name in signatures["functions"]:
                result = self.ida.get_functions(search=func_name, limit=5)
                if result.get("status") == "ok":
                    # Handle two possible return formats
                    data = result.get("data", [])
                    if isinstance(data, dict):
                        functions = data.get("functions", [])
                    else:
                        functions = data  # data itself is the function list
                    
                    if functions:
                        score += 1
                        features.append(f"func:{func_name}")
                        print(f"  [+] {arch_name}: Found function '{func_name}'")
            
            # Check strings
            for string in signatures["strings"]:
                result = self.ida.search_strings(string)
                if result.get("status") == "ok":
                    # Handle two possible return formats
                    data = result.get("data", [])
                    if isinstance(data, dict):
                        strings = data.get("strings", [])
                    else:
                        strings = data  # data itself is the string list
                    
                    if strings:
                        score += 1
                        features.append(f"str:{string}")
                        print(f"  [+] {arch_name}: Found string '{string}'")
            
            if score > 0:
                confidence = score / max_score
                min_conf = signatures.get("min_confidence", 0.3)
                
                # Only consider it a match if minimum confidence is reached
                if confidence >= min_conf:
                    scores[arch_name] = confidence
                    matched_features[arch_name] = features
                else:
                    print(f"  [-] {arch_name}: confidence {confidence:.1%} < min {min_conf:.0%}, skipped")
        
        if not scores:
            print("  [-] No architecture detected with sufficient confidence")
            print("  [*] Falling back to standard RouteExtractor (GoAhead/Generic)")
            self.detected_arch = "Unknown"
            self.confidence = 0.0
            return ("Unknown", 0.0)
        
        # Select highest scoring architecture
        best_arch = max(scores, key=scores.get)
        best_confidence = scores[best_arch]
        
        self.detected_arch = best_arch
        self.confidence = best_confidence
        
        # Check if it's a pure web server
        if best_arch in self.WEBSERVER_ONLY_ARCHS:
            self.is_webserver_only = True
        
        print(f"\n[Architecture Detector] Result: {best_arch} (confidence: {best_confidence:.1%})")
        if best_arch in matched_features:
            print(f"  Matched features: {', '.join(matched_features[best_arch])}")
        
        return (best_arch, best_confidence)
    
    def is_pure_webserver(self) -> bool:
        """
        Check if it's a pure web server (does not contain application routes)
        
        Returns:
            True if it's a pure web server like lighttpd/nginx
        """
        return self.is_webserver_only


def create_extractor_for_architecture(
    arch: str, 
    ida_client: IDAProClient, 
    llm: Optional[LLMProvider] = None
):
    """
    Create appropriate route extractor based on architecture type
    
    Args:
        arch: Architecture name
        ida_client: IDA client
        llm: LLM provider
    
    Returns:
        Route extractor instance
    """
    from analysis.route_extractor import RouteExtractor
    
    if arch in ["FastCGI", "Lighttpd"]:
        return FastCGIExtractor(ida_client, llm)
    elif arch == "JSONRPC":
        from analysis.jsonrpc_extractor import JSONRPCExtractor
        return JSONRPCExtractor(ida_client, llm)
    elif arch == "GoForm":
        from analysis.goform_extractor import GoFormExtractor
        return GoFormExtractor(ida_client)
    elif arch == "DistributedCGI":
        from analysis.distributed_cgi_extractor import DistributedCGIExtractor
        return DistributedCGIExtractor(ida_client, llm)
    else:
        # Default to original RouteExtractor (GoAhead etc.)
        return RouteExtractor(ida_client, llm)

