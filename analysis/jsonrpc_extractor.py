# Copyright (c) 2026 The Pangu Project Authors. All rights reserved.
# analysis/jsonrpc_extractor.py
# PANGU JSON-RPC Architecture Adapter
# Specialized for Nginx + CGI + JSON-RPC dispatch pattern route extraction
# Target Devices: Cisco RV34x series and other devices using similar architectures

"""
JSON-RPC CGI Architecture Characteristics:
1. Entry point is an independent CGI program (e.g., jsonrpc.cgi)
2. Retrieves HTTP parameters via getenv("CONTENT_LENGTH"), getenv("CONTENT_TYPE"), etc.
3. Parses POST body JSON to extract "method" field
4. Uses strcmp(method, "xxx") for route dispatch
5. Authentication typically performed before dispatch (or certain methods like login are Auth-Free)

Route Extraction Strategy:
1. Locate main function or CGI entry point
2. Find JSON parsing point (json_tokener_parse or json_object_object_get_ex)
3. Analyze all strcmp calls to extract method names
4. Trace method -> handler mappings
5. Identify Auth-Free methods (e.g., login, logout)
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


class JSONRPCArchitecture(Enum):
    """JSON-RPC Architecture Subtypes"""
    STANDARD = "standard"           # Standard JSON-RPC (Cisco style)
    DISPATCH_TABLE = "dispatch_table"  # Uses function pointer table dispatch
    HYBRID = "hybrid"               # Hybrid mode


@dataclass
class JSONRPCMethodInfo:
    """JSON-RPC Method Information"""
    method: str                         # Method name (e.g., "login", "get_config")
    handler: str                        # Handler function name or address
    handler_addr: str                   # Handler function address
    is_auth_free: bool = False          # Whether authentication is required (e.g., login)
    requires_privilege: int = 0         # Required privilege level (0=none, 1=user, 2=admin)
    source_location: str = ""           # strcmp call location
    has_sensitive_operation: bool = False  # Whether involves sensitive operations
    
    def to_route_node(self) -> RouteNode:
        """Convert to standard RouteNode"""
        # Infer authentication state based on method characteristics
        if self.is_auth_free:
            auth_state = AuthState.AUTH_FREE
            protection = ProtectionType.NONE
            detail = f"Auth-Free JSON-RPC method: {self.method}"
        else:
            auth_state = AuthState.AUTH_REQUIRED
            protection = ProtectionType.GATEKEEPER
            detail = f"JSON-RPC method protected by session/token check"
        
        # JSON-RPC method path format
        path = f"/jsonrpc#{self.method}"
        
        return RouteNode(
            path=path,
            sub_path=self.method,
            handler=self.handler,
            source_hub=self.source_location,
            source_type="jsonrpc_method",
            root="/cgi-bin/jsonrpc",
            auth_state=auth_state,
            protection_type=protection,
            protection_detail=detail
        )


class JSONRPCExtractor:
    """
    JSON-RPC Route Extractor
    
    Specialized for JSON-RPC CGI applications using strcmp dispatch
    """
    
    # JSON-RPC characteristic functions
    JSONRPC_MARKERS = {
        "cgi_env_functions": [
            "getenv",  # getenv("CONTENT_LENGTH"), getenv("HTTP_COOKIE")
        ],
        "json_parse_functions": [
            "json_tokener_parse", "json_object_object_get_ex",
            "json_object_get_string", "cJSON_Parse", "yyjson_read"
        ],
        "auth_functions": [
            "check_session", "verify_session", "session_check",
            "auth_check", "validate_token", "jsess_get_sess_sock",
            "sub_1306C",  # Cisco RV34x privilege check function
        ],
        "compare_functions": [
            "strcmp", "strncmp", "strcasecmp"
        ]
    }
    
    # Common Auth-Free methods (typically authentication related)
    COMMON_AUTH_FREE_METHODS = [
        "login", "logout", "authenticate", "get_session", 
        "get_csrf_token", "get_login_page", "check_license",
        "get_system_info", "get_version", "ping"
    ]
    
    # Sensitive operation methods (require special attention even with authentication)
    SENSITIVE_METHODS = [
        "change_password", "add_users", "del_users", "modify_users",
        "upload_firmware", "backup_config", "restore_config",
        "exec_cmd", "run_command", "system", "execute",
        "set_admin", "reset_factory", "reboot"
    ]
    
    def __init__(self, ida_client: IDAProClient, llm: Optional[LLMProvider] = None):
        self.ida = ida_client
        self.llm = llm
        
        # Extraction results
        self.methods: List[JSONRPCMethodInfo] = []
        self.main_func: Optional[str] = None
        self.main_func_addr: Optional[str] = None
        self.dispatch_func: Optional[str] = None
        self.auth_check_func: Optional[str] = None
        
        # Architecture info
        self.architecture: JSONRPCArchitecture = JSONRPCArchitecture.STANDARD
        
        # Configuration
        self.output_dir = "output"
        self.verbose = True
    
    def log(self, msg: str):
        """Log output"""
        if self.verbose:
            print(msg)
    
    @staticmethod
    def _extract_data(result: Dict, key: str, default=None):
        """Extract data from IDA return result"""
        if result.get("status") != "ok":
            return default if default is not None else []
        
        data = result.get("data")
        if data is None:
            return default if default is not None else []
        
        if isinstance(data, dict):
            value = data.get(key)
            if value is not None:
                return value
            if key == "code":
                for alt_key in ["decompiled", "source", "pseudocode"]:
                    if alt_key in data:
                        return data[alt_key]
            return default if default is not None else []
        
        if isinstance(data, str) and key == "code":
            return data
        
        return data if data else (default if default is not None else [])
    
    def detect_architecture(self) -> bool:
        """
        Detect if this is a JSON-RPC CGI architecture
        
        Returns:
            True if JSON-RPC architecture detected
        """
        self.log("\n[JSONRPC] Detecting architecture...")
        
        score = 0
        
        # 1. Search JSON-RPC characteristic strings
        jsonrpc_strings = [
            "method", "params", "jsonrpc", "result", "error",
            "CONTENT_LENGTH", "CONTENT_TYPE", "HTTP_COOKIE",
            "/tmp/jsonrpcLogLevel"  # Cisco specific
        ]
        
        for s in jsonrpc_strings:
            result = self.ida.search_strings(s)
            strings = self._extract_data(result, "strings", [])
            if not strings and isinstance(result.get("data"), list):
                strings = result.get("data", [])
            if strings:
                score += 1
                self.log(f"  [+] Found JSONRPC string: {s}")
        
        # 2. Search JSON parse functions
        for func_name in self.JSONRPC_MARKERS["json_parse_functions"]:
            result = self.ida.get_functions(search=func_name, limit=5)
            functions = self._extract_data(result, "functions", [])
            if not functions and isinstance(result.get("data"), list):
                functions = result.get("data", [])
            if functions:
                score += 2
                self.log(f"  [+] Found JSON parse function: {func_name}")
        
        # 3. Search characteristic file paths
        cisco_paths = [
            "/tmp/websession/session",
            "/tmp/webcache",
            "/www/cgi-bin"
        ]
        for path in cisco_paths:
            result = self.ida.search_strings(path)
            strings = self._extract_data(result, "strings", [])
            if not strings and isinstance(result.get("data"), list):
                strings = result.get("data", [])
            if strings:
                score += 1
                self.log(f"  [+] Found path string: {path}")
        
        detected = score >= 3
        if detected:
            self.log(f"  [+] JSON-RPC CGI architecture detected (score: {score})")
        else:
            self.log(f"  [-] No JSON-RPC markers found (score: {score})")
        
        return detected
    
    def find_main_or_entry(self) -> Optional[str]:
        """
        Locate main function or CGI entry point
        
        CGI programs typically have a main function as entry point
        """
        self.log("\n[JSONRPC] Finding main/entry function...")
        
        # Method 1: Directly search for main function
        result = self.ida.get_functions(search="main", limit=10)
        functions = self._extract_data(result, "functions", [])
        if not functions and isinstance(result.get("data"), list):
            functions = result.get("data", [])
        
        for func in functions:
            if isinstance(func, dict):
                func_name = func.get("name", func.get("func_name", ""))
                func_addr = func.get("address", func.get("ea", func.get("addr", "")))
            elif isinstance(func, str) and "@" in func:
                parts = func.split("@")
                func_name = parts[0].strip()
                func_addr = parts[1].strip() if len(parts) > 1 else ""
            else:
                continue
            
            # Exact match for main (exclude __libc_start_main etc.)
            if func_name == "main" or func_name == "_main":
                self.log(f"  [+] Found main function: {func_name} @ {func_addr}")
                self.main_func = func_name
                self.main_func_addr = func_addr
                return func_addr
        
        # Method 2: Find entry via getenv("CONTENT_LENGTH") call
        result = self.ida.search_strings("CONTENT_LENGTH")
        strings = self._extract_data(result, "strings", [])
        if not strings and isinstance(result.get("data"), list):
            strings = result.get("data", [])
        
        for s in strings:
            addr = s.get("address", s.get("ea", "")) if isinstance(s, dict) else ""
            if addr:
                xrefs = self.ida.get_xrefs(addr, direction="to")
                refs = self._extract_data(xrefs, "xrefs", [])
                if not refs and isinstance(xrefs.get("data"), list):
                    refs = xrefs.get("data", [])
                
                for ref in refs:
                    func_addr = ref.get("from", ref.get("func", ""))
                    func_name = ref.get("from_name", ref.get("func_name", ""))
                    if func_addr:
                        self.log(f"  [+] Found entry via CONTENT_LENGTH: {func_name} @ {func_addr}")
                        self.main_func = func_name if func_name else f"sub_{func_addr}"
                        self.main_func_addr = func_addr
                        return func_addr
        
        self.log("  [-] Could not find main/entry function")
        return None
    
    def find_dispatch_function(self) -> Optional[str]:
        """
        Locate method dispatch function
        
        Typically a function containing multiple strcmp(method, "xxx") calls
        """
        self.log("\n[JSONRPC] Finding dispatch function...")
        
        candidates = []  # Collect candidate functions
        
        # Method 1: Recursively search from main function's callees
        if self.main_func_addr:
            visited = set()
            self._find_dispatch_recursive(self.main_func_addr, candidates, visited, depth=0, max_depth=3)
        
        # Method 2: Directly search for functions referencing 'login' string
        if not candidates:
            self.log("  [*] Trying fallback: searching for 'login' string references...")
            result = self.ida.search_strings("login")
            strings = self._extract_data(result, "strings", [])
            if not strings and isinstance(result.get("data"), list):
                strings = result.get("data", [])
            
            for s in strings:
                if isinstance(s, dict):
                    content = s.get("content", s.get("string", ""))
                    addr = s.get("address", s.get("ea", ""))
                else:
                    continue
                
                # Only exact "login"
                if content and content.lower() == "login" and addr:
                    xrefs = self.ida.get_xrefs(addr, direction="to")
                    refs = self._extract_data(xrefs, "xrefs", [])
                    if not refs and isinstance(xrefs.get("data"), list):
                        refs = xrefs.get("data", [])
                    
                    for ref in refs:
                        func_addr = ref.get("from", ref.get("func", ""))
                        if func_addr:
                            code = self._decompile_function(func_addr)
                            if code:
                                strcmp_count = code.count("strcmp")
                                if strcmp_count >= 2:
                                    candidates.append((func_addr, strcmp_count))
                                    self.log(f"  [+] Found via 'login': sub_{func_addr} ({strcmp_count} strcmp)")
        
        # Method 3: Search all functions with multiple strcmp calls
        if not candidates:
            self.log("  [*] Trying fallback: searching all functions with multiple strcmp calls...")
            result = self.ida.get_functions(search="sub_14", limit=20)  # Guess address range
            functions = self._extract_data(result, "functions", [])
            if not functions and isinstance(result.get("data"), list):
                functions = result.get("data", [])
            
            for func in functions:
                if isinstance(func, dict):
                    func_addr = func.get("address", func.get("ea", ""))
                elif isinstance(func, str) and "@" in func:
                    func_addr = func.split("@")[1].strip()
                else:
                    continue
                
                if func_addr:
                    code = self._decompile_function(func_addr)
                    if code:
                        strcmp_count = code.count("strcmp")
                    if strcmp_count >= 5:  # Require more strcmp
                        candidates.append((func_addr, strcmp_count))
                        self.log(f"  [+] Found candidate: sub_{func_addr} ({strcmp_count} strcmp)")
        
        # Select candidate with most strcmp
        if candidates:
            candidates.sort(key=lambda x: x[1], reverse=True)
            best_addr, best_count = candidates[0]
            self.log(f"  [+] Selected dispatch function: {best_addr} ({best_count} strcmp calls)")
            self.dispatch_func = best_addr
            return best_addr
        
        self.log("  [-] Could not find dispatch function")
        return None
    
    def _find_dispatch_recursive(self, func_addr: str, candidates: list, visited: set, depth: int, max_depth: int):
        """Recursively find dispatch function containing strcmp"""
        if depth > max_depth or func_addr in visited:
            return
        visited.add(func_addr)
        
        result = self.ida.get_callees(func_addr)
        callees = self._extract_data(result, "callees", [])
        if not callees and isinstance(result.get("data"), list):
            callees = result.get("data", [])
        
        for callee in callees:
            if isinstance(callee, dict):
                callee_name = callee.get("name", callee.get("func_name", ""))
                callee_addr = callee.get("address", callee.get("addr", ""))
            elif isinstance(callee, str):
                if "@" in callee:
                    parts = callee.split("@")
                    callee_name = parts[0].strip()
                    callee_addr = parts[1].strip() if len(parts) > 1 else ""
                else:
                    # Pure function name format, use function name as decompile parameter
                    callee_name = callee
                    callee_addr = callee  # IDA API supports function name
            else:
                continue
            
            # Exclude library functions
            if not callee_name or callee_name.startswith("_"):
                continue
            lib_funcs = ["getenv", "malloc", "free", "fread", "fopen", 
                         "strcmp", "strncmp", "strlen", "printf", "fclose",
                         "fgets", "atoi", "strtoul", "openlog", "getppid",
                         "automation_jsonrpc_post", "debug", "info", "warn", "error"]
            if callee_name.lower() in [f.lower() for f in lib_funcs]:
                continue
            if "json_" in callee_name.lower():
                continue
            if callee_name == "main":  # Exclude recursive to main
                continue
            
            # Check if this function contains multiple strcmp
            decompile_target = callee_addr if callee_addr else callee_name
            code = self._decompile_function(decompile_target)
            if code:
                strcmp_count = code.count("strcmp")
                if strcmp_count >= 3:
                    candidates.append((decompile_target, strcmp_count))
                    if self.verbose:
                        self.log(f"  [+] Found candidate at depth {depth}: {callee_name} ({strcmp_count} strcmp)")
                
                # Recursive search
                self._find_dispatch_recursive(decompile_target, candidates, visited, depth + 1, max_depth)
    
    def _decompile_function(self, addr: str) -> Optional[str]:
        """Decompile function"""
        result = self.ida.decompile(addr)
        if result.get("status") != "ok":
            return None
        
        code = self._extract_data(result, "code", "")
        if not code and isinstance(result.get("data"), str):
            code = result.get("data")
        
        return code
    
    def extract_methods_from_dispatch(self, dispatch_addr: str) -> List[JSONRPCMethodInfo]:
        """
        Extract all JSON-RPC methods from dispatch function
        
        Analyze strcmp(method, "xxx") pattern
        """
        self.log(f"\n[JSONRPC] Extracting methods from dispatch function @ {dispatch_addr}...")
        
        code = self._decompile_function(dispatch_addr)
        if not code:
            self.log("  [-] Failed to decompile dispatch function")
            return []
        
        methods = []
        
        # Pattern 1: strcmp(var, "method_name")
        # Example: if ( !strcmp(v2, "login") )
        strcmp_patterns = [
            r'strcmp\s*\(\s*\w+\s*,\s*["\']([^"\']+)["\']\s*\)',
            r'strcmp\s*\([^,]+,\s*["\']([^"\']+)["\']\s*\)',
            r'!strcmp\s*\(\s*\w+\s*,\s*["\']([^"\']+)["\']\s*\)',
        ]
        
        found_methods = set()
        
        for pattern in strcmp_patterns:
            for match in re.finditer(pattern, code):
                method_name = match.group(1)
                
                # Filter strings that are obviously not method names
                if self._is_valid_method_name(method_name) and method_name not in found_methods:
                    found_methods.add(method_name)
                    
                    # Try to find corresponding handler
                    handler_name, handler_addr = self._find_handler_for_method(
                        code, method_name, match.start()
                    )
                    
                    # Determine if Auth-Free
                    is_auth_free = method_name.lower() in [m.lower() for m in self.COMMON_AUTH_FREE_METHODS]
                    
                    # Determine if sensitive operation
                    is_sensitive = any(s in method_name.lower() for s in 
                                       ["password", "user", "admin", "config", "firmware", 
                                        "cmd", "exec", "system", "reboot", "reset"])
                    
                    info = JSONRPCMethodInfo(
                        method=method_name,
                        handler=handler_name,
                        handler_addr=handler_addr,
                        is_auth_free=is_auth_free,
                        source_location=dispatch_addr,
                        has_sensitive_operation=is_sensitive
                    )
                    methods.append(info)
                    
                    auth_status = "[AUTH-FREE]" if is_auth_free else "[PROTECTED]"
                    sensitive_mark = " [SENSITIVE]" if is_sensitive else ""
                    self.log(f"    {auth_status} {method_name} -> {handler_name}{sensitive_mark}")
        
        # Pattern 2: strncmp prefix route
        # Example: if ( !strncmp(v3, "get_", 4u) )
        strncmp_patterns = [
            r'strncmp\s*\(\s*\w+\s*,\s*["\']([^"\']+)["\']\s*,\s*(\d+)',
            r'!strncmp\s*\(\s*\w+\s*,\s*["\']([^"\']+)["\']\s*,\s*\d+',
        ]
        
        prefix_routes = []
        found_prefixes = set()
        
        for pattern in strncmp_patterns:
            for match in re.finditer(pattern, code):
                prefix = match.group(1)
                
                # Only handle prefixes like "get_", "set_", "action"
                if prefix in found_prefixes:
                    continue
                
                if len(prefix) >= 2 and (prefix.endswith("_") or prefix in ["action"]):
                    found_prefixes.add(prefix)
                    
                    # Try to find corresponding handler
                    handler_name, handler_addr = self._find_handler_for_method(
                        code, prefix, match.start()
                    )
                    
                    info = JSONRPCMethodInfo(
                        method=f"{prefix}*",  # Mark as prefix route
                        handler=handler_name,
                        handler_addr=handler_addr,
                        is_auth_free=False,  # Prefix routes typically require auth
                        source_location=dispatch_addr,
                        has_sensitive_operation=True  # Prefix routes cover multiple operations
                    )
                    prefix_routes.append(info)
                    
                    self.log(f"    [PREFIX] {prefix}* -> {handler_name}")
        
        methods.extend(prefix_routes)
        self.log(f"\n  [+] Extracted {len(methods)} JSON-RPC methods ({len(prefix_routes)} prefix routes)")
        return methods
    
    def _is_valid_method_name(self, name: str) -> bool:
        """Check if this is a valid method name"""
        # Exclude common non-method strings
        invalid_patterns = [
            r'^[A-Z_]+$',           # All-caps constants
            r'^v\d+$',              # Variable names
            r'^\d+$',               # Pure numbers
            r'^[a-z]{1,2}$',        # Too short variables
            r'^(GET|POST|HEAD)$',   # HTTP methods
            r'^(true|false|null)$', # JSON values
            r'/',                   # Contains path separator
            r'^0x',                 # Hexadecimal
        ]
        
        for pattern in invalid_patterns:
            if re.match(pattern, name):
                return False
        
        # Method name should be reasonable length identifier
        if len(name) < 2 or len(name) > 50:
            return False
        
        # Should be identifier format (alphanumeric and underscore)
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
            return False
        
        return True
    
    def _find_handler_for_method(self, code: str, method_name: str, position: int) -> Tuple[str, str]:
        """
        Find handler function for method in code
        
        Search for function call after strcmp
        """
        # Search for function call in code after position
        search_window = code[position:position + 1000]
        
        # Pattern 1: Function call assignment v7 = sub_xxxxx(...)
        handler_patterns = [
            r'(\w+)\s*=\s*(sub_[0-9A-Fa-f]+)\s*\(',
            r'(v\d+)\s*=\s*(sub_[0-9A-Fa-f]+)\s*\(',
            r'(\w+)\s*=\s*(\w+Process)\s*\(',
            r'(\w+)\s*=\s*(\w+Handler)\s*\(',
        ]
        
        for pattern in handler_patterns:
            match = re.search(pattern, search_window)
            if match:
                handler_name = match.group(2)
                # Extract address
                addr_match = re.search(r'sub_([0-9A-Fa-f]+)', handler_name)
                handler_addr = f"0x{addr_match.group(1)}" if addr_match else ""
                return (handler_name, handler_addr)
        
        # Pattern 2: Direct call sub_xxxxx(...)
        direct_call_pattern = r'(sub_[0-9A-Fa-f]+)\s*\('
        match = re.search(direct_call_pattern, search_window)
        if match:
            handler_name = match.group(1)
            addr_match = re.search(r'sub_([0-9A-Fa-f]+)', handler_name)
            handler_addr = f"0x{addr_match.group(1)}" if addr_match else ""
            return (handler_name, handler_addr)
        
        # Fallback: Generate from method name
        return (f"handle_{method_name}", "")
    
    def analyze_privilege_check(self, dispatch_addr: str) -> Dict[str, int]:
        """
        Analyze privilege check logic
        
        Cisco RV34x uses sub_1306C(a1, level, 2) for privilege checks
        Returns: {method_name: required_privilege_level}
        """
        self.log("\n[JSONRPC] Analyzing privilege checks...")
        
        code = self._decompile_function(dispatch_addr)
        if not code:
            return {}
        
        privilege_map = {}
        
        # Cisco style: sub_1306C(a1, level, 2) 
        # level=1 means user privilege, level=2 means admin privilege
        priv_check_pattern = r'!strcmp\s*\(\s*\w+\s*,\s*["\'](\w+)["\']\s*\)[^{]*sub_1306C\s*\([^,]+,\s*(\d+)'
        
        for match in re.finditer(priv_check_pattern, code, re.DOTALL):
            method_name = match.group(1)
            priv_level = int(match.group(2))
            privilege_map[method_name] = priv_level
            self.log(f"    {method_name} requires privilege level {priv_level}")
        
        return privilege_map
    
    def run(self, use_llm: bool = False) -> List[RouteNode]:
        """
        Execute JSON-RPC route extraction
        
        Args:
            use_llm: Whether to use LLM-assisted analysis
        
        Returns:
            Extracted route list
        """
        self.log("\n" + "=" * 60)
        self.log("  JSON-RPC Extractor - Starting")
        self.log("=" * 60)
        
        # 1. Detect architecture
        if not self.detect_architecture():
            self.log("\n[!] This binary may not be a JSON-RPC CGI application")
            # Still try to continue
        
        # 2. Locate entry function
        entry = self.find_main_or_entry()
        if not entry:
            self.log("\n[!] Could not find entry point, trying alternative methods...")
        
        # 3. Locate dispatch function
        dispatch = self.find_dispatch_function()
        if not dispatch:
            # If can't find dedicated dispatch function, use main
            dispatch = entry
        
        if not dispatch:
            self.log("\n[ERROR] Could not find dispatch function")
            return []
        
        # 4. Extract methods
        self.methods = self.extract_methods_from_dispatch(dispatch)
        
        # 5. Analyze privilege checks
        privilege_map = self.analyze_privilege_check(dispatch)
        
        # Update methods privilege info
        for method in self.methods:
            if method.method in privilege_map:
                method.requires_privilege = privilege_map[method.method]
                # Has privilege check means not Auth-Free
                method.is_auth_free = False
        
        # 6. If LLM available, perform enhanced analysis
        if use_llm and self.llm and len(self.methods) > 0:
            self.methods = self._enhance_with_llm(dispatch, self.methods)
        
        # 7. Convert to RouteNode
        routes = [m.to_route_node() for m in self.methods]
        
        # 8. Statistics
        auth_free_count = sum(1 for m in self.methods if m.is_auth_free)
        sensitive_count = sum(1 for m in self.methods if m.has_sensitive_operation)
        
        self.log("\n" + "=" * 60)
        self.log(f"  Extraction Complete")
        self.log(f"  Total Methods: {len(self.methods)}")
        self.log(f"  Auth-Free: {auth_free_count}")
        self.log(f"  Sensitive Operations: {sensitive_count}")
        self.log("=" * 60)
        
        return routes
    
    def _enhance_with_llm(self, dispatch_addr: str, methods: List[JSONRPCMethodInfo]) -> List[JSONRPCMethodInfo]:
        """Use LLM to enhance analysis"""
        if not self.llm:
            return methods
        
        self.log("\n[JSONRPC] Enhancing analysis with LLM...")
        
        code = self._decompile_function(dispatch_addr)
        if not code:
            return methods
        
        # Build LLM prompt
        prompt = f"""Analyze the following JSON-RPC dispatch function code and identify authentication status for each method:

```c
{code[:4000]}  // First 4000 characters truncated
```

Identified methods: {[m.method for m in methods]}

Please analyze:
1. Which methods are handled before authentication check (Auth-Free)?
2. Which methods involve sensitive operations (e.g., password change, user management, system configuration)?
3. Are there any authentication bypass risks?

Please return in JSON format:
{{"auth_free": ["method1", "method2"], "sensitive": ["method3"], "bypass_risks": ["description"]}}
"""
        
        try:
            response = self.llm.chat(prompt)
            # Parse LLM response...
            # Simplified handling here, can be more complex
            self.log("  [+] LLM analysis completed")
        except Exception as e:
            self.log(f"  [-] LLM analysis failed: {e}")
        
        return methods
    
    def save_routes(self, firmware_name: str) -> str:
        """Save extracted routes to file"""
        routes = [m.to_route_node() for m in self.methods]
        routes_data = [r.to_dict() for r in routes]
        
        output_file = os.path.join(self.output_dir, f"{firmware_name}_routes.json")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(routes_data, f, indent=2, ensure_ascii=False)
        
        self.log(f"\n[+] Saved {len(routes)} routes to {output_file}")
        return output_file


def detect_jsonrpc_architecture(ida_client: IDAProClient) -> Tuple[bool, float]:
    """
    Quick detection of JSON-RPC architecture
    
    Returns:
        (is_jsonrpc, confidence)
    """
    extractor = JSONRPCExtractor(ida_client, None)
    extractor.verbose = False
    
    score = 0
    max_score = 10
    
    # Detect characteristic strings
    jsonrpc_strings = ["method", "params", "CONTENT_LENGTH", "json_tokener_parse"]
    for s in jsonrpc_strings:
        result = ida_client.search_strings(s)
        if result.get("status") == "ok":
            data = result.get("data", [])
            if data:
                score += 2
    
    # Detect JSON parse functions
    for func in ["json_tokener_parse", "json_object_object_get_ex"]:
        result = ida_client.get_functions(search=func, limit=3)
        if result.get("status") == "ok":
            data = result.get("data", [])
            if data:
                score += 1
    
    confidence = score / max_score
    is_jsonrpc = confidence >= 0.3
    
    return (is_jsonrpc, confidence)
