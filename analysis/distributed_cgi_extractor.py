# Copyright (c) 2026 The Pangu Project Authors. All rights reserved.
# analysis/distributed_cgi_extractor.py
# PANGU Distributed CGI Architecture Route Extractor
# Specialized for Lighttpd + Multiple Independent CGI Program Firmware Architecture
# Target Devices: Wavlink WN530H4 and other devices using similar architectures

"""
Distributed CGI Architecture Characteristics:
1. Each .cgi file is an independent executable program
2. Route URL = CGI file path (e.g., /cgi-bin/adm.cgi)
3. Sub-routes determined by POST parameters (e.g., page=sysAdm)
4. Authentication logic implemented inside each CGI program's main function
5. Multiple CGIs share a common authentication library (e.g., libshare.so)

Architecture Diagram:
    Lighttpd (mod_cgi)
        ├── /cgi-bin/adm.cgi      → Admin functions (with auth)
        ├── /cgi-bin/login.cgi    → Login interface (no auth)
        ├── /cgi-bin/firewall.cgi → Firewall config (with auth)
        ├── /cgi-bin/wireless.cgi → Wireless config (with auth)
        └── /cgi-bin/upload.cgi   → File upload (may be auth-free!)

Phase 1 Route Extraction Strategy:
1. Phase 0 has identified all CGI files
2. Analyze each CGI's main function:
   - Extract sub-route dispatch logic (strcmp(page, "xxx"))
   - Identify route dispatch parameter types (page, action, cmd, etc.)
   - Build complete CGI URL + sub-route mapping
3. Support batch analysis of multiple CGI files

Phase 2 Authentication Identification Strategy:
1. Distinguish two types of authentication functions:
   - Login authentication: check_valid_user, verify_session (requires login)
   - CSRF protection: check_csrf_referer (not equivalent to login authentication)
2. Analyze authentication check position:
   - Before route dispatch → All sub-routes protected (GLOBAL_CHECK)
   - No auth check → CGI is entirely auth-free (NO_AUTH)
   - CSRF only → No login required but CSRF protected (NO_AUTH, with CSRF)
   - Some routes bypass auth → Need fine-grained analysis (PARTIAL_AUTH)
3. Output compatible with standard RouteNode and ACDG format
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


class CGIAuthPattern(Enum):
    """CGI Authentication Pattern - For Phase 2 ACDG construction"""
    GLOBAL_CHECK = "global_check"       # Unified check at main() entry (requires login)
    NO_AUTH = "no_auth"                 # No authentication check (auth-free)
    CSRF_ONLY = "csrf_only"             # Only CSRF check (auth-free but CSRF protected)
    PARTIAL_AUTH = "partial_auth"       # Partial routes have authentication
    UNKNOWN = "unknown"


@dataclass
class CGISubRoute:
    """CGI Sub-route Information - Phase 1 Route Extraction Output"""
    page_name: str                      # page parameter value (e.g., "sysAdm")
    handler: str                        # Handler function name
    handler_addr: str                   # Handler function address
    cgi_name: str                       # Owning CGI file
    cgi_path: str                       # CGI URL path
    dispatch_param: str = "page"        # Dispatch parameter name (page, action, cmd, etc.)
    is_auth_protected: bool = True      # Whether protected by login authentication
    has_csrf_protection: bool = False   # Whether has CSRF protection
    auth_detail: str = ""               # Authentication details
    
    @property
    def full_path(self) -> str:
        """Full URL path"""
        return f"{self.cgi_path}?{self.dispatch_param}={self.page_name}"
    
    def to_route_node(self) -> RouteNode:
        """Convert to standard RouteNode - For Phase 2 use"""
        if self.is_auth_protected:
            auth_state = AuthState.AUTH_REQUIRED
            protection = ProtectionType.GATEKEEPER
        else:
            auth_state = AuthState.AUTH_FREE
            protection = ProtectionType.NONE
        
        # Build protection detail
        protection_detail = self.auth_detail
        if self.has_csrf_protection and not self.is_auth_protected:
            protection_detail = f"CSRF-only protection (no login required). {self.auth_detail}"
        
        return RouteNode(
            path=self.full_path,
            sub_path=self.page_name,
            handler=self.handler,
            source_hub=self.handler_addr,
            source_type="cgi_dispatch",
            root=self.cgi_path,
            auth_state=auth_state,
            protection_type=protection,
            protection_detail=protection_detail
        )


@dataclass
class CGIBinaryInfo:
    """CGI Binary File Analysis Information - Phase 1+2 Combined Results"""
    name: str                                   # Filename (e.g., adm.cgi)
    path: str                                   # Full path
    url_path: str                               # URL path (e.g., /cgi-bin/adm.cgi)
    
    # Phase 2 authentication analysis results
    auth_pattern: CGIAuthPattern = CGIAuthPattern.UNKNOWN
    auth_functions: List[str] = field(default_factory=list)   # Imported auth functions
    auth_check_addr: str = ""                   # Auth check location
    has_login_auth: bool = False                # Whether main() actually calls login auth
    has_csrf_check: bool = False                # Whether main() actually calls CSRF check
    imports_login_auth: bool = False            # Whether imports login auth function (not same as actual call)
    imports_csrf_check: bool = False            # Whether imports CSRF check function (not same as actual call)
    
    # Phase 1 sub-routes
    sub_routes: List[CGISubRoute] = field(default_factory=list)
    dispatch_param: str = "page"                # Main dispatch parameter name
    
    # Sensitive function detection (for Phase 3 use)
    has_system_call: bool = False
    has_nvram_write: bool = False
    has_file_write: bool = False
    sensitive_functions: List[str] = field(default_factory=list)
    
    # Metadata
    main_addr: str = ""
    function_count: int = 0
    is_analyzed: bool = False


class DistributedCGIExtractor:
    """
    Distributed CGI Route Extractor
    
    Specialized for firmware architectures with multiple independent CGI programs
    
    Phase 1 Function: Extract CGI routes and sub-routes
    Phase 2 Function: Identify authentication patterns, distinguish protected and auth-free routes
    """
    
    # ==================== Authentication Function Classification ====================
    # Login Authentication Function Patterns (Real user authentication, requires login to access)
    LOGIN_AUTH_PATTERNS = [
        "check_valid_user", "verify_session", "check_auth", "checkAuth", 
        "auth_check", "session_check", "validate_user", "is_logged_in", 
        "check_login", "CheckUser", "CheckSession", "validate_session",
        "checkLogin", "isLoggedIn", "verifyAuth", "user_auth_check",
        # Zyxel NAS specific authentication functions
        "checking session", "get_auth_data", "authtok", "gcgiFetchCookies"
    ]
    
    # CSRF Protection Functions (Not equivalent to login authentication, only verifies request origin)
    CSRF_CHECK_PATTERNS = [
        "check_csrf_referer", "check_referer", "csrf_check", 
        "validate_referer", "check_csrf", "verify_referer",
        "checkReferer", "validateReferer"
    ]
    
    # CGI Library Initialization Functions (Used to identify CGI programs)
    CGI_INIT_PATTERNS = [
        "initCgi", "freeCgi",           # Zyxel gcgi
        "cgi_init", "cgi_free",         # Generic
        "gcgiSetLimits", "gcgiOut",     # Zyxel gcgi
        "cgiInit", "cgiFree"            # Others
    ]
    
    # All authentication-related functions (Used for searching)
    AUTH_FUNCTION_PATTERNS = LOGIN_AUTH_PATTERNS + CSRF_CHECK_PATTERNS
    
    # ==================== Route Dispatch Parameter Names ====================
    # Used to identify sub-route dispatch logic
    DISPATCH_PARAM_NAMES = [
        "page", "action", "cmd", "op", "func", "act", "do", "command",
        "method", "type", "module", "request", "api"
    ]
    
    # Excluded Parameter Values (Non-route strings)
    EXCLUDE_ROUTE_VALUES = [
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS",  # HTTP methods
        "init", "1", "0", "true", "false", "null", "none",  # Special values
        "application/json", "text/html", "multipart",       # Content-Type
        "HTTP/1.1", "HTTP/1.0",                             # HTTP version
    ]
    
    # Business Parameter Values (Non-route parameters, common in single-function CGIs)
    BUSINESS_PARAM_VALUES = [
        "sharename", "path", "filename", "file", "dir", "folder",  # File operations
        "user", "pass", "password", "username", "admin",           # User authentication
        "ip", "addr", "address", "host", "port",                   # Network
        "type", "format", "mode", "status", "result",              # Generic
        "share-path", "smb_user", "smb_group",                     # SMB
    ]
    
    # Sensitive Functions (For Phase 3 use)
    SENSITIVE_SINKS = {
        "rce": ["system", "popen", "exec", "execve", "doSystemCmd", "do_system", 
                "exec_cmd", "twsystem", "CsteSystem", "run_command"],
        "nvram": ["nvram_set", "nvram_bufset", "cfm_set", "uci_set"],
        "file": ["fwrite", "fopen", "open", "write", "unlink", "remove"],
        "config": ["set_config", "save_config", "apply_settings"]
    }
    
    def __init__(self, ida_client: IDAProClient, llm: Optional[LLMProvider] = None):
        self.ida = ida_client
        self.llm = llm
        
        # Current CGI being analyzed
        self.current_cgi: Optional[CGIBinaryInfo] = None
        
        # Analysis result cache - Supports batch analysis
        self.cgi_binaries: List[CGIBinaryInfo] = []
        self.all_routes: List[RouteNode] = []
        
        # Shared authentication function info (Shared across CGIs)
        self.shared_auth_lib: str = ""
        self.auth_functions_found: List[str] = []
        
        # Cached imported functions
        self._imported_functions_cache: Set[str] = set()
        self._imports_analyzed: bool = False
        
        # Configuration
        self.output_dir = "output"
        self.verbose = True
    
    def log(self, msg: str):
        """Log output"""
        if self.verbose:
            print(msg)
    
    @staticmethod
    def _extract_data(result: Dict, default=None):
        """Extract data from IDA return result"""
        if result.get("status") != "ok":
            return default if default is not None else []
        return result.get("data", default if default is not None else [])
    
    def analyze_current_binary(self) -> Optional[CGIBinaryInfo]:
        """
        Analyze the CGI binary file currently open in IDA
        
        Returns:
            CGIBinaryInfo or None
        """
        self.log("\n" + "=" * 60)
        self.log("  Distributed CGI Extractor - Binary Analysis")
        self.log("=" * 60)
        
        # 1. Get current binary info
        status = self.ida.get_status()
        status_data = self._extract_data(status, {})
        
        if not status_data:
            self.log("  [ERROR] Cannot get IDA status")
            return None
        
        binary_name = status_data.get("binary_name", "unknown")
        binary_path = status_data.get("binary_path", "")
        
        self.log(f"\n[*] Current binary: {binary_name}")
        self.log(f"    Path: {binary_path}")
        
        # Create CGI info object
        cgi_info = CGIBinaryInfo(
            name=binary_name,
            path=binary_path,
            url_path=self._infer_url_path(binary_name),
            function_count=status_data.get("function_count", 0)
        )
        
        # 2. Analyze authentication mechanism
        self.log("\n[Phase 1] Analyzing authentication mechanism...")
        self._analyze_auth_mechanism(cgi_info)
        
        # 3. Extract sub-routes
        self.log("\n[Phase 2] Extracting sub-routes from main()...")
        self._extract_sub_routes(cgi_info)
        
        # 4. Detect sensitive functions
        self.log("\n[Phase 3] Detecting sensitive functions...")
        self._detect_sensitive_functions(cgi_info)
        
        cgi_info.is_analyzed = True
        self.current_cgi = cgi_info
        
        # Print summary
        self._print_analysis_summary(cgi_info)
        
        return cgi_info
    
    def _infer_url_path(self, binary_name: str) -> str:
        """Infer CGI's URL path"""
        if binary_name.endswith(".cgi"):
            return f"/cgi-bin/{binary_name}"
        return f"/cgi-bin/{binary_name}"
    
    def _analyze_auth_mechanism(self, cgi_info: CGIBinaryInfo):
        """Analyze CGI's authentication mechanism"""
        
        # 1. Search for auth-related functions
        auth_funcs_found = []
        for pattern in self.AUTH_FUNCTION_PATTERNS:
            result = self.ida.get_functions(search=pattern, limit=20)
            functions = self._extract_data(result, [])
            for func in functions:
                name = func.get("name", "")
                addr = func.get("addr", "")
                # Filter out PLT/import stubs
                if name.startswith(".") or "plt" in name.lower():
                    continue
                auth_funcs_found.append({"name": name, "addr": addr})
                self.log(f"  [+] Found auth function: {name} @ {addr}")
        
        cgi_info.auth_functions = [f["name"] for f in auth_funcs_found]
        
        # 2. Analyze auth calls in main function
        main_result = self.ida.get_functions(search="main", limit=5)
        main_funcs = self._extract_data(main_result, [])
        
        main_func = None
        for f in main_funcs:
            if f.get("name") == "main":
                main_func = f
                break
        
        if not main_func:
            self.log("  [WARN] main function not found")
            cgi_info.auth_pattern = CGIAuthPattern.UNKNOWN
            return
        
        cgi_info.main_addr = main_func.get("addr", "")
        
        # 3. Decompile main function to analyze auth flow
        decompile_result = self.ida.decompile("main")
        if decompile_result.get("status") != "ok":
            self.log("  [WARN] Failed to decompile main")
            cgi_info.auth_pattern = CGIAuthPattern.UNKNOWN
            return
        
        main_code = decompile_result.get("data", {})
        if isinstance(main_code, dict):
            main_code = main_code.get("code", "")
        
        # 4. Analyze authentication pattern
        auth_pattern = self._analyze_auth_pattern_in_code(main_code, cgi_info)
        cgi_info.auth_pattern = auth_pattern
        
        self.log(f"\n  [*] Auth pattern detected: {auth_pattern.value}")
    
    def _analyze_auth_pattern_in_code(self, code: str, cgi_info: CGIBinaryInfo) -> CGIAuthPattern:
        """Analyze authentication pattern in code - Phase 2 core logic"""
        
        # Check for actual login auth function calls
        has_login_auth = False
        has_csrf_check = False
        login_auth_line = -1
        csrf_check_line = -1
        
        lines = code.split('\n')
        
        # ========== Step 1: Analyze imported functions ==========
        # Determine which auth functions the CGI actually imports
        if not self._imports_analyzed:
            self._analyze_imported_functions()
        
        # Check if real login auth function is imported
        has_login_auth_import = any(
            func in self._imported_functions_cache or func.lower() in [f.lower() for f in self._imported_functions_cache]
            for func in self.LOGIN_AUTH_PATTERNS
        )
        has_csrf_import = any(
            func in self._imported_functions_cache or func.lower() in [f.lower() for f in self._imported_functions_cache]
            for func in self.CSRF_CHECK_PATTERNS
        )
        
        # Record import status to separate field (not same as actual call)
        cgi_info.imports_login_auth = has_login_auth_import
        cgi_info.imports_csrf_check = has_csrf_import
        
        self.log(f"  [*] Login auth function imported: {has_login_auth_import}")
        self.log(f"  [*] CSRF check function imported: {has_csrf_import}")
        
        # ========== Step 2: Locate auth calls in code ==========
        for i, line in enumerate(lines):
            # Check login auth
            for auth_func in self.LOGIN_AUTH_PATTERNS:
                if auth_func in line and has_login_auth_import:
                    has_login_auth = True
                    login_auth_line = i
                    self.log(f"  [+] Login auth check at line {i}: {line.strip()[:60]}...")
                    break
            
            # Check CSRF
            for csrf_func in self.CSRF_CHECK_PATTERNS:
                if csrf_func in line and has_csrf_import:
                    has_csrf_check = True
                    csrf_check_line = i
                    self.log(f"  [+] CSRF check at line {i}: {line.strip()[:60]}...")
                    break
        
        # ========== Step 3: Key judgment logic ==========
        # 1. Has login auth (check_valid_user) = Requires login authentication
        # 2. Only CSRF check = Auth-free (but CSRF protected)
        # 3. Neither = Completely auth-free
        
        # Update cgi_info auth status based on actual code calls, not just imports
        # This is important for correct Phase 2 judgment
        cgi_info.has_login_auth = has_login_auth  # Actual call status
        cgi_info.has_csrf_check = has_csrf_check  # Actual call status
        
        if not has_login_auth and not has_csrf_check:
            self.log("  [!] No authentication check found - CGI is AUTH-FREE!")
            return CGIAuthPattern.NO_AUTH
        
        if not has_login_auth and has_csrf_check:
            self.log("  [!] Only CSRF check, no login auth - CGI is AUTH-FREE (CSRF-only protection)!")
            cgi_info.auth_check_addr = f"csrf_only_line_{csrf_check_line}"
            return CGIAuthPattern.CSRF_ONLY
        
        # ========== Step 4: Analyze auth check position ==========
        cgi_info.auth_check_addr = f"line_{login_auth_line}"
        
        # Check if auth check is before route dispatch
        dispatch_line = -1
        dispatch_patterns = [
            (r'web_get\s*\(\s*"page"', "web_get page"),
            (r'web_get\s*\(\s*"action"', "web_get action"),
            (r'strcmp\s*\([^,]+,\s*"(sysAdm|ntp|ddns|wan|reboot|loaddefault|wzdap|clone|UPNP|ping_test|login|logoff)"', "route dispatch"),
            (r'getenv\s*\(\s*"REQUEST_METHOD"', "request method"),
            (r'strcmp\s*\([^,]+,\s*"(POST|GET)"', "method check"),
        ]
        
        exclude_patterns = [
            r'strcmp\s*\(\s*argv\[',
            r'strcmp\s*\([^,]+,\s*"init"\s*\)',
            r'strcmp\s*\([^,]+,\s*"1"\s*\)',
            r'strcmp\s*\([^,]+,\s*"0"\s*\)',
        ]
        
        for i, line in enumerate(lines):
            is_excluded = any(re.search(p, line) for p in exclude_patterns)
            if is_excluded:
                continue
            
            for pattern, desc in dispatch_patterns:
                if re.search(pattern, line):
                    dispatch_line = i
                    self.log(f"  [+] Route dispatch at line {i}: {desc}")
                    break
            if dispatch_line >= 0:
                break
        
        if login_auth_line >= 0 and dispatch_line >= 0:
            if login_auth_line < dispatch_line:
                self.log(f"  [+] Login auth (line {login_auth_line}) before dispatch (line {dispatch_line})")
                self.log(f"  [+] All routes protected by global authentication")
                return CGIAuthPattern.GLOBAL_CHECK
            else:
                self.log(f"  [!] Login auth (line {login_auth_line}) after dispatch (line {dispatch_line})")
                return CGIAuthPattern.PARTIAL_AUTH
        
        if has_login_auth:
            self.log(f"  [+] Login auth check found - assuming global protection")
            return CGIAuthPattern.GLOBAL_CHECK
        
        return CGIAuthPattern.UNKNOWN
    
    def _analyze_imported_functions(self):
        """Analyze and cache list of imported functions"""
        if self._imports_analyzed:
            return
        
        imports_result = self.ida.get_functions(limit=500)
        imported_funcs = self._extract_data(imports_result, [])
        
        for f in imported_funcs:
            name = f.get("name", "")
            if name.startswith("."):
                self._imported_functions_cache.add(name[1:])  # Remove prefix dot
            else:
                self._imported_functions_cache.add(name)
        
        self._imports_analyzed = True
        self.log(f"  [*] Cached {len(self._imported_functions_cache)} imported functions")
    
    def _extract_sub_routes(self, cgi_info: CGIBinaryInfo):
        """Extract sub-route dispatch logic from main function - Phase 1 core"""
        
        # Decompile main
        decompile_result = self.ida.decompile("main")
        if decompile_result.get("status") != "ok":
            self.log("  [WARN] Failed to decompile main for route extraction")
            return
        
        main_code = decompile_result.get("data", {})
        if isinstance(main_code, dict):
            main_code = main_code.get("code", "")
        
        # 1. Detect dispatch parameter type (page, action, cmd, etc.)
        detected_param = self._detect_dispatch_param(main_code)
        cgi_info.dispatch_param = detected_param
        self.log(f"  [+] Detected dispatch parameter: {detected_param}")
        
        # 2. First detect if it's a "single-function CGI" (no page/action dispatch logic)
        # Single-function CGI characteristics: no web_get("page") or similar dispatch param retrieval
        is_single_function_cgi = self._is_single_function_cgi(main_code, cgi_info)
        
        if is_single_function_cgi:
            self.log(f"  [!] Detected SINGLE-FUNCTION CGI (no sub-route dispatch)")
            self.log(f"      This CGI handles one specific function: {cgi_info.name}")
            # Single-function CGI doesn't need sub-route extraction
            return
        
        # 3. Extract all string constants from strcmp calls
        # Pattern: strcmp(v38, "sysAdm") or !strcmp(page, "ntp")
        route_pattern = re.compile(
            r'strcmp\s*\(\s*\w+\s*,\s*"([^"]+)"\s*\)',
            re.IGNORECASE
        )
        
        matches = route_pattern.findall(main_code)
        
        # 4. Filter and deduplicate
        seen_routes = set()
        for match in matches:
            page_name = match
            
            # Filter non-route strings
            if page_name in self.EXCLUDE_ROUTE_VALUES:
                continue
            if page_name.startswith("/") or page_name.startswith("http"):
                continue
            if len(page_name) < 2 or len(page_name) > 50:
                continue
            # Filter common non-route parameters
            if page_name.lower() in ["get", "post", "init", "1", "0", ""]:
                continue
            # Filter business parameters (non-route params)
            if page_name.lower() in self.BUSINESS_PARAM_VALUES:
                continue
            
            if page_name in seen_routes:
                continue
            seen_routes.add(page_name)
            
            # Try to find corresponding handler function
            handler_name, handler_addr = self._find_handler_for_page(main_code, page_name)
            
            # Determine if protected by auth (based on CGI-level auth pattern)
            is_protected = cgi_info.auth_pattern == CGIAuthPattern.GLOBAL_CHECK
            has_csrf = cgi_info.has_csrf_check
            
            sub_route = CGISubRoute(
                page_name=page_name,
                handler=handler_name,
                handler_addr=handler_addr,
                cgi_name=cgi_info.name,
                cgi_path=cgi_info.url_path,
                dispatch_param=detected_param,
                is_auth_protected=is_protected,
                has_csrf_protection=has_csrf,
                auth_detail=f"CGI auth pattern: {cgi_info.auth_pattern.value}"
            )
            
            cgi_info.sub_routes.append(sub_route)
            self.log(f"  [+] Route: {detected_param}={page_name} → {handler_name}")
    
    def _is_single_function_cgi(self, code: str, cgi_info: CGIBinaryInfo) -> bool:
        """
        Detect if this is a single-function CGI (no page/action based route dispatch)
        
        Single-function CGI characteristics:
        1. No web_get("page") or web_get("action") calls
        2. No typical route dispatch switch/if-else structure
        3. Uses gcgi/libcgi library to directly handle requests
        4. Parameters are business parameters (e.g., shareName, path) not route parameters
        
        Typical single-function CGIs:
        - file_download.cgi: Only handles file download
        - weblogin.cgi: Only handles login
        - access.cgi: Only handles access control
        """
        # Check if has route dispatch parameter retrieval
        dispatch_param_patterns = [
            r'web_get\s*\(\s*"page"\s*\)',
            r'web_get\s*\(\s*"action"\s*\)',
            r'web_get\s*\(\s*"cmd"\s*\)',
            r'web_get\s*\(\s*"func"\s*\)',
            r'getenv\s*\(\s*"page"\s*\)',
            r'cgi_get\s*\(\s*"page"\s*\)',
        ]
        
        has_dispatch_param = any(re.search(p, code, re.IGNORECASE) for p in dispatch_param_patterns)
        
        if has_dispatch_param:
            return False  # Has dispatch param, not single-function CGI
        
        # Check if uses gcgi library (Zyxel characteristic)
        uses_gcgi = any(func in code for func in ["initCgi", "gcgiOut", "gcgiFetchStringNext"])
        
        # Check if has typical route strings (e.g., "sysAdm", "wan", "ntp")
        # These usually appear in multi-route CGIs
        typical_route_strings = [
            "sysAdm", "ntp", "ddns", "wan", "reboot", "loaddefault",
            "wireless", "firewall", "qos", "vpn", "upnp"
        ]
        has_typical_routes = any(route in code for route in typical_route_strings)
        
        if has_typical_routes:
            return False  # Has typical route strings, not single-function CGI
        
        # Check if CGI name suggests single function
        single_function_names = [
            "download", "upload", "login", "logout", "access", "auth",
            "file", "export", "import", "backup", "restore", "setuser"
        ]
        cgi_lower = cgi_info.name.lower()
        is_single_function_name = any(name in cgi_lower for name in single_function_names)
        
        # Comprehensive judgment
        if uses_gcgi and is_single_function_name and not has_dispatch_param:
            return True
        
        # If no dispatch param and no typical route strings, also consider single-function
        if not has_dispatch_param and not has_typical_routes:
            return True
        
        return False
    
    def _detect_dispatch_param(self, code: str) -> str:
        """
        Detect route dispatch parameter name used
        
        Common patterns:
        - web_get("page")
        - getenv("QUERY_STRING") then parse page=xxx
        - CGI parameter parsing
        """
        # Search for web_get calls
        web_get_pattern = re.compile(r'web_get\s*\(\s*"(\w+)"\s*\)')
        matches = web_get_pattern.findall(code)
        
        # Count parameter occurrences
        param_counts = {}
        for match in matches:
            if match.lower() in [p.lower() for p in self.DISPATCH_PARAM_NAMES]:
                param_counts[match] = param_counts.get(match, 0) + 1
        
        # Return most common dispatch parameter
        if param_counts:
            return max(param_counts, key=param_counts.get)
        
        # Default to page
        return "page"
    
    def _find_handler_for_page(self, code: str, page_name: str) -> Tuple[str, str]:
        """Find handler function based on page name"""
        
        # Search pattern: function call after strcmp(xxx, "page_name")
        # Example: if (!strcmp(v38, "sysAdm")) { set_sys_adm(v29); }
        
        # Pattern 1: Direct function pointer assignment v40 = (int (*)())set_sys_adm;
        pattern1 = re.compile(
            rf'strcmp\s*\([^,]+,\s*"{re.escape(page_name)}"\s*\)[^;]*?'
            rf'(\w+)\s*=\s*(?:\([^)]*\))?\s*&?\s*(\w+)',
            re.DOTALL
        )
        
        # Pattern 2: Direct call set_xxx(xxx);
        pattern2 = re.compile(
            rf'strcmp\s*\([^,]+,\s*"{re.escape(page_name)}"\s*\).*?'
            rf'(set_\w+|get\w+|do\w+)\s*\(',
            re.DOTALL
        )
        
        # Pattern 3: goto LABEL then unified call
        # v40 = set_sys_adm; ... goto LABEL_83; ... v40(xxx);
        lines = code.split('\n')
        for i, line in enumerate(lines):
            if f'"{page_name}"' in line:
                # Find function references nearby
                context = '\n'.join(lines[max(0,i-2):min(len(lines),i+5)])
                
                # Search for set_xxx, get_xxx etc. function names
                func_refs = re.findall(r'\b(set_\w+|get\w+|do\w+|check_\w+|load_\w+|reboot_\w+|ping_\w+|sch_\w+|auto_\w+|rep_\w+|arplookup|GetMacClone)\b', context)
                if func_refs:
                    func_name = func_refs[0]
                    # Try to get function address
                    result = self.ida.get_functions(search=func_name, limit=5)
                    funcs = self._extract_data(result, [])
                    for f in funcs:
                        if f.get("name") == func_name:
                            return func_name, f.get("addr", "")
                    return func_name, ""
        
        # Guess: Infer handler name based on page name
        handler_guess = f"set_{page_name}" if not page_name.startswith("set_") else page_name
        return handler_guess, ""
    
    def _detect_sensitive_functions(self, cgi_info: CGIBinaryInfo):
        """Detect sensitive function calls in CGI"""
        
        for category, funcs in self.SENSITIVE_SINKS.items():
            for func in funcs:
                result = self.ida.get_functions(search=func, limit=10)
                functions = self._extract_data(result, [])
                for f in functions:
                    name = f.get("name", "")
                    if name.startswith(".") or "plt" in name.lower():
                        # This is an import, meaning CGI calls this function
                        cgi_info.sensitive_functions.append(f"{category}:{func}")
                        self.log(f"  [!] Sensitive function: {func} ({category})")
                        
                        if category == "rce":
                            pass  # Mark for later use
                        elif category == "nvram":
                            cgi_info.has_nvram_write = True
                        elif category == "file":
                            cgi_info.has_file_write = True
    
    def _print_analysis_summary(self, cgi_info: CGIBinaryInfo):
        """Print analysis summary"""
        
        self.log("\n" + "=" * 60)
        self.log("  ANALYSIS SUMMARY")
        self.log("=" * 60)
        
        self.log(f"\n  CGI Binary: {cgi_info.name}")
        self.log(f"  URL Path:   {cgi_info.url_path}")
        self.log(f"  Functions:  {cgi_info.function_count}")
        
        self.log(f"\n  Authentication Pattern: {cgi_info.auth_pattern.value}")
        if cgi_info.auth_functions:
            self.log(f"  Auth Functions: {', '.join(cgi_info.auth_functions)}")
        
        self.log(f"\n  Sub-Routes Found: {len(cgi_info.sub_routes)}")
        for route in cgi_info.sub_routes:
            auth_mark = "🔒" if route.is_auth_protected else "⚠️"
            self.log(f"    {auth_mark} page={route.page_name} → {route.handler}")
        
        if cgi_info.sensitive_functions:
            self.log(f"\n  ⚠️  Sensitive Functions Detected:")
            for sf in cgi_info.sensitive_functions:
                self.log(f"      - {sf}")
        
        # Risk assessment
        self.log("\n  Risk Assessment:")
        if cgi_info.auth_pattern == CGIAuthPattern.NO_AUTH:
            self.log("    🔴 HIGH RISK: No authentication check in this CGI!")
            if cgi_info.sensitive_functions:
                self.log("    🔴 CRITICAL: Sensitive functions accessible without authentication!")
        elif cgi_info.auth_pattern == CGIAuthPattern.PARTIAL_AUTH:
            self.log("    🟠 MEDIUM RISK: Partial authentication - some routes may be unprotected")
        elif cgi_info.auth_pattern == CGIAuthPattern.GLOBAL_CHECK:
            self.log("    🟢 Protected: Global authentication check in place")
        else:
            self.log("    ⚪ UNKNOWN: Unable to determine authentication pattern")
    
    def analyze_handler_auth_bypass(self, handler_name: str) -> Dict:
        """
        Analyze conditional auth bypass patterns in a single handler
        
        Example: if (popup == "1" && !check_valid_user()) - this pattern can be bypassed
        
        Returns:
            Analysis result dictionary
        """
        result = {
            "handler": handler_name,
            "has_auth_check": False,
            "auth_check_conditional": False,
            "bypass_conditions": [],
            "sensitive_operations": []
        }
        
        # Decompile handler
        decompile_result = self.ida.decompile(handler_name)
        if decompile_result.get("status") != "ok":
            return result
        
        code = decompile_result.get("data", {})
        if isinstance(code, dict):
            code = code.get("code", "")
        
        # Check if has auth check
        for auth_func in self.LOGIN_AUTH_PATTERNS:
            if auth_func in code:
                result["has_auth_check"] = True
                
                # Check if conditional check (can be bypassed)
                # Pattern: if ( strcmp(xxx, "1") && !check_valid_user() )
                # Or: if ( !strcmp(xxx, "1") || check_valid_user() )
                bypass_patterns = [
                    # Skip auth when popup == "1"
                    (r'strcmp\s*\([^,]+,\s*"1"\s*\)\s*&&\s*!?' + auth_func, "popup=1 bypass"),
                    (r'!strcmp\s*\([^,]+,\s*"1"\s*\)\s*\|\|', "popup=1 bypass"),
                    # firstFlage condition
                    (r'strcmp\s*\([^,]+firstFlage[^,]*,\s*"1"\s*\)', "firstFlage bypass"),
                ]
                
                for pattern, desc in bypass_patterns:
                    if re.search(pattern, code):
                        result["auth_check_conditional"] = True
                        result["bypass_conditions"].append(desc)
                        self.log(f"  [!] Potential auth bypass in {handler_name}: {desc}")
                break
        
        # Check sensitive operations
        sensitive_ops = {
            "password_change": [r'nvram_bufset.*"Password"', r'nvram_set.*password'],
            "system_cmd": [r'\bsystem\s*\(', r'\bpopen\s*\(', r'do_system\s*\('],
            "config_write": [r'nvram_bufset', r'nvram_commit'],
        }
        
        for op_type, patterns in sensitive_ops.items():
            for pattern in patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    result["sensitive_operations"].append(op_type)
                    break
        
        return result
    
    def get_routes_as_nodes(self) -> List[RouteNode]:
        """
        Get all routes as RouteNode list - for Phase 2 ACDG construction
        
        Output format is compatible with other architectures' RouteNode, can be directly used for LogicDecoupler
        """
        routes = []
        
        if self.current_cgi:
            # Add CGI itself as a top-level route
            cgi_auth_state = self._get_auth_state_for_pattern(self.current_cgi.auth_pattern)
            cgi_protection = self._get_protection_type_for_pattern(self.current_cgi.auth_pattern)
            
            # Build detailed protection description - based on actual auth_pattern judgment, not has_login_auth
            # Because CGI may import auth functions but not actually call them in main
            auth_pattern = self.current_cgi.auth_pattern
            if auth_pattern == CGIAuthPattern.GLOBAL_CHECK:
                protection_detail = "Global login authentication check"
            elif auth_pattern == CGIAuthPattern.CSRF_ONLY:
                protection_detail = "CSRF-only protection (no login required)"
            elif auth_pattern == CGIAuthPattern.NO_AUTH:
                protection_detail = "No authentication required"
            elif auth_pattern == CGIAuthPattern.PARTIAL_AUTH:
                protection_detail = "Partial authentication - some routes protected"
            else:
                protection_detail = f"Auth pattern: {auth_pattern.value}"
            
            cgi_route = RouteNode(
                path=self.current_cgi.url_path,
                sub_path=self.current_cgi.name,
                handler="main",
                source_hub=self.current_cgi.main_addr,
                source_type="cgi_binary",
                root="/cgi-bin",
                auth_state=cgi_auth_state,
                protection_type=cgi_protection,
                protection_detail=protection_detail
            )
            routes.append(cgi_route)
            
            # Add all sub-routes
            for sub_route in self.current_cgi.sub_routes:
                routes.append(sub_route.to_route_node())
        
        return routes
    
    def _get_auth_state_for_pattern(self, pattern: CGIAuthPattern) -> AuthState:
        """Return AuthState based on auth pattern"""
        if pattern == CGIAuthPattern.GLOBAL_CHECK:
            return AuthState.AUTH_REQUIRED
        elif pattern in [CGIAuthPattern.NO_AUTH, CGIAuthPattern.CSRF_ONLY]:
            return AuthState.AUTH_FREE
        elif pattern == CGIAuthPattern.PARTIAL_AUTH:
            return AuthState.UNKNOWN  # Needs fine-grained analysis
        else:
            return AuthState.UNKNOWN
    
    def _get_protection_type_for_pattern(self, pattern: CGIAuthPattern) -> ProtectionType:
        """Return ProtectionType based on auth pattern"""
        if pattern == CGIAuthPattern.GLOBAL_CHECK:
            return ProtectionType.GATEKEEPER
        elif pattern == CGIAuthPattern.PARTIAL_AUTH:
            return ProtectionType.LOCAL
        else:
            return ProtectionType.NONE
    
    def deep_analyze_all_handlers(self) -> List[Dict]:
        """
        Deep analyze all handlers in current CGI for auth bypass and sensitive operations
        
        Returns:
            List of analysis results for each handler
        """
        if not self.current_cgi:
            return []
        
        results = []
        self.log("\n[Deep Analysis] Checking all handlers for vulnerabilities...")
        
        for sub_route in self.current_cgi.sub_routes:
            handler = sub_route.handler
            if not handler or handler.startswith("set_"):
                # Try to analyze
                analysis = self.analyze_handler_auth_bypass(handler)
                
                # Add route info
                analysis["route"] = sub_route.full_path
                analysis["cgi"] = self.current_cgi.name
                
                # Determine risk level
                risk = "LOW"
                if analysis["auth_check_conditional"]:
                    risk = "HIGH"
                    if "password_change" in analysis["sensitive_operations"]:
                        risk = "CRITICAL"
                elif not analysis["has_auth_check"] and analysis["sensitive_operations"]:
                    risk = "HIGH"
                
                analysis["risk_level"] = risk
                
                if risk in ["HIGH", "CRITICAL"]:
                    self.log(f"  [!] {risk}: {handler} - bypass: {analysis['bypass_conditions']}, ops: {analysis['sensitive_operations']}")
                
                results.append(analysis)
        
        return results
    
    def save_analysis(self, output_path: str):
        """Save analysis result"""
        
        if not self.current_cgi:
            return
        
        # Execute deep analysis (optional, for Phase 3 use)
        vuln_analysis = self.deep_analyze_all_handlers()
        
        result = {
            "cgi_info": {
                "name": self.current_cgi.name,
                "path": self.current_cgi.path,
                "url_path": self.current_cgi.url_path,
                "auth_pattern": self.current_cgi.auth_pattern.value,
                # Actual call status (Phase 2 key judgment basis)
                "has_login_auth": self.current_cgi.has_login_auth,
                "has_csrf_check": self.current_cgi.has_csrf_check,
                # Import status (for reference only, not used for auth judgment)
                "imports_login_auth": self.current_cgi.imports_login_auth,
                "imports_csrf_check": self.current_cgi.imports_csrf_check,
                "dispatch_param": self.current_cgi.dispatch_param,
                "auth_functions": self.current_cgi.auth_functions,
                "function_count": self.current_cgi.function_count,
                "sensitive_functions": self.current_cgi.sensitive_functions,
                "has_nvram_write": self.current_cgi.has_nvram_write,
                "has_file_write": self.current_cgi.has_file_write
            },
            "sub_routes": [
                {
                    "page": r.page_name,
                    "handler": r.handler,
                    "handler_addr": r.handler_addr,
                    "dispatch_param": r.dispatch_param,
                    "full_path": r.full_path,
                    "is_auth_protected": r.is_auth_protected,
                    "has_csrf_protection": r.has_csrf_protection
                }
                for r in self.current_cgi.sub_routes
            ],
            "vulnerability_analysis": vuln_analysis,
            "high_risk_findings": [v for v in vuln_analysis if v.get("risk_level") in ["HIGH", "CRITICAL"]],
            "routes": [r.to_dict() for r in self.get_routes_as_nodes()]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        self.log(f"\n[*] Analysis saved to: {output_path}")
    
    def add_cgi_to_cache(self, cgi_info: CGIBinaryInfo):
        """Add analyzed CGI to cache for batch analysis use"""
        if cgi_info and cgi_info.is_analyzed:
            # Check if already exists
            existing = [c for c in self.cgi_binaries if c.name == cgi_info.name]
            if not existing:
                self.cgi_binaries.append(cgi_info)
                self.log(f"  [+] Added {cgi_info.name} to analysis cache")
    
    def get_all_routes_from_cache(self) -> List[RouteNode]:
        """
        Get all routes from cached CGI info
        
        Used for merging analysis results from multiple CGIs
        """
        all_routes = []
        
        for cgi_info in self.cgi_binaries:
            # Save current CGI reference
            original_cgi = self.current_cgi
            self.current_cgi = cgi_info
            
            # Get routes
            routes = self.get_routes_as_nodes()
            all_routes.extend(routes)
            
            # Restore
            self.current_cgi = original_cgi
        
        return all_routes
    
    def generate_acdg_summary(self) -> Dict:
        """
        Generate ACDG summary for Phase 2 use
        
        Returns auth info compatible with other architectures
        """
        summary = {
            "architecture": "DistributedCGI",
            "total_cgi_binaries": len(self.cgi_binaries),
            "auth_summary": {
                "global_check": 0,
                "no_auth": 0,
                "csrf_only": 0,
                "partial_auth": 0,
                "unknown": 0
            },
            "cgi_auth_patterns": [],
            "auth_free_endpoints": [],
            "protected_endpoints": []
        }
        
        for cgi_info in self.cgi_binaries:
            # Auth mode statistics
            pattern = cgi_info.auth_pattern.value
            if pattern in summary["auth_summary"]:
                summary["auth_summary"][pattern] += 1
            
            # Record CGI-level auth mode
            summary["cgi_auth_patterns"].append({
                "cgi": cgi_info.url_path,
                "auth_pattern": pattern,
                "has_login_auth": cgi_info.has_login_auth,
                "has_csrf_check": cgi_info.has_csrf_check,
                "sub_routes_count": len(cgi_info.sub_routes)
            })
            
            # Classify endpoints
            for sub_route in cgi_info.sub_routes:
                endpoint = {
                    "path": sub_route.full_path,
                    "handler": sub_route.handler,
                    "cgi": cgi_info.name
                }
                if sub_route.is_auth_protected:
                    summary["protected_endpoints"].append(endpoint)
                else:
                    summary["auth_free_endpoints"].append(endpoint)
        
        return summary


# ==================== Convenience Functions ====================

def analyze_cgi_binary(ida_client: IDAProClient, 
                       llm: Optional[LLMProvider] = None,
                       output_dir: str = "output") -> Optional[CGIBinaryInfo]:
    """
    Analyze the CGI binary file currently opened in IDA
    
    This is the entry function for analyzing a single CGI program (Phase 1 + Phase 2)
    """
    extractor = DistributedCGIExtractor(ida_client, llm)
    extractor.output_dir = output_dir
    
    cgi_info = extractor.analyze_current_binary()
    
    if cgi_info:
        # Save result
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f"{cgi_info.name}_analysis.json")
        extractor.save_analysis(output_path)
    
    return cgi_info


def extract_cgi_routes(ida_client: IDAProClient,
                       llm: Optional[LLMProvider] = None) -> List[RouteNode]:
    """
    Extract routes from current CGI (Phase 1 only)
    
    Returns:
        List of RouteNode
    """
    extractor = DistributedCGIExtractor(ida_client, llm)
    extractor.analyze_current_binary()
    return extractor.get_routes_as_nodes()


def merge_cgi_analyses(output_dir: str, firmware_name: str) -> Dict:
    """
    Merge multiple CGI analysis result files
    
    Used for Phase 2 to generate complete ACDG
    
    Args:
        output_dir: Output directory (containing *_analysis.json files)
        firmware_name: Firmware name
    
    Returns:
        Merged analysis result
    """
    import glob
    
    merged = {
        "firmware_name": firmware_name,
        "architecture": "DistributedCGI",
        "cgi_binaries": [],
        "all_routes": [],
        "auth_summary": {
            "total_routes": 0,
            "auth_required": 0,
            "auth_free": 0,
            "csrf_only": 0,
            "unknown": 0
        }
    }
    
    # Find all CGI analysis files
    pattern = os.path.join(output_dir, "*_analysis.json")
    analysis_files = glob.glob(pattern)
    
    for filepath in analysis_files:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if "cgi_info" in data:
                # Add CGI info
                merged["cgi_binaries"].append(data["cgi_info"])
                
                # Merge routes
                for route in data.get("routes", []):
                    merged["all_routes"].append(route)
                    merged["auth_summary"]["total_routes"] += 1
                    
                    # Auth status statistics
                    auth_state = route.get("auth_state", "UNKNOWN")
                    if auth_state == "AUTH_REQUIRED":
                        merged["auth_summary"]["auth_required"] += 1
                    elif auth_state == "AUTH_FREE":
                        merged["auth_summary"]["auth_free"] += 1
                    else:
                        merged["auth_summary"]["unknown"] += 1
        except Exception as e:
            print(f"[WARN] Failed to load {filepath}: {e}")
    
    # Save merged result
    merged_path = os.path.join(output_dir, f"{firmware_name}_merged_cgi_analysis.json")
    with open(merged_path, 'w', encoding='utf-8') as f:
        json.dump(merged, f, indent=2, ensure_ascii=False)
    
    print(f"[*] Merged {len(merged['cgi_binaries'])} CGI analyses -> {merged_path}")
    
    return merged


def load_cgi_routes_from_preanalysis(preanalysis_result, output_dir: str) -> List[RouteNode]:
    """
    Load known CGI routes from Phase 0 pre-analysis result
    
    Used to provide basic route info when individual CGI analysis is not possible
    
    Args:
        preanalysis_result: FirmwareAnalysisResult object
        output_dir: Output directory
    
    Returns:
        List of RouteNode
    """
    routes = []
    
    if not preanalysis_result:
        return routes
    
    # Extract CGI candidates from pre-analysis result
    cgi_candidates = [
        c for c in preanalysis_result.binary_candidates 
        if c.binary_type == "cgi_program" or c.name.endswith(".cgi")
    ]
    
    for candidate in cgi_candidates:
        # Infer URL path
        url_path = f"/cgi-bin/{candidate.name}"
        
        # Create basic route (auth status unknown)
        route = RouteNode(
            path=url_path,
            sub_path=candidate.name,
            handler="main",
            source_hub=candidate.path,
            source_type="preanalysis",
            root="/cgi-bin",
            auth_state=AuthState.UNKNOWN,
            protection_type=ProtectionType.NONE,
            protection_detail="From Phase 0 preanalysis (not yet analyzed in IDA)"
        )
        routes.append(route)
    
    return routes
