# Copyright (c) 2026 The Pangu Project Authors. All rights reserved.
# analysis/httpd_gatekeeper_analyzer.py
# PANGU HTTP Server Layer Gatekeeper Analyzer
# Specialized for analyzing global authentication logic in mini_httpd/thttpd and similar lightweight HTTP servers
#
# Applicable Scenarios:
#   - Netgear and similar devices using mini_httpd + CGI architecture
#   - Authentication implemented at HTTP Server layer, CGI layer does not handle authentication
#   - Currently analyzing CGI program but need to trace back HTTP Server layer gatekeeper
#
# Trigger Conditions:
#   - Currently analyzing a .cgi file (e.g., setup.cgi)
#   - Firmware filesystem contains mini_httpd/thttpd/boa or similar binaries
#   - Not GoAhead/GoForm/JSONRPC or similar integrated architectures
#
# Note: This module is only called when trigger conditions are met, does not affect other architecture analysis

"""
HTTP Server Layer Gatekeeper Analyzer

Used for handling the following architecture:
    Browser -> mini_httpd (authentication) -> CGI program (business logic)

In this architecture, authentication checks are completed at the mini_httpd layer,
CGI programs obtain user identity through environment variables,
but typically do not perform authentication checks. Therefore, analyzing CGI alone would miss gatekeeper information.

This module's purpose:
1. Detect if this is a mini_httpd+CGI architecture
2. If so, analyze mini_httpd's authentication logic
3. Extract whitelist paths and authentication mechanisms
4. Supplement discovered gatekeeper information to ACDG
"""

import os
import re
import json
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field

try:
    from core.bridge.ida_client import IDAProClient
    from core.llm import LLMProvider
    from analysis.models import AuthMechanism
except ImportError:
    # For standalone testing
    pass


@dataclass
class HttpdGatekeeperInfo:
    """HTTP Server Layer Gatekeeper Information"""
    server_type: str = "mini_httpd"           # mini_httpd, thttpd, boa, etc.
    server_binary: str = ""                    # Server binary file path
    auth_function: str = ""                    # Authentication function name/address
    auth_function_addr: str = ""               # Authentication function address
    whitelist_paths: List[str] = field(default_factory=list)      # Whitelist paths
    whitelist_extensions: List[str] = field(default_factory=list) # Whitelist extensions
    session_mechanism: str = ""                # Session mechanism description
    confidence: float = 0.0                    # Confidence score
    description: str = ""                      # Detailed description


# Known lightweight HTTP server signatures
LIGHTWEIGHT_HTTPD_SIGNATURES = {
    "mini_httpd": {
        "binary_names": ["mini_httpd", "minihttpd", "mini-httpd"],
        "auth_functions": [
            "auth_check",           # Common auth function name
            "check_authorization",
            "do_authentication",
            "handle_auth",
        ],
        "auth_patterns": [
            r"\.htpasswd",          # HTTP Basic Auth password file
            r"Authorization:\s*Basic",  # Basic Auth Header
            r"WWW-Authenticate",    # 401 response header
            r"send_authenticate",   # Send authentication request
        ],
        "whitelist_patterns": [
            r"\.gif|\.jpg|\.png|\.css|\.js",  # Static resources
        ]
    },
    "thttpd": {
        "binary_names": ["thttpd", "tiny_httpd"],
        "auth_functions": ["auth_check", "do_auth"],
        "auth_patterns": [r"\.htpasswd", r"Authorization"],
    },
    "boa": {
        "binary_names": ["boa"],
        "auth_functions": ["check_authorization"],
        "auth_patterns": [r"\.htpasswd"],
    }
}


class HttpdArchitectureDetector:
    """
    HTTP Server + CGI Architecture Detector
    
    Determines whether current analysis needs to trace back HTTP Server layer authentication logic
    """
    
    def __init__(self, firmware_root: str = None, current_binary: str = None):
        """
        Args:
            firmware_root: Firmware filesystem root directory
            current_binary: Currently analyzed binary filename
        """
        self.firmware_root = firmware_root
        self.current_binary = current_binary or ""
        self.detected_httpd: Optional[str] = None
        self.httpd_path: Optional[str] = None
    
    def is_mini_httpd_cgi_architecture(self) -> bool:
        """
        Detect if this is a mini_httpd + CGI architecture
        
        Trigger conditions:
        1. Currently analyzing a CGI file
        2. Firmware contains lightweight HTTP servers like mini_httpd/thttpd
        
        Returns:
            True if this is a mini_httpd+CGI architecture
        """
        # Condition 1: Currently analyzing a CGI program
        if not self._is_cgi_binary():
            return False
        
        # Condition 2: Firmware contains lightweight HTTP server
        if not self._find_lightweight_httpd():
            return False
        
        return True
    
    def _is_cgi_binary(self) -> bool:
        """Check if current binary is a CGI program"""
        binary_lower = self.current_binary.lower()
        
        # CGI program characteristics
        cgi_patterns = [
            r"\.cgi$",              # Ends with .cgi
            r"setup\.cgi",          # Common in Netgear
            r"apply\.cgi",
            r"form2.*\.cgi",        # Common in D-Link
            r"webcgi",
        ]
        
        for pattern in cgi_patterns:
            if re.search(pattern, binary_lower):
                return True
        
        return False
    
    def _find_lightweight_httpd(self) -> bool:
        """
        Find lightweight HTTP server in firmware filesystem
        
        Returns:
            True if found
        """
        if not self.firmware_root or not os.path.exists(self.firmware_root):
            return False
        
        # Common httpd locations
        search_dirs = [
            "usr/sbin",
            "sbin",
            "usr/bin",
            "bin",
            "www",
        ]
        
        # All known lightweight httpd names
        httpd_names = []
        for server_info in LIGHTWEIGHT_HTTPD_SIGNATURES.values():
            httpd_names.extend(server_info["binary_names"])
        
        for search_dir in search_dirs:
            dir_path = os.path.join(self.firmware_root, search_dir)
            if not os.path.exists(dir_path):
                continue
            
            try:
                for filename in os.listdir(dir_path):
                    filename_lower = filename.lower()
                    for httpd_name in httpd_names:
                        if httpd_name in filename_lower:
                            self.httpd_path = os.path.join(dir_path, filename)
                            self.detected_httpd = httpd_name
                            return True
            except (PermissionError, OSError):
                continue
        
        return False
    
    def get_httpd_info(self) -> Dict:
        """Get detected HTTP Server information"""
        return {
            "detected": self.detected_httpd is not None,
            "server_type": self.detected_httpd,
            "server_path": self.httpd_path,
            "current_binary": self.current_binary,
        }


class HttpdGatekeeperAnalyzer:
    """
    HTTP Server Layer Gatekeeper Analyzer
    
    Analyzes authentication logic in lightweight HTTP servers like mini_httpd,
    extracts gatekeeper information and whitelist paths.
    
    Usage:
    1. First use HttpdArchitectureDetector to check if analysis is needed
    2. If needed, call analyze_httpd() to analyze the HTTP Server
    3. Merge the analysis results into ACDG
    """
    
    def __init__(self, ida_client: IDAProClient = None, llm: LLMProvider = None):
        self.ida = ida_client
        self.llm = llm
        self.gatekeeper_info: Optional[HttpdGatekeeperInfo] = None
        self.verbose = True
    
    def analyze_httpd(self, httpd_path: str, server_type: str = "mini_httpd") -> Optional[HttpdGatekeeperInfo]:
        """
        Analyze HTTP Server authentication logic
        
        Note: This method requires the httpd binary to be opened in IDA
        
        Args:
            httpd_path: HTTP Server binary file path
            server_type: Server type (mini_httpd, thttpd, etc.)
        
        Returns:
            HttpdGatekeeperInfo or None
        """
        if not self.ida:
            print("[HttpdGatekeeper] ERROR: IDA client not available")
            return None
        
        print(f"\n[HttpdGatekeeper] Analyzing {server_type} authentication...")
        print(f"    Binary: {httpd_path}")
        
        info = HttpdGatekeeperInfo(
            server_type=server_type,
            server_binary=httpd_path
        )
        
        # Step 1: Find authentication function
        auth_func = self._find_auth_function(server_type)
        if auth_func:
            info.auth_function = auth_func["name"]
            info.auth_function_addr = auth_func.get("address", "")
            info.confidence = 0.9
            print(f"    [+] Found auth function: {auth_func['name']} @ {auth_func.get('address', 'N/A')}")
        else:
            print("    [-] No auth function found")
            info.confidence = 0.3
        
        # Step 2: Extract whitelist
        whitelist = self._extract_whitelist(info.auth_function)
        info.whitelist_paths = whitelist.get("paths", [])
        info.whitelist_extensions = whitelist.get("extensions", [])
        
        if info.whitelist_paths or info.whitelist_extensions:
            print(f"    [+] Whitelist paths: {info.whitelist_paths[:5]}...")
            print(f"    [+] Whitelist extensions: {info.whitelist_extensions}")
        
        # Step 3: Analyze session mechanism
        session_info = self._analyze_session_mechanism()
        info.session_mechanism = session_info
        
        # Generate description
        info.description = self._generate_description(info)
        
        self.gatekeeper_info = info
        return info
    
    def _find_auth_function(self, server_type: str) -> Optional[Dict]:
        """
        Find authentication function in HTTP Server
        
        Uses multiple strategies:
        1. Search for known authentication function names
        2. Search for references to authentication-related strings
        3. Use LLM to analyze candidate functions
        """
        # Strategy 1: Search for known function names
        known_funcs = LIGHTWEIGHT_HTTPD_SIGNATURES.get(server_type, {}).get("auth_functions", [])
        for func_name in known_funcs:
            result = self.ida.search_functions(func_name)
            if result.get("status") == "ok":
                funcs = result.get("data", [])
                if funcs:
                    return {"name": funcs[0], "address": funcs[0]}
        
        # Strategy 2: Search for authentication-related strings
        auth_strings = [".htpasswd", "WWW-Authenticate", "Authorization"]
        for auth_str in auth_strings:
            str_result = self.ida.search_strings(auth_str)
            if str_result.get("status") == "ok":
                strings = str_result.get("data", [])
                for s in strings:
                    # Get references to the string
                    xrefs = self.ida.get_xrefs(s.get("address", ""), "to")
                    if xrefs.get("status") == "ok":
                        for xref in xrefs.get("data", []):
                            func_name = xref.get("func_name", "")
                            if func_name and "auth" in func_name.lower():
                                return {"name": func_name, "address": xref.get("address", "")}
        
        # Strategy 3: Search for send_authenticate function (mini_httpd specific)
        result = self.ida.search_functions("send_authenticate")
        if result.get("status") == "ok":
            funcs = result.get("data", [])
            if funcs:
                # Found send_authenticate, trace back to its callers
                xrefs = self.ida.get_xrefs(funcs[0], "to")
                if xrefs.get("status") == "ok":
                    for xref in xrefs.get("data", []):
                        func_name = xref.get("func_name", "")
                        if func_name:
                            # This caller is likely the auth_check function
                            return {"name": func_name, "address": xref.get("address", "")}
        
        return None
    
    def _extract_whitelist(self, auth_func: str) -> Dict:
        """
        Extract whitelist paths and extensions from authentication function
        
        Returns:
            {"paths": [...], "extensions": [...]}
        """
        if not auth_func or not self.ida:
            return {"paths": [], "extensions": []}
        
        # Decompile authentication function
        res = self.ida.decompile(auth_func)
        if res.get("status") != "ok":
            return {"paths": [], "extensions": []}
        
        code = res.get("data", {}).get("code", "")
        
        # Use LLM to analyze whitelist
        if self.llm:
            return self._extract_whitelist_with_llm(code, auth_func)
        
        # Simple regex extraction
        paths = []
        extensions = []
        
        # Extract path strings
        path_matches = re.findall(r'"(/[^"]+)"', code)
        paths.extend(path_matches)
        
        # Extract extensions
        ext_matches = re.findall(r'"\.([a-zA-Z0-9]{2,4})"', code)
        extensions.extend([f".{ext}" for ext in ext_matches])
        
        return {"paths": list(set(paths)), "extensions": list(set(extensions))}
    
    def _extract_whitelist_with_llm(self, code: str, func_name: str) -> Dict:
        """Use LLM to analyze whitelist"""
        prompt = f"""Analyze this HTTP server authentication function "{func_name}".
Identify paths and file types that BYPASS authentication (whitelist).

Look for:
- String comparisons that skip auth check
- File extension checks (e.g., .gif, .css, .js)
- Path prefix checks
- Conditions that return early without authentication

CODE:
```c
{code[:8000]}
```

Output JSON:
{{
    "paths": ["/login.htm", "/currentsetting.htm"],
    "extensions": [".gif", ".css", ".js", ".png"]
}}

JSON only:"""

        try:
            response = self.llm.chat([{"role": "user", "content": prompt}], json_mode=True)
            
            if isinstance(response, str):
                response = response.strip()
                if response.startswith("```"):
                    response = re.sub(r'^```json?\s*', '', response)
                    response = re.sub(r'\s*```$', '', response)
                response = json.loads(response)
            
            return {
                "paths": response.get("paths", []),
                "extensions": response.get("extensions", [])
            }
        except Exception as e:
            print(f"[HttpdGatekeeper] LLM whitelist extraction failed: {e}")
            return {"paths": [], "extensions": []}
    
    def _analyze_session_mechanism(self) -> str:
        """Analyze session mechanism"""
        # Search for session-related strings
        session_indicators = []
        
        session_strings = ["session", "cookie", "timeout", "last_access"]
        for s in session_strings:
            result = self.ida.search_strings(s) if self.ida else {"status": "error"}
            if result.get("status") == "ok" and result.get("data"):
                session_indicators.append(s)
        
        if "session" in session_indicators and "cookie" in session_indicators:
            return "Cookie-based session with timeout"
        elif "timeout" in session_indicators:
            return "Timeout-based session"
        else:
            return "Basic HTTP Authentication (no persistent session)"
    
    def _generate_description(self, info: HttpdGatekeeperInfo) -> str:
        """Generate gatekeeper description"""
        desc_parts = [f"{info.server_type} HTTP Basic Authentication"]
        
        if info.auth_function:
            desc_parts.append(f"Auth function: {info.auth_function}")
        
        if info.whitelist_paths:
            desc_parts.append(f"Whitelisted paths: {len(info.whitelist_paths)}")
        
        if info.whitelist_extensions:
            desc_parts.append(f"Whitelisted extensions: {', '.join(info.whitelist_extensions)}")
        
        if info.session_mechanism:
            desc_parts.append(f"Session: {info.session_mechanism}")
        
        return ". ".join(desc_parts)
    
    def to_auth_mechanism(self) -> Optional[AuthMechanism]:
        """Convert analysis result to AuthMechanism object"""
        if not self.gatekeeper_info:
            return None
        
        info = self.gatekeeper_info
        return AuthMechanism(
            address=info.auth_function_addr,
            name=f"{info.server_type}_gatekeeper",
            mechanism_type="httpd_gatekeeper",
            confidence=info.confidence,
            description=info.description,
            detection_method="httpd_layer_analysis"
        )
    
    def get_whitelist_paths(self) -> List[str]:
        """Get whitelist paths"""
        if not self.gatekeeper_info:
            return []
        return self.gatekeeper_info.whitelist_paths
    
    def get_whitelist_extensions(self) -> List[str]:
        """Get whitelist extensions"""
        if not self.gatekeeper_info:
            return []
        return self.gatekeeper_info.whitelist_extensions
    
    def is_path_whitelisted(self, path: str) -> Tuple[bool, str]:
        """
        Check if path is in whitelist
        
        Args:
            path: Path to check
            
        Returns:
            (is_whitelisted, reason)
        """
        if not self.gatekeeper_info:
            return False, ""
        
        # Check exact path
        for wl_path in self.gatekeeper_info.whitelist_paths:
            if path == wl_path or path.endswith(wl_path):
                return True, f"Matches whitelist path: {wl_path}"
        
        # Check extension
        for ext in self.gatekeeper_info.whitelist_extensions:
            if path.endswith(ext):
                return True, f"Matches whitelist extension: {ext}"
        
        return False, ""


def should_analyze_httpd_layer(
    firmware_root: str,
    current_binary: str,
    detected_architecture: str
) -> Tuple[bool, Optional[str]]:
    """
    Determine if HTTP Server layer analysis is needed
    
    This is a convenience function for quick judgment in LogicDecoupler
    
    Args:
        firmware_root: Firmware filesystem root directory
        current_binary: Currently analyzed binary file name
        detected_architecture: Detected architecture type
    
    Returns:
        (should_analyze, httpd_path)
    """
    # Exclusion conditions: These architectures don't need httpd layer tracing
    excluded_architectures = [
        "GoAhead",      # GoAhead is an integrated architecture, httpd is the app
        "GoForm",       # GoForm already includes auth analysis
        "JSONRPC",      # JSONRPC already includes auth analysis
        "Lighttpd",     # Already has dedicated FastCGI handling
        "FastCGI",      # Same as above
    ]
    
    if detected_architecture in excluded_architectures:
        return False, None
    
    # Use architecture detector
    detector = HttpdArchitectureDetector(firmware_root, current_binary)
    
    if detector.is_mini_httpd_cgi_architecture():
        return True, detector.httpd_path
    
    return False, None


# ==================== Test Code ====================

if __name__ == "__main__":
    # Test architecture detection
    print("=" * 60)
    print("HttpdGatekeeperAnalyzer Test")
    print("=" * 60)
    
    # Test 1: Architecture detection
    test_firmware = r"/path/to/firmware/squashfs-root"
    test_binary = "setup.cgi"
    
    detector = HttpdArchitectureDetector(test_firmware, test_binary)
    result = detector.is_mini_httpd_cgi_architecture()
    
    print(f"\nTest case: {test_binary} in Netgear firmware")
    print(f"  Is mini_httpd+CGI architecture: {result}")
    print(f"  Detected info: {detector.get_httpd_info()}")
    
    # Test 2: should_analyze_httpd_layer function
    print("\n" + "-" * 60)
    print("Testing should_analyze_httpd_layer():")
    
    test_cases = [
        ("setup.cgi", "auto", "Should trigger"),
        ("httpd", "GoAhead", "Should NOT trigger (GoAhead)"),
        ("cgibin.cgi", "FastCGI", "Should NOT trigger (FastCGI)"),
    ]
    
    for binary, arch, expected in test_cases:
        should, path = should_analyze_httpd_layer(test_firmware, binary, arch)
        print(f"  {binary} ({arch}): {should} - {expected}")
