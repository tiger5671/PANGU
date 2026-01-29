# Copyright (c) 2026 The Pangu Project Authors. All rights reserved.
# analysis/goform_extractor.py
# PANGU GoForm Route Extractor
# For extracting routes from lighttpd mod_form.so style (if-else strcmp dispatch)

"""
GoForm Route Extractor

Applicable to:
- Linksys E1700 and other devices using lighttpd + mod_form.so
- Route dispatch implemented through strcmp(action, "routeName") if-else chains
- /goform/ style routes

Architecture Characteristics:
1. Has mod_form_plugin_init initialization function
2. Route dispatch function uses strcmp(a3, "routeName") pattern
3. Each route calls corresponding handler function
"""

import re
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass
from analysis.models import RouteNode, AuthState


@dataclass
class GoFormRoute:
    """GoForm Route Information"""
    name: str                    # Route name (e.g., "setWan")
    handler_addr: int           # Handler function address
    handler_name: str           # Handler function name
    path: str = ""              # Full path (e.g., "/goform/setWan")
    method: str = "POST"        # HTTP method
    auth_state: str = "Unknown" # Authentication state (consistent with AuthState enum)


class GoFormExtractor:
    """
    GoForm Route Extractor
    
    Specialized for extracting routes from lighttpd mod_form modules.
    These modules use strcmp chains to dispatch route requests.
    """
    
    # Architecture detection features
    DETECTION_STRINGS = [
        "mod_form_plugin_init",
        "form.path",
        "/goform/",
    ]
    
    def __init__(self, ida_client, llm_client=None, verbose: bool = True):
        self.ida = ida_client
        self.llm = llm_client
        self.verbose = verbose
        self.routes: List[GoFormRoute] = []
        self.output_dir = "output"
        
    def log(self, msg: str):
        if self.verbose:
            print(msg)
    
    def run(self, use_llm: bool = False) -> List[RouteNode]:
        """
        Run route extraction (consistent interface with other Extractors)
        
        Args:
            use_llm: Whether to use LLM assistance (currently unused)
            
        Returns:
            List[RouteNode]
        """
        return self.extract()
    
    def save_routes(self, firmware_name: str) -> str:
        """
        Save extracted routes to file
        
        Args:
            firmware_name: Firmware name
            
        Returns:
            Output file path
        """
        import os
        import json
        
        output_file = os.path.join(self.output_dir, f"{firmware_name}_routes.json")
        
        # Get authentication info
        auth_func = getattr(self, 'auth_info', {}).get('auth_function', 'checkToken')
        has_global_auth = getattr(self, 'auth_info', {}).get('has_global_auth', False)
        
        # Convert to dictionary format (compatible with RouteNode.from_dict)
        routes_data = []
        for route in self.routes:
            # Determine protection_type
            if route.auth_state == "Auth-Required" and has_global_auth:
                protection_type = "Gatekeeper"
                protection_detail = f"Protected by {auth_func}"
            elif route.auth_state == "Auth-Free":
                protection_type = "None"
                protection_detail = "Whitelisted route (no auth required)"
            else:
                protection_type = "None"
                protection_detail = ""
            
            routes_data.append({
                "path": route.path,
                "sub_path": route.name,
                "handler": route.handler_name,  # RouteNode uses handler field
                "source_hub": "mod_form_dispatcher",
                "source_type": "GoForm",
                "root": "/goform/",
                "auth_state": route.auth_state,
                "protection_type": protection_type,
                "protection_detail": protection_detail,
                "metadata": {
                    "architecture": "GoForm",
                    "route_name": route.name,
                    "handler_addr": hex(route.handler_addr) if route.handler_addr else "0x0",
                    "method": route.method
                }
            })
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(routes_data, f, indent=2, ensure_ascii=False)
        
        return output_file
    
    def detect(self) -> Tuple[bool, float]:
        """
        Detect if this is GoForm architecture
        
        Returns:
            (is_goform, confidence)
        """
        score = 0
        
        # Check key functions
        result = self.ida.get_functions()
        if result.get("status") != "ok":
            return False, 0.0
        
        funcs = {f['name']: f for f in result.get("data", [])}
        
        if "mod_form_plugin_init" in funcs:
            score += 40
            self.log("  [+] Found mod_form_plugin_init")
        
        # Check key strings
        for pattern in self.DETECTION_STRINGS:
            str_result = self.ida.search_strings(pattern)
            if str_result.get("status") == "ok" and str_result.get("data"):
                score += 20
                self.log(f"  [+] Found string: {pattern}")
        
        confidence = min(score / 100.0, 1.0)
        return confidence > 0.5, confidence
    
    def extract(self) -> List[RouteNode]:
        """
        Extract GoForm routes
        
        Returns:
            List[RouteNode]
        """
        self.log("\n" + "=" * 60)
        self.log("[GoForm Extractor] Starting route extraction")
        self.log("=" * 60)
        
        # Step 1: Find route dispatcher function
        dispatcher = self._find_dispatcher()
        if not dispatcher:
            self.log("[!] Could not find route dispatcher function")
            return []
        
        self.log(f"\n[+] Found dispatcher at {hex(dispatcher)}")
        self.dispatcher_addr = dispatcher  # Save dispatcher address
        
        # Step 2: Extract routes from dispatcher function
        self._extract_routes_from_dispatcher(dispatcher)
        
        # Step 3: Analyze authentication mechanism and apply to routes
        auth_info = self.analyze_authentication(dispatcher)
        self.auth_info = auth_info  # Save auth info
        
        if auth_info.get("has_global_auth"):
            self.apply_auth_analysis_to_routes(auth_info)
        
        # Step 4: Convert to RouteNode
        route_nodes = self._to_route_nodes()
        
        self.log(f"\n[GoForm] Extracted {len(route_nodes)} routes")
        return route_nodes
        return route_nodes
    
    def _find_dispatcher(self) -> Optional[int]:
        """
        Find route dispatcher function
        
        Strategy:
        1. Trace registered handler from mod_form_plugin_init
        2. Deep trace to find function containing route strcmp chains
        3. Select function with most strcmp calls as dispatcher
        """
        result = self.ida.get_functions()
        if result.get("status") != "ok":
            return None
        
        funcs = {f['name']: f for f in result.get("data", [])}
        
        best_dispatcher = None
        best_strcmp_count = 0
        
        # Find mod_form_plugin_init
        if "mod_form_plugin_init" in funcs:
            init_addr = int(funcs["mod_form_plugin_init"]['addr'], 16)
            self.log(f"  [*] Analyzing mod_form_plugin_init at {hex(init_addr)}...")
            
            # Decompile init function
            code_result = self.ida.decompile(init_addr)
            if code_result.get("status") == "ok":
                code = code_result.get("data", {}).get("code", "")
                
                # Find registered handlers from init
                handler_matches = re.findall(r'a1\[\d+\]\s*=\s*(sub_[0-9A-Fa-f]+)', code)
                self.log(f"    Found {len(handler_matches)} registered handlers")
                
                # Deep traverse each handler function
                for handler in handler_matches:
                    handler_addr = int(handler.replace("sub_", ""), 16)
                    
                    # Check this function itself
                    strcmp_count = self._count_strcmp_calls(handler_addr)
                    if strcmp_count > best_strcmp_count:
                        best_strcmp_count = strcmp_count
                        best_dispatcher = handler_addr
                        self.log(f"    [+] {handler} has {strcmp_count} strcmp calls")
                    
                    # Trace sub-functions called by this function
                    called_funcs = self._get_called_functions(handler_addr)
                    for called_addr in called_funcs:
                        sub_strcmp_count = self._count_strcmp_calls(called_addr)
                        if sub_strcmp_count > best_strcmp_count:
                            best_strcmp_count = sub_strcmp_count
                            best_dispatcher = called_addr
                            self.log(f"    [+] sub_{called_addr:X} has {sub_strcmp_count} strcmp calls")
        
        # If dispatcher found, return it
        if best_dispatcher and best_strcmp_count > 10:
            return best_dispatcher
        
        # Method 2: Scan all functions, find one with most strcmp
        self.log("  [*] Scanning all functions for dispatcher...")
        for func in result.get("data", []):
            addr = int(func['addr'], 16)
            strcmp_count = self._count_strcmp_calls(addr)
            if strcmp_count > best_strcmp_count:
                best_strcmp_count = strcmp_count
                best_dispatcher = addr
        
        return best_dispatcher
    
    def _count_strcmp_calls(self, addr: int) -> int:
        """Count strcmp calls in a function"""
        code_result = self.ida.decompile(addr)
        if code_result.get("status") != "ok":
            return 0
        
        code = code_result.get("data", {}).get("code", "")
        
        # Count strcmp calls
        strcmp_count = len(re.findall(r'strcmp\s*\(\s*\w+\s*,\s*"[^"]+"\s*\)', code))
        return strcmp_count
    
    def _get_called_functions(self, addr: int) -> List[int]:
        """Get addresses of other functions called within this function"""
        code_result = self.ida.decompile(addr)
        if code_result.get("status") != "ok":
            return []
        
        code = code_result.get("data", {}).get("code", "")
        
        # Extract called sub_XXXXX functions
        called_funcs = []
        matches = re.findall(r'(sub_[0-9A-Fa-f]+)\s*\(', code)
        for match in matches:
            func_addr = int(match.replace("sub_", ""), 16)
            called_funcs.append(func_addr)
        
        return list(set(called_funcs))
        
        return None
    
    def _is_route_dispatcher(self, addr: int) -> bool:
        """Check if function is a route dispatcher"""
        code_result = self.ida.decompile(addr)
        if code_result.get("status") != "ok":
            return False
        
        code = code_result.get("data", {}).get("code", "")
        
        # Count strcmp calls
        strcmp_count = len(re.findall(r'strcmp\s*\(\s*\w+\s*,\s*"[^"]+"\s*\)', code))
        
        # If more than 10 strcmp calls, likely a route dispatcher
        if strcmp_count > 10:
            self.log(f"    [+] Function at {hex(addr)} has {strcmp_count} strcmp calls")
            return True
        
        return False
    
    def _extract_routes_from_dispatcher(self, dispatcher_addr: int):
        """Extract routes from dispatcher function"""
        code_result = self.ida.decompile(dispatcher_addr)
        if code_result.get("status") != "ok":
            self.log("[!] Failed to decompile dispatcher")
            return
        
        code = code_result.get("data", {}).get("code", "")
        
        # Extract strcmp(a3, "routeName") pattern
        # Support multiple variants:
        # - if ( !strcmp(a3, "setWan") )
        # - strcmp(v5, "routeName")
        patterns = [
            r'strcmp\s*\(\s*\w+\s*,\s*"([^"]+)"\s*\)',  # strcmp(a3, "name")
            r'!strcmp\s*\(\s*\w+\s*,\s*"([^"]+)"\s*\)',  # !strcmp(a3, "name")
        ]
        
        route_names = set()
        for pattern in patterns:
            matches = re.findall(pattern, code)
            route_names.update(matches)
        
        self.log(f"\n[+] Found {len(route_names)} route patterns")
        
        # Extract corresponding handler function for each route
        for route_name in route_names:
            handler = self._find_handler_for_route(code, route_name)
            
            route = GoFormRoute(
                name=route_name,
                handler_addr=handler.get("addr", 0) if handler else 0,
                handler_name=handler.get("name", "unknown") if handler else "unknown",
                path=f"/goform/{route_name}",
                method="POST"
            )
            
            self.routes.append(route)
            self.log(f"    /goform/{route_name} -> {route.handler_name}")
    
    def _find_handler_for_route(self, dispatcher_code: str, route_name: str) -> Optional[Dict]:
        """
        Find handler function for a specific route
        
        Pattern:
        if ( !strcmp(a3, "routeName") )
        {
            handler(a1, a2, v5);
            return 0;
        }
        """
        # Build regex to match route and its handler function
        # Pattern 1: Direct call to named function
        pattern1 = rf'strcmp\s*\([^,]+,\s*"{re.escape(route_name)}"\s*\)[^{{]*\{{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        match = re.search(pattern1, dispatcher_code)
        if match:
            func_name = match.group(1)
            return {"name": func_name, "addr": 0}
        
        # Pattern 2: Call to sub_XXXXX
        pattern2 = rf'strcmp\s*\([^,]+,\s*"{re.escape(route_name)}"\s*\)[^{{]*\{{\s*(sub_[0-9A-Fa-f]+)\s*\('
        match = re.search(pattern2, dispatcher_code)
        if match:
            func_name = match.group(1)
            addr = int(func_name.replace("sub_", ""), 16)
            return {"name": func_name, "addr": addr}
        
        # Pattern 3: Simplified matching - just find function name
        pattern3 = rf'"{re.escape(route_name)}"[^;]*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\s*a\d'
        match = re.search(pattern3, dispatcher_code)
        if match:
            func_name = match.group(1)
            return {"name": func_name, "addr": 0}
        
        return None
    
    def _to_route_nodes(self) -> List[RouteNode]:
        """Convert to RouteNode list"""
        nodes = []
        
        for route in self.routes:
            node = RouteNode(
                path=route.path,
                sub_path=route.name,
                handler=route.handler_name,
                source_hub="mod_form_dispatcher",
                source_type="GoForm",
                root="/goform/",
                auth_state=AuthState(route.auth_state) if route.auth_state in ["Auth-Required", "Auth-Free", "Unknown"] else AuthState.UNKNOWN
            )
            nodes.append(node)
        
        return nodes
    
    def analyze_authentication(self, dispatcher_addr: int) -> Dict:
        """
        Analyze GoForm architecture authentication mechanism
        
        GoForm typical authentication pattern:
        1. Get token parameter: sub_3970(v5, "token", "")
        2. Read TokenDisable config: nvram_bufget(0, "TokenDisable")
        3. Whitelist check: for (i=16; i>=0; --i) if (!strcmp(a3, *v15++)) v6=0;
        4. Auth check: if (atoi(v8) != 1 && v6 && !checkToken(a1, v7)) { redirect; return; }
        
        Returns:
            {
                "has_global_auth": True/False,
                "auth_function": "checkToken",
                "whitelist_routes": ["webLogin", "formLogin", ...],
                "bypass_conditions": ["TokenDisable=1"]
            }
        """
        self.log("\n[GoForm Auth] Analyzing authentication mechanism...")
        
        result = {
            "has_global_auth": False,
            "auth_function": None,
            "auth_function_addr": None,
            "whitelist_routes": [],
            "bypass_conditions": []
        }
        
        # Decompile dispatcher
        code_result = self.ida.decompile(dispatcher_addr)
        if code_result.get("status") != "ok":
            return result
        
        code = code_result.get("data", {}).get("code", "")
        
        # Detect checkToken call
        if "checkToken" in code:
            result["has_global_auth"] = True
            result["auth_function"] = "checkToken"
            self.log("  [+] Found global auth: checkToken()")
            
            # Get checkToken address
            funcs_result = self.ida.get_functions()
            if funcs_result.get("status") == "ok":
                for f in funcs_result.get("data", []):
                    if f["name"] == "checkToken":
                        result["auth_function_addr"] = f["addr"]
                        break
        
        # Detect TokenDisable bypass condition
        if "TokenDisable" in code:
            result["bypass_conditions"].append("TokenDisable=1 (NVRAM flag)")
            self.log("  [+] Found bypass condition: TokenDisable NVRAM flag")
        
        # Extract whitelist routes
        # Pattern: Before checkToken there's a whitelist check loop
        # for ( i = 16; i >= 0; --i ) { if ( !strcmp(a3, *v15++) ) v6 = 0; }
        # Whitelist routes stored in an array (off_AF84C)
        whitelist = self._extract_auth_whitelist(code)
        result["whitelist_routes"] = whitelist
        
        if whitelist:
            self.log(f"  [+] Found {len(whitelist)} whitelisted routes:")
            for r in whitelist[:10]:
                self.log(f"      - {r}")
            if len(whitelist) > 10:
                self.log(f"      ... and {len(whitelist) - 10} more")
        
        return result
    
    def _extract_auth_whitelist(self, dispatcher_code: str) -> List[str]:
        """
        Extract authentication whitelist from dispatcher code
        
        Whitelisted routes are those handled directly before the checkToken check,
        or routes that skip authentication through whitelist array check.
        
        GoForm authentication logic:
        1. Copy whitelist array from off_AF84C to v100
        2. Loop for (i=16; i>=0; --i) { if (!strcmp(a3, *v15++)) v6=0; }
        3. If v6==0, route is whitelisted, skip authentication
        """
        whitelist = []
        
        # Method 1: Extract off_XXXXX array address from dispatcher code
        array_match = re.search(r'v\d+\s*=\s*(off_[0-9A-Fa-f]+)', dispatcher_code)
        if array_match:
            array_name = array_match.group(1)
            array_addr = int(array_name.replace("off_", ""), 16)
            self.log(f"  [*] Found whitelist array at {array_name} ({hex(array_addr)})")
            
            # Determine array size - get from loop counter (i = 16 means 17 elements)
            loop_match = re.search(r'for\s*\(\s*i\s*=\s*(\d+)', dispatcher_code)
            array_size = 17  # Default
            if loop_match:
                array_size = int(loop_match.group(1)) + 1
                self.log(f"  [*] Array size: {array_size} elements")
            
            # Read array content via IDA
            whitelist = self._read_string_array(array_addr, array_size)
        
        # Method 2: Based on known whitelist route patterns
        # These routes are typically whitelisted
        known_whitelist_patterns = [
            "webLogin", "formLogin", "formLogout", "setToken",
            "updateBurnProgress", "updateIPAddress", "langSwitch",
        ]
        
        for route in self.routes:
            if route.name in known_whitelist_patterns:
                if route.name not in whitelist:
                    whitelist.append(route.name)
        
        return whitelist
    
    def _read_string_array(self, array_addr: int, count: int) -> List[str]:
        """
        Read string pointer array from IDA
        
        Args:
            array_addr: Array start address
            count: Number of elements
            
        Returns:
            List of strings
        """
        strings = []
        
        try:
            for i in range(count):
                ptr_addr = array_addr + i * 4  # 32-bit pointer
                
                # Read pointer value
                r = self.ida.resolve_data(ptr_addr, 4)
                if r.get("status") != "ok":
                    continue
                
                # Parse pointer
                data = r.get("data", {})
                ptr_value = data.get("value", 0)
                
                if not ptr_value:
                    continue
                
                # Read string
                str_r = self.ida.resolve_data(ptr_value, 64)
                if str_r.get("status") == "ok":
                    raw = str_r.get("data", {}).get("raw", "")
                    if raw:
                        try:
                            # Convert hex string to bytes
                            str_bytes = bytes.fromhex(raw)
                            # Extract null-terminated string
                            null_idx = str_bytes.find(b'\x00')
                            if null_idx > 0:
                                s = str_bytes[:null_idx].decode('latin-1', errors='ignore')
                                if s and s.isprintable():
                                    strings.append(s)
                                    self.log(f"      Whitelist[{i}]: {s}")
                        except:
                            pass
        except Exception as e:
            self.log(f"  [!] Error reading string array: {e}")
        
        return strings
    
    def apply_auth_analysis_to_routes(self, auth_info: Dict):
        """
        Apply authentication analysis results to routes
        
        Args:
            auth_info: Result from analyze_authentication()
        """
        if not auth_info.get("has_global_auth"):
            # No global authentication, mark all routes as Auth-Free (high risk)
            self.log("[!] WARNING: No global authentication detected!")
            for route in self.routes:
                route.auth_state = "Auth-Free"
            return
        
        # Has global authentication
        whitelist = set(auth_info.get("whitelist_routes", []))
        
        for route in self.routes:
            if route.name in whitelist:
                # Whitelisted route
                route.auth_state = "Auth-Free"
            else:
                # Protected route
                route.auth_state = "Auth-Required"
        
        # Statistics
        auth_required = sum(1 for r in self.routes if r.auth_state == "Auth-Required")
        auth_free = sum(1 for r in self.routes if r.auth_state == "Auth-Free")
        self.log(f"\n[GoForm Auth] Applied auth analysis:")
        self.log(f"  Auth-Required: {auth_required}")
        self.log(f"  Auth-Free: {auth_free}")


def detect_goform_architecture(ida_client) -> Tuple[bool, float]:
    """
    Quick detection of GoForm architecture
    
    Returns:
        (is_goform, confidence)
    """
    extractor = GoFormExtractor(ida_client, verbose=False)
    return extractor.detect()
