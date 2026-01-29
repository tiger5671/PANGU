# Copyright (c) 2026 The Pangu Project Authors. All rights reserved.
# analysis/logic_decoupler.py
# PANGU Logic Decoupling Module
# Implementation of Section 3.3: Logic Decoupling and State Identification
# Includes: Global authentication mechanism identification, local constraint analysis, ACDG construction

import sys
import os
import json
import glob
import re
from datetime import datetime
from collections import Counter
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field

sys.path.append(os.getcwd())

from core.bridge.ida_client import IDAProClient
from core.llm import LLMProvider
from analysis.models import (
    ACDG, RouteNode, AuthMechanism, AuthState, ProtectionType
)

# Import GoAhead-specific analyzer
try:
    from analysis.goahead_analyzer import GoAheadAnalyzer, GoAheadHandlerInfo, StaticTableContext
    GOAHEAD_AVAILABLE = True
except ImportError:
    GOAHEAD_AVAILABLE = False

# Import HTTP Server layer gatekeeper analyzer (for mini_httpd+CGI architecture)
try:
    from analysis.httpd_gatekeeper_analyzer import (
        HttpdGatekeeperAnalyzer,
        HttpdArchitectureDetector,
        should_analyze_httpd_layer
    )
    HTTPD_GATEKEEPER_AVAILABLE = True
except ImportError:
    HTTPD_GATEKEEPER_AVAILABLE = False


@dataclass
class GatekeeperInfo:
    """Gatekeeper Information"""
    name: str                                    # Gatekeeper function name
    address: str = ""                            # Function address
    protected_prefixes: List[str] = field(default_factory=list)  # Protected URL prefixes
    whitelist_paths: List[str] = field(default_factory=list)     # Whitelist paths
    whitelist_patterns: List[str] = field(default_factory=list)  # Whitelist patterns
    confidence: float = 0.0                      # Confidence score
    description: str = ""                        # Description


class GatekeeperAnalyzer:
    """
    Gatekeeper Analyzer
    Uses LLM semantic understanding to analyze global authentication function protection scope and whitelist
    """
    
    def __init__(self, ida_client: IDAProClient, llm: LLMProvider):
        self.ida = ida_client
        self.llm = llm
        self.gatekeepers: List[GatekeeperInfo] = []
    
    def find_gatekeepers_from_init(self, init_func: str = "sub_2E9EC") -> List[GatekeeperInfo]:
        """
        Discover gatekeepers from initialization function
        
        Args:
            init_func: Web initialization function name/address
        
        Returns:
            List of discovered gatekeepers
        """
        print(f"[Gatekeeper] Analyzing init function: {init_func}")
        
        # Decompile initialization function
        res = self.ida.decompile(init_func)
        if res.get("status") != "ok":
            print(f"[Gatekeeper] Failed to decompile {init_func}")
            return []
        
        code = res.get("data", {}).get("code", "")
        
        # === Detect TP-Link architecture ===
        # TP-Link uses httpRpmConfAdd + unCheckRefererUrlAdd pattern
        if "unCheckRefererUrlAdd" in code or "httpRpmConfAdd" in code:
            print(f"[Gatekeeper] Detected TP-Link architecture (Referer-based auth)")
            return self._analyze_tplink_init(code, init_func)
        
        # Use LLM to analyze initialization code and identify handler registration patterns
        gatekeepers = self._analyze_init_with_llm(code)
        
        # Deep analysis for each gatekeeper
        for gk in gatekeepers:
            self._analyze_gatekeeper_function(gk)
        
        self.gatekeepers = gatekeepers
        return gatekeepers
    
    def _analyze_tplink_init(self, init_code: str, init_func: str) -> List[GatekeeperInfo]:
        """
        Analyze TP-Link architecture initialization code
        
        TP-Link uses Referer check mechanism:
        - unCheckRefererUrlAdd("/path") adds whitelist path
        - httpRpmConfAdd(priority, path, handler) registers route
        
        Returns:
            List of gatekeepers (with whitelist information)
        """
        import re
        
        # Extract all unCheckRefererUrlAdd call parameters (whitelist paths)
        whitelist_paths = []
        
        # Extract from current initialization function
        pattern = r'unCheckRefererUrlAdd\s*\(\s*"([^"]+)"\s*\)'
        matches = re.findall(pattern, init_code)
        whitelist_paths.extend(matches)
        
        # Search all functions that call unCheckRefererUrlAdd to collect complete whitelist
        try:
            xrefs_res = self.ida.get_xrefs("unCheckRefererUrlAdd", "to")
            if xrefs_res.get("status") == "ok":
                xrefs = xrefs_res.get("data", [])
                seen_funcs = set()
                
                for xref in xrefs:
                    func_name = xref.get("func_name", "")
                    if func_name and func_name not in seen_funcs:
                        seen_funcs.add(func_name)
                        # Decompile this function to extract whitelist
                        func_res = self.ida.decompile(func_name)
                        if func_res.get("status") == "ok":
                            func_code = func_res.get("data", {}).get("code", "")
                            matches = re.findall(pattern, func_code)
                            whitelist_paths.extend(matches)
        except Exception as e:
            print(f"[Gatekeeper] Error collecting TP-Link whitelist: {e}")
        
        # Deduplicate
        whitelist_paths = list(set(whitelist_paths))
        
        if whitelist_paths:
            print(f"[Gatekeeper] TP-Link whitelist paths ({len(whitelist_paths)}):")
            for path in whitelist_paths[:10]:
                print(f"    - {path}")
            if len(whitelist_paths) > 10:
                print(f"    ... and {len(whitelist_paths) - 10} more")
        
        # Create a virtual gatekeeper to represent TP-Link's Referer check mechanism
        gatekeeper = GatekeeperInfo(
            name="TPLinkRefererCheck",
            address="",
            protected_prefixes=["/userRpm/"],  # TP-Link primarily protects /userRpm/ paths
            whitelist_paths=whitelist_paths,
            whitelist_patterns=[],
            confidence=0.85,
            description="TP-Link Referer-based authentication. Routes not in whitelist require valid Referer header from authenticated session."
        )
        
        self.gatekeepers = [gatekeeper]
        return [gatekeeper]
    
    def _analyze_init_with_llm(self, init_code: str) -> List[GatekeeperInfo]:
        """Use LLM to analyze initialization code and identify gatekeepers"""
        
        prompt = f"""Analyze this Web server initialization code from router firmware.
Identify any GLOBAL SECURITY HANDLER that processes ALL requests before routing.

Look for patterns like:
- Handler registered with security/auth keywords in name
- Handler registered before route-specific handlers  
- Handler with higher priority parameter
- Handler without URL path prefix (handles all paths)

CODE:
```c
{init_code[:6000]}
```

For each security handler found, output JSON:
{{
    "gatekeepers": [
        {{
            "name": "function_name",
            "reason": "why this is a global security handler",
            "protected_prefixes": ["/goform", "/cgi-bin"],  // URL prefixes this handler protects, empty means all
            "confidence": 0.9  // 0.0-1.0
        }}
    ]
}}

If no global security handler found, return {{"gatekeepers": []}}
Output JSON only:"""

        try:
            response = self.llm.chat([{"role": "user", "content": prompt}], json_mode=True)
            
            if isinstance(response, str):
                response = response.strip()
                # Clean markdown markers
                if response.startswith("```"):
                    response = re.sub(r'^```json?\s*', '', response)
                    response = re.sub(r'\s*```$', '', response)
                response = json.loads(response)
            
            gatekeepers = []
            for gk_data in response.get("gatekeepers", []):
                gk = GatekeeperInfo(
                    name=gk_data.get("name", ""),
                    protected_prefixes=gk_data.get("protected_prefixes", []),
                    confidence=gk_data.get("confidence", 0.5),
                    description=gk_data.get("reason", "")
                )
                if gk.name:
                    gatekeepers.append(gk)
                    print(f"[Gatekeeper] Found: {gk.name} (confidence: {gk.confidence})")
            
            return gatekeepers
            
        except Exception as e:
            print(f"[Gatekeeper] LLM analysis failed: {e}")
            return []
    
    def _analyze_gatekeeper_function(self, gatekeeper: GatekeeperInfo):
        """Deep analysis of gatekeeper function to extract whitelist"""
        print(f"[Gatekeeper] Analyzing whitelist for: {gatekeeper.name}")
        
        # Decompile gatekeeper function
        res = self.ida.decompile(gatekeeper.name)
        if res.get("status") != "ok":
            print(f"[Gatekeeper] Failed to decompile {gatekeeper.name}")
            return
        
        code = res.get("data", {}).get("code", "")
        gatekeeper.address = res.get("data", {}).get("address", "")
        
        # Use LLM to extract whitelist
        whitelist = self._extract_whitelist_with_llm(code, gatekeeper.name)
        gatekeeper.whitelist_paths = whitelist.get("paths", [])
        gatekeeper.whitelist_patterns = whitelist.get("patterns", [])
        
        print(f"[Gatekeeper] Whitelist paths: {gatekeeper.whitelist_paths}")
        print(f"[Gatekeeper] Whitelist patterns: {gatekeeper.whitelist_patterns}")
    
    def _extract_whitelist_with_llm(self, gatekeeper_code: str, func_name: str) -> Dict:
        """Use LLM to extract whitelist from gatekeeper code"""
        
        prompt = f"""Analyze this security handler function "{func_name}" from router firmware.
This function checks authentication before allowing access to routes.

Identify ALL paths/patterns that BYPASS authentication (whitelist):
- Look for string comparisons with paths (strcmp, strncmp, memcmp)
- Look for paths that skip authentication check
- Look for conditions that allow unauthenticated access

CODE:
```c
{gatekeeper_code[:8000]}
```

Output JSON with:
{{
    "paths": ["/login.html", "/redirect.html"],  // Exact paths that bypass auth
    "patterns": ["*.js", "*.css", "/public/*"],  // Patterns that bypass auth
    "analysis": "Brief explanation of the auth logic"
}}

Output JSON only:"""

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
                "patterns": response.get("patterns", [])
            }
            
        except Exception as e:
            print(f"[Gatekeeper] Whitelist extraction failed: {e}")
            return {"paths": [], "patterns": []}
    
    def is_path_whitelisted(self, path: str) -> Tuple[bool, str]:
        """
        Check if path is in whitelist
        
        Returns:
            (is_whitelisted, reason)
        """
        for gk in self.gatekeepers:
            # Check exact path match
            for wl_path in gk.whitelist_paths:
                if path == wl_path or path.endswith(wl_path):
                    return True, f"Matches whitelist path: {wl_path}"
            
            # Check patterns
            for pattern in gk.whitelist_patterns:
                if self._match_pattern(path, pattern):
                    return True, f"Matches whitelist pattern: {pattern}"
        
        return False, ""
    
    def _match_pattern(self, path: str, pattern: str) -> bool:
        """Simple pattern matching"""
        if pattern.startswith("*"):
            return path.endswith(pattern[1:])
        elif pattern.endswith("*"):
            return path.startswith(pattern[:-1])
        elif "*" in pattern:
            parts = pattern.split("*")
            return path.startswith(parts[0]) and path.endswith(parts[-1])
        else:
            return path == pattern
    
    def is_path_protected(self, path: str) -> Tuple[bool, str]:
        """
        Check if path is protected by gatekeeper
        
        Returns:
            (is_protected, gatekeeper_name)
        """
        for gk in self.gatekeepers:
            # If gatekeeper has no specified protection prefix, protect all paths
            if not gk.protected_prefixes:
                return True, gk.name
            
            # Check if path matches protection prefix
            for prefix in gk.protected_prefixes:
                if path.startswith(prefix):
                    return True, gk.name
        
        return False, ""


class GlobalAuthIdentifier:
    """
    Global Authentication Mechanism Identifier
    Implementation of Section 3.3.1: Global Authentication Mechanism Identification
    """
    
    def __init__(self, ida_client: IDAProClient, llm: LLMProvider):
        self.ida = ida_client
        self.llm = llm
        self.identified_mechanisms: List[AuthMechanism] = []
    
    def identify(self, dispatch_hubs: List[str]) -> List[AuthMechanism]:
        """
        Identify global authentication mechanisms
        
        Args:
            dispatch_hubs: List of route dispatch hub addresses
        
        Returns:
            List of identified global authentication mechanisms
        """
        print("[GlobalAuth] Starting global authentication mechanism identification...")
        
        for hub_addr in dispatch_hubs:
            self._analyze_hub_context(hub_addr)
        
        print(f"[GlobalAuth] Identified {len(self.identified_mechanisms)} global auth mechanisms")
        return self.identified_mechanisms
    
    def _analyze_hub_context(self, hub_addr: str):
        """Analyze hub dominator context"""
        print(f"[GlobalAuth] Analyzing hub context: {hub_addr}")
        
        # Step 1: Get basic blocks
        blocks_res = self.ida.get_basic_blocks(hub_addr)
        if blocks_res.get("status") != "ok":
            return
        
        # Step 2: Build dominator tree
        dom_res = self.ida.build_dominator_tree(hub_addr)
        if dom_res.get("status") != "ok":
            return
        
        dom_tree = dom_res.get("data", {})
        
        # Step 3: Scan authentication patterns
        auth_res = self.ida.scan_auth_patterns(hub_addr)
        if auth_res.get("status") != "ok":
            return
        
        auth_data = auth_res.get("data", {})
        
        # Step 4: Analyze possible authentication checks
        auth_calls = auth_data.get("auth_calls", [])
        blocking_checks = auth_data.get("blocking_checks", [])
        
        # Find authentication calls in dominator context
        for call in auth_calls:
            call_addr = call.get("address")
            callee = call.get("callee")
            
            # Check if on dominator path
            if self._is_in_dominator_context(call_addr, dom_tree):
                # Further verify
                is_auth = self._verify_auth_function(callee)
                if is_auth:
                    mechanism = AuthMechanism(
                        address=call_addr,
                        name=callee,
                        mechanism_type="function",
                        confidence=0.8,
                        description=f"Auth function called in dominator context",
                        detection_method="dominator_analysis"
                    )
                    self.identified_mechanisms.append(mechanism)
                    print(f"[GlobalAuth] Found auth mechanism: {callee}")
        
        # Analyze high TIS blocking checks
        for check in blocking_checks:
            if check.get("tis", 0) >= 3.0:  # High threshold
                mechanism = AuthMechanism(
                    address=check.get("address"),
                    name=f"inline_check_{check.get('address')}",
                    mechanism_type="inline",
                    confidence=0.6,
                    tis_score=check.get("tis"),
                    description=f"High-TIS blocking check ({check.get('pattern')})",
                    detection_method="tis_analysis"
                )
                self.identified_mechanisms.append(mechanism)
    
    def _is_in_dominator_context(self, addr: str, dom_tree: dict) -> bool:
        """Check if address is in dominator context"""
        # Simplified implementation: check if address is a dominator of some block
        return addr in dom_tree or addr in dom_tree.values()
    
    def _verify_auth_function(self, func_name: str) -> bool:
        """Use LLM to verify if function is an authentication function"""
        if not func_name:
            return False
        
        # Quick heuristic check
        auth_indicators = ["auth", "login", "session", "check", "verify", "security"]
        name_lower = func_name.lower()
        
        if any(ind in name_lower for ind in auth_indicators):
            return True
        
        # For unclear cases, can invoke LLM (simplified here)
        return False


class LocalConstraintAnalyzer:
    """
    Local Constraint Analyzer
    Implementation of Section 3.3.2: Local Constraint Analysis
    """
    
    def __init__(self, ida_client: IDAProClient, llm: LLMProvider):
        self.ida = ida_client
        self.llm = llm
        
        # Analysis results
        self.shared_utilities: List[AuthMechanism] = []
        self.handler_protections: Dict[str, AuthMechanism] = {}  # handler -> protection
    
    def analyze(self, handlers: List[str]) -> Dict[str, AuthMechanism]:
        """
        Analyze local constraints for all handlers
        
        Args:
            handlers: List of handler function addresses
        
        Returns:
            {handler_addr: AuthMechanism} mapping
        """
        print(f"[LocalConstraint] Analyzing {len(handlers)} handlers...")
        
        # Phase 1: Scan shared resources
        self._identify_shared_utilities(handlers)
        
        # Phase 2: Analyze each handler
        for idx, handler in enumerate(handlers):
            if idx % 20 == 0:
                print(f"[LocalConstraint] Progress: {idx}/{len(handlers)}")
            
            protection = self._analyze_handler(handler)
            if protection:
                self.handler_protections[handler] = protection
        
        print(f"[LocalConstraint] Found {len(self.shared_utilities)} shared utilities")
        print(f"[LocalConstraint] {len(self.handler_protections)} handlers have local protection")
        
        return self.handler_protections
    
    def _identify_shared_utilities(self, handlers: List[str]):
        """Identify shared authentication utility functions"""
        print("[LocalConstraint] Phase 1: Identifying shared utilities...")
        
        # Count functions called by all handlers
        callee_counter = Counter()
        handler_callees = {}
        
        for handler in handlers:
            res = self.ida.get_callees(handler)
            if res.get("status") == "ok":
                callees = res.get("data", [])
                handler_callees[handler] = callees
                for callee in callees:
                    # Filter out system functions
                    if not self._is_noise_function(callee):
                        callee_counter[callee] += 1
        
        # Find frequently called functions
        hotspots = [func for func, count in callee_counter.most_common(30) if count >= 3]
        
        for func in hotspots:
            # Check if it has blocking characteristics
            blocking_res = self.ida.find_blocking_checks(func, threshold=2.0)
            if blocking_res.get("status") == "ok":
                checks = blocking_res.get("data", [])
                if checks:
                    # Use LLM to confirm
                    is_auth = self._verify_shared_utility(func, checks)
                    if is_auth:
                        mechanism = AuthMechanism(
                            address=func,
                            name=func,
                            mechanism_type="shared_utility",
                            confidence=0.75,
                            tis_score=max(c.get("tis", 0) for c in checks),
                            description=f"Shared utility called by {callee_counter[func]} handlers",
                            detection_method="frequency_analysis"
                        )
                        self.shared_utilities.append(mechanism)
                        print(f"[LocalConstraint] Found shared utility: {func}")
    
    def _analyze_handler(self, handler: str) -> Optional[AuthMechanism]:
        """Analyze local constraints for a single handler"""
        # Check if it calls shared authentication utilities
        res = self.ida.get_callees(handler)
        if res.get("status") != "ok":
            return None
        
        callees = res.get("data", [])
        
        # Check if it calls identified shared utilities
        for utility in self.shared_utilities:
            if utility.name in callees or utility.address in callees:
                return AuthMechanism(
                    address=handler,
                    name=f"uses_{utility.name}",
                    mechanism_type="shared_utility_call",
                    confidence=utility.confidence,
                    description=f"Calls shared utility {utility.name}",
                    detection_method="callee_analysis"
                )
        
        # Check inline constraints
        tis_res = self.ida.calculate_tis(handler)
        if tis_res.get("status") == "ok":
            tis_data = tis_res.get("data", [])
            
            # Find high TIS checks
            high_tis = [t for t in tis_data if t.get("tis", 0) >= 2.5 and t.get("terminates")]
            if high_tis:
                return AuthMechanism(
                    address=handler,
                    name=f"inline_check_{handler}",
                    mechanism_type="inline",
                    confidence=0.5,
                    tis_score=max(t.get("tis", 0) for t in high_tis),
                    description=f"Has {len(high_tis)} inline blocking checks",
                    detection_method="tis_analysis"
                )
        
        return None
    
    def _is_noise_function(self, func_name: str) -> bool:
        """Check if function is a noise function"""
        noise_patterns = [
            "memset", "memcpy", "strcpy", "strlen", "printf", "sprintf",
            "malloc", "free", "fopen", "fclose", "fread", "fwrite",
            "nvram_get", "nvram_set", "websWrite", "websDone"
        ]
        func_lower = func_name.lower()
        return any(p in func_lower for p in noise_patterns)
    
    def _verify_shared_utility(self, func: str, checks: list) -> bool:
        """Verify if function is a shared authentication utility"""
        # Simplified implementation: if it has high TIS checks, consider it might be an auth utility
        max_tis = max(c.get("tis", 0) for c in checks) if checks else 0
        return max_tis >= 3.0


class LogicDecoupler:
    """
    Logic Decoupler - Main Entry Class
    Integrates global authentication and local constraint analysis to build ACDG
    
    Improvement: Adopts conservative strategy
    - Default all routes to Auth-Required
    - Only mark Auth-Free with sufficient evidence
    """
    
    def __init__(self, ida_client: IDAProClient = None, llm: LLMProvider = None):
        self.ida = ida_client if ida_client else IDAProClient()
        self.llm = llm if llm else LLMProvider()
        
        self.global_identifier = GlobalAuthIdentifier(self.ida, self.llm)
        self.local_analyzer = LocalConstraintAnalyzer(self.ida, self.llm)
        self.gatekeeper_analyzer = GatekeeperAnalyzer(self.ida, self.llm)  # Added
        
        # GoAhead-specific analyzer
        self.goahead_analyzer = None
        if GOAHEAD_AVAILABLE:
            self.goahead_analyzer = GoAheadAnalyzer(self.ida)
        
        # HTTP Server layer gatekeeper analyzer (for mini_httpd+CGI architecture)
        self.httpd_gatekeeper_analyzer = None
        if HTTPD_GATEKEEPER_AVAILABLE:
            self.httpd_gatekeeper_analyzer = HttpdGatekeeperAnalyzer(self.ida, self.llm)
        
        # Input/output configuration
        self.input_dir = "output"
        self.output_dir = "output"
        
        # Configuration
        self.verbose = True
        self.init_func = None  # Web initialization function for gatekeeper discovery
        self.firmware_root = None  # Firmware filesystem root directory (for httpd layer analysis)
        self.current_binary = None  # Current binary being analyzed
        
        # Results
        self.acdg = ACDG()
        
        # Static table hierarchy information
        self.static_table_hierarchy: Dict[str, str] = {}  # table_addr -> parent_path
    
    def load_routes(self, routes_file: str = None) -> List[dict]:
        """Load route data."""
        if routes_file is None:
            # Find latest routes file
            pattern = os.path.join(self.input_dir, "routes_v3_hierarchical.json")
            if not os.path.exists(pattern):
                pattern = os.path.join(self.input_dir, "routes_v3_latest.json")
            routes_file = pattern
        
        if not os.path.exists(routes_file):
            print(f"[-] Routes file not found: {routes_file}")
            return []
        
        print(f"[*] Loading routes from: {routes_file}")
        with open(routes_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Flatten route data
        flat_routes = []
        
        def flatten(node, parent_root=""):
            if isinstance(node, list):
                for item in node:
                    if isinstance(item, dict):
                        flat_routes.append(item)
            elif isinstance(node, dict):
                for key, value in node.items():
                    if isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict):
                                item['root'] = key
                                flat_routes.append(item)
                    else:
                        flatten(value, key)
        
        flatten(data)
        print(f"[*] Loaded {len(flat_routes)} routes")
        return flat_routes
    
    def run(self, routes: List[RouteNode] = None, firmware_name: str = "Unknown",
            init_func: str = None, firmware_root: str = None, 
            current_binary: str = None, detected_architecture: str = "auto") -> ACDG:
        """
        Execute complete logic decoupling analysis.
        
        Args:
            routes: List of RouteNodes, or None to load from file
            firmware_name: Firmware name
            init_func: Web initialization function name (for gatekeeper discovery)
            firmware_root: Firmware filesystem root directory (for httpd layer analysis)
            current_binary: Current binary being analyzed (to determine if httpd layer analysis needed)
            detected_architecture: Detected architecture type
        
        Returns:
            Constructed ACDG
        """
        print("\n" + "=" * 60)
        print("PANGU Logic Decoupler - Starting Analysis")
        print("=" * 60)
        
        # Save configuration for later use
        self.firmware_root = firmware_root
        self.current_binary = current_binary or firmware_name
        
        # Step 1: Get route data
        if routes:
            # Use provided RouteNode list directly, preserving all fields including auth_state and protection_type
            raw_routes = [
                {
                    "path": r.path,
                    "full_path": r.path,
                    "sub_path": r.sub_path,
                    "handler": r.handler,
                    "source_hub": r.source_hub,
                    "source_type": r.source_type,
                    "root": r.root,
                    # Preserve auth state analyzed in Phase 1
                    "auth_state": r.auth_state.value if hasattr(r.auth_state, 'value') else str(r.auth_state),
                    "protection_type": r.protection_type.value if hasattr(r.protection_type, 'value') else str(r.protection_type),
                    "protection_detail": r.protection_detail or ""
                }
                for r in routes
            ]
            print(f"[*] Using {len(raw_routes)} provided routes")
        else:
            # Load from file
            raw_routes = self.load_routes()
        
        if not raw_routes:
            print("[-] No routes to analyze")
            return self.acdg
        
        # Step 2: Extract Hubs and Handlers
        hubs = set()
        handlers = []
        
        for route in raw_routes:
            hub = route.get("source_hub", "")
            handler = route.get("handler", "")
            
            if hub:
                hubs.add(hub)
            if handler and handler not in handlers:
                handlers.append(handler)
        
        print(f"[*] Found {len(hubs)} unique hubs, {len(handlers)} unique handlers")
        
        # Step 3: Gatekeeper discovery and analysis [Core step]
        gatekeepers = []
        goahead_auth_handlers = []
        
        # [Optimization] Detect architecture type, GoForm/JSONRPC auth analysis already done in Phase 1, no need for LLM
        is_goform_arch = any(r.get("source_type") == "GoForm" for r in raw_routes)
        is_jsonrpc_arch = any(r.get("source_type") == "JSONRPC" for r in raw_routes)
        skip_llm_gatekeeper = is_goform_arch or is_jsonrpc_arch
        
        if skip_llm_gatekeeper:
            print(f"\n[*] Step 3: Gatekeeper Discovery [OPTIMIZED - Using Phase 1 results]")
            print(f"    Architecture: {'GoForm' if is_goform_arch else 'JSONRPC'}")
            print(f"    Auth analysis already completed in Phase 1 - skipping LLM calls")
        
        try:
            if hasattr(self.ida, 'connect') and self.ida.connect() and not skip_llm_gatekeeper:
                # Auto-discover initialization function (if not specified) - pass route info to assist
                if not init_func:
                    init_func = self._find_init_function(routes)
                
                if init_func:
                    print(f"\n[*] Step 3: Gatekeeper Discovery (init_func={init_func})")
                    
                    # === 3a: GoAhead-specific analysis ===
                    # Prioritize GoAhead analyzer which can precisely identify flag=1 auth functions
                    if self.goahead_analyzer and GOAHEAD_AVAILABLE:
                        print("[*] Step 3a: GoAhead-specific analysis...")
                        self.goahead_analyzer.discover_api_addresses()
                        self.goahead_analyzer.analyze_init_function(init_func)
                        
                        # Get global authentication functions
                        goahead_auth_handlers = self.goahead_analyzer.global_auth_handlers
                        
                        for auth_handler in goahead_auth_handlers:
                            mech = AuthMechanism(
                                address=auth_handler.handler_addr or auth_handler.handler_func,
                                name=auth_handler.handler_func,
                                mechanism_type="gatekeeper",
                                confidence=0.95,  # GoAhead flag=1 is highly reliable
                                description=f"GoAhead global auth handler (flag={auth_handler.priority}) for prefix '{auth_handler.url_prefix}'",
                                detection_method="goahead_flag_analysis"
                            )
                            self.acdg.add_global_auth(mech)
                            print(f"    [+] GoAhead AUTH: {auth_handler.handler_func} (flag={auth_handler.priority})")
                        
                        # Trace static table hierarchy
                        static_table_addrs = list(set(r.get("source_hub", "") for r in raw_routes 
                                                       if r.get("source_type") == "static_table"))
                        if static_table_addrs:
                            print(f"[*] Step 3b: Tracing static table hierarchy ({len(static_table_addrs)} tables)...")
                            self.goahead_analyzer.trace_all_static_tables(static_table_addrs)
                            
                            # Save hierarchy info for later use
                            for table_addr, ctx in self.goahead_analyzer.static_table_contexts.items():
                                self.static_table_hierarchy[table_addr] = ctx.parent_path
                                print(f"    [+] Table {table_addr} -> parent: {ctx.parent_path}")
                    
                    # === 3b: LLM analysis as supplement ===
                    gatekeepers = self.gatekeeper_analyzer.find_gatekeepers_from_init(init_func)
                    
                    # Add gatekeepers to ACDG global auth mechanisms (excluding those already found via GoAhead)
                    goahead_names = set(h.handler_func for h in goahead_auth_handlers)
                    for gk in gatekeepers:
                        if gk.name not in goahead_names:
                            mech = AuthMechanism(
                                address=gk.address,
                                name=gk.name,
                                mechanism_type="gatekeeper",
                                confidence=gk.confidence,
                                description=gk.description,
                                detection_method="llm_semantic_analysis"
                            )
                            self.acdg.add_global_auth(mech)
        except Exception as e:
            if self.verbose:
                print(f"[!] Gatekeeper discovery failed: {e}")
                import traceback
                traceback.print_exc()
        
        # Step 4: Global auth mechanism identification (traditional method, as supplement)
        # [Optimization] For GoForm/JSONRPC architectures, skip this step as it's done in Phase 1
        global_mechs = []
        if not skip_llm_gatekeeper:
            try:
                if hasattr(self.ida, 'connect') and self.ida.connect():
                    global_mechs = self.global_identifier.identify(list(hubs))
                    for mech in global_mechs:
                        self.acdg.add_global_auth(mech)
            except Exception as e:
                if self.verbose:
                    print(f"[!] Global auth identification skipped: {e}")
        
        # Step 4b: Extract JSONRPC architecture's global auth mechanisms from routes
        # JSONRPC routes have auth state marked in Phase 1, need to extract auth functions
        self._extract_jsonrpc_auth_mechanisms(raw_routes)
        
        # Step 4c: Extract GoForm architecture's global auth mechanisms from routes
        self._extract_goform_auth_mechanisms(raw_routes)
        
        # Step 4d-1: Detect if currently analyzing mini_httpd itself
        # If so, directly analyze its internal auth functions
        mini_httpd_gatekeeper = self._analyze_mini_httpd_internal_auth(
            current_binary=self.current_binary,
            skip_if_has_gatekeeper=(len(gatekeepers) > 0 or len(goahead_auth_handlers) > 0)
        )
        
        # Step 4d-2: HTTP Server layer gatekeeper analysis [only for mini_httpd+CGI architecture]
        # This step handles devices like Netgear that use mini_httpd + CGI two-layer architecture
        # Trigger conditions: (1) Currently analyzing CGI file (2) mini_httpd exists in firmware
        httpd_gatekeeper = self._analyze_httpd_layer_gatekeeper(
            firmware_root=self.firmware_root,
            current_binary=self.current_binary,
            detected_architecture=detected_architecture,
            skip_if_has_gatekeeper=(len(gatekeepers) > 0 or len(goahead_auth_handlers) > 0 or mini_httpd_gatekeeper is not None)
        )
        
        # Step 5: Local constraint analysis (requires IDA connection)
        # [Optimization] For GoForm/JSONRPC architectures, auth state fully determined in Phase 1, skip this step
        local_protections = {}
        if not skip_llm_gatekeeper:
            try:
                if hasattr(self.ida, 'connect'):
                    local_protections = self.local_analyzer.analyze(handlers)
                    for utility in self.local_analyzer.shared_utilities:
                        self.acdg.add_shared_utility(utility)
            except Exception as e:
                if self.verbose:
                    print(f"[!] Local constraint analysis skipped: {e}")
        else:
            print(f"[*] Step 5: Local Constraint Analysis [SKIPPED - Auth state from Phase 1]")
        
        # Step 6: Build ACDG - Use conservative strategy to annotate auth state
        self._build_acdg_conservative(raw_routes, gatekeepers, local_protections)
        
        # Step 7: Set metadata
        self.acdg.firmware_name = firmware_name
        self.acdg.analysis_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Print summary
        self.acdg.print_summary()
        
        return self.acdg
    
    def _find_init_function(self, routes: List[RouteNode] = None) -> Optional[str]:
        """
        Auto-discover Web initialization function.
        
        Core approach:
        1. Prioritize using extracted top-level route information (/goform, /HNAP1, /cgi-bin, etc.)
        2. Find the caller function of top-level route registration API
        3. This caller function is likely the initialization function, which usually also registers global gatekeepers
        
        Args:
            routes: Extracted route list
            
        Returns:
            Initialization function name or address
        """
        print("[*] Auto-discovering initialization function...")
        
        # === Strategy 1: Determine from top-level route's source_hub ===
        if routes:
            # Identify top-level routes (root path registrations starting with /)
            top_level_routes = []
            top_level_hubs = set()
            
            for r in routes:
                path = r.path if hasattr(r, 'path') else ""
                # Top-level route feature: short paths starting directly with /
                if path in ["/goform", "/HNAP1", "/cgi-bin", "/", "/EXCU_SHELL", "/upnp", "/AJAX"]:
                    top_level_routes.append(r)
                    if hasattr(r, 'source_hub') and r.source_hub:
                        top_level_hubs.add(r.source_hub)
            
            if top_level_hubs:
                print(f"    Found {len(top_level_hubs)} top-level route registration hubs")
                
                for hub_addr in top_level_hubs:
                    # First check: this hub itself might be the init function
                    # (if it directly contains top-level route registration)
                    if self._verify_init_function(hub_addr):
                        print(f"    [OK] Hub {hub_addr} is the init function itself")
                        return hub_addr
                    
                    # If not, try to find its caller
                    init_func = self._find_caller_of_hub(hub_addr)
                    if init_func:
                        # Verify this function indeed contains multiple route registrations
                        if self._verify_init_function(init_func):
                            print(f"    [OK] Found init function via hub caller: {init_func}")
                            return init_func
        
        # === Strategy 2: Search for registration calls containing top-level route strings ===
        init_func = self._find_init_by_route_strings()
        if init_func:
            print(f"    [OK] Found init function via route string search: {init_func}")
            return init_func
        
        # === Strategy 3: Common initialization function name patterns ===
        init_patterns = ["initWebs", "init_web", "web_init", "httpd_init", 
                        "start_httpd", "main"]
        
        for pattern in init_patterns:
            res = self.ida.decompile(pattern)
            if res.get("status") == "ok":
                code = res.get("data", {}).get("code", "")
                if "Handler" in code or "websUrlHandler" in code or "formHandler" in code:
                    print(f"    [OK] Found init function by name: {pattern}")
                    return pattern
        
        # === Strategy 3b: TP-Link architecture specific initialization function patterns ===
        tplink_init_patterns = ["webFramesRpmsInit", "httpRpmsInit", "httpWebInit"]
        for pattern in tplink_init_patterns:
            res = self.ida.decompile(pattern)
            if res.get("status") == "ok":
                code = res.get("data", {}).get("code", "")
                if "httpRpmConfAdd" in code or "unCheckRefererUrlAdd" in code:
                    print(f"    [OK] Found TP-Link init function: {pattern}")
                    return pattern
        
        # === Strategy 4: Find initialization function via Security Handler cross-references ===
        # This is the most reliable method, as Security Handler is usually registered in init function
        security_handler_patterns = [
            "R7WebsSecurityHandler",      # Tenda
            "websSecurityHandler",        # GoAhead standard
            "SecurityHandler",            # Generic
            "authHandler",                # Generic
            "checkAuthHandler",           # Generic
        ]
        
        for pattern in security_handler_patterns:
            try:
                xrefs_res = self.ida.get_xrefs(pattern, "to")
                if xrefs_res.get("status") == "ok":
                    xrefs = xrefs_res.get("data", [])
                    for xref in xrefs:
                        func_name = xref.get("func_name", "")
                        if func_name and func_name != "None" and func_name != "":
                            # Verify if this function looks like an init function
                            res = self.ida.decompile(func_name)
                            if res.get("status") == "ok":
                                code = res.get("data", {}).get("code", "")
                                # Check if it contains multiple Handler registrations
                                if ("Handler" in code and 
                                    (code.count("Handler") >= 2 or "/goform" in code or "/cgi-bin" in code)):
                                    print(f"    [OK] Found init function via {pattern} xref: {func_name}")
                                    return func_name
            except Exception as e:
                if self.verbose:
                    print(f"    [DEBUG] Security handler search error: {e}")
        
        # === Strategy 5: Search for functions containing multiple route registration calls ===
        init_func = self._find_init_by_registration_pattern()
        if init_func:
            print(f"    [OK] Found init function via registration pattern: {init_func}")
            return init_func
        
        print("    [WARN] Could not auto-discover init function")
        return None
    
    def _find_caller_of_hub(self, hub_addr: str) -> Optional[str]:
        """
        Find the caller of the Hub registration function
        
        Args:
            hub_addr: Address of the registration API
            
        Returns:
            Caller function name
        """
        try:
            # Get cross-references to this function (who called it)
            xrefs_res = self.ida.get_xrefs(hub_addr, "to")
            if xrefs_res.get("status") != "ok":
                return None
            
            callers = xrefs_res.get("data", [])
            if not callers:
                return None
            
            # Return the first caller (usually the initialization function)
            # Can further filter: select the function with the most calls
            caller_counts = {}
            for caller in callers:
                func_name = caller.get("func_name", caller.get("from_func", ""))
                if func_name and func_name != "None":
                    caller_counts[func_name] = caller_counts.get(func_name, 0) + 1
            
            if caller_counts:
                # Select the function with the most calls
                best_caller = max(caller_counts, key=caller_counts.get)
                return best_caller
                
        except Exception as e:
            if self.verbose:
                print(f"    [DEBUG] _find_caller_of_hub error: {e}")
        
        return None
    
    def _find_init_by_route_strings(self) -> Optional[str]:
        """
        Find the initialization function by searching for functions containing top-level route strings
        """
        try:
            # Search for functions containing strings like "/goform" or "/HNAP1"
            for route_str in ["/goform", "/HNAP1", "/cgi-bin"]:
                search_res = self.ida.get_xrefs(route_str, "to")
                if search_res.get("status") == "ok":
                    refs = search_res.get("data", [])
                    for ref in refs:
                        func_name = ref.get("func_name", "")
                        if func_name and self._verify_init_function(func_name):
                            return func_name
        except:
            pass
        return None
    
    def _find_init_by_registration_pattern(self) -> Optional[str]:
        """
        Search for functions containing multiple route registration calls (GoAhead pattern)
        """
        try:
            # Get some functions to check
            funcs_res = self.ida.get_functions(search="sub_", limit=200)
            if funcs_res.get("status") != "ok":
                return None
            
            funcs = funcs_res.get("data", [])
            
            for func in funcs:
                func_name = func.get("name", "")
                if not func_name:
                    continue
                
                res = self.ida.decompile(func_name)
                if res.get("status") != "ok":
                    continue
                
                code = res.get("data", {}).get("code", "")
                
                # GoAhead feature: multiple consecutive route registration calls
                # Also check if it contains top-level route strings
                registration_count = (
                    code.count('sub_40B1F4') +  # D-Link goahead
                    code.count('websUrlHandler') +
                    code.count('formDefineHandler') +
                    code.count('cgiHandler')
                )
                
                has_top_routes = any(r in code for r in ['/goform', '/HNAP1', '/cgi-bin', '"/EXCU_SHELL"'])
                
                if registration_count >= 3 and has_top_routes:
                    return func_name
                    
        except Exception as e:
            if self.verbose:
                print(f"    [DEBUG] _find_init_by_registration_pattern error: {e}")
        
        return None
    
    def _verify_init_function(self, func_name: str) -> bool:
        """
        Verify if a function might be an initialization function
        
        Check conditions:
        1. Contains multiple Handler registration calls
        2. Contains top-level route strings
        3. Contains GoAhead-related API calls
        """
        try:
            res = self.ida.decompile(func_name)
            if res.get("status") != "ok":
                return False
            
            code = res.get("data", {}).get("code", "")
            
            # Check if contains top-level route strings
            top_route_keywords = ['/goform', '/HNAP1', '/cgi-bin', '/EXCU_SHELL', '/AJAX', '"/"']
            has_top_routes = sum(1 for k in top_route_keywords if k in code) >= 1
            
            # Check if contains GoAhead-related API calls
            goahead_apis = ['sub_4CC6A4', 'sub_4BD16C', 'sub_4CBDAC', 'websUrlHandler', 
                           'websFormDefine', 'websAspDefine', 'formDefine', 'aspDefine']
            has_goahead_api = sum(1 for api in goahead_apis if api in code) >= 2
            
            # Check if there are multiple function calls (possibly registration calls)
            call_pattern = re.compile(r'sub_[0-9A-Fa-f]+\s*\(')
            calls = call_pattern.findall(code)
            has_many_calls = len(calls) >= 5
            
            return has_goahead_api or has_top_routes or (has_many_calls and any(k in code for k in top_route_keywords))
            
        except:
            return False
    
    def _extract_jsonrpc_auth_mechanisms(self, raw_routes: List[dict]):
        """
        Extract authentication mechanism information from JSONRPC routes
        
        JSONRPC routes have already determined authentication status in Phase 1
        by analyzing the dispatch function. Here we need to extract the authentication
        functions used and add them to the global authentication mechanism list.
        """
        # Check if this is JSONRPC architecture
        jsonrpc_routes = [r for r in raw_routes if r.get("source_type") == "jsonrpc_method"]
        
        if not jsonrpc_routes:
            return
        
        print("[*] Step 4b: Extracting JSONRPC auth mechanisms...")
        
        # Extract all routes with Gatekeeper protection
        auth_required_routes = [r for r in jsonrpc_routes 
                               if r.get("auth_state") == "Auth-Required" 
                               and r.get("protection_type") == "Gatekeeper"]
        
        if not auth_required_routes:
            print("    [INFO] No JSONRPC routes with gatekeeper protection found")
            return
        
        # Extract dispatch functions from source_hub (only real function names, not file paths)
        dispatch_hubs = set()
        for r in jsonrpc_routes:
            hub = r.get("source_hub", "")
            # Filter out file paths (like "web\\xxx.js"), only keep function names
            if hub and not hub.startswith("web") and not hub.endswith(".js") and not hub.endswith(".html"):
                # Check if it looks like a function name (contains letters and numbers, possibly underscores)
                import re
                if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', hub) or hub.startswith("sub_"):
                    dispatch_hubs.add(hub)
        
        if dispatch_hubs:
            for hub in dispatch_hubs:
                mech = AuthMechanism(
                    address=hub,
                    name=hub,
                    mechanism_type="jsonrpc_dispatch_auth",
                    confidence=0.85,
                    description=f"JSONRPC dispatch function with session/token verification",
                    detection_method="jsonrpc_phase1_analysis"
                )
                self.acdg.add_global_auth(mech)
                print(f"    [+] JSONRPC auth mechanism: {hub}")
            
            print(f"    [OK] Identified {len(dispatch_hubs)} JSONRPC auth dispatch functions")
        else:
            print("    [INFO] No valid JSONRPC dispatch functions found (excluding static file sources)")
    
    def _extract_goform_auth_mechanisms(self, raw_routes: List[dict]):
        """
        Extract authentication mechanism information from GoForm routes
        
        GoForm routes have already determined authentication status in Phase 1
        by analyzing checkToken calls in the dispatcher function. Here we need to
        extract the authentication functions used and add them to the global list.
        """
        # Check if this is GoForm architecture
        is_goform = any(r.get("source_type") == "GoForm" for r in raw_routes)
        
        if not is_goform:
            return
        
        print("[*] Step 4c: Extracting GoForm auth mechanisms...")
        
        # Extract all routes with Gatekeeper protection
        auth_required_routes = [r for r in raw_routes 
                               if r.get("auth_state") == "Auth-Required" 
                               and r.get("protection_type") == "Gatekeeper"]
        
        if not auth_required_routes:
            print("    [INFO] No GoForm routes with gatekeeper protection found")
            return
        
        # Extract auth function name from protection_detail
        # Format: "Protected by checkToken"
        auth_functions = set()
        for route in auth_required_routes:
            detail = route.get("protection_detail", "")
            if "Protected by " in detail:
                func_name = detail.replace("Protected by ", "").strip()
                auth_functions.add(func_name)
        
        # Add authentication mechanisms
        for func_name in auth_functions:
            # Try to get function address
            func_addr = ""
            try:
                funcs_result = self.ida.get_functions()
                if funcs_result.get("status") == "ok":
                    for f in funcs_result.get("data", []):
                        if f["name"] == func_name:
                            func_addr = f["addr"]
                            break
            except:
                pass
            
            mech = AuthMechanism(
                address=func_addr,
                name=func_name,
                mechanism_type="goform_token_auth",
                confidence=0.9,
                description=f"GoForm global authentication via {func_name}() - token-based session verification",
                detection_method="goform_phase1_analysis"
            )
            self.acdg.add_global_auth(mech)
            print(f"    [+] GoForm auth mechanism: {func_name} @ {func_addr}")
        
        # Count whitelist routes
        auth_free_routes = [r for r in raw_routes if r.get("auth_state") == "Auth-Free"]
        print(f"    [OK] Global auth: {len(auth_functions)} functions, protecting {len(auth_required_routes)} routes")
        print(f"    [OK] Auth-Free (whitelist): {len(auth_free_routes)} routes")
    
    def _analyze_mini_httpd_internal_auth(
        self,
        current_binary: str = None,
        skip_if_has_gatekeeper: bool = True
    ) -> Optional[AuthMechanism]:
        """
        Detect and analyze mini_httpd's internal authentication functions.
        
        When directly analyzing mini_httpd itself, we should be able to identify
        its internal authentication functions. mini_httpd uses inline authentication
        (calling auth checks directly in request handlers), not through gatekeeper
        registration functions.
        
        Trigger conditions:
        1. Current binary name is mini_httpd/thttpd/boa, etc.
        2. No other gatekeepers have been discovered yet
        
        Returns:
            AuthMechanism or None
        """
        if not current_binary:
            return None
        
        # Check if it's a lightweight HTTP server
        binary_lower = current_binary.lower()
        httpd_names = ["mini_httpd", "minihttpd", "mini-httpd", "thttpd", "boa"]
        
        is_httpd = any(name in binary_lower for name in httpd_names)
        if not is_httpd:
            return None
        
        # Skip condition check
        if skip_if_has_gatekeeper and self.acdg.global_auth_mechanisms:
            if self.verbose:
                print(f"\n[*] Step 4d-1: mini_httpd Internal Auth Analysis [SKIPPED]")
                print(f"    Reason: Already found {len(self.acdg.global_auth_mechanisms)} gatekeeper(s)")
            return None
        
        print(f"\n[*] Step 4d-1: mini_httpd Internal Auth Analysis [TRIGGERED]")
        print(f"    Current binary: {current_binary}")
        print(f"    Note: mini_httpd uses inline authentication (not registered gatekeepers)")
        
        # Search for known authentication functions
        auth_func_names = [
            "auth_check", "check_authorization", "do_authentication",
            "handle_auth", "send_authenticate", "usb_auth_check"
        ]
        
        found_auth_funcs = []
        try:
            for func_name in auth_func_names:
                # Use get_functions(search=...) to search functions
                result = self.ida.get_functions(search=func_name, limit=10)
                if result.get("status") == "ok":
                    funcs = result.get("data", [])
                    if funcs:
                        for func in funcs:
                            if isinstance(func, str):
                                found_auth_funcs.append({"name": func, "addr": ""})
                            elif isinstance(func, dict):
                                found_auth_funcs.append(func)
                            elif isinstance(func, list) and len(func) >= 2:
                                found_auth_funcs.append({"addr": str(func[0]), "name": func[1]})
        except Exception as e:
            if self.verbose:
                print(f"    [WARN] Function search failed: {e}")
        
        # Search for authentication-related strings
        auth_strings = [".htpasswd", "WWW-Authenticate", "Authorization"]
        found_auth_strings = []
        try:
            for auth_str in auth_strings:
                result = self.ida.search_strings(auth_str)
                if result.get("status") == "ok":
                    strings = result.get("data", [])
                    if strings:
                        found_auth_strings.append(auth_str)
        except Exception as e:
            pass
        
        if found_auth_funcs:
            print(f"    [+] Found {len(found_auth_funcs)} authentication function(s):")
            for func in found_auth_funcs[:5]:
                name = func.get("name", func) if isinstance(func, dict) else func
                addr = func.get("addr", "") if isinstance(func, dict) else ""
                print(f"        - {name} @ {addr}")
        
        if found_auth_strings:
            print(f"    [+] Found authentication patterns: {found_auth_strings}")
        
        # Create gatekeeper record
        if found_auth_funcs or found_auth_strings:
            auth_func = found_auth_funcs[0] if found_auth_funcs else {}
            auth_name = auth_func.get("name", "mini_httpd_inline_auth") if isinstance(auth_func, dict) else str(auth_func)
            auth_addr = auth_func.get("addr", "") if isinstance(auth_func, dict) else ""
            
            mech = AuthMechanism(
                address=auth_addr,
                name=f"mini_httpd_auth_{auth_name}",
                mechanism_type="httpd_inline_auth",
                confidence=0.85,
                description=(
                    f"mini_httpd inline authentication. "
                    f"Auth functions: {[f.get('name', f) if isinstance(f, dict) else f for f in found_auth_funcs[:3]]}. "
                    f"Uses HTTP Basic Auth via .htpasswd file."
                ),
                detection_method="mini_httpd_internal_analysis"
            )
            
            self.acdg.add_global_auth(mech)
            print(f"    [+] Added mini_httpd inline auth mechanism to ACDG")
            print(f"    [+] Gatekeepers now: {len(self.acdg.global_auth_mechanisms)}")
            
            return mech
        else:
            print(f"    [-] No authentication functions found in mini_httpd")
            return None
    
    def _analyze_httpd_layer_gatekeeper(
        self, 
        firmware_root: str = None, 
        current_binary: str = None,
        detected_architecture: str = "auto",
        skip_if_has_gatekeeper: bool = True
    ) -> Optional[AuthMechanism]:
        """
        Analyze HTTP Server layer gatekeeper [only for mini_httpd+CGI architecture].
        
        This feature is designed specifically for devices like Netgear that use
        mini_httpd + CGI two-layer architecture. In such devices, authentication
        is handled at the mini_httpd layer, and CGI programs don't handle auth.
        Therefore, analyzing only CGI would miss gatekeeper info, resulting in Gatekeepers=0.
        
        Trigger conditions (all must be met):
        1. HTTPD_GATEKEEPER_AVAILABLE = True (httpd_gatekeeper_analyzer.py exists)
        2. Currently analyzing a .cgi file (e.g., setup.cgi)
        3. mini_httpd/thttpd binary exists in firmware filesystem
        4. Architecture is not GoAhead/GoForm/JSONRPC/FastCGI (these have dedicated handlers)
        5. No other gatekeepers have been discovered yet (avoid duplicate analysis)
        
        Args:
            firmware_root: Firmware filesystem root directory
            current_binary: Current binary being analyzed
            detected_architecture: Detected architecture type
            skip_if_has_gatekeeper: Skip if gatekeeper already found
        
        Returns:
            AuthMechanism or None
        """
        # Condition 1: Check if module is available
        if not HTTPD_GATEKEEPER_AVAILABLE:
            return None
        
        # Condition 5: If gatekeeper already found and skip is set, skip
        if skip_if_has_gatekeeper and self.acdg.global_auth_mechanisms:
            if self.verbose:
                print(f"\n[*] Step 4d: HTTP Server Layer Analysis [SKIPPED]")
                print(f"    Reason: Already found {len(self.acdg.global_auth_mechanisms)} gatekeeper(s) in CGI analysis")
            return None
        
        # Conditions 2-4: Use architecture detector to determine
        should_analyze, httpd_path = should_analyze_httpd_layer(
            firmware_root=firmware_root or "",
            current_binary=current_binary or "",
            detected_architecture=detected_architecture
        )
        
        if not should_analyze:
            if self.verbose:
                print(f"\n[*] Step 4d: HTTP Server Layer Analysis [SKIPPED]")
                print(f"    Reason: Not a mini_httpd+CGI architecture")
                print(f"      - Current binary: {current_binary}")
                print(f"      - Detected arch: {detected_architecture}")
            return None
        
        # === Execute httpd layer analysis ===
        print(f"\n[*] Step 4d: HTTP Server Layer Analysis [TRIGGERED]")
        print(f"    Detected: mini_httpd+CGI architecture (like Netgear)")
        print(f"    Current binary: {current_binary}")
        print(f"    HTTP Server: {httpd_path}")
        print(f"    Note: Authentication is handled at HTTP server layer, not CGI")
        
        # Prompt user that mini_httpd needs to be opened in IDA for complete analysis
        print(f"\n    [INFO] For complete httpd-layer analysis, please:")
        print(f"      1. Open '{httpd_path}' in IDA Pro")
        print(f"      2. Run: python tools/analyze_mini_httpd.py")
        print(f"      3. Or use the HttpdGatekeeperAnalyzer programmatically")
        
        # Create a placeholder gatekeeper to mark this as httpd layer auth architecture
        httpd_gatekeeper = AuthMechanism(
            address="",
            name="mini_httpd_gatekeeper",
            mechanism_type="httpd_layer_gatekeeper",
            confidence=0.7,  # Medium confidence since no deep analysis performed
            description=(
                f"HTTP Server layer authentication (mini_httpd at {httpd_path}). "
                f"Authentication is handled at HTTP server layer before request reaches CGI. "
                f"CGI program ({current_binary}) receives pre-authenticated requests."
            ),
            detection_method="httpd_architecture_detection"
        )
        
        # Add to ACDG
        self.acdg.add_global_auth(httpd_gatekeeper)
        
        print(f"    [+] Added httpd-layer gatekeeper to ACDG")
        print(f"    [+] Gatekeepers now: {len(self.acdg.global_auth_mechanisms)}")
        
        return httpd_gatekeeper
    
    def run_from_file(self, routes_file: str, firmware_name: str = "Unknown",
                      init_func: str = None) -> ACDG:
        """
        Execute logic decoupling analysis from file.
        
        Args:
            routes_file: Route file path
            firmware_name: Firmware name
            init_func: Web initialization function name
        """
        raw_routes = self.load_routes(routes_file)
        
        # Convert to RouteNode
        route_nodes = []
        for r in raw_routes:
            node = RouteNode(
                path=r.get("full_path", r.get("path", "")),
                sub_path=r.get("sub_path", ""),
                handler=r.get("handler", ""),
                source_hub=r.get("source_hub", ""),
                source_type=r.get("source_type", "unknown"),
                root=r.get("root", "/")
            )
            route_nodes.append(node)
        
        return self.run(route_nodes, firmware_name, init_func)
    
    def _build_acdg_conservative(self, raw_routes: List[dict], 
                                  gatekeepers: List[GatekeeperInfo],
                                  local_protections: Dict[str, AuthMechanism]):
        """
        Build ACDG - Use conservative strategy.
        
        Core principles:
        1. If gatekeeper exists, default all routes to protected (Auth-Required)
        2. Only mark Auth-Free for routes in whitelist or with clear bypass evidence
        3. When uncertain, handle conservatively, mark as Auth-Required
        4. Use static table hierarchy info to correct route's root field
        """
        print("[*] Building ACDG with CONSERVATIVE strategy...")
        print(f"    Gatekeepers found: {len(gatekeepers)}")
        
        # Check if GoAhead found global auth functions
        has_goahead_auth = (self.goahead_analyzer and 
                           hasattr(self.goahead_analyzer, 'global_auth_handlers') and 
                           len(self.goahead_analyzer.global_auth_handlers) > 0)
        
        has_gatekeeper = len(gatekeepers) > 0 or has_goahead_auth
        
        # Initialize whitelist variables
        gk_names = []
        all_whitelist_paths = set()
        all_whitelist_patterns = []
        
        if has_gatekeeper:
            gk_names = [gk.name for gk in gatekeepers]
            if has_goahead_auth:
                gk_names.extend([h.handler_func for h in self.goahead_analyzer.global_auth_handlers])
            print(f"    Gatekeeper functions: {gk_names}")
            
            # Aggregate all whitelists
            for gk in gatekeepers:
                all_whitelist_paths.update(gk.whitelist_paths)
                all_whitelist_patterns.extend(gk.whitelist_patterns)
            
            print(f"    Whitelist paths: {all_whitelist_paths}")
            print(f"    Whitelist patterns: {all_whitelist_patterns}")
        
        # Check static table hierarchy info
        if self.static_table_hierarchy:
            print(f"    Static table hierarchy: {len(self.static_table_hierarchy)} tables mapped")
        
        auth_free_count = 0
        auth_required_count = 0
        
        for route_data in raw_routes:
            handler = route_data.get("handler", "")
            path = route_data.get("full_path", route_data.get("path", ""))
            root = route_data.get("root", "/")
            source_hub = route_data.get("source_hub", "")
            source_type = route_data.get("source_type", "")
            
            # === Correct route hierarchy ===
            # If this route comes from static table and we know its hierarchy, correct root
            if source_type == "static_table" and source_hub in self.static_table_hierarchy:
                parent_path = self.static_table_hierarchy[source_hub]
                if parent_path and parent_path != "/":
                    root = parent_path
                    # Note: don't modify path since path is the complete path
                    # Only modify root field to represent hierarchy
            
            # Create RouteNode
            route = RouteNode(
                path=path,
                sub_path=route_data.get("sub_path", route_data.get("path", "")),
                handler=handler,
                source_hub=source_hub,
                source_type=source_type,
                root=root
            )
            
            # === Conservative strategy: determine auth state ===
            
            # === Prioritize using auth state already analyzed in Phase 1 ===
            # (Applies to JSONRPC, GoForm, DistributedCGI architectures where auth state is determined during route extraction)
            pre_analyzed_auth_state = route_data.get("auth_state")
            pre_analyzed_protection = route_data.get("protection_type")
            pre_analyzed_detail = route_data.get("protection_detail", "")
            
            # Special handling for distributed CGI architecture routes (from distributed_cgi_extractor)
            if source_type in ["cgi_binary", "cgi_dispatch"]:
                # Distributed CGI architecture's auth state is fully determined in Phase 1
                # Directly use Phase 1 analysis results
                if pre_analyzed_auth_state == "Auth-Required" or pre_analyzed_auth_state == "AUTH_REQUIRED":
                    route.auth_state = AuthState.AUTH_REQUIRED
                    route.protection_type = ProtectionType.GATEKEEPER
                    route.protection_detail = pre_analyzed_detail or "CGI global login authentication"
                    auth_required_count += 1
                elif pre_analyzed_auth_state == "Auth-Free" or pre_analyzed_auth_state == "AUTH_FREE":
                    route.auth_state = AuthState.AUTH_FREE
                    route.protection_type = ProtectionType.NONE
                    route.protection_detail = pre_analyzed_detail or "CGI no login authentication (may have CSRF-only)"
                    auth_free_count += 1
                else:
                    # Unknown: conservative strategy, mark as needing further analysis
                    route.auth_state = AuthState.UNKNOWN
                    route.protection_type = ProtectionType.NONE
                    route.protection_detail = "CGI auth pattern unknown - needs manual review"
                
                self.acdg.add_route(route)
                continue  # Skip subsequent processing
            
            # Special handling for static analysis source routes
            if source_type == "static_analysis":
                # Static analysis routes have no handler, cannot do binary-level auth analysis
                # Determine based on path characteristics and auth_hint
                if pre_analyzed_auth_state == "Auth-Required":
                    # Known auth-required routes (e.g., UCI module API)
                    route.auth_state = AuthState.AUTH_REQUIRED
                    route.protection_type = ProtectionType.GATEKEEPER
                    route.protection_detail = pre_analyzed_detail or "API route - assumed protected"
                    auth_required_count += 1
                elif pre_analyzed_auth_state == "Auth-Free":
                    route.auth_state = AuthState.AUTH_FREE
                    route.protection_type = ProtectionType.NONE
                    route.protection_detail = pre_analyzed_detail or "Login/Auth endpoint - no auth required"
                    auth_free_count += 1
                else:
                    # Unknown: determine based on path characteristics
                    # API paths usually require authentication
                    if "/api/" in path or "/module/" in path or "/cgi-bin/" in path:
                        route.auth_state = AuthState.AUTH_REQUIRED
                        route.protection_type = ProtectionType.GATEKEEPER
                        route.protection_detail = "API endpoint - assumed protected by gatekeeper"
                        auth_required_count += 1
                    elif "login" in path.lower() or "auth" in path.lower():
                        route.auth_state = AuthState.AUTH_FREE
                        route.protection_type = ProtectionType.NONE
                        route.protection_detail = "Login/auth page - no authentication required"
                        auth_free_count += 1
                    else:
                        # Conservative strategy: assume other paths require auth
                        route.auth_state = AuthState.AUTH_REQUIRED
                        route.protection_type = ProtectionType.NONE
                        route.protection_detail = "Conservative: static route from filesystem"
                        auth_required_count += 1
                        
            elif pre_analyzed_auth_state and pre_analyzed_auth_state != "Unknown":
                # Phase 1 already analyzed auth state, use directly
                if pre_analyzed_auth_state == "Auth-Required":
                    route.auth_state = AuthState.AUTH_REQUIRED
                    route.protection_type = ProtectionType.GATEKEEPER if pre_analyzed_protection == "Gatekeeper" else ProtectionType.INLINE_CHECK
                    route.protection_detail = pre_analyzed_detail or "Pre-analyzed by route extractor"
                    auth_required_count += 1
                elif pre_analyzed_auth_state == "Auth-Free":
                    route.auth_state = AuthState.AUTH_FREE
                    route.protection_type = ProtectionType.NONE
                    route.protection_detail = pre_analyzed_detail or "Pre-analyzed by route extractor (Auth-Free)"
                    auth_free_count += 1
                else:
                    # Unknown or other -> continue with subsequent analysis
                    pass
            elif has_gatekeeper:
                # Case 1: Gatekeeper exists
                
                # Check if path is protected by gatekeeper
                is_protected, gk_name = self.gatekeeper_analyzer.is_path_protected(path)
                
                if is_protected:
                    # Path is within gatekeeper protection scope
                    
                    # Check if in whitelist
                    is_whitelisted, whitelist_reason = self.gatekeeper_analyzer.is_path_whitelisted(path)
                    
                    if is_whitelisted:
                        # In whitelist -> Auth-Free
                        route.auth_state = AuthState.AUTH_FREE
                        route.protection_type = ProtectionType.NONE
                        route.protection_detail = f"Whitelisted: {whitelist_reason}"
                        auth_free_count += 1
                    else:
                        # Not in whitelist -> Auth-Required (protected by gatekeeper)
                        route.auth_state = AuthState.AUTH_REQUIRED
                        route.protection_type = ProtectionType.GATEKEEPER
                        route.protection_detail = f"Protected by {gk_name}"
                        auth_required_count += 1
                else:
                    # Path not in gatekeeper protection scope, check for local protection
                    if handler in local_protections:
                        route.auth_state = AuthState.AUTH_REQUIRED
                        protection = local_protections[handler]
                        route.protection_type = ProtectionType.INLINE_CHECK
                        route.protection_detail = protection.description
                        route.tis_score = protection.tis_score
                        auth_required_count += 1
                    else:
                        # Conservative strategy: mark as auth-required when uncertain
                        route.auth_state = AuthState.AUTH_REQUIRED
                        route.protection_type = ProtectionType.NONE
                        route.protection_detail = "Conservative: no clear bypass evidence"
                        auth_required_count += 1
            else:
                # Case 2: No gatekeeper found
                # Check for local protection
                if handler in local_protections:
                    route.auth_state = AuthState.AUTH_REQUIRED
                    protection = local_protections[handler]
                    route.protection_type = ProtectionType.INLINE_CHECK
                    route.protection_detail = protection.description
                    route.tis_score = protection.tis_score
                    auth_required_count += 1
                else:
                    # No gatekeeper and no local protection
                    # Conservative strategy: keep as Unknown (needs manual review) instead of assuming Auth-Free
                    # Authentication may be at web server layer (e.g., uhttpd) not in binary
                    route.auth_state = AuthState.UNKNOWN
                    route.protection_type = ProtectionType.NONE
                    route.protection_detail = "No gatekeeper found in binary, auth may be at web server level"
                    # Note: Unknown routes don't count toward auth_free_count or auth_required_count
            
            self.acdg.add_route(route)
        
        # === Add whitelist paths as Auth-Free routes ===
        # Whitelist paths (e.g., /userLogin.asp) may not be in extracted routes
        # But they are explicitly allowed by auth function, should be marked Auth-Free
        if has_gatekeeper and (all_whitelist_paths or all_whitelist_patterns):
            existing_paths = set(route_data.get("full_path", route_data.get("path", "")) 
                               for route_data in raw_routes)
            
            # Build sub_path -> handler mapping to associate whitelist routes with handlers
            # E.g., from /goform/telnet can find telnet's handler
            subpath_to_handler = {}
            for route_data in raw_routes:
                path = route_data.get("full_path", route_data.get("path", ""))
                sub_path = route_data.get("sub_path", "")
                handler = route_data.get("handler", "")
                if sub_path and handler:
                    subpath_to_handler[sub_path.lower()] = handler
                # Also use full path as key
                if path and handler:
                    subpath_to_handler[path.lower()] = handler
            
            # Add whitelist paths
            for wl_path in all_whitelist_paths:
                if wl_path and wl_path not in existing_paths:
                    # Try to find corresponding handler from existing routes
                    handler = "(whitelisted)"
                    wl_sub = wl_path.split("/")[-1] if "/" in wl_path else wl_path
                    
                    # Try multiple matching methods
                    lookup_keys = [
                        wl_path.lower(),           # Full path
                        wl_sub.lower(),            # sub_path
                        wl_sub.split(".")[0].lower() if "." in wl_sub else wl_sub.lower()  # Remove extension
                    ]
                    
                    for key in lookup_keys:
                        if key in subpath_to_handler:
                            handler = subpath_to_handler[key]
                            print(f"    [+] Found handler for {wl_path}: {handler}")
                            break
                    
                    whitelist_route = RouteNode(
                        path=wl_path,
                        sub_path=wl_sub,
                        handler=handler,
                        source_hub="",
                        source_type="whitelist",
                        root="/"
                    )
                    whitelist_route.auth_state = AuthState.AUTH_FREE
                    whitelist_route.protection_type = ProtectionType.NONE
                    whitelist_route.protection_detail = f"Whitelisted in gatekeeper: {gk_names[0] if gk_names else 'unknown'}"
                    self.acdg.add_route(whitelist_route)
                    auth_free_count += 1
                    print(f"    [+] Whitelist route added: {wl_path} -> {handler} (Auth-Free)")
            
            # Record whitelist patterns (these are pattern matching, cannot be added as specific routes)
            if all_whitelist_patterns:
                print(f"    [INFO] Whitelist patterns (for pattern matching): {all_whitelist_patterns}")
        
        print(f"[*] ACDG built: {auth_required_count} Auth-Required, {auth_free_count} Auth-Free")
    
    def _build_acdg(self, raw_routes: List[dict], 
                   global_mechs: List[AuthMechanism],
                   local_protections: Dict[str, AuthMechanism]):
        """Build ACDG, annotate auth state for each route."""
        print("[*] Building ACDG...")
        
        # Extract globally protected Handler set
        global_protected = set()
        for mech in global_mechs:
            global_protected.add(mech.name)
            global_protected.add(mech.address)
        
        for route_data in raw_routes:
            handler = route_data.get("handler", "")
            
            # Create RouteNode
            route = RouteNode(
                path=route_data.get("full_path", route_data.get("path", "")),
                sub_path=route_data.get("sub_path", route_data.get("path", "")),
                handler=handler,
                source_hub=route_data.get("source_hub", ""),
                source_type=route_data.get("source_type", "unknown"),
                root=route_data.get("root", "/")
            )
            
            # Determine auth state
            if handler in global_protected:
                # Global protection
                route.auth_state = AuthState.AUTH_REQUIRED
                route.protection_type = ProtectionType.GATEKEEPER
                route.protection_detail = "Global gatekeeper protection"
            elif handler in local_protections:
                # Local protection
                protection = local_protections[handler]
                route.auth_state = AuthState.AUTH_REQUIRED
                route.protection_type = ProtectionType(
                    "SharedUtility" if "shared" in protection.mechanism_type 
                    else "InlineCheck"
                )
                route.protection_detail = protection.description
                route.tis_score = protection.tis_score
            else:
                # Check if it calls shared utilities
                has_shared = False
                for utility in self.local_analyzer.shared_utilities:
                    # Simplified check
                    if utility.name.lower() in handler.lower():
                        has_shared = True
                        route.auth_state = AuthState.AUTH_REQUIRED
                        route.protection_type = ProtectionType.SHARED_UTILITY
                        route.protection_detail = f"Likely calls {utility.name}"
                        break
                
                if not has_shared:
                    # No protection found -> Auth-Free
                    route.auth_state = AuthState.AUTH_FREE
                    route.protection_type = ProtectionType.NONE
            
            self.acdg.add_route(route)
    
    def _save_results(self):
        """Save analysis results."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(self.output_dir, f"acdg_{timestamp}.json")
        
        self.acdg.save_json(output_file)
        print(f"[+] ACDG saved to: {output_file}")
        
        # Also save a latest version
        latest_file = os.path.join(self.output_dir, "acdg_latest.json")
        self.acdg.save_json(latest_file)


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="PANGU Logic Decoupler")
    parser.add_argument("--routes", type=str, help="Routes file path")
    parser.add_argument("--firmware", type=str, default="Unknown", help="Firmware name")
    args = parser.parse_args()
    
    decoupler = LogicDecoupler()
    acdg = decoupler.run(routes_file=args.routes, firmware_name=args.firmware)
    
    # Output high-risk routes
    auth_free = acdg.get_auth_free_routes()
    if auth_free:
        print(f"\n[!] WARNING: {len(auth_free)} Auth-Free routes detected!")
        for route in auth_free[:10]:
            print(f"    - {route.path} -> {route.handler}")


if __name__ == "__main__":
    main()
