# Copyright (c) 2026 The Pangu Project Authors. All rights reserved.
# analysis/route_extractor.py
# PANGU Route Extractor - Enhanced Version
# Integrates static scanning and dynamic analysis, supports multiple route table formats
# Corresponds to Section 3.2: Route Extraction

import sys
import os
import json
import re
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Set

sys.path.append(os.getcwd())

from core.bridge.ida_client import IDAProClient
from core.llm import LLMProvider
from analysis.models import RouteNode, AuthState


class RouteExtractor:
    """
    Route Extractor - Implementation of Section 3.2 Route Extraction Algorithm
    
    Two-phase extraction:
    1. Static Scanning: Identify route table structures in memory
    2. Dynamic Tracing: Trace route registration API calls
    
    Supported route table types:
    - STATIC_ADAPTIVE: Traditional [String, Handler] pairs
    - MIXED_TABLE: Resource + Multiple Handlers (CRUD operations)
    - REGISTRATION_HUB: Dynamic registration call sites
    """
    
    # Route table classification keywords
    TABLE_PATTERNS = {
        "HNAP": {
            "keywords": ["HNAP", "GetDeviceSettings", "SetWLanRadio", "Login"],
            "root_hint": "/HNAP1",
            "style": "CamelCase"
        },
        "GoForm": {
            "keywords": ["goform", "formSet", "formGet", "http_passwd", "lan_ipaddr"],
            "root_hint": "/goform",
            "style": "snake_case"
        },
        "CGI": {
            "keywords": [".cgi", "cgi-bin", "apply.cgi", "config.cgi"],
            "root_hint": "/cgi-bin",
            "style": "extension"
        },
        "ASP": {
            "keywords": [".asp", ".htm", "index.asp", "main.asp"],
            "root_hint": "/",
            "style": "extension"
        },
        "UPnP": {
            "keywords": ["upnp", "control", "WANIPConnection", "GetExternalIP"],
            "root_hint": "/upnp/control",
            "style": "UPnP"
        }
    }
    
    # Noise patterns - need to filter
    NOISE_PATTERNS = [
        r"^nvram_",          # NVRAM internal binding
        r"^gpio_",           # GPIO operations
        r"^mfcp_",           # Internal protocol
        r"^text/",           # MIME types
        r"^image/",          # MIME types
        r"^application/",    # MIME types
    ]
    
    # HTTP route feature patterns - used to identify actual route URLs
    HTTP_ROUTE_PATTERNS = [
        r"^[A-Z][a-z]+[A-Z]",         # CamelCase (GetInfo, SetWifi)
        r"^(get|set|form|asp|from)[A-Z]",  # Tenda style (getXxx, setXxx, formXxx)
        r"^\w+Handle$",               # xxxHandle
        r"^\w+Handler$",              # xxxHandler  
        r"^\w+\.\w+$",               # xxx.cgi, xxx.asp
        r"^/",                         # Paths starting with /
        r"_get$|_set$",               # xxx_get, xxx_set
        r"^[a-z]{5,}$",               # 5+ lowercase letters (telnet, login, redirect, etc.)
        r"^[a-z]+-[a-z]+$",           # Lowercase with hyphen (kns-query, web-status)
    ]
    
    # Configuration item patterns - these are not HTTP routes
    # [Fix] Relaxed short lowercase word restriction since 'ate' etc. are valid routes
    CONFIG_PATTERNS = [
        r"^[a-z]+_[a-z0-9]+$",        # All lowercase with underscore (ssid_5g, wan_type)
        # r"^[a-z]{2,4}$",            # [Removed] Short lowercase words too strict, incorrectly filtered 'ate' etc.
        r"^\d+$",                     # Pure numbers
        r"^[A-Z_]+$",                 # All uppercase (constants)
        r"^v\d+",                     # Version numbers (v6En)
    ]
    
    # Known valid short route names whitelist (to prevent false filtering)
    KNOWN_SHORT_ROUTES = {
        "ate", "arp", "dns", "lan", "wan", "vpn", "usb", "ntp", "ftp", "nfs",
        "qos", "wps", "wds", "log", "sys", "upnp", "dhcp"
    }
    
    def __init__(self, ida_client: IDAProClient, llm: LLMProvider):
        self.ida = ida_client
        self.llm = llm
        
        # Extraction results
        self.routes: List[RouteNode] = []
        self.static_tables: List[Dict] = []
        self.registration_hubs: List[Dict] = []
        
        # Configuration
        self.output_dir = "output"
        self.log_dir = "logs"
        self.verbose = True
        
        # Cache
        self._table_whitelist: Dict[str, Dict] = {}
        self._api_knowledge: Dict[str, Dict] = {}
    
    def log(self, msg: str):
        """Log output"""
        if self.verbose:
            print(msg)
    
    def run_static_scan(self) -> Dict:
        """
        Execute static scanning
        Calls IDA Server's static analysis functionality
        """
        self.log("\n[Phase 1] Running Static Scan...")
        
        res = self.ida._send("run_static_scan", {"output_dir": os.path.abspath(self.log_dir)})
        
        if res.get("status") != "ok":
            self.log(f"  [!] Static scan failed: {res.get('error')}")
            return {}
        
        scan_data = res.get("data", {})
        
        # Classify memory structures
        memory_structures = scan_data.get("memory_structures", [])
        
        self.static_tables = [s for s in memory_structures if s['type'] in ['STATIC_ADAPTIVE', 'MIXED_TABLE']]
        self.registration_hubs = [s for s in memory_structures if s['type'] == 'REGISTRATION_HUB']
        
        self.log(f"  [+] Found {len(self.static_tables)} static tables")
        self.log(f"  [+] Found {len(self.registration_hubs)} registration hubs")
        
        return scan_data
    
    def run_enhanced_scan(self) -> Dict:
        """
        Execute enhanced static scan (using EnhancedTableScanner)
        Corresponds to paper Section 3.2.1: Smart Table Detection
        """
        self.log("\n[Phase 1+] Running Enhanced Static Scan...")
        
        # Call enhanced scan interface
        res = self.ida.run_enhanced_scan(scan_type="all", min_entries=3)
        
        if res.get("status") != "ok":
            self.log(f"  [!] Enhanced scan failed: {res.get('error')}")
            # Fall back to traditional scan
            return self.run_static_scan()
        
        scan_data = res.get("data", {})
        
        # Process string-handler tables
        string_handler_tables = scan_data.get("string_handler_tables", [])
        for table in string_handler_tables:
            table['type'] = 'STATIC_ADAPTIVE'
            # Convert format for compatibility with subsequent processing
            if 'entries' in table:
                table['all_entries'] = table['entries']
        self.static_tables.extend(string_handler_tables)
        
        # Process mixed tables
        mixed_tables = scan_data.get("mixed_tables", [])
        for table in mixed_tables:
            table['type'] = 'MIXED_TABLE'
        self.static_tables.extend(mixed_tables)
        
        self.log(f"  [+] Found {len(string_handler_tables)} string-handler tables")
        self.log(f"  [+] Found {len(mixed_tables)} mixed tables")
        self.log(f"  [+] Total routes: {scan_data.get('total_routes', 0)}")
        
        return scan_data
    
    def trace_handler_with_backward_slice(self, handler_addr: str, max_depth: int = 5) -> Dict:
        """
        Use backward slicing to trace handler registration point
        Corresponds to paper Section 3.2.2: Registration Site Analysis
        
        Args:
            handler_addr: Handler function address
            max_depth: Maximum trace depth
        
        Returns:
            Registration site information
        """
        self.log(f"  [*] Backward slicing from {handler_addr}...")
        
        res = self.ida.backward_slice(
            table_address=handler_addr,  # Reusing interface here
            handler_address=handler_addr,
            max_depth=max_depth
        )
        
        if res.get("status") != "ok":
            return {}
        
        return res.get("data", {})
    
    def analyze_dispatch_function(self, func_addr: str) -> Dict:
        """
        Analyze dispatch function to extract route mapping
        Corresponds to paper Section 3.2.3: Dispatch Hub Analysis
        
        Args:
            func_addr: Dispatch function address
        
        Returns:
            Dispatch logic and route mapping
        """
        self.log(f"  [*] Analyzing dispatch hub at {func_addr}...")
        
        res = self.ida.analyze_dispatch_hub(func_addr, extract_routes=True)
        
        if res.get("status") != "ok":
            return {}
        
        return res.get("data", {})
    
    def classify_table(self, table: Dict) -> Tuple[str, str, bool]:
        """
        Classify routing table
        Returns: (table_class, root_hint, is_valid)
        """
        entries = table.get('all_entries', table.get('entries', []))
        if not entries:
            return "UNKNOWN", "/", False
        
        # Collect all paths/keys
        paths = []
        for entry in entries[:10]:  # Sample first 10
            if 'url' in entry:
                paths.append(entry['url'])
            elif 'key' in entry:
                paths.append(entry['key'])
        
        if not paths:
            return "UNKNOWN", "/", False
        
        # Check noise patterns
        noise_count = 0
        for path in paths:
            for pattern in self.NOISE_PATTERNS:
                if re.match(pattern, path, re.IGNORECASE):
                    noise_count += 1
                    break
        
        if noise_count > len(paths) * 0.5:  # Over 50% is noise
            return "NOISE", "/", False
        
        # Pattern matching
        for pattern_name, pattern_info in self.TABLE_PATTERNS.items():
            match_count = 0
            for path in paths:
                for keyword in pattern_info["keywords"]:
                    if keyword.lower() in path.lower():
                        match_count += 1
                        break
            
            if match_count >= len(paths) * 0.3:  # 30% or more matches
                return pattern_name, pattern_info["root_hint"], True
        
        # Generic classification
        # Check if contains path separator
        has_path_sep = any('/' in p or '.' in p for p in paths)
        if has_path_sep:
            return "STANDARD_PATH", "/", True
        
        # Check if it's action mapping
        has_camel = any(re.match(r'^[A-Z][a-z]+[A-Z]', p) for p in paths)
        has_snake = any('_' in p for p in paths)
        
        if has_camel:
            return "ACTION_MAP", "/HNAP1", True
        elif has_snake:
            return "ACTION_MAP", "/goform", True
        
        return "UNKNOWN", "/", True
    
    def filter_tables_with_llm(self, tables: List[Dict]) -> Dict[str, Dict]:
        """
        Use LLM for table classification and filtering
        """
        self.log("\n[Phase 2] LLM-assisted Table Classification...")
        
        if not tables:
            return {}
        
        # Prepare LLM input
        candidates = []
        for table in tables[:30]:  # Limit quantity
            entries = table.get('all_entries', table.get('entries', []))
            samples = []
            for entry in entries[:5]:
                if 'url' in entry:
                    samples.append({"path": entry['url'], "handler": entry.get('handler', 'N/A')})
                elif 'key' in entry:
                    handlers = entry.get('handlers', [])
                    samples.append({
                        "key": entry['key'],
                        "handlers": [h.get('address', 'N/A') for h in handlers[:3]]
                    })
            
            if samples:
                candidates.append({
                    "id": table['address'],
                    "type": table.get('type', 'UNKNOWN'),
                    "samples": samples
                })
        
        if not candidates:
            return {}
        
        # Construct prompt
        prompt = """Classify these firmware routing tables.

VALID CLASSES:
- STANDARD_PATH: URL paths with / or extensions (.asp, .cgi)
- ACTION_MAP: Function mapping (CamelCase or snake_case actions)
- RESOURCE_MAP: CRUD resource operations
- NOISE: Internal bindings, MIME types (DISCARD)

For each table, determine:
1. verdict: KEEP or DISCARD
2. class: One of the above
3. parent_hint: Likely URL root (/HNAP1, /goform, /cgi-bin, etc.)

INPUT:
""" + json.dumps(candidates, indent=2) + """

OUTPUT FORMAT (JSON):
{
    "decisions": [
        {"id": "0xADDR", "verdict": "KEEP", "class": "ACTION_MAP", "parent_hint": "/HNAP1"}
    ]
}
"""
        
        try:
            response = self.llm.chat([{"role": "user", "content": prompt}], json_mode=True)
            
            if isinstance(response, str):
                response = json.loads(response)
            
            decisions = response.get("decisions", [])
            
            whitelist = {}
            for d in decisions:
                if d.get("verdict") == "KEEP":
                    whitelist[d["id"]] = {
                        "class": d.get("class", "UNKNOWN"),
                        "parent_hint": d.get("parent_hint", "/")
                    }
                    self.log(f"    [KEEP] {d['id']} -> {d.get('class')} (root: {d.get('parent_hint')})")
                else:
                    self.log(f"    [DROP] {d['id']}")
            
            return whitelist
            
        except Exception as e:
            self.log(f"  [!] LLM classification failed: {e}")
            # Fall back to heuristic classification
            return self._fallback_classification(tables)
    
    def _fallback_classification(self, tables: List[Dict]) -> Dict[str, Dict]:
        """Heuristic classification fallback"""
        whitelist = {}
        for table in tables:
            table_class, root_hint, is_valid = self.classify_table(table)
            if is_valid:
                whitelist[table['address']] = {
                    "class": table_class,
                    "parent_hint": root_hint
                }
        return whitelist
    
    def extract_from_static_tables(self) -> List[RouteNode]:
        """
        Extract routes from static tables
        """
        self.log("\n[Phase 3] Extracting Routes from Static Tables...")
        
        # LLM classification filtering
        self._table_whitelist = self.filter_tables_with_llm(self.static_tables)
        
        routes = []
        
        for table in self.static_tables:
            addr = table['address']
            
            if addr not in self._table_whitelist:
                continue
            
            meta = self._table_whitelist[addr]
            table_class = meta.get("class", "UNKNOWN")
            root_hint = meta.get("parent_hint", "/")
            
            # Process different types of tables
            if table['type'] == 'STATIC_ADAPTIVE':
                for entry in table.get('all_entries', []):
                    url = entry.get('url', '')
                    handler = entry.get('handler', '')
                    
                    if not url or not handler:
                        continue
                    
                    # [VALIDATION] Filter garbage data
                    # Common patterns where machine code is misinterpreted as strings
                    if url in ('0H-', 'pH-', '0H', 'pH') or len(url) < 2:
                        continue
                    
                    # Build full path
                    if url.startswith('/'):
                        full_path = url
                    elif root_hint != '/':
                        full_path = f"{root_hint}/{url}"
                    else:
                        full_path = f"/{url}"
                    
                    route = RouteNode(
                        path=full_path,
                        sub_path=url,
                        handler=handler,
                        source_hub=addr,
                        source_type="static_table"
                    )
                    routes.append(route)
            
            elif table['type'] == 'MIXED_TABLE':
                for entry in table.get('entries', []):
                    key = entry.get('key', '')
                    handlers = entry.get('handlers', [])
                    
                    if not key or not handlers:
                        continue
                    
                    # Create route for each handler
                    for idx, h in enumerate(handlers):
                        handler_addr = h.get('address', '')
                        if not handler_addr:
                            continue
                        
                        full_path = f"{root_hint}/{key}" if root_hint != '/' else f"/{key}"
                        
                        route = RouteNode(
                            path=f"{full_path}#{idx}",  # Distinguish different operations on same resource
                            sub_path=key,
                            handler=handler_addr,
                            source_hub=addr,
                            source_type="mixed_table"
                        )
                        routes.append(route)
        
        self.log(f"  [+] Extracted {len(routes)} routes from static tables")
        return routes
    
    def _is_likely_http_route(self, url: str) -> bool:
        """
        Determine if URL looks like an HTTP route (rather than config item name)
        
        [Fix 2026-01-22] Improved filtering logic:
        1. Added short route whitelist (ate, dns, vpn, etc.)
        2. Relaxed pure lowercase restriction (5+ char lowercase words treated as routes)
        3. Support hyphenated route names (kns-query)
        """
        import re
        if not url or len(url) < 3:
            return False
        
        # [New] Check whitelist - known short route names
        if url.lower() in self.KNOWN_SHORT_ROUTES:
            return True
        
        # Check if matches config item pattern
        for pattern in self.CONFIG_PATTERNS:
            if re.match(pattern, url):
                return False
        
        # Check if matches HTTP route pattern
        for pattern in self.HTTP_ROUTE_PATTERNS:
            if re.search(pattern, url):
                return True
        
        # Default: Length > 8 with uppercase letters may be route
        if len(url) > 8 and any(c.isupper() for c in url):
            return True
        
        # [New] Special case: 3-4 chars without numbers may be route name
        # But need caution, if handler name is passed in needs further validation
        if len(url) >= 3 and url.isalpha():
            return True
        
        return False
    
    def _filter_registration_hubs(self) -> List[Dict]:
        """
        Filter registration hubs, keeping only those likely to be HTTP route registrations
        """
        filtered = []
        
        for hub in self.registration_hubs:
            traces = hub.get("raw_call_traces", [])
            if not traces:
                continue
            
            # Count how many entries in this hub look like HTTP routes
            http_route_count = 0
            for trace in traces:
                args = trace.get("args", [])
                for arg in args:
                    if arg.get("type") == "string":
                        url = arg.get("val", "")
                        if self._is_likely_http_route(url):
                            http_route_count += 1
                        break
            
            # If >= 30% of entries look like HTTP routes, keep this hub
            if len(traces) > 0 and http_route_count / len(traces) >= 0.3:
                filtered.append(hub)
        
        return filtered
    
    def extract_from_registration_hubs(self, target_apis: List[str] = None) -> List[RouteNode]:
        """
        Extract dynamic routes from registration hubs
        """
        self.log("\n[Phase 4] Extracting Routes from Registration Hubs...")
        
        # Filter to actual HTTP route registration hubs
        filtered_hubs = self._filter_registration_hubs()
        self.log(f"  [*] Filtered to {len(filtered_hubs)} HTTP route hubs (from {len(self.registration_hubs)})")
        
        routes = []
        
        for hub in filtered_hubs:
            traces = hub.get("raw_call_traces", [])
            
            for trace in traces:
                callee = trace.get("callee_addr")
                if not callee:
                    continue
                
                # If target APIs specified, only process those
                if target_apis:
                    callee_lower = str(callee).lower()
                    if not any(t.lower() == callee_lower for t in target_apis):
                        continue
                
                # Parse arguments
                args = trace.get("args", [])
                raw_args = trace.get("raw_args", [])
                url = None
                handler = None
                
                for i, arg in enumerate(args):
                    if arg.get("type") == "string" and not url:
                        url = arg.get("val")
                    elif arg.get("type") == "obj" and not handler:
                        handler = arg.get("val")
                
                # [FALLBACK] If handler not found, try to recover from raw_args
                # Some function pointers are incorrectly identified as strings (machine code misinterpreted as strings)
                if url and not handler and len(raw_args) >= 2:
                    raw_handler = raw_args[1]  # Second argument is usually handler
                    if raw_handler.startswith('&'):
                        # Remove & prefix to get function name
                        handler = raw_handler[1:]
                        # Verify it looks like a function name (not garbage like "0H-")
                        if not handler or len(handler) < 3 or handler in ('0H-', 'pH-'):
                            handler = None
                
                # [VALIDATION] Validate route data validity
                # 1. URL cannot be garbage data (like "0H-", "pH-" etc. machine code misinterpretation)
                # 2. Handler must exist and be valid
                # 3. URL must look like HTTP route
                if url and url in ('0H-', 'pH-', '0H', 'pH'):
                    continue  # Skip invalid URL
                if not url or not handler:
                    continue
                if len(url) < 2 or len(handler) < 3:
                    continue
                if not self._is_likely_http_route(url):
                    continue  # Skip URL that doesn't look like HTTP route
                
                # === Path prefix handling ===
                # For route names without / prefix, determine type based on handler name:
                # - form*/From* prefix: GoForm route, add /goform/ prefix
                # - asp* prefix: ASP embedded function, skip (not independent route)
                # - Other: Default add /goform/ prefix (Tenda style)
                if not url.startswith('/'):
                    handler_lower = handler.lower()
                    # Skip ASP embedded functions (they are not independent routes, but function calls embedded in .asp files)
                    if handler_lower.startswith('asp') or url.lower().startswith('asp'):
                        continue
                    # GoForm style route, add /goform/ prefix
                    url = f"/goform/{url}"
                
                route = RouteNode(
                    path=url,
                    sub_path=url.split('/')[-1] if '/' in url else url,
                    handler=handler,
                    source_hub=hub['address'],
                    source_type="registration_hub"
                )
                routes.append(route)
        
        self.log(f"  [+] Extracted {len(routes)} routes from registration hubs")
        return routes
    
    def deduplicate_routes(self, routes: List[RouteNode]) -> List[RouteNode]:
        """
        Route deduplication
        """
        seen: Set[Tuple[str, str]] = set()
        unique = []
        
        for route in routes:
            key = (route.path.lower(), route.handler.lower())
            if key not in seen:
                seen.add(key)
                unique.append(route)
        
        return unique
    
    def run(self, use_llm_filter: bool = True) -> List[RouteNode]:
        """
        Execute complete route extraction workflow
        """
        self.log("\n" + "=" * 60)
        self.log("PANGU Route Extractor - Starting")
        self.log("=" * 60)
        
        # 1. Static scan
        scan_data = self.run_static_scan()
        
        if not scan_data:
            self.log("[!] Static scan returned no data")
            return []
        
        all_routes = []
        
        # 2. Extract from static tables
        static_routes = self.extract_from_static_tables()
        all_routes.extend(static_routes)
        
        # 3. Extract from registration hubs
        hub_routes = self.extract_from_registration_hubs()
        all_routes.extend(hub_routes)
        
        # 4. Deduplicate
        self.routes = self.deduplicate_routes(all_routes)
        
        self.log(f"\n[Summary]")
        self.log(f"  Total Routes: {len(self.routes)}")
        self.log(f"  From Static Tables: {len(static_routes)}")
        self.log(f"  From Registration Hubs: {len(hub_routes)}")
        
        return self.routes
    
    def run_enhanced(self, use_llm_filter: bool = True) -> List[RouteNode]:
        """
        Execute route extraction using enhanced scan
        Corresponds to paper Section 3.2.1-3.2.3 improved algorithm
        """
        self.log("\n" + "=" * 60)
        self.log("PANGU Route Extractor - Enhanced Mode")
        self.log("=" * 60)
        
        # 1. Enhanced static scan
        scan_data = self.run_enhanced_scan()
        
        if not scan_data:
            self.log("[!] Enhanced scan returned no data, falling back to standard scan")
            return self.run(use_llm_filter)
        
        all_routes = []
        
        # 2. Extract from static tables
        static_routes = self.extract_from_static_tables()
        all_routes.extend(static_routes)
        
        # 3. Extract from registration hubs (if any)
        hub_routes = self.extract_from_registration_hubs()
        all_routes.extend(hub_routes)
        
        # 4. Deduplicate
        self.routes = self.deduplicate_routes(all_routes)
        
        # 5. Optional: Analyze dispatch functions to extract extra routes
        if self.registration_hubs:
            self.log("\n[Phase 5] Analyzing Dispatch Hubs...")
            for hub in self.registration_hubs:
                hub_addr = hub.get('address')
                if hub_addr:
                    dispatch_info = self.analyze_dispatch_function(hub_addr)
                    if dispatch_info:
                        extra_routes = self._extract_routes_from_dispatch(dispatch_info, hub_addr)
                        all_routes.extend(extra_routes)
            
            # Re-deduplicate
            self.routes = self.deduplicate_routes(all_routes)
        
        self.log(f"\n[Summary]")
        self.log(f"  Total Routes: {len(self.routes)}")
        self.log(f"  From Static Tables: {len(static_routes)}")
        self.log(f"  From Registration Hubs: {len(hub_routes)}")
        
        return self.routes
    
    def _extract_routes_from_dispatch(self, dispatch_info: Dict, hub_addr: str) -> List[RouteNode]:
        """Extract extra routes from dispatch function analysis result"""
        routes = []
        
        for route_info in dispatch_info.get('routes', []):
            path = route_info.get('path', '')
            if path:
                route = RouteNode(
                    path=path,
                    sub_path=path.split('/')[-1] if '/' in path else path,
                    handler="",  # Needs further analysis
                    source_hub=hub_addr,
                    source_type="dispatch_analysis"
                )
                routes.append(route)
        
        return routes
    
    def extract_from_dispatch_function(self, func_addr: str, root_path: str = "/goform") -> List[RouteNode]:
        """
        Extract routes from dispatch/registration function
        By decompiling function and using LLM to parse route registration calls
        
        Args:
            func_addr: Dispatch function address (e.g., "0x42378")
            root_path: Route root path (e.g., "/goform")
        
        Returns:
            Extracted route list
        """
        self.log(f"\n[Dispatch] Analyzing dispatch function {func_addr}...")
        
        # Decompile function
        result = self.ida.decompile(func_addr)
        if result.get("status") != "ok":
            self.log(f"  [!] Decompilation failed: {result.get('error')}")
            return []
        
        code = result.get("data", {}).get("code", "")
        if not code:
            self.log("  [!] No pseudocode retrieved")
            return []
        
        self.log(f"  [+] Retrieved pseudocode ({len(code)} chars)"))
        
        # Use LLM to extract route registration patterns
        prompt = f"""Analyze this decompiled C code from a router firmware's route registration/dispatch function.
Extract all route registrations in the format: route_name -> handler_function

Look for patterns like:
- register_route("route_name", handler_func)
- sub_XXXX("route_name", handler_func)  
- websFormDefine("route_name", handler_func)
- if (strcmp(param, "route_name") == 0) handler_func()

CODE:
```c
{code[:8000]}  
```

Output a JSON array of objects with "route" and "handler" fields.
Example: [{{"route": "GetWanStatus", "handler": "formGetWanStatus"}}]

Only output the JSON array, no explanation."""

        try:
            response = self.llm.chat([{"role": "user", "content": prompt}], json_mode=True)
            
            if isinstance(response, str):
                # Clean response
                response = response.strip()
                if response.startswith("```"):
                    response = response.split("```")[1]
                    if response.startswith("json"):
                        response = response[4:]
                response = json.loads(response)
            
            routes = []
            if isinstance(response, list):
                for item in response:
                    route_name = item.get("route", "")
                    handler = item.get("handler", "")
                    
                    if route_name:
                        full_path = f"{root_path}/{route_name}" if not route_name.startswith("/") else route_name
                        
                        route = RouteNode(
                            path=full_path,
                            sub_path=route_name,
                            handler=handler,
                            source_hub=func_addr,
                            source_type="dispatch_function"
                        )
                        routes.append(route)
            
            self.log(f"  [+] Extracted {len(routes)} routes from dispatch function")
            return routes
            
        except Exception as e:
            self.log(f"  [!] LLM parsing failed: {e}")
            return []
    
    def run_with_dispatch(self, dispatch_func: str, root_path: str = "/goform") -> List[RouteNode]:
        """
        Use dispatch function for complete route extraction
        
        Args:
            dispatch_func: Dispatch function address
            root_path: Route root path
        """
        self.log("\n" + "=" * 60)
        self.log("PANGU Route Extractor - Dispatch Function Mode")
        self.log("=" * 60)
        
        all_routes = []
        
        # 1. First try enhanced scan
        self.log("\n[Phase 1] Enhanced static scan...")
        scan_data = self.run_enhanced_scan()
        
        # 2. Extract from static tables
        static_routes = self.extract_from_static_tables()
        all_routes.extend(static_routes)
        self.log(f"  [+] Static tables: {len(static_routes)} routes")
        
        # 3. Extract from dispatch function (core)
        self.log("\n[Phase 2] Analyzing dispatch function...")
        dispatch_routes = self.extract_from_dispatch_function(dispatch_func, root_path)
        all_routes.extend(dispatch_routes)
        self.log(f"  [+] Dispatch function: {len(dispatch_routes)} routes")
        
        # 4. Deduplicate
        self.routes = self.deduplicate_routes(all_routes)
        
        self.log(f"\n[Summary]")
        self.log(f"  Total Routes: {len(self.routes)}")
        
        return self.routes
    
    def save_routes(self, filepath: str = None):
        """
        Save routes to JSON file
        """
        if filepath is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = os.path.join(self.output_dir, f"routes_extracted_{timestamp}.json")
        
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        data = [route.to_dict() for route in self.routes]
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        self.log(f"\n[*] Routes saved to: {filepath}")
        return filepath
    
    def load_routes_from_file(self, filepath: str) -> List[RouteNode]:
        """
        Load routes from existing file
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        routes = []
        
        # Handle different formats
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            # Hierarchical format
            if all(k.startswith('/') or k == '/' for k in data.keys()):
                items = []
                for root, entries in data.items():
                    for entry in entries:
                        entry['root'] = root
                        items.append(entry)
            else:
                items = data.get('routes', data.get('hubs', []))
        else:
            items = []
        
        for item in items:
            route = RouteNode(
                path=item.get('full_path', item.get('path', '')),
                sub_path=item.get('sub_path', ''),
                handler=item.get('handler', ''),
                source_hub=item.get('source_hub', ''),
                source_type=item.get('source_type', 'loaded'),
                root=item.get('root', '/')
            )
            routes.append(route)
        
        self.routes = routes
        self.log(f"[*] Loaded {len(routes)} routes from {filepath}")
        return routes


# CLI Entry
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="PANGU Route Extractor")
    parser.add_argument("--host", default="localhost", help="IDA Pro host")
    parser.add_argument("--port", type=int, default=18811, help="IDA Pro port")
    parser.add_argument("--output", "-o", help="Output file path")
    parser.add_argument("--load", "-l", help="Load routes from existing file instead of scanning")
    
    args = parser.parse_args()
    
    ida = IDAProClient(args.host, args.port)
    llm = LLMProvider()
    
    extractor = RouteExtractor(ida, llm)
    
    if args.load:
        extractor.load_routes_from_file(args.load)
    else:
        if not ida.connect():
            print("[!] Cannot connect to IDA Pro")
            sys.exit(1)
        extractor.run()
    
    if args.output:
        extractor.save_routes(args.output)
    else:
        extractor.save_routes()
