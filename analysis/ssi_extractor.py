# Copyright (c) 2026 The Pangu Project Authors. All rights reserved.
# analysis/ssi_extractor.py
# PANGU SSI/CGI Architecture Route Extractor
# Specialized for uhttpd + SSI (Server Side Includes) pattern
# Target Devices: Trendnet TEW-827DRU and other devices using ssc_action dispatch

"""
SSI/CGI Architecture Characteristics:
1. Uses ssc_action_register() to register action tables
2. Uses CGI environment variables (REQUEST_METHOD, PATH_TRANSLATED, etc.)
3. Dispatches requests via /apply.cgi?action=xxx or similar patterns
4. Action names stored in static tables

Route Extraction Strategy:
1. Locate init_plugin function
2. Find ssc_action_register calls to get table addresses
3. Parse action tables to extract all action names
4. Also scan for .cgi route strings
"""

import sys
import os
import json
import re
import struct
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, field

sys.path.append(os.getcwd())

from core.bridge.ida_client import IDAProClient
from core.llm import LLMProvider
from analysis.models import RouteNode, AuthState, ProtectionType


@dataclass
class SSIRouteInfo:
    """SSI Route Information"""
    action_name: str                    # Action name (e.g., setup_wizard, adv_portforward)
    handler_addr: str                   # Handler function address
    handler_name: str = ""              # Handler function name
    route_type: str = "action"          # Type: action, cgi, asp
    source_table: str = ""              # Source table address
    is_secure: bool = False             # Whether this is a secure action (requires auth)
    
    def to_route_node(self) -> RouteNode:
        """Convert to standard RouteNode"""
        # SSI actions are accessed through different CGI entry points:
        # - /apply_sec.cgi?action=xxx  (may require auth, controlled by uhttpd)
        # - /apply.cgi?action=xxx      (may not require auth)
        # 
        # Note: Actual auth checks are usually at the uhttpd (web server) level, not within the CGI program
        # Therefore, Phase 1 marks auth state as Unknown, to be further analyzed in Phase 2
        # The is_secure flag only indicates which registration table the action came from (SSC_SEC_OBJS vs SSC_OBJS)
        if self.route_type == "action":
            if self.is_secure:
                # Secure action - accessed via /apply_sec.cgi
                path = f"/apply_sec.cgi?action={self.action_name}"
                root = "/apply_sec.cgi"
                # Mark as Unknown, needs Phase 2 to verify uhttpd level access control
                auth_state = AuthState.UNKNOWN
                protection = ProtectionType.NONE
                detail = "Secure action table (SSC_SEC_OBJS), auth check may be at uhttpd level"
            else:
                # Normal action - accessed via /apply.cgi
                path = f"/apply.cgi?action={self.action_name}"
                root = "/apply.cgi"
                auth_state = AuthState.UNKNOWN
                protection = ProtectionType.NONE
                detail = "Normal action table (SSC_OBJS), auth check may be at uhttpd level"
            sub_path = self.action_name
        elif self.route_type == "cgi":
            path = self.action_name if self.action_name.startswith('/') else f"/{self.action_name}"
            sub_path = self.action_name.lstrip('/')
            root = "/"
            # CGI route auth state is unknown, needs further analysis
            auth_state = AuthState.UNKNOWN
            protection = ProtectionType.NONE
            detail = None
        else:
            path = self.action_name
            sub_path = self.action_name
            root = "/"
            auth_state = AuthState.UNKNOWN
            protection = ProtectionType.NONE
            detail = None
        
        return RouteNode(
            path=path,
            sub_path=sub_path,
            handler=self.handler_name or self.handler_addr,
            source_hub=self.source_table,
            source_type="ssi_action_table" if self.route_type == "action" else "ssi_cgi",
            root=root,
            auth_state=auth_state,
            protection_type=protection,
            protection_detail=detail
        )


class SSIExtractor:
    """
    SSI/CGI Route Extractor
    
    Specialized for firmware with uhttpd + SSI architecture
    """
    
    # SSI signature functions
    SSI_MARKERS = {
        "init_functions": [
            "init_plugin", "ssi_init", "plugin_init", "cgi_init"
        ],
        "action_register_functions": [
            "ssc_action_register", "ssc_sec_action_register",
            "ssi_action_register", "action_register"
        ],
        "method_register_functions": [
            "ssi_get_method_register", "ssc_post_method_register",
            "register_mime_handler"
        ]
    }
    
    # CGI route patterns
    CGI_PATTERNS = [
        r"\.cgi$", r"\.sh$", r"/apply", r"/upload", r"/download"
    ]
    
    def __init__(self, ida_client: IDAProClient, llm: Optional[LLMProvider] = None):
        self.ida = ida_client
        self.llm = llm
        
        # Extraction results
        self.routes: List[SSIRouteInfo] = []
        self.action_tables: Dict[str, List] = {}  # table address -> action list
        
        # Configuration
        self.output_dir = "output"
        self.verbose = True
    
    def log(self, msg: str):
        """Log output"""
        if self.verbose:
            print(msg)
    
    def run(self, use_llm: bool = True) -> List[RouteNode]:
        """
        Execute SSI route extraction
        
        Returns:
            List of RouteNodes
        """
        self.log("\n[SSI Extractor] Starting extraction...")
        
        # 1. Find initialization function
        init_func = self._find_init_function()
        if init_func:
            self.log(f"  [+] Found init function: {init_func}")
            
            # 2. Extract action table addresses from init function
            self._extract_action_tables(init_func)
        
        # 3. Parse all action tables
        self._parse_action_tables()
        
        # 4. Search CGI route strings
        self._search_cgi_routes()
        
        # 5. Convert to RouteNode
        route_nodes = [r.to_route_node() for r in self.routes]
        
        self.log(f"\n[SSI Extractor] Extracted {len(route_nodes)} routes")
        
        return route_nodes
    
    def _find_init_function(self) -> Optional[str]:
        """Find initialization function"""
        self.log("  [*] Searching for init function...")
        
        for func_name in self.SSI_MARKERS["init_functions"]:
            result = self.ida.get_functions(search=func_name, limit=5)
            if result.get("status") == "ok":
                funcs = result.get("data", [])
                for func in funcs:
                    name = func.get("name", "")
                    addr = func.get("addr", "")
                    if name == func_name or name == f"_{func_name}":
                        return addr or name
        
        return None
    
    def _extract_action_tables(self, init_func: str):
        """Extract action table addresses from initialization function"""
        self.log(f"  [*] Analyzing init function for action tables...")
        
        # Decompile initialization function
        result = self.ida.decompile(init_func)
        if result.get("status") != "ok":
            self.log(f"  [-] Failed to decompile {init_func}")
            return
        
        code = result.get("data", {}).get("code", "")
        
        # Find action_register calls
        # Match pattern: ssc_action_register(&off_4F16B0) or ssc_sec_action_register(&off_4F1598)
        # Note: Need to accurately distinguish ssc_sec_action_register (secure) from ssc_action_register (normal)
        patterns = [
            (r'ssc_sec_action_register\s*\(\s*&?(\w+)\s*\)', True),   # secure
            (r'(?<![_a-z])ssc_action_register\s*\(\s*&?(\w+)\s*\)', False),  # normal (exclude xxx_ssc_action_register)
        ]
        
        for pattern, is_secure in patterns:
            matches = re.findall(pattern, code)
            for match in matches:
                table_name = match
                # Skip tables that already exist
                addr = table_name.replace("off_", "0x") if table_name.startswith("off_") else table_name
                if addr in self.action_tables:
                    continue
                    
                self.log(f"    [+] Found action table: {table_name} (secure={is_secure})")
                
                # Try to parse as address
                if table_name.startswith("off_") or table_name.startswith("0x"):
                    addr = table_name.replace("off_", "0x")
                    self.action_tables[addr] = {"secure": is_secure, "actions": []}
                else:
                    # Try to search for this symbol
                    self.action_tables[table_name] = {"secure": is_secure, "actions": []}
    
    def _parse_action_tables(self):
        """Parse all action tables"""
        self.log("  [*] Parsing action tables...")
        
        for table_addr, table_info in self.action_tables.items():
            self.log(f"    [*] Parsing table at {table_addr}...")
            
            # Convert address
            if table_addr.startswith("0x"):
                addr = table_addr
            elif table_addr.startswith("off_"):
                addr = "0x" + table_addr[4:]
            else:
                # Try to search for symbol
                result = self.ida.search_strings(table_addr)
                if result.get("status") == "ok" and result.get("data"):
                    # Found symbol, get address
                    continue
                else:
                    continue
            
            # Read table data
            self._parse_single_table(addr, table_info["secure"])
    
    def _parse_single_table(self, table_addr: str, is_secure: bool):
        """Parse a single action table"""
        # Try multiple table formats
        
        # Format 1: [string_ptr, func_ptr] - 8 bytes/entry
        result = self.ida.read_bytes(table_addr, length=2000)
        if result.get("status") != "ok":
            return
        
        data = bytes.fromhex(result.get("data", ""))
        
        # First try to determine table format
        # Read first few entries to detect format
        entries_found = []
        
        # Helper function: get string from resolve_data result
        def get_string_value(result):
            if result.get("status") != "ok":
                return ""
            # Handle multiple return formats
            if result.get("type") == "string":
                return result.get("value", "")
            elif result.get("type") == "pointer_to_string":
                return result.get("target_string", "")
            return ""
        
        # Try format: [string_ptr, func_ptr] (8 bytes)
        for i in range(0, min(len(data), 200), 8):
            if i + 8 > len(data):
                break
            str_ptr = struct.unpack('<I', data[i:i+4])[0]
            func_ptr = struct.unpack('<I', data[i+4:i+8])[0]
            
            if str_ptr == 0:
                break
            
            # Verify if this is a valid string pointer
            str_result = self.ida.resolve_data(hex(str_ptr), length=4)
            str_val = get_string_value(str_result)
            if str_val and len(str_val) > 2 and not str_val.startswith('\x00'):
                entries_found.append((str_val, hex(func_ptr), 8))
        
        # If format 1 found few entries, try format 2
        if len(entries_found) < 5:
            entries_found_20 = []
            # Try format: [string_ptr, 0, 0, func_ptr, 0] (20 bytes)
            for i in range(0, min(len(data), 3000), 20):
                if i + 20 > len(data):
                    break
                str_ptr = struct.unpack('<I', data[i:i+4])[0]
                func_ptr = struct.unpack('<I', data[i+12:i+16])[0]
                
                if str_ptr == 0:
                    break
                
                str_result = self.ida.resolve_data(hex(str_ptr), length=4)
                str_val = get_string_value(str_result)
                if str_val and len(str_val) > 2:
                    entries_found_20.append((str_val, hex(func_ptr), 20))
            
            if len(entries_found_20) > len(entries_found):
                entries_found = entries_found_20
        
        # Add found routes
        for action_name, handler_addr, _ in entries_found:
            # Get function name
            handler_name = ""
            func_result = self.ida.get_functions(search=handler_addr, limit=1)
            if func_result.get("status") == "ok" and func_result.get("data"):
                handler_name = func_result["data"][0].get("name", "")
            
            route = SSIRouteInfo(
                action_name=action_name,
                handler_addr=handler_addr,
                handler_name=handler_name,
                route_type="action",
                source_table=table_addr,
                is_secure=is_secure
            )
            self.routes.append(route)
            
            self.log(f"      [+] {action_name:35} -> {handler_name or handler_addr}")
    
    def _search_cgi_routes(self):
        """Search for CGI route strings"""
        self.log("  [*] Searching for CGI routes...")
        
        # Search for .cgi file routes
        result = self.ida.search_strings(".cgi")
        if result.get("status") == "ok":
            data = result.get("data", [])
            for entry in data:
                val = entry.get("val", "")
                addr = entry.get("addr", "")
                
                # Filter valid CGI routes
                if val.endswith(".cgi") and "/" in val and len(val) < 100:
                    # Check if already exists
                    existing = [r for r in self.routes if r.action_name == val]
                    if not existing:
                        route = SSIRouteInfo(
                            action_name=val,
                            handler_addr=addr,
                            handler_name="",
                            route_type="cgi",
                            source_table="string_search"
                        )
                        self.routes.append(route)
                        self.log(f"      [+] CGI: {val}")
        
        # Search for other CGI patterns
        for pattern in ["/upload", "/download", "/apply", "/seama", "/fwupload"]:
            result = self.ida.search_strings(pattern)
            if result.get("status") == "ok":
                data = result.get("data", [])
                for entry in data[:10]:  # Limit quantity
                    val = entry.get("val", "")
                    if val and "/" in val and len(val) < 80:
                        # Extract route part
                        if val.endswith(".cgi") or val.endswith(".sh"):
                            existing = [r for r in self.routes if r.action_name == val]
                            if not existing:
                                route = SSIRouteInfo(
                                    action_name=val,
                                    handler_addr="",
                                    handler_name="",
                                    route_type="cgi",
                                    source_table="string_search"
                                )
                                self.routes.append(route)
