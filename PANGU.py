#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2026 The Pangu Project Authors. All rights reserved.
"""
PANGU - Automated Broken Access Control Vulnerability Detection System for IoT Firmware
Program Analysis for uNauthorized access detection using Graph-based Understanding

Main program entry point, supporting phased execution:
  --phase 1: Route Extraction
  --phase 2: Logic Decoupling and ACDG Construction
  --phase 3: Dual-Agent Vulnerability Detection
  --phase all: Complete Pipeline

Usage:
  python PANGU.py --firmware "Tenda_AC15" --phase all
  python PANGU.py --firmware "DLink_823G" --phase 2 --init-func "sub_423F90"
"""

import sys
import os
import json
import argparse
import time
from datetime import datetime
from typing import List, Dict, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.bridge.ida_client import IDAProClient
from core.llm import LLMProvider
from analysis.models import ACDG, RouteNode, VulnerabilityFinding, AuthState, ProtectionType
from rag.knowledge_base import KnowledgeBase
from analysis.fastcgi_extractor import FastCGIExtractor, ArchitectureDetector
from analysis.firmware_analyzer import FirmwareAnalyzer, FirmwareAnalysisResult


# ==================== Banner ====================

BANNER = r"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   ██████╗  █████╗ ███╗   ██╗ ██████╗ ██╗   ██╗                            ║
║   ██╔══██╗██╔══██╗████╗  ██║██╔════╝ ██║   ██║                            ║
║   ██████╔╝███████║██╔██╗ ██║██║  ███╗██║   ██║                            ║
║   ██╔═══╝ ██╔══██║██║╚██╗██║██║   ██║██║   ██║                            ║
║   ██║     ██║  ██║██║ ╚████║╚██████╔╝╚██████╔╝                            ║
║   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝                             ║
║                                                                           ║
║   IoT Firmware Broken Access Control Vulnerability Detection System       ║
║   Version 1.0.0                                                           ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""


# ==================== Helper Functions ====================

def _find_cgi_backend_hints(ida: IDAProClient) -> Dict[str, List[str]]:
    """
    Search for CGI backend related hints in web server binary.
    
    Returns:
        Dictionary containing various hints
    """
    hints = {
        "fastcgi_backends": [],
        "cgi_paths": [],
        "socket_paths": [],
        "script_extensions": []
    }
    
    # Search for FastCGI backend configuration
    fastcgi_patterns = ["fastcgi.server", "socket =>", ".sock", "fastcgi("]
    for pattern in fastcgi_patterns:
        try:
            result = ida.search_strings(pattern)
            if result.get("status") == "ok":
                for s in result.get("data", []):
                    val = s.get("val", "")
                    if val and len(val) < 200:
                        if ".sock" in val or "socket" in val.lower():
                            hints["socket_paths"].append(val)
                        elif "fastcgi" in val.lower():
                            hints["fastcgi_backends"].append(val)
        except:
            pass
    
    # Search for CGI paths
    cgi_patterns = ["/cgi-bin", "/www/cgi", ".cgi", "/jnap", "/api/"]
    for pattern in cgi_patterns:
        try:
            result = ida.search_strings(pattern)
            if result.get("status") == "ok":
                for s in result.get("data", []):
                    val = s.get("val", "")
                    if val and len(val) < 100:
                        hints["cgi_paths"].append(val)
        except:
            pass
    
    # Search for script extension configuration
    ext_patterns = [".lua", ".php", ".asp", ".cgi"]
    for pattern in ext_patterns:
        try:
            result = ida.search_strings(pattern)
            if result.get("status") == "ok":
                data = result.get("data", [])
                if data:
                    hints["script_extensions"].append(pattern)
        except:
            pass
    
    return hints


def _merge_static_routes(static_routes: List, existing_paths: set, verbose: bool = True) -> List[RouteNode]:
    """
    Convert and merge Phase 0 static routes into RouteNode list.
    
    Args:
        static_routes: Static routes discovered in Phase 0 (StaticRouteInfo objects)
        existing_paths: Set of existing route paths (for deduplication)
        verbose: Whether to output detailed information
    
    Returns:
        List of converted RouteNodes
    """
    from analysis.models import AuthState, ProtectionType
    
    merged_routes = []
    
    # Filter out static assets (CSS/JS/images, etc.)
    STATIC_ASSET_PATTERNS = [
        r'\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|ttf|eot|map)$',
        r'/fonts/',
        r'/images/',
        r'/static/',
        r'^\.\./',  # Relative path reference
        r'\.min\.',  # Compressed file
    ]
    
    # API route feature patterns (high priority)
    API_ROUTE_PATTERNS = [
        (r'^/api/', 100),          # /api/* style
        (r'^/cgi-bin/', 90),       # CGI routes
        (r'^/stok=', 85),          # TP-Link stok authentication
        (r'/module/', 80),          # UCI module
        (r'\?action=', 75),         # action parameter
        (r'\.cgi$', 70),           # CGI extension
        (r'/goform/', 65),          # goform style
        (r'/HNAP1/', 60),           # HNAP style
    ]
    
    api_routes = []
    
    for sr in static_routes:
        path = sr.path
        
        # Skip static assets
        skip = False
        import re
        for pattern in STATIC_ASSET_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                skip = True
                break
        
        if skip:
            continue
        
        # Check if already exists
        if path in existing_paths:
            continue
        
        # Calculate route priority
        priority = 0
        route_type = "static_file"
        
        for pattern, score in API_ROUTE_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                priority = max(priority, score)
                route_type = "api_endpoint"
        
        # Only keep API routes (non-static files)
        if priority > 0 or sr.method == "POST":
            api_routes.append({
                "sr": sr,
                "priority": priority,
                "route_type": route_type
            })
    
    # Sort by priority
    api_routes.sort(key=lambda x: x["priority"], reverse=True)
    
    # Convert to RouteNode
    for item in api_routes:
        sr = item["sr"]
        
        # Determine authentication state hint
        auth_state = AuthState.UNKNOWN
        auth_hint = ""
        protection_type = ProtectionType.NONE
        
        if hasattr(sr, 'auth_hint') and sr.auth_hint:
            auth_hint = sr.auth_hint
            if "UCI" in sr.auth_hint:
                auth_state = AuthState.AUTH_REQUIRED  # UCI usually requires authentication
                protection_type = ProtectionType.GATEKEEPER
            elif "login" in sr.path.lower() or "auth" in sr.path.lower():
                auth_state = AuthState.AUTH_FREE  # Login pages usually don't require authentication
        
        route = RouteNode(
            path=sr.path,
            sub_path=sr.path.split('/')[-1] if '/' in sr.path else sr.path,
            handler="",  # Static analysis cannot determine handler
            source_hub=sr.source_file if hasattr(sr, 'source_file') else "",
            source_type="static_analysis",
            http_method=sr.method,
            root="/",
            auth_state=AuthState.UNKNOWN,
            protection_type=ProtectionType.NONE,
            analysis_gaps=["Filesystem endpoint and authentication hints require binary verification"],
            protection_detail=f"From static analysis: {auth_hint}" if auth_hint else "From filesystem analysis"
        )
        
        merged_routes.append(route)
        existing_paths.add(sr.path)
    
    if verbose and merged_routes:
        # Show first few merged routes
        print(f"    Sample merged routes:")
        for route in merged_routes[:5]:
            print(f"      - {route.path} ({route.auth_state.value})")
        if len(merged_routes) > 5:
            print(f"      ... and {len(merged_routes) - 5} more")
    
    return merged_routes


# ==================== Phase 0: Firmware Pre-Analysis ====================

def run_phase0(firmware_root: str, firmware_name: str, output_dir: str,
               verbose: bool = True) -> Optional[FirmwareAnalysisResult]:
    """
    Phase 0: Firmware Filesystem Pre-Analysis (Optional)
    
    Analyze firmware filesystem, identify web architecture, locate CGI binaries, extract static routes.
    This is an independent pre-analysis phase that provides context for Phase 1.
    
    Args:
        firmware_root: Firmware filesystem root directory
        firmware_name: Firmware name
        output_dir: Output directory
        verbose: Verbose output
    
    Returns:
        FirmwareAnalysisResult or None
    """
    print("\n" + "=" * 70)
    print("  PHASE 0: FIRMWARE FILESYSTEM PRE-ANALYSIS")
    print("  Analyzing firmware structure to identify web components...")
    print("=" * 70)
    
    if not os.path.exists(firmware_root):
        print(f"\n[ERROR] Firmware root not found: {firmware_root}")
        return None
    
    start_time = time.time()
    
    # Create analyzer
    analyzer = FirmwareAnalyzer(firmware_root, verbose)
    result = analyzer.analyze()
    
    # Save result
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, f"{firmware_name}_preanalysis.json")
    analyzer.save_result(output_path)
    
    # Print summary
    analyzer.print_summary()

    # Prompt next binary file to open
    top_candidates = result.binary_candidates[:5] if result else []
    print("\n" + "=" * 70)
    print("  NEXT STEPS:")
    print("=" * 70)
    if top_candidates:
        print("\n  [TARGET] Recommended binaries to analyze (sorted by priority):")
        print("-" * 70)
        for i, c in enumerate(top_candidates, 1):
            rel_path = os.path.relpath(c.path, firmware_root) if os.path.isabs(c.path) else c.path
            print(f"\n  [{i}] {c.name}")
            print(f"      Path:     {rel_path}")
            print(f"      Type:     {c.binary_type}")
            print(f"      Priority: {c.priority}")
            print(f"      Size:     {c.size:,} bytes ({c.size/1024:.1f} KB)")
            # Show Web features (if available)
            if hasattr(c, 'web_features') and c.web_features:
                print(f"      Features: {', '.join(c.web_features)}")
            # Show architecture (if available)
            if hasattr(c, 'architecture') and c.architecture:
                print(f"      Arch:     {c.architecture}")
            print(f"      Reason:   {c.reason}")
        
        # Give specific next step instructions
        best_candidate = top_candidates[0]
        best_rel_path = os.path.relpath(best_candidate.path, firmware_root) if os.path.isabs(best_candidate.path) else best_candidate.path
        
        print("\n" + "-" * 70)
        print("  [ACTION] RECOMMENDED ACTION:")
        print(f"     1. Open '{best_candidate.name}' in IDA Pro")
        print(f"        Full path: {best_candidate.path}")
        print(f"\n     2. Run Phase 1 route extraction:")
        print(f"        python PANGU.py --firmware \"{firmware_name}\" --phase 1 --arch auto")
        
        if best_candidate.binary_type == "main_service":
            print("\n     [TIP] This appears to be the main management service.")
            print("        It likely contains embedded HTTP server and route handlers.")
            if hasattr(best_candidate, 'web_features') and 'goform' in best_candidate.web_features:
                print("        Look for /goform/* style routes.")
            if hasattr(best_candidate, 'web_features') and 'json_api' in best_candidate.web_features:
                print("        JSON API handlers detected - look for jsonObject* functions.")
    else:
        print("\n  [WARNING] No web binaries were detected automatically.")
        print("\n  Possible reasons:")
        print("    - The firmware uses an unusual architecture")
        print("    - Web service is implemented in scripts (Lua/PHP/Shell)")
        print("    - The binary names don't match known patterns")
        print("\n  Manual investigation suggestions:")
        print("    1. List large binaries: find . -type f -executable -size +50k")
        print("    2. Search for HTTP strings: grep -r 'HTTP/1' --include='*'")
        print("    3. Check startup scripts in /etc/init.d/ or /etc/rc.d/")
        print("    4. Look for web-related config files in /etc/")
    
    elapsed = time.time() - start_time
    print(f"\n[*] Phase 0 completed in {elapsed:.2f}s")
    
    return result


def load_preanalysis_result(firmware_name: str, output_dir: str) -> Optional[FirmwareAnalysisResult]:
    """
    Load existing pre-analysis result.
    
    Args:
        firmware_name: Firmware name
        output_dir: Output directory
    
    Returns:
        FirmwareAnalysisResult or None
    """
    preanalysis_path = os.path.join(output_dir, f"{firmware_name}_preanalysis.json")
    if os.path.exists(preanalysis_path):
        try:
            with open(preanalysis_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Rebuild result object
            from analysis.firmware_analyzer import (
                FirmwareAnalysisResult, WebServerInfo, 
                BinaryCandidate, StaticRouteInfo
            )
            
            result = FirmwareAnalysisResult(firmware_root=data.get("firmware_root", ""))
            result.analysis_time = data.get("analysis_time", "")
            
            # Rebuild webserver info
            ws_data = data.get("webserver", {})
            result.webserver = WebServerInfo(
                server_type=ws_data.get("server_type", "unknown"),
                config_file=ws_data.get("config_file", ""),
                document_root=ws_data.get("document_root", ""),
                cgi_paths=ws_data.get("cgi_paths", []),
                fastcgi_sockets=ws_data.get("fastcgi_sockets", []),
                lua_paths=ws_data.get("lua_paths", []),
                modules=ws_data.get("modules", [])
            )
            
            # Rebuild binary candidates
            result.binary_candidates = [
                BinaryCandidate(**bc) for bc in data.get("binary_candidates", [])
            ]
            
            # Rebuild static routes
            result.static_routes = [
                StaticRouteInfo(**sr) for sr in data.get("static_routes", [])
            ]
            
            result.auth_findings = data.get("auth_findings", [])
            result.recommendations = data.get("recommendations", [])
            
            return result
        except Exception as e:
            print(f"[WARN] Failed to load preanalysis: {e}")
    
    return None


# ==================== Phase 1: Route Extraction ====================

def run_phase1(ida: IDAProClient, llm: LLMProvider, 
               firmware_name: str, output_dir: str, 
               verbose: bool = True,
               architecture: str = "auto",
               preanalysis: Optional[FirmwareAnalysisResult] = None) -> Tuple[List[RouteNode], float]:
    """
    Phase 1: Route Extraction
    
    Args:
        ida: IDA Pro client
        llm: LLM provider
        firmware_name: Firmware name
        output_dir: Output directory
        verbose: Verbose output
        architecture: Architecture type ("auto", "GoAhead", "FastCGI", "JSONRPC", etc.)
        preanalysis: Optional Phase 0 pre-analysis result
    
    Returns:
        (routes, elapsed_time)
    """
    print("\n" + "=" * 70)
    print("  PHASE 1: ROUTE EXTRACTION")
    print("  Section 3.2: Smart Table Detection & Hierarchical Reconstruction")
    print("=" * 70)
    
    start_time = time.time()
    
    # If pre-analysis result available, show context info
    if preanalysis:
        print("\n[Phase 1.0] Using pre-analysis context from Phase 0...")
        if preanalysis.webserver.server_type != "unknown":
            print(f"  Web Server: {preanalysis.webserver.server_type}")
        if preanalysis.static_routes:
            print(f"  Static routes hint: {len(preanalysis.static_routes)} routes found in HTML/JS")
        if preanalysis.webserver.cgi_paths:
            print(f"  CGI paths: {preanalysis.webserver.cgi_paths}")
    
    # Architecture detection
    detected_arch = architecture
    detector = None
    if architecture == "auto":
        print("\n[Phase 1.0] Auto-detecting architecture...")
        detector = ArchitectureDetector(ida)
        detected_arch, confidence = detector.detect()
        print(f"  Detected: {detected_arch} (confidence: {confidence:.1%})")
        
        # Check if it is a pure web server
        if detector.is_pure_webserver():
            print("\n" + "=" * 70)
            print("  ⚠️  PURE WEB SERVER DETECTED - NO APPLICATION ROUTES")
            print("=" * 70)
            
            # Try to find CGI backend hints from binary
            cgi_hints = _find_cgi_backend_hints(ida)
            
            # Apache specific hints
            if detected_arch == "ApacheServer":
                print(f"""
  The binary '{firmware_name}' is Apache httpd - a standalone web server.
  Apache itself does not contain application routes.
  
  Application routes are handled by:
    1. CGI programs in /usr/local/apache/cgi-bin/
    2. Apache modules (.so files, like mod_auth_zyxel.so)
    3. Python/WSGI applications""")
                
                # Get recommended CGI files from pre-analysis result
                if preanalysis:
                    print("\n  📍 Recommended CGI binaries from Phase 0 pre-analysis:")
                    auth_free_cgis = []
                    other_cgis = []
                    
                    for candidate in preanalysis.binary_candidates:
                        if candidate.binary_type == "cgi":
                            if "[Auth-Free WHITELIST]" in candidate.reason:
                                auth_free_cgis.append(candidate)
                            else:
                                other_cgis.append(candidate)
                    
                    if auth_free_cgis:
                        print("\n    🔴 HIGH PRIORITY (Auth-Free, no authentication required):")
                        for cgi in auth_free_cgis[:5]:
                            print(f"      - {cgi.name}: {cgi.path}")
                    
                    if other_cgis:
                        print("\n    Other CGI binaries:")
                        for cgi in other_cgis[:5]:
                            print(f"      - {cgi.name}: {cgi.path}")
                    
                    # Extract auth whitelist information
                    whitelist_paths = []
                    for finding in preanalysis.auth_findings:
                        if "Auth-Free (whitelist):" in finding:
                            path = finding.replace("Auth-Free (whitelist):", "").strip()
                            whitelist_paths.append(path)
                    
                    if whitelist_paths:
                        print(f"\n    📋 Auth-Free whitelist from Apache config ({len(whitelist_paths)} paths):")
                        for path in whitelist_paths[:10]:
                            print(f"      {path}")
                        if len(whitelist_paths) > 10:
                            print(f"      ... and {len(whitelist_paths) - 10} more")
                
                print("""
  Recommended actions:
    1. Run Phase 0 first to identify CGI binaries:
       python PANGU.py --firmware "{}" --phase 0 --firmware-root "<path>"
    
    2. Open the recommended CGI binary in IDA Pro (e.g., weblogin.cgi)
    
    3. Run Phase 1 again with the CGI binary loaded:
       python PANGU.py --firmware "{}" --phase 1
""".format(firmware_name, firmware_name))
            
            else:
                # Generic pure web server hints
                print(f"""
  The binary '{firmware_name}' appears to be a standalone web server
  (like lighttpd, nginx, or Apache) that does not contain application
  routes directly.
  
  Application routes are typically handled by:
    1. CGI scripts (e.g., /www/cgi-bin/*.cgi)
    2. FastCGI backend programs
    3. Lua scripts in /www/lua/
    4. Separate application binaries""")

                # Display found hints
                if any(cgi_hints.values()):
                    print("\n  📍 Hints found in this binary:")
                    if cgi_hints["fastcgi_backends"]:
                        print(f"    FastCGI config: {cgi_hints['fastcgi_backends'][:3]}")
                    if cgi_hints["socket_paths"]:
                        print(f"    Socket paths: {cgi_hints['socket_paths'][:3]}")
                    if cgi_hints["cgi_paths"]:
                        print(f"    CGI paths: {cgi_hints['cgi_paths'][:5]}")
                    if cgi_hints["script_extensions"]:
                        print(f"    Script extensions: {cgi_hints['script_extensions']}")
                
                print("""
  Recommended actions:
    1. Look for CGI binaries in the firmware's /www/cgi-bin/ directory
    2. Search for FastCGI backend programs (often named like 'fcgi_*')
    3. Check for application-specific binaries (e.g., 'httpd_app', 'webapi')
    4. Analyze Lua scripts if the device uses OpenWrt/LEDE
  
  Common CGI/application binaries to look for:
    - cgi-bin/*.cgi
    - goahead, goform
    - uhttpd-mod-*.so
    - www/api/* or www/jnap/*
""")
            elapsed = time.time() - start_time
            return [], elapsed
    else:
        print(f"\n[Phase 1.0] Using specified architecture: {architecture}")
        detected_arch = architecture
    
    # Select extractor based on architecture
    if detected_arch == "GoForm":
        # Use GoForm extractor (lighttpd mod_form module)
        print("\n[Phase 1.1] Using GoForm Extractor (lighttpd mod_form strcmp dispatch)...")
        from analysis.goform_extractor import GoFormExtractor
        
        extractor = GoFormExtractor(ida, llm)
        extractor.verbose = verbose
        extractor.output_dir = output_dir
        
        routes = extractor.run(use_llm=True)
        
        # Save result (will merge later)
        output_file = os.path.join(output_dir, f"{firmware_name}_routes.json")
    
    elif detected_arch in ["FastCGI", "Lighttpd"]:
        # Use FastCGI extractor
        print("\n[Phase 1.1] Using FastCGI Extractor (strncmp dispatch mode)...")
        extractor = FastCGIExtractor(ida, llm)
        extractor.verbose = verbose
        extractor.output_dir = output_dir
        
        routes = extractor.run(use_llm=True)
        
        # Save result (will merge later)
        output_file = os.path.join(output_dir, f"{firmware_name}_routes.json")
    
    elif detected_arch == "JSONRPC":
        # Use JSON-RPC extractor (Cisco RV34x, etc.)
        print("\n[Phase 1.1] Using JSONRPC Extractor (strcmp method dispatch mode)...")
        from analysis.jsonrpc_extractor import JSONRPCExtractor
        
        extractor = JSONRPCExtractor(ida, llm)
        extractor.verbose = verbose
        extractor.output_dir = output_dir
        
        routes = extractor.run(use_llm=True)
        
        # Save result (will merge later)
        output_file = os.path.join(output_dir, f"{firmware_name}_routes.json")
    
    elif detected_arch == "SSI_CGI":
        # SSI/CGI architecture (uhttpd + ssi, common in Trendnet, etc.)
        # Use static table extractor + specific action table analysis
        print("\n[Phase 1.1] Using SSI/CGI Extractor (ssc_action static table mode)...")
        
        from analysis.ssi_extractor import SSIExtractor
        
        extractor = SSIExtractor(ida, llm)
        extractor.verbose = verbose
        extractor.output_dir = output_dir
        
        routes = extractor.run(use_llm=True)
        
        # Save result (will merge later)
        output_file = os.path.join(output_dir, f"{firmware_name}_routes.json")
    
    elif detected_arch == "DistributedCGI":
        # Distributed CGI architecture (Lighttpd + multiple independent CGI programs)
        # Each .cgi is an independent executable, auth logic implemented within each CGI
        print("\n[Phase 1.1] Using Distributed CGI Extractor...")
        print("  NOTE: This architecture uses separate CGI binaries.")
        print("  Each CGI analysis is saved separately and merged in Phase 2.")
        
        from analysis.distributed_cgi_extractor import DistributedCGIExtractor, analyze_cgi_binary
        
        extractor = DistributedCGIExtractor(ida, llm)
        extractor.verbose = verbose
        extractor.output_dir = output_dir
        
        # Analyze current open CGI
        cgi_info = extractor.analyze_current_binary()
        
        if cgi_info:
            routes = extractor.get_routes_as_nodes()
            
            # Save individual CGI analysis to separate file (won't overwrite other CGIs)
            cgi_output = os.path.join(output_dir, f"{cgi_info.name}_analysis.json")
            extractor.save_analysis(cgi_output)
            print(f"\n  [*] CGI analysis saved to: {cgi_output}")
            
            # === Accumulate mode: merge to total routes file ===
            output_file = os.path.join(output_dir, f"{firmware_name}_routes.json")
            existing_routes = []
            
            # Load existing routes (if exists)
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r', encoding='utf-8') as f:
                        existing_data = json.load(f)
                    existing_routes = [RouteNode.from_dict(r) for r in existing_data]
                    print(f"  [*] Loaded {len(existing_routes)} existing routes from previous CGI analyses")
                except Exception as e:
                    print(f"  [WARN] Failed to load existing routes: {e}")
            
            # Deduplicate merge: by path
            existing_paths = set(r.path for r in existing_routes)
            new_routes = [r for r in routes if r.path not in existing_paths]
            
            if new_routes:
                print(f"  [+] Adding {len(new_routes)} new routes from {cgi_info.name}")
                routes = existing_routes + new_routes
            else:
                print(f"  [*] No new routes from {cgi_info.name} (all duplicates)")
                routes = existing_routes
        else:
            routes = []
            output_file = os.path.join(output_dir, f"{firmware_name}_routes.json")
        
    else:
        # Use original RouteExtractor (GoAhead / TP-Link / Unknown, etc.)
        # TP-Link custom architecture also uses standard extractor as it has similar static table structure
        arch_note = ""
        if detected_arch == "TPLink":
            arch_note = "TP-Link SSI/Rpm.htm style"
        elif detected_arch == "Unknown":
            arch_note = "Unknown architecture, trying generic extraction"
        else:
            arch_note = "GoAhead/Static table mode"
        
        print(f"\n[Phase 1.1] Using Standard Extractor ({arch_note})...")
        
        from analysis.route_extractor import RouteExtractor
        
        extractor = RouteExtractor(ida, llm)
        extractor.verbose = verbose
        extractor.output_dir = output_dir
        
        # Execute route extraction
        routes = extractor.run(use_llm_filter=True)
        
        # Save result (will merge later)
        output_file = os.path.join(output_dir, f"{firmware_name}_routes.json")
    
    # ========== Merge Phase 0 Static Routes ==========
    binary_route_count = len(routes)
    static_route_count = 0
    
    if preanalysis and preanalysis.static_routes:
        print("\n[Phase 1.2] Merging static routes from Phase 0 pre-analysis...")
        
        # Deduplication set for existing routes
        existing_paths = set()
        for route in routes:
            existing_paths.add(route.path)
            if route.sub_path:
                existing_paths.add(route.sub_path)
        
        # Merge static routes from pre-analysis result
        static_routes = _merge_static_routes(preanalysis.static_routes, existing_paths, verbose)
        routes.extend(static_routes)
        static_route_count = len(static_routes)
        
        print(f"  [+] Merged {static_route_count} static routes from filesystem analysis")
    
    # An HTTP-server whitelist cannot erase a CGI/handler-local check.
    if preanalysis and preanalysis.auth_findings:
        whitelist_paths = [item.replace("Auth-Free (whitelist):", "").strip()
                           for item in preanalysis.auth_findings if "Auth-Free (whitelist):" in item]
        for route in routes:
            if route.path.split("?", 1)[0] in whitelist_paths:
                route.analysis_gaps.append("HTTP server whitelist observed; handler-local authentication requires separate verification")
    status = ida.get_status()
    binary_id = status.get("data", {}).get("binary_id", "") if status.get("status") == "ok" else ""
    for route in routes:
        if route.handler and not route.binary_id:
            route.binary_id = binary_id

    # Save merged result
    routes_data = [r.to_dict() for r in routes]
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(routes_data, f, indent=2, ensure_ascii=False)
    
    elapsed = time.time() - start_time
    
    # Statistics
    print(f"\n[Phase 1 Complete]")
    print(f"  Architecture: {detected_arch}")
    print(f"  Binary Routes: {binary_route_count}")
    if static_route_count > 0:
        print(f"  Static Routes (from Phase 0): {static_route_count}")
    print(f"  Total Routes: {len(routes)}")
    if detected_arch not in ["FastCGI", "Lighttpd", "JSONRPC", "GoForm"]:
        from analysis.route_extractor import RouteExtractor
        if hasattr(extractor, 'static_tables'):
            print(f"  Static Tables: {len(extractor.static_tables)}")
            print(f"  Registration Hubs: {len(extractor.registration_hubs)}")
    print(f"  [*] Elapsed Time: {elapsed:.2f} seconds")
    print(f"  [*] Saved to: {output_file}")
    
    return routes, elapsed


# ==================== Phase 2: Logic Decoupling ====================

def run_phase2(ida: IDAProClient, llm: LLMProvider,
               firmware_name: str, output_dir: str,
               routes: List[RouteNode] = None,
               init_func: str = None,
               verbose: bool = True,
               architecture: str = None,
               firmware_root: str = None) -> Tuple[ACDG, float]:
    """
    Phase 2: Logic Decoupling and ACDG Construction
    
    Args:
        ida: IDA Pro client
        llm: LLM provider
        firmware_name: Firmware name
        output_dir: Output directory
        routes: Routes extracted in Phase 1
        init_func: Web initialization function name
        verbose: Verbose output
        architecture: Architecture type (for optimizing analysis strategy)
        firmware_root: Firmware filesystem root directory (for httpd layer analysis)
    
    Returns:
        (acdg, elapsed_time)
    """
    print("\n" + "=" * 70)
    print("  PHASE 2: LOGIC DECOUPLING & ACDG CONSTRUCTION")
    print("  Section 3.3: Global Gatekeeper & Authentication State Identification")
    print("=" * 70)
    
    start_time = time.time()
    
    # If routes not provided, try to load
    if routes is None:
        routes_file = os.path.join(output_dir, f"{firmware_name}_routes.json")
        if os.path.exists(routes_file):
            print(f"\n[Phase 2.0] Loading routes from {routes_file}")
            with open(routes_file, 'r', encoding='utf-8') as f:
                routes_data = json.load(f)
            routes = [RouteNode.from_dict(r) for r in routes_data]
            print(f"  Loaded {len(routes)} routes")
        else:
            print(f"[ERROR] Routes file not found: {routes_file}")
            print("        Please run Phase 1 first or provide routes.")
            return None, 0
    
    # Detect architecture type - for optimizing analysis strategy
    detected_arch = architecture
    if not detected_arch and routes:
        # Infer architecture from route source_type
        source_types = set(r.source_type for r in routes if hasattr(r, 'source_type'))
        if "cgi_binary" in source_types or "cgi_dispatch" in source_types:
            detected_arch = "DistributedCGI"
        elif "fastcgi_strncmp" in source_types:
            detected_arch = "FastCGI"
        elif "GoForm" in source_types or any("goform" in str(st).lower() for st in source_types):
            detected_arch = "GoForm"
        elif "jsonrpc_method" in source_types:
            detected_arch = "JSONRPC"
    
    # For distributed CGI architecture, display special handling info
    if detected_arch == "DistributedCGI":
        print(f"\n[Phase 2.0] Detected DistributedCGI architecture")
        print(f"  Authentication analysis already completed in Phase 1 (per-CGI)")
        print(f"  Phase 2 will: aggregate results, build ACDG, generate summary")
        
        # Try to merge multiple CGI analysis results
        try:
            from analysis.distributed_cgi_extractor import merge_cgi_analyses
            merged = merge_cgi_analyses(output_dir, firmware_name)
            if merged and merged.get("cgi_binaries"):
                print(f"  [+] Merged {len(merged['cgi_binaries'])} CGI analysis results")
        except Exception as e:
            if verbose:
                print(f"  [INFO] CGI analysis merge skipped: {e}")
    
    from analysis.logic_decoupler import LogicDecoupler
    
    decoupler = LogicDecoupler(ida, llm)
    decoupler.verbose = verbose
    
    # Get current analyzed binary name
    current_binary = firmware_name
    try:
        status = ida.get_status()
        if status.get("status") == "ok":
            current_binary = status.get("data", {}).get("binary_name", firmware_name)
    except:
        pass
    
    # Execute logic decoupling
    print("\n[Phase 2.1] Global Gatekeeper Discovery...")
    
    acdg = decoupler.run(
        routes, 
        firmware_name=firmware_name, 
        init_func=init_func,
        firmware_root=firmware_root,
        current_binary=current_binary,
        detected_architecture=detected_arch or "auto"
    )
    
    elapsed = time.time() - start_time
    
    if acdg:
        # Update statistics
        acdg._update_stats()
        
        print(f"\n[Phase 2 Complete]")
        print(f"  Architecture: {detected_arch or 'Unknown'}")
        print(f"  Total Routes: {acdg.total_routes}")
        print(f"  Auth-Required: {acdg.auth_required_count}")
        print(f"  Auth-Free: {acdg.auth_free_count} (HIGH RISK)")
        if acdg.unknown_count > 0:
            print(f"  Unknown: {acdg.unknown_count} (needs review)")
        print(f"  Global Gatekeepers: {len(acdg.global_auth_mechanisms)}")
        print(f"  Shared Auth Utils: {len(acdg.shared_auth_utilities)}")
        print(f"  [*] Elapsed Time: {elapsed:.2f} seconds")
        
        # Save ACDG
        output_file = os.path.join(output_dir, f"{firmware_name}_acdg.json")
        acdg.save_json(output_file)
        print(f"  [*] Saved to: {output_file}")
    else:
        print(f"\n[Phase 2 Failed] ACDG construction failed")
    
    return acdg, elapsed


# ==================== Phase 3: Dual-Agent Detection ====================

def run_phase3(ida: IDAProClient, llm: LLMProvider,
               firmware_name: str, output_dir: str,
               acdg: ACDG = None,
               verbose: bool = True,
               knowledge_base: KnowledgeBase = None,
               max_routes: int = 50, storage_graph=None) -> Tuple[List[VulnerabilityFinding], float]:
    """
    Phase 3: Dual-Agent Vulnerability Detection
    
    Args:
        ida: IDA Pro client
        llm: LLM provider
        firmware_name: Firmware name
        output_dir: Output directory
        acdg: Access Control Dependency Graph
        verbose: Verbose output
        knowledge_base: RAG knowledge base (optional)
    
    Returns:
        (findings, elapsed_time)
    """
    print("\n" + "=" * 70)
    print("  PHASE 3: DUAL-AGENT VULNERABILITY DETECTION")
    print("  Section 3.4: Detective Agent (ReAct) + Reviewer Agent (Counterfactual)")
    print("=" * 70)
    
    # Display RAG status
    if knowledge_base and knowledge_base.is_loaded:
        print(f"\n[RAG] Knowledge Base: ENABLED")
        print(f"      Device: {knowledge_base.device_info.vendor} {knowledge_base.device_info.model}")
        print(f"      Known CVEs: {len(knowledge_base.known_vulnerabilities)}")
    else:
        print(f"\n[RAG] Knowledge Base: DISABLED (use --rag to enable)")
    
    start_time = time.time()
    
    # If ACDG not provided, try to load
    if acdg is None:
        acdg_file = os.path.join(output_dir, f"{firmware_name}_acdg.json")
        if os.path.exists(acdg_file):
            print(f"\n[Phase 3.0] Loading ACDG from {acdg_file}")
            acdg = ACDG.load_json(acdg_file)
            print(f"  Loaded ACDG: {acdg.total_routes} routes")
        else:
            raise FileNotFoundError(f"ACDG file not found: {acdg_file}; run Phase 2 first")

    from analysis.dual_agent_detector import DualAgentDetector
    detector = DualAgentDetector(ida_client=ida, llm=llm, knowledge_base=knowledge_base, storage_graph=storage_graph)
    detector.verbose = verbose
    detector.max_routes_per_session = max_routes
    detector.set_acdg(acdg)
    report = detector.run(output_dir)
    elapsed = time.time() - start_time
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{firmware_name}_vulnerabilities.json")
    with open(output_file, "w", encoding="utf-8") as stream:
        json.dump([f.to_dict() for f in report.findings], stream, indent=2, ensure_ascii=False)
    report.save_json(os.path.join(output_dir, f"{firmware_name}_detection_report.json"))
    return report.findings, elapsed


# ==================== Main ====================

def main():
    parser = argparse.ArgumentParser(
        description="PANGU - IoT Firmware BAC Vulnerability Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python PANGU.py --firmware "Tenda_AC15" --phase all
  python PANGU.py --firmware "DLink_823G" --phase 1
  python PANGU.py --firmware "DLink_823G" --phase 2 --init-func "sub_423F90"
  python PANGU.py --firmware "Tenda_AC15" --phase 3 --verbose
  python PANGU.py --firmware "H3C_NX15" --phase 1 --arch fastcgi
  python PANGU.py --firmware "Cisco_RV34x" --phase 1 --arch jsonrpc
  
  # Phase 0 - Firmware filesystem pre-analysis (optional)
  python PANGU.py --firmware "Linksys_E1700" --phase 0 --firmware-root "/path/to/cpio-root"
  
  # Full analysis with firmware pre-analysis
  python PANGU.py --firmware "Device" --phase all --firmware-root "/path/to/fs-root"
  
Supported Phases:
  0        - Firmware filesystem pre-analysis (requires --firmware-root)
  1        - Route extraction from IDA binary
  2        - Logic decoupling and ACDG construction
  3        - Dual-agent vulnerability detection
  all      - Complete pipeline (1-2-3)

Supported Architectures:
  auto     - Auto-detect (default)
  goahead  - GoAhead Web Server (websFormDefine/websUrlHandlerDefine)
  fastcgi  - FastCGI/Lighttpd (strncmp dispatch pattern, e.g. H3C NX15)
  jsonrpc  - JSON-RPC CGI (Nginx + CGI backend, e.g. Cisco RV34x)
        """
    )
    
    parser.add_argument('--firmware', '-f', required=True,
                        help='Firmware name identifier')
    parser.add_argument('--phase', '-p', default='all',
                        choices=['0', '1', '2', '3', 'all'],
                        help='Phase to execute (0/1/2/3/all). Phase 0 requires --firmware-root')
    parser.add_argument('--firmware-root', '--fs', default=None,
                        help='Firmware filesystem root path for Phase 0 pre-analysis (optional)')
    parser.add_argument('--arch', '-a', default='auto',
                        choices=['auto', 'goahead', 'fastcgi', 'jsonrpc', 'goform',
                                 'GoAhead', 'FastCGI', 'JSONRPC', 'GoForm'],
                        help='Web server architecture (auto/goahead/fastcgi/jsonrpc/goform)')
    parser.add_argument('--init-func', '-i', default=None,
                        help='Web initialization function name (for gatekeeper discovery)')
    parser.add_argument('--output', '-o', default='output',
                        help='Output directory')
    parser.add_argument('--review-mailbox', help='File-based human/agent review directory; no model API required')
    parser.add_argument('--storage-graph', help='Candidate cross-binary storage channels for this firmware')
    parser.add_argument('--ida-snapshot', help='Replay a read-only IDA snapshot; missing queries remain unresolved')
    parser.add_argument('--ida-port', type=int, default=4455,
                        help='IDA Pro server port')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output')
    parser.add_argument('--rag', '-r', action='store_true',
                        help='Enable RAG knowledge base for enhanced vulnerability detection')
    parser.add_argument('--rag-dir', default='rag',
                        help='Directory containing RAG knowledge base files')
    
    parser.add_argument('--max-routes', type=int, default=50,
                        help='Phase 3 route budget (0 = all); deferred routes remain in report')
    args = parser.parse_args()
    if args.max_routes < 0:
        parser.error('--max-routes must be nonnegative')
    storage_graph = None
    if args.storage_graph:
        from analysis.storage_graph import StorageGraph
        storage_graph = StorageGraph.load(args.storage_graph)
        if storage_graph.firmware_id != args.firmware:
            parser.error('--storage-graph firmware_id must match --firmware')
    
    # Banner
    print(BANNER)
    print(f"Analysis Target: {args.firmware}")
    print(f"Phase: {args.phase}")
    if args.firmware_root:
        print(f"Firmware Root: {args.firmware_root}")
    print(f"Architecture: {args.arch}")
    print(f"Output Directory: {args.output}")
    print(f"RAG Enabled: {args.rag}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Create output directory
    os.makedirs(args.output, exist_ok=True)
    
    # Phase 0 check: If only executing Phase 0, IDA is not required
    if args.phase == '0':
        if not args.firmware_root:
            print("[ERROR] --firmware-root is required for Phase 0!")
            print("        Usage: python PANGU.py --firmware NAME --phase 0 --firmware-root /path/to/fs")
            sys.exit(1)
        
        # Execute Phase 0 only
        preanalysis_result = run_phase0(args.firmware_root, args.firmware, 
                                        args.output, args.verbose)
        
        print("\n" + "=" * 70)
        print("  Thank you for using PANGU!")
        print("=" * 70 + "\n")
        return 0 if preanalysis_result else 1
    
    # Connect to IDA (Required for Phase 1/2/3/all)
    print("\n" + "-" * 70)
    print("Connecting to IDA Pro...")
    if args.ida_snapshot:
        from core.bridge.snapshot_client import SnapshotIDAClient
        ida = SnapshotIDAClient(args.ida_snapshot)
    else:
        ida = IDAProClient(port=args.ida_port)
    if not ida.connect():
        print("[ERROR] Failed to connect to IDA Pro!")
        print("        Please ensure IDA is running with ida_server.py loaded.")
        sys.exit(1)
    
    status = ida.get_status()
    if status.get("status") == "ok":
        info = status["data"]
        print(f"  Binary: {info.get('binary_name', 'unknown')}")
        print(f"  Architecture: {info.get('processor', 'unknown')} {info.get('architecture', '')}")
        print(f"  Functions: {info.get('function_count', 0)}")
    
    # Connect to LLM
    print("\nInitializing LLM...")
    if args.review_mailbox:
        from core.review_mailbox import ReviewMailboxProvider
        llm = ReviewMailboxProvider(args.review_mailbox)
    else:
        llm = LLMProvider()
    try:
        llm.validate_configuration()
    except ValueError as exc:
        print(f"[ERROR] {exc}")
        ida.close()
        return 1
    test_resp = ({"status": "ok"} if args.review_mailbox else
                 llm.chat([{"role": "user", "content": 'Return JSON {"status": "ok"}.'}], json_mode=True))
    if test_resp:
        print("  LLM connection: OK")
    else:
        print("[ERROR] LLM structured-response preflight failed; analysis was not started")
        ida.close()
        return 1
    
    # Load RAG knowledge base (if enabled)
    knowledge_base = None
    if args.rag:
        print("\n" + "-" * 70)
        print("Loading RAG Knowledge Base...")
        knowledge_base = KnowledgeBase(args.firmware, args.rag_dir)
        if knowledge_base.load():
            print("  Knowledge base loaded successfully!")
            # Display knowledge base summary
            if knowledge_base.known_vulnerabilities:
                print(f"  Known CVEs: {[v.cve_id for v in knowledge_base.known_vulnerabilities]}")
        else:
            print("  [WARN] Knowledge base not found, continuing without RAG")
            knowledge_base = None
    
    # Execute analysis
    total_start = time.time()
    routes = None
    acdg = None
    findings = []
    preanalysis_result = None
    
    phase_times = {}
    
    # Phase 0: If firmware-root provided, execute pre-analysis first
    if args.firmware_root:
        preanalysis_result = run_phase0(args.firmware_root, args.firmware, 
                                        args.output, args.verbose)
        if preanalysis_result:
            phase_times['Phase 0 (Firmware Pre-Analysis)'] = 0  # Time already recorded in run_phase0
            
            # Display pre-analysis assistance info for Phase 1
            if preanalysis_result.static_routes:
                print(f"\n[INFO] Pre-analysis found {len(preanalysis_result.static_routes)} routes from static files")
                print("       These will supplement binary analysis in Phase 1")
    
    # Normalize architecture parameter
    arch_mapping = {
        'auto': 'auto',
        'goahead': 'GoAhead',
        'GoAhead': 'GoAhead',
        'fastcgi': 'FastCGI',
        'FastCGI': 'FastCGI',
        'jsonrpc': 'JSONRPC',
        'JSONRPC': 'JSONRPC'
    }
    normalized_arch = arch_mapping.get(args.arch, 'auto')
    
    # Try to load existing pre-analysis result (if Phase 0 not run in real-time)
    if not preanalysis_result:
        preanalysis_result = load_preanalysis_result(args.firmware, args.output)
        if preanalysis_result:
            print(f"\n[INFO] Loaded existing pre-analysis result for {args.firmware}")
            print(f"       Static routes: {len(preanalysis_result.static_routes)}")
    
    if args.phase in ['1', 'all']:
        routes, t1 = run_phase1(ida, llm, args.firmware, args.output, args.verbose, 
                                architecture=normalized_arch, 
                                preanalysis=preanalysis_result)
        phase_times['Phase 1 (Route Extraction)'] = t1
    
    if args.phase in ['2', 'all']:
        acdg, t2 = run_phase2(ida, llm, args.firmware, args.output, routes, 
                              args.init_func, args.verbose, architecture=normalized_arch,
                              firmware_root=args.firmware_root if hasattr(args, 'firmware_root') else None)
        phase_times['Phase 2 (Logic Decoupling)'] = t2
    
    if args.phase in ['3', 'all']:
        findings, t3 = run_phase3(ida, llm, args.firmware, args.output, acdg, 
                                   args.verbose, knowledge_base, args.max_routes, storage_graph)
        phase_times['Phase 3 (Vulnerability Detection)'] = t3
    
    total_elapsed = time.time() - total_start
    
    # Final Report
    print("\n" + "=" * 70)
    print("  PANGU ANALYSIS COMPLETE")
    print("=" * 70)
    
    print(f"\n[*] Performance Summary:")
    print("-" * 50)
    for phase, elapsed in phase_times.items():
        print(f"  {phase}: {elapsed:.2f}s")
    print("-" * 50)
    print(f"  Total Time: {total_elapsed:.2f}s")
    
    print(f"\n[*] Results Summary:")
    print("-" * 50)
    if routes:
        print(f"  Routes Extracted: {len(routes)}")
    if acdg:
        acdg._update_stats()
        print(f"  Auth-Required Routes: {acdg.auth_required_count}")
        print(f"  Auth-Free Routes: {acdg.auth_free_count}")
        if acdg.unknown_count > 0:
            print(f"  Unknown Routes: {acdg.unknown_count}")
        print(f"  Global Gatekeepers: {len(acdg.global_auth_mechanisms)}")
    if findings:
        print(f"  Vulnerabilities Found: {len(findings)}")
        for f in findings:
            print(f"    [!] {f.vuln_type} @ {f.route.path} ({f.confidence})")
    
    print(f"\n[*] Output Files:")
    print("-" * 50)
    for f in os.listdir(args.output):
        if args.firmware in f:
            print(f"  - {os.path.join(args.output, f)}")
    
    print("\n" + "=" * 70)
    print("  Thank you for using PANGU!")
    print("=" * 70 + "\n")
    
    # Return status code
    ida.close()
    return 0 if phase_times else 1


if __name__ == "__main__":
    from core.review_mailbox import ReviewPending
    try:
        sys.exit(main())
    except ReviewPending as pending:
        print(f"\n[REVIEW PENDING] Read: {pending.request_path}")
        print(f"Write {{\"request_id\": \"...\", \"response\": ...}} to: {pending.response_path}")
        print("Then rerun the same command. Matching reviewed responses will be replayed.")
        sys.exit(2)
