# Copyright (c) 2026 The Pangu Project Authors. All rights reserved.
# analysis/firmware_analyzer.py
# PANGU Firmware Filesystem Pre-analysis Module (Phase 0)
# Analyzes firmware filesystem to provide context and suggestions for subsequent binary analysis

"""
Firmware Pre-analysis Module

Features:
1. Scan firmware filesystem structure
2. Identify Web server type and configuration
3. Locate CGI/FastCGI binary files
4. Extract routes from static files (HTML/JS/PHP)
5. Analyze authentication mechanism clues
6. Generate analysis recommendation report

This is an independent optional module that does not affect existing functionality.
"""

import os
import re
import json
import glob
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime


@dataclass
class WebServerInfo:
    """Web Server Information"""
    server_type: str = "unknown"          # lighttpd, nginx, apache, goahead, etc.
    config_file: str = ""                 # Configuration file path
    document_root: str = ""               # Web root directory
    cgi_paths: List[str] = field(default_factory=list)      # CGI directories
    fastcgi_sockets: List[str] = field(default_factory=list) # FastCGI sockets
    lua_paths: List[str] = field(default_factory=list)       # Lua script directories
    modules: List[str] = field(default_factory=list)         # Loaded modules


@dataclass
class BinaryCandidate:
    """Candidate Binary File"""
    path: str                             # File path
    name: str                             # File name
    binary_type: str = "unknown"          # cgi, fastcgi, httpd, library, main_service
    priority: int = 0                     # Analysis priority (higher = analyze first)
    reason: str = ""                      # Recommendation reason
    size: int = 0                         # File size
    web_features: List[str] = field(default_factory=list)  # Detected Web features
    architecture: str = ""                # ELF architecture (MIPS, ARM, etc.)


@dataclass 
class StaticRouteInfo:
    """Route Information Extracted from Static Files"""
    path: str                             # API path
    method: str = "GET"                   # HTTP method
    source_file: str = ""                 # Source file
    auth_hint: str = ""                   # Authentication hint


@dataclass
class FirmwareAnalysisResult:
    """Firmware Pre-analysis Result"""
    firmware_root: str                    # Firmware root directory
    analysis_time: str = ""               # Analysis timestamp
    
    # Web server information
    webserver: WebServerInfo = field(default_factory=WebServerInfo)
    
    # Candidate binary files
    binary_candidates: List[BinaryCandidate] = field(default_factory=list)
    
    # Routes extracted from static files
    static_routes: List[StaticRouteInfo] = field(default_factory=list)
    
    # Authentication-related findings
    auth_findings: List[str] = field(default_factory=list)
    
    # Analysis recommendations
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "firmware_root": self.firmware_root,
            "analysis_time": self.analysis_time,
            "webserver": asdict(self.webserver),
            "binary_candidates": [asdict(b) for b in self.binary_candidates],
            "static_routes": [asdict(r) for r in self.static_routes],
            "auth_findings": self.auth_findings,
            "recommendations": self.recommendations
        }


class FirmwareAnalyzer:
    """
    Firmware Filesystem Pre-analyzer
    
    Analyzes firmware filesystem, identifies Web architecture, provides context for Phase 1
    """
    
    # Web server configuration file patterns
    WEBSERVER_CONFIGS = {
        "lighttpd": ["lighttpd.conf", "lighttpd/*.conf"],
        "nginx": ["nginx.conf", "nginx/*.conf"],
        "apache": ["httpd.conf", "apache2/*.conf"],
        "goahead": ["goahead.conf", "goform.conf"],
        "uhttpd": ["uhttpd.conf"],
        "mini_httpd": ["mini_httpd.conf", "thttpd.conf"],
        "boa": ["boa.conf"]
    }
    
    # Common CGI/binary directories
    CGI_DIRECTORIES = [
        "www/cgi-bin", "cgi-bin", "www/cgi", "usr/lib/cgi-bin",
        "home/httpd/cgi-bin", "var/www/cgi-bin"
    ]
    
    # Web application binary file patterns
    WEB_BINARY_PATTERNS = [
        "*.cgi", "goahead", "httpd", "lighttpd", "nginx",
        "uhttpd", "mini_httpd", "boa", "webs", "webproc",
        "fcgi_*", "*_cgi", "cgibin", "webcgi"
    ]
    
    # Static file extensions
    STATIC_EXTENSIONS = {
        "html": [".html", ".htm", ".asp", ".aspx", ".shtml"],  # Added .shtml support
        "javascript": [".js"],
        "php": [".php", ".php3", ".php5"],
        "lua": [".lua"],
        "config": [".conf", ".cfg", ".ini"]
    }
    
    # Web feature strings - for identifying Web functionality in binaries
    WEB_FEATURE_PATTERNS = {
        "http_server": [b"HTTP/1.", b"Content-Type:", b"Content-Length:", b"GET /", b"POST /"],
        "goform": [b"/goform/", b"goform_", b"formDefine"],
        "cgi": [b"cgi-bin", b"CONTENT_TYPE", b"REQUEST_METHOD", b"QUERY_STRING"],
        "json_api": [b"application/json", b"jsonObject", b"JSON_", b"json_"],
        "auth": [b"login", b"logout", b"password", b"session", b"cookie", b"token", b"auth"],
        "socket": [b"socket", b"bind", b"listen", b"accept", b"recv", b"send"],
        "url_handler": [b"url", b"/api/", b"/cgi/", b"/stok=", b"httpd"],
        "xml_rpc": [b"xmlrpc", b"<methodCall>", b"soap"],
        "upnp": [b"upnp", b"ssdp", b"UPnP"],
        "router_mgmt": [b"wan", b"lan", b"dhcp", b"firewall", b"nat", b"wireless", b"wlan"],
    }
    
    # Main service program common names (Mercury/TP-Link and other vendors)
    MAIN_SERVICE_NAMES = [
        "dms", "cms", "httpd", "management", "webmgmt", "router",
        "daemon", "service", "server", "main", "core", "app"
    ]
    
    def __init__(self, firmware_root: str, verbose: bool = True):
        self.firmware_root = Path(firmware_root)
        self.verbose = verbose
        self.result = FirmwareAnalysisResult(firmware_root=str(self.firmware_root))
        
        # Multi-partition support: store additional discovered filesystem partitions
        self.additional_roots: List[Path] = []
        
    def log(self, msg: str):
        """Log output"""
        if self.verbose:
            print(msg)
    
    def _detect_additional_partitions(self):
        """
        Detect additional filesystem partitions
        
        Some firmware (e.g., Zyxel NAS326) has multiple partitions:
        - cpio-root: Base system (configuration files)
        - ext-root: Applications (Apache, CGI, etc.)
        - squashfs-root: Compressed filesystem
        
        This function searches for other extracted partitions in sibling and parent directories
        """
        # Common partition directory name patterns
        partition_patterns = [
            "*-root",        # ext-root, cpio-root, squashfs-root
            "rootfs*",       # rootfs, rootfs-x
            "filesystem*",   # filesystem
        ]
        
        # Check multiple levels of parent directories
        search_dirs = [
            self.firmware_root.parent,           # Direct parent directory
            self.firmware_root.parent.parent,    # Two levels up (for cpio-root in _xxx.extracted)
        ]
        
        for parent_dir in search_dirs:
            if not parent_dir.exists():
                continue
                
            # Search partition patterns
            for pattern in partition_patterns:
                for match in parent_dir.glob(pattern):
                    if match.is_dir() and match != self.firmware_root:
                        if match not in self.additional_roots:
                            if self._looks_like_filesystem(match):
                                self.additional_roots.append(match)
                                self.log(f"  [+] Found additional partition: {match.name}")
            
            # Search for sub-partitions in *extracted* directories
            for extracted_dir in parent_dir.glob("*extracted*"):
                if extracted_dir.is_dir():
                    for nested in extracted_dir.glob("*-root"):
                        if nested.is_dir() and nested != self.firmware_root:
                            if nested not in self.additional_roots:
                                if self._looks_like_filesystem(nested):
                                    self.additional_roots.append(nested)
                                    self.log(f"  [+] Found nested partition: {extracted_dir.name}/{nested.name}")
    
    def _looks_like_filesystem(self, path: Path) -> bool:
        """Check if directory looks like a filesystem"""
        # Check if it contains common system directories
        system_dirs = ["bin", "etc", "lib", "usr", "var", "sbin"]
        found_dirs = sum(1 for d in system_dirs if (path / d).is_dir())
        return found_dirs >= 2
    
    def _get_all_search_roots(self) -> List[Path]:
        """Get list of all root directories to search"""
        return [self.firmware_root] + self.additional_roots
    
    def analyze(self) -> FirmwareAnalysisResult:
        """
        Execute complete firmware pre-analysis
        
        Returns:
            FirmwareAnalysisResult: Analysis result
        """
        self.log("\n" + "=" * 60)
        self.log("  PHASE 0: FIRMWARE FILESYSTEM PRE-ANALYSIS")
        self.log("  Analyzing firmware structure for web components...")
        self.log("=" * 60)
        
        self.result.analysis_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if not self.firmware_root.exists():
            self.log(f"\n[ERROR] Firmware root not found: {self.firmware_root}")
            return self.result
        
        # Step 0.0: Detect additional filesystem partitions (supports multi-partition firmware like Zyxel NAS)
        self.log("\n[Phase 0.0] Detecting additional filesystem partitions...")
        self._detect_additional_partitions()
        if self.additional_roots:
            self.log(f"  [*] Found {len(self.additional_roots)} additional partition(s)")
            self.result.recommendations.append(f"Multi-partition firmware detected. Found {len(self.additional_roots)} additional root(s).")
        
        # Step 1: Identify web server (search all partitions)
        self.log("\n[Phase 0.1] Identifying web server...")
        self._identify_webserver()
        
        # Step 2: Scan CGI and binary files (search all partitions)
        self.log("\n[Phase 0.2] Scanning for CGI and web binaries...")
        self._scan_binaries()
        
        # Step 2.5: Deep scan large ELF binaries (newly added)
        self.log("\n[Phase 0.2.5] Deep scanning large ELF binaries for web features...")
        self._deep_scan_binaries()
        
        # Step 3: Extract routes from static files
        self.log("\n[Phase 0.3] Extracting routes from static files...")
        self._extract_static_routes()
        
        # Step 3.5: Extract routes from Python WSGI applications (for Zyxel and similar devices)
        self.log("\n[Phase 0.3.5] Extracting routes from Python WSGI applications...")
        self._extract_python_wsgi_routes()
        
        # Step 4: Analyze authentication mechanisms
        self.log("\n[Phase 0.4] Analyzing authentication mechanisms...")
        self._analyze_auth()
        
        # Step 5: Generate recommendations
        self.log("\n[Phase 0.5] Generating recommendations...")
        self._generate_recommendations()
        
        return self.result
    
    def _identify_webserver(self):
        """Identify Web server type and configuration - search all partitions"""
        
        # Search all known partitions
        for search_root in self._get_all_search_roots():
            etc_dir = search_root / "etc"
            
            for server_type, config_patterns in self.WEBSERVER_CONFIGS.items():
                for pattern in config_patterns:
                    # Search under etc directory
                    matches = list(etc_dir.glob(f"**/{pattern}")) if etc_dir.exists() else []
                    # Also search under root directory
                    matches.extend(list(search_root.glob(f"**/{pattern}")))
                    
                    for config_path in matches:
                        if config_path.is_file():
                            try:
                                rel_path = config_path.relative_to(search_root)
                            except ValueError:
                                rel_path = config_path.name
                            self.log(f"  [+] Found {server_type} config: {rel_path} (in {search_root.name})")
                            self.result.webserver.server_type = server_type
                            self.result.webserver.config_file = str(config_path)
                            
                            # Parse configuration file
                            self._parse_webserver_config(config_path, server_type)
                            return
        
        # If no config file found, try to infer from binaries
        self.log("  [-] No web server config found, will infer from binaries")
    
    def _parse_webserver_config(self, config_path: Path, server_type: str):
        """Parse Web server configuration file"""
        try:
            content = config_path.read_text(encoding='utf-8', errors='ignore')
            
            if server_type == "lighttpd":
                self._parse_lighttpd_config(content, config_path)
            elif server_type == "nginx":
                self._parse_nginx_config(content)
            elif server_type == "apache":
                self._parse_apache_config(content, config_path)
            elif server_type in ["goahead", "uhttpd"]:
                self._parse_simple_config(content)
                
        except Exception as e:
            self.log(f"  [!] Error parsing config: {e}")
    
    def _parse_lighttpd_config(self, content: str, config_path: Path = None):
        """Parse lighttpd configuration"""
        # Extract document root
        match = re.search(r'server\.document-root\s*=\s*["\']([^"\']+)["\']', content)
        if match:
            self.result.webserver.document_root = match.group(1)
            self.log(f"    Document root: {match.group(1)}")
        
        # Extract FastCGI configuration
        fastcgi_matches = re.findall(r'"socket"\s*=>\s*["\']([^"\']+)["\']', content)
        for socket in fastcgi_matches:
            self.result.webserver.fastcgi_sockets.append(socket)
            self.log(f"    FastCGI socket: {socket}")
        
        # Extract CGI paths
        cgi_matches = re.findall(r'cgi\.assign.*?["\']([^"\']+\.cgi)["\']', content, re.DOTALL)
        for cgi in cgi_matches:
            self.result.webserver.cgi_paths.append(cgi)
        
        # Extract modules
        module_matches = re.findall(r'"mod_(\w+)"', content)
        self.result.webserver.modules = list(set(module_matches))
        if self.result.webserver.modules:
            self.log(f"    Modules: {self.result.webserver.modules}")
        
        # Parse additional configurations in conf.d directory
        if config_path:
            conf_d_dir = config_path.parent / "conf.d"
            if conf_d_dir.exists():
                self._parse_lighttpd_conf_d(conf_d_dir)
    
    def _parse_lighttpd_conf_d(self, conf_d_dir: Path):
        """Parse additional configuration files in lighttpd conf.d directory"""
        self.log(f"  [+] Scanning {conf_d_dir.name}/ for additional configs...")
        
        for conf_file in conf_d_dir.glob("*.conf"):
            try:
                content = conf_file.read_text(encoding='utf-8', errors='ignore')
                
                # Extract additional modules
                module_matches = re.findall(r'"mod_(\w+)"', content)
                for mod in module_matches:
                    if mod not in self.result.webserver.modules:
                        self.result.webserver.modules.append(mod)
                        self.log(f"    [+] Module from {conf_file.name}: mod_{mod}")
                
                # Extract route path configurations (form.path, cgi.path, etc.)
                path_matches = re.findall(r'(?:form|cgi|fastcgi)\.path\s*=\s*\(\s*["\']([^"\']+)["\']', content)
                for path in path_matches:
                    if path not in self.result.webserver.cgi_paths:
                        self.result.webserver.cgi_paths.append(path)
                        self.log(f"    [+] Route path from {conf_file.name}: {path}")
                
                # Extract FastCGI socket
                socket_matches = re.findall(r'"socket"\s*=>\s*["\']([^"\']+)["\']', content)
                for socket in socket_matches:
                    if socket not in self.result.webserver.fastcgi_sockets:
                        self.result.webserver.fastcgi_sockets.append(socket)
                        self.log(f"    [+] FastCGI socket: {socket}")
                
            except Exception as e:
                pass
    
    def _parse_apache_config(self, content: str, config_path: Path = None):
        """
        Parse Apache httpd configuration file
        
        Special handling for devices using mod_auth_zyxel (e.g., Zyxel):
        - Identify AuthZyxelSkipPattern (whitelist paths)
        - Identify ScriptAlias (CGI path mapping)
        - Identify LoadModule (loaded authentication modules)
        """
        # Extract DocumentRoot
        match = re.search(r'DocumentRoot\s+["\']?([^\s"\']+)["\']?', content)
        if match:
            self.result.webserver.document_root = match.group(1)
            self.log(f"    Document root: {match.group(1)}")
        
        # Extract ServerRoot
        server_root = ""
        match = re.search(r'ServerRoot\s+["\']?([^\s"\']+)["\']?', content)
        if match:
            server_root = match.group(1)
            self.log(f"    Server root: {match.group(1)}")
        
        # Extract ScriptAlias (CGI path mapping)
        script_aliases = re.findall(r'ScriptAlias\s+([^\s]+)\s+["\']?([^\s"\']+)["\']?', content)
        for url_path, fs_path in script_aliases:
            self.result.webserver.cgi_paths.append(url_path)
            self.log(f"    ScriptAlias: {url_path} -> {fs_path}")
        
        # Extract loaded modules (especially auth modules)
        modules = re.findall(r'LoadModule\s+(\w+)\s+([^\s]+)', content)
        for mod_name, mod_path in modules:
            self.result.webserver.modules.append(mod_name)
            self.log(f"    Module: {mod_name} ({mod_path})")
            
            # Special mark for Zyxel authentication module
            if "auth_zyxel" in mod_name.lower():
                self.result.auth_findings.append(f"Zyxel authentication module detected: {mod_name}")
        
        # Extract AuthZyxelSkipPattern (whitelist paths - no auth required)
        # Format: AuthZyxelSkipPattern /path1 /prefix,/path2 /prefix,/path3 ...
        skip_matches = re.findall(r'AuthZyxelSkipPattern\s+(.+)', content)
        for skip_line in skip_matches:
            # Parse space-separated path pairs
            patterns = skip_line.strip().split()
            for pattern in patterns:
                if pattern.startswith('/'):
                    # Could be /prefix,/path format
                    if ',' in pattern:
                        parts = pattern.split(',')
                        for part in parts:
                            if part.startswith('/'):
                                self.log(f"    Auth-Free path: {part}")
                                self.result.auth_findings.append(f"Auth-Free (whitelist): {part}")
                    else:
                        self.log(f"    Auth-Free path: {pattern}")
                        self.result.auth_findings.append(f"Auth-Free (whitelist): {pattern}")
        
        # Extract AuthZyxelSkipUserPattern (user-level whitelist)
        skip_user_matches = re.findall(r'AuthZyxelSkipUserPattern\s+(.+)', content)
        for skip_line in skip_user_matches:
            patterns = skip_line.strip().split()
            for pattern in patterns:
                if pattern.startswith('/') or ',' in pattern:
                    self.log(f"    Auth-Free (user pattern): {pattern}")
                    self.result.auth_findings.append(f"Auth-Free (user pattern): {pattern}")
        
        # Extract AuthZyxelRedirect (auth redirect page)
        redirect_matches = re.findall(r'AuthZyxelRedirect\s+(.+)', content)
        for redirect in redirect_matches:
            self.log(f"    Auth redirect: {redirect}")
            self.result.auth_findings.append(f"Auth redirect page: {redirect}")
        
        # Parse Include extra config files
        if config_path:
            include_matches = re.findall(r'Include\s+([^\s]+)', content)
            for inc_path in include_matches:
                # Try to resolve relative path
                if not inc_path.startswith('/'):
                    inc_full = config_path.parent / inc_path
                else:
                    # Could be absolute path, map to firmware root
                    inc_full = self.firmware_root / inc_path.lstrip('/')
                
                if inc_full.exists():
                    self.log(f"    Parsing included config: {inc_path}")
                    try:
                        inc_content = inc_full.read_text(encoding='utf-8', errors='ignore')
                        self._parse_apache_config(inc_content, inc_full)
                    except:
                        pass
    
    def _parse_nginx_config(self, content: str):
        """Parse nginx configuration"""
        # Extract root
        match = re.search(r'root\s+([^\s;]+)', content)
        if match:
            self.result.webserver.document_root = match.group(1)
        
        # Extract fastcgi_pass
        fastcgi_matches = re.findall(r'fastcgi_pass\s+([^\s;]+)', content)
        self.result.webserver.fastcgi_sockets.extend(fastcgi_matches)
        
        # Extract location
        location_matches = re.findall(r'location\s+([^\s{]+)', content)
        for loc in location_matches:
            if 'cgi' in loc.lower():
                self.result.webserver.cgi_paths.append(loc)
    
    def _parse_simple_config(self, content: str):
        """Parse simple configuration file"""
        # Generic path extraction
        path_matches = re.findall(r'["\']?(/\w[^\s"\'<>]+)["\']?', content)
        for path in path_matches:
            if 'cgi' in path.lower():
                self.result.webserver.cgi_paths.append(path)
    
    def _scan_binaries(self):
        """Scan CGI and Web binary files - search all partitions"""
        candidates = []
        
        # Search all partitions
        for search_root in self._get_all_search_roots():
            root_name = search_root.name
            
            # 1. Scan CGI directories
            for cgi_dir in self.CGI_DIRECTORIES:
                cgi_path = search_root / cgi_dir
                if cgi_path.exists():
                    self.log(f"  [+] Found CGI directory: {cgi_dir} (in {root_name})")
                    for f in cgi_path.iterdir():
                        if f.is_file() and self._is_binary(f):
                            if not any(c.path == str(f) for c in candidates):
                                candidates.append(BinaryCandidate(
                                    path=str(f),
                                    name=f.name,
                                    binary_type="cgi",
                                    priority=10,
                                    reason=f"Located in CGI directory ({root_name})",
                                    size=f.stat().st_size
                                ))
                                self.log(f"    [CGI] {f.name} ({f.stat().st_size} bytes)")
            
            # 1.5 Scan Apache CGI directories (specific to Zyxel etc.)
            apache_cgi_dirs = [
                "usr/local/apache/cgi-bin",
                "var/www/cgi-bin",
                "home/httpd/cgi-bin"
            ]
            for cgi_dir in apache_cgi_dirs:
                cgi_path = search_root / cgi_dir
                if cgi_path.exists():
                    self.log(f"  [+] Found Apache CGI directory: {cgi_dir} (in {root_name})")
                    for f in cgi_path.iterdir():
                        if f.is_file() and self._is_binary(f):
                            if not any(c.path == str(f) for c in candidates):
                                candidates.append(BinaryCandidate(
                                    path=str(f),
                                    name=f.name,
                                    binary_type="cgi",
                                    priority=12,  # High priority
                                    reason=f"Apache CGI binary ({root_name})",
                                    size=f.stat().st_size
                                ))
                                self.log(f"    [Apache CGI] {f.name} ({f.stat().st_size} bytes)")
            
            # 1.6 Scan Apache modules directory
            apache_mod_dirs = [
                "usr/local/apache/modules",
                "usr/lib/apache2/modules"
            ]
            for mod_dir in apache_mod_dirs:
                mod_path = search_root / mod_dir
                if mod_path.exists():
                    self.log(f"  [+] Found Apache modules directory: {mod_dir} (in {root_name})")
                    for f in mod_path.iterdir():
                        if f.is_file() and f.name.endswith('.so'):
                            if not any(c.path == str(f) for c in candidates):
                                priority = 8
                                reason = "Apache module"
                                # Auth modules have higher priority
                                if "auth" in f.name.lower():
                                    priority = 15
                                    reason = "Apache authentication module (HIGH PRIORITY)"
                                    self.result.auth_findings.append(f"Found auth module: {f.name}")
                                candidates.append(BinaryCandidate(
                                    path=str(f),
                                    name=f.name,
                                    binary_type="apache_module",
                                    priority=priority,
                                    reason=reason,
                                    size=f.stat().st_size
                                ))
                                self.log(f"    [Apache Module] {f.name}")
            
            # 2. Search Web binary file patterns
            for pattern in self.WEB_BINARY_PATTERNS:
                for match in search_root.glob(f"**/{pattern}"):
                    if match.is_file() and self._is_binary(match):
                        # Avoid duplicates
                        if not any(c.path == str(match) for c in candidates):
                            binary_type = self._classify_binary(match)
                            priority = self._calculate_priority(match, binary_type)
                            
                            try:
                                rel_path = match.relative_to(search_root)
                            except ValueError:
                                rel_path = match.name
                            
                            candidates.append(BinaryCandidate(
                                path=str(match),
                                name=match.name,
                                binary_type=binary_type,
                                priority=priority,
                                reason=self._get_binary_reason(match, binary_type),
                                size=match.stat().st_size
                            ))
                            self.log(f"    [{binary_type.upper()}] {rel_path} (in {root_name})")
            
            # 3. Search for httpd-related files in /usr/bin, /usr/sbin
            for bin_dir in ["usr/bin", "usr/sbin", "bin", "sbin"]:
                bin_path = search_root / bin_dir
                if bin_path.exists():
                    for f in bin_path.iterdir():
                        if f.is_file() and self._is_web_binary(f.name):
                            # Skip IDA database files
                            if f.name.lower().endswith(('.i64', '.idb', '.id0', '.id1', '.id2', '.nam', '.til')):
                                continue
                            if not any(c.path == str(f) for c in candidates):
                                candidates.append(BinaryCandidate(
                                    path=str(f),
                                    name=f.name,
                                    binary_type="httpd",
                                    priority=5,
                                    reason=f"Web server binary ({root_name})",
                                    size=f.stat().st_size
                                ))
        
        # 3. Scan detected lighttpd modules (these are critical!)
        if self.result.webserver.modules:
            self._scan_lighttpd_modules(candidates)
        
        # Sort by priority
        candidates.sort(key=lambda x: x.priority, reverse=True)
        self.result.binary_candidates = candidates
        
        self.log(f"\n  [*] Found {len(candidates)} binary candidates")
    
    def _scan_lighttpd_modules(self, candidates: List[BinaryCandidate]):
        """Scan lighttpd module .so files (these usually contain route logic!)"""
        # Key modules: these modules usually contain application routes
        key_modules = {
            "form": ("mod_form.so", 15, "GoForm-style route handler - contains /goform/ routes"),
            "cgi": ("mod_cgi.so", 8, "CGI handler module"),
            "fastcgi": ("mod_fastcgi.so", 10, "FastCGI handler module"),
            "proxy": ("mod_proxy.so", 7, "Reverse proxy module"),
            "lua": ("mod_lua.so", 9, "Lua scripting module - may contain routes"),
            "auth": ("mod_auth.so", 6, "Authentication module"),
            "ssi": ("mod_ssi.so", 5, "Server-side includes module"),
        }
        
        # Search module .so files
        lib_dirs = ["usr/local/lib", "usr/lib", "lib", "usr/lib/lighttpd"]
        
        for mod_name in self.result.webserver.modules:
            mod_info = key_modules.get(mod_name)
            if mod_info:
                so_name, priority, reason = mod_info
            else:
                so_name = f"mod_{mod_name}.so"
                priority = 4
                reason = f"Lighttpd module for {mod_name}"
            
            # Search in multiple directories
            for lib_dir in lib_dirs:
                so_path = self.firmware_root / lib_dir / so_name
                if so_path.exists() and so_path.is_file():
                    candidates.append(BinaryCandidate(
                        path=str(so_path),
                        name=so_name,
                        binary_type="lighttpd_module",
                        priority=priority,
                        reason=reason,
                        size=so_path.stat().st_size
                    ))
                    self.log(f"  [+] Found key module: {so_name} ({so_path.stat().st_size} bytes)")
                    self.log(f"      Type: {reason}")
                    break
            else:
                # Global search
                for match in self.firmware_root.glob(f"**/{so_name}"):
                    if match.is_file():
                        candidates.append(BinaryCandidate(
                            path=str(match),
                            name=so_name,
                            binary_type="lighttpd_module",
                            priority=priority,
                            reason=reason,
                            size=match.stat().st_size
                        ))
                        self.log(f"  [+] Found key module: {so_name} ({match.stat().st_size} bytes)")
                        break
    
    def _deep_scan_binaries(self):
        """
        Deep scan large ELF binaries, identifying Web service features by analyzing internal strings
        This is a key improvement in the preprocessing phase, capable of discovering main service programs missed by traditional methods
        
        Also enhances feature information for existing candidates
        """
        MIN_SIZE = 50000  # At least 50KB
        MAX_SIZE = 50000000  # Maximum 50MB
        
        # Scan large binary files in all directories
        scan_dirs = ["bin", "sbin", "usr/bin", "usr/sbin", "usr/local/bin"]
        
        large_binaries = []
        
        # First perform deep feature analysis on existing candidates
        for candidate in self.result.binary_candidates:
            try:
                path = Path(candidate.path)
                if path.exists() and MIN_SIZE <= path.stat().st_size <= MAX_SIZE:
                    features = self._analyze_binary_features(path)
                    if features:
                        # Update existing candidate features
                        candidate.web_features = features
                        candidate.architecture = self._get_elf_architecture(path)
                        
                        # Recalculate priority based on new features
                        new_priority = self._calculate_web_priority(features, path)
                        if new_priority > candidate.priority:
                            candidate.priority = new_priority
                        
                        # Update type
                        if "http_server" in features or "goform" in features:
                            if "json_api" in features or len(features) >= 5:
                                candidate.binary_type = "main_service"
                                candidate.reason = self._generate_feature_reason(features, path)
            except Exception as e:
                pass
        
        # Collect large binaries not yet discovered - search all partitions (including additional_roots)
        # Exclude known system tools (these are not web service programs)
        excluded_binaries = {
            # Network tools
            'busybox', 'iptables', 'ip6tables', 'ip', 'iwconfig', 'iwlist',
            'brctl', 'vconfig', 'route', 'ifconfig', 'arp', 'netstat',
            'tc', 'ss', 'ethtool', 'mii-tool',
            # Package management
            'opkg', 'ipkg',
            # Filesystem
            'mount', 'umount', 'fdisk', 'mkfs', 'fsck', 'flash_erase',
            # Remote access services (non-Web management)
            'dropbear', 'telnetd', 'sshd', 'ftpd', 'vsftpd',
            # DNS/DHCP
            'dnsmasq', 'dnrd', 'dhcpcd', 'dhcps',
            # WiFi/Wireless
            'hostapd', 'wpa_supplicant', 'wps_monitor',
            # VPN/PPP
            'pppd', 'pppoe', 'xl2tpd', 'pptp', 'l2tpd', 'openvpn',
            # Storage/Media services (auxiliary services, not main Web management)
            'minidlna', 'dlna', 'samba', 'smbd', 'nmbd',
            # UPnP (auxiliary service)
            'miniupnpd', 'upnpd',
            # Flash tools
            'ubi', 'mtd', 'nand', 'flash', 'unbzip2',
            # Other common system tools
            'ntpd', 'ntpclient', 'crond', 'logd', 'syslogd',
            'udevd', 'hotplug', 'init', 'preinit',
            # Miscellaneous
            'chkntfs', 'phddns', 'cfmd',
        }
        
        for search_root in self._get_all_search_roots():
            for scan_dir in scan_dirs:
                dir_path = search_root / scan_dir
                if not dir_path.exists():
                    continue
                    
                for f in dir_path.iterdir():
                    if not f.is_file():
                        continue
                    try:
                        # Exclude IDA database files
                        if f.name.lower().endswith(('.i64', '.idb', '.id0', '.id1', '.id2', '.nam', '.til')):
                            continue
                        
                        if f.name.lower() in excluded_binaries:
                            continue
                        
                        size = f.stat().st_size
                        if MIN_SIZE <= size <= MAX_SIZE and self._is_binary(f):
                            # Check if already in candidate list
                            if not any(c.path == str(f) for c in self.result.binary_candidates):
                                large_binaries.append(f)
                    except:
                        continue
        
        self.log(f"  [*] Found {len(large_binaries)} large binaries to deep scan")
        
        # Deep analyze each large binary
        for binary_path in large_binaries:
            try:
                features = self._analyze_binary_features(binary_path)
                
                # Only add if has genuine Web features
                web_essential_features = {"http_server", "goform", "json_api", "cgi"}
                has_essential_web = bool(set(features) & web_essential_features)
                
                if features and has_essential_web:
                    arch = self._get_elf_architecture(binary_path)
                    priority = self._calculate_web_priority(features, binary_path)
                    
                    # Determine type based on features
                    if "http_server" in features or "goform" in features:
                        binary_type = "main_service"
                    elif "json_api" in features:
                        binary_type = "api_service"
                    elif "router_mgmt" in features:
                        binary_type = "mgmt_service"
                    else:
                        binary_type = "potential_web"
                    
                    reason = self._generate_feature_reason(features, binary_path)
                    
                    candidate = BinaryCandidate(
                        path=str(binary_path),
                        name=binary_path.name,
                        binary_type=binary_type,
                        priority=priority,
                        reason=reason,
                        size=binary_path.stat().st_size,
                        web_features=features,
                        architecture=arch
                    )
                    
                    self.result.binary_candidates.append(candidate)
                    
                    self.log(f"\n  [+] FOUND: {binary_path.name}")
                    self.log(f"      Type: {binary_type} | Priority: {priority} | Size: {binary_path.stat().st_size:,} bytes")
                    self.log(f"      Architecture: {arch}")
                    self.log(f"      Web Features: {', '.join(features)}")
                    self.log(f"      Reason: {reason}")
                    
            except Exception as e:
                self.log(f"  [!] Error scanning {binary_path.name}: {e}")
        
        # Re-sort candidate list
        self.result.binary_candidates.sort(key=lambda x: x.priority, reverse=True)
        
        self.log(f"\n  [*] Deep scan complete. Total candidates: {len(self.result.binary_candidates)}")
    
    def _analyze_binary_features(self, path: Path) -> List[str]:
        """
        Analyze Web feature strings in binary file
        
        Args:
            path: Binary file path
            
        Returns:
            List of detected features
        """
        features = []
        try:
            # Read binary file (limit read size for performance)
            max_read_size = 5 * 1024 * 1024  # Read at most 5MB
            with open(path, 'rb') as f:
                content = f.read(max_read_size)
            
            # Check each feature category
            for feature_name, patterns in self.WEB_FEATURE_PATTERNS.items():
                for pattern in patterns:
                    if pattern in content:
                        if feature_name not in features:
                            features.append(feature_name)
                        break
            
            # Extra check: extract printable strings and look for URL path patterns
            strings = self._extract_strings(content)
            url_patterns = [s for s in strings if self._is_url_pattern(s)]
            if url_patterns:
                if "url_routes" not in features:
                    features.append("url_routes")
            
            # Check if there are many API-related strings
            api_strings = [s for s in strings if any(kw in s.lower() for kw in 
                          ['get', 'set', 'add', 'del', 'update', 'config', 'param', 'req', 'handle'])]
            if len(api_strings) > 20:
                if "rich_api" not in features:
                    features.append("rich_api")
                    
        except Exception as e:
            pass
        
        return features
    
    def _extract_strings(self, content: bytes, min_length: int = 6) -> List[str]:
        """
        Extract printable ASCII strings from binary content
        
        Args:
            content: Binary content
            min_length: Minimum string length
            
        Returns:
            List of extracted strings
        """
        strings = []
        current = []
        
        for byte in content:
            if 32 <= byte < 127:  # Printable ASCII
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []
        
        if len(current) >= min_length:
            strings.append(''.join(current))
        
        # Limit return count
        return strings[:5000]
    
    def _is_url_pattern(self, s: str) -> bool:
        """Check if string looks like URL path"""
        if not s.startswith('/'):
            return False
        if len(s) < 3 or len(s) > 100:
            return False
        # Exclude common non-URL paths
        exclude_patterns = ['/dev/', '/proc/', '/sys/', '/etc/', '/lib/', '/usr/lib/', 
                           '/tmp/', '/var/', '.so', '.a', '.o']
        if any(ep in s for ep in exclude_patterns):
            return False
        # URL path characteristics
        url_indicators = ['/', '.', '_', 'api', 'cgi', 'form', 'get', 'set', 'json']
        return any(ind in s.lower() for ind in url_indicators)
    
    def _get_elf_architecture(self, path: Path) -> str:
        """Get ELF file architecture"""
        try:
            with open(path, 'rb') as f:
                header = f.read(20)
                
                if len(header) < 20 or header[:4] != b'\x7fELF' or header[4] not in (1, 2) or header[5] not in (1, 2):
                    return "unknown"
                
                # ELF class (32/64 bit)
                ei_class = header[4]
                class_str = "32-bit" if ei_class == 1 else "64-bit"
                
                # Machine type
                machine = int.from_bytes(header[18:20], 'little' if header[5] == 1 else 'big')
                machine_map = {
                    3: "x86",
                    8: "MIPS",
                    40: "ARM",
                    62: "x86_64",
                    183: "AArch64",
                }
                machine_str = machine_map.get(machine, f"unknown({machine})")
                
                # Endianness
                ei_data = header[5]
                endian = "LE" if ei_data == 1 else "BE"
                
                return f"{machine_str} {class_str} {endian}"
        except:
            return "unknown"
    
    def _calculate_web_priority(self, features: List[str], path: Path) -> int:
        """
        Calculate priority based on Web features
        
        Args:
            features: List of detected features
            path: Binary file path
            
        Returns:
            Priority score
        """
        priority = 0
        
        # Feature weights
        feature_weights = {
            "http_server": 20,
            "goform": 25,
            "json_api": 15,
            "url_handler": 15,
            "cgi": 12,
            "auth": 10,
            "router_mgmt": 8,
            "socket": 5,
            "url_routes": 12,
            "rich_api": 10,
            "xml_rpc": 8,
            "upnp": 5,
        }
        
        for feature in features:
            priority += feature_weights.get(feature, 2)
        
        # Filename bonus
        name_lower = path.name.lower()
        for service_name in self.MAIN_SERVICE_NAMES:
            if service_name in name_lower:
                priority += 10
                break
        
        # === Lightweight HTTP server demotion ===
        # mini_httpd, thttpd, lighttpd etc. are generic lightweight HTTP servers
        # They usually only do request forwarding, real business logic is in CGI programs
        lightweight_http_servers = ["mini_httpd", "thttpd", "micro_httpd", "busybox"]
        for lightweight in lightweight_http_servers:
            if lightweight in name_lower:
                priority -= 15  # Lower priority
                break
        
        # === Large CGI program bonus ===
        # Programs with .cgi in filename and large size are more likely to contain business logic
        size = path.stat().st_size
        if ".cgi" in name_lower and size > 100000:  # > 100KB CGI program
            priority += 15
            if size > 500000:  # > 500KB
                priority += 10
        
        # File size bonus (larger programs usually have more complete functionality)
        if size > 500000:  # > 500KB
            priority += 5
        if size > 1000000:  # > 1MB
            priority += 5
        if size > 2000000:  # > 2MB
            priority += 5
        
        return priority
    
    def _generate_feature_reason(self, features: List[str], path: Path) -> str:
        """Generate recommendation reason based on features"""
        reasons = []
        
        if "http_server" in features:
            reasons.append("contains HTTP server implementation")
        if "goform" in features:
            reasons.append("contains GoForm route handlers (/goform/*)")
        if "json_api" in features:
            reasons.append("JSON API processing detected")
        if "auth" in features:
            reasons.append("authentication logic present")
        if "router_mgmt" in features:
            reasons.append("router management functions")
        if "url_routes" in features:
            reasons.append("URL route patterns found")
        if "rich_api" in features:
            reasons.append("rich API function set detected")
        
        if not reasons:
            reasons.append("potential web service binary")
        
        size_mb = path.stat().st_size / (1024 * 1024)
        return f"Main service binary ({size_mb:.1f}MB) - " + ", ".join(reasons)
    
    def _is_binary(self, path: Path) -> bool:
        """Check if file is binary"""
        try:
            with open(path, 'rb') as f:
                header = f.read(4)
                # ELF magic
                if header[:4] == b'\x7fELF':
                    return True
                # Check if script (starts with #!)
                if header[:2] == b'#!':
                    return False
            return False
        except:
            return False
    
    def _is_web_binary(self, name: str) -> bool:
        """Check if binary is Web-related"""
        web_keywords = ['http', 'cgi', 'web', 'goahead', 'lighttpd', 
                       'nginx', 'uhttpd', 'boa', 'mini_httpd']
        name_lower = name.lower()
        return any(kw in name_lower for kw in web_keywords)
    
    def _classify_binary(self, path: Path) -> str:
        """Classify binary file"""
        name = path.name.lower()
        path_str = str(path).lower()
        
        if 'cgi' in path_str or name.endswith('.cgi'):
            return "cgi"
        elif 'fcgi' in name or 'fastcgi' in name:
            return "fastcgi"
        elif any(s in name for s in ['httpd', 'lighttpd', 'nginx', 'goahead']):
            return "httpd"
        elif name.endswith('.so'):
            return "library"
        else:
            return "unknown"
    
    def _calculate_priority(self, path: Path, binary_type: str) -> int:
        """Calculate analysis priority"""
        priority = 0
        name = path.name.lower()
        
        # CGI files have highest priority
        if binary_type == "cgi":
            priority += 10
        elif binary_type == "fastcgi":
            priority += 8
        elif binary_type == "httpd":
            priority += 3  # httpd itself has lower priority
        
        # Files with moderate size have priority (too small may be wrapper script, too large may be full server)
        size = path.stat().st_size
        if 10000 < size < 500000:
            priority += 2
        
        # Files containing specific keywords have priority
        if any(kw in name for kw in ['api', 'json', 'rpc', 'form', 'action']):
            priority += 3
        
        return priority
    
    def _get_binary_reason(self, path: Path, binary_type: str) -> str:
        """Get recommendation reason"""
        if binary_type == "cgi":
            return "CGI binary - likely contains route handlers"
        elif binary_type == "fastcgi":
            return "FastCGI binary - likely contains application logic"
        elif binary_type == "httpd":
            return "Web server binary - may contain embedded routes"
        else:
            return "Potential web component"
    
    def _extract_static_routes(self):
        """Extract routes from static files"""
        routes = []
        
        # Step 1: Add identified CGI binaries as routes
        for binary in self.result.binary_candidates:
            if binary.binary_type == "cgi" or ".cgi" in binary.name.lower():
                # Infer URL from path
                path_str = str(binary.path)
                cgi_url = None
                
                # Common CGI directory mapping
                if "/cgi-bin/" in path_str:
                    cgi_url = "/cgi-bin/" + binary.name
                elif "/cgi/" in path_str:
                    cgi_url = "/cgi/" + binary.name
                elif "/www/" in path_str and binary.name.endswith(".cgi"):
                    # CGI file under www directory
                    try:
                        rel_path = Path(path_str).relative_to(self.firmware_root)
                        # Find the part after www
                        parts = rel_path.parts
                        for i, part in enumerate(parts):
                            if part == "www" or part == "htdocs" or part == "html":
                                cgi_url = "/" + "/".join(parts[i+1:])
                                break
                    except:
                        cgi_url = "/" + binary.name
                else:
                    # Default to /cgi-bin/
                    cgi_url = "/cgi-bin/" + binary.name
                
                if cgi_url:
                    routes.append(StaticRouteInfo(
                        path=cgi_url,
                        method="GET",  # CGI usually supports GET and POST
                        source_file=str(binary.path)
                    ))
                    self.log(f"  [+] Added CGI route: {cgi_url}")
        
        # Step 2: Search static files in www directory
        www_dirs = ["www", "home/httpd/htdocs", "var/www", "usr/www", "web"]
        
        for www_dir in www_dirs:
            www_path = self.firmware_root / www_dir
            if not www_path.exists():
                continue
            
            self.log(f"  [+] Scanning {www_dir}...")
            
            # Scan HTML files
            for ext in self.STATIC_EXTENSIONS["html"]:
                for html_file in www_path.glob(f"**/*{ext}"):
                    routes.extend(self._extract_routes_from_html(html_file))
            
            # Scan JavaScript files
            for ext in self.STATIC_EXTENSIONS["javascript"]:
                for js_file in www_path.glob(f"**/*{ext}"):
                    routes.extend(self._extract_routes_from_js(js_file))
            
            # Scan PHP files
            for ext in self.STATIC_EXTENSIONS["php"]:
                for php_file in www_path.glob(f"**/*{ext}"):
                    routes.extend(self._extract_routes_from_php(php_file))
            
            # Scan Lua files
            for ext in self.STATIC_EXTENSIONS["lua"]:
                for lua_file in www_path.glob(f"**/*{ext}"):
                    routes.extend(self._extract_routes_from_lua(lua_file))
        
        # Deduplicate
        seen = set()
        unique_routes = []
        for r in routes:
            key = (r.path, r.method)
            if key not in seen:
                seen.add(key)
                unique_routes.append(r)
        
        self.result.static_routes = unique_routes
        self.log(f"\n  [*] Extracted {len(unique_routes)} unique routes from static files")
    
    def _extract_routes_from_html(self, path: Path) -> List[StaticRouteInfo]:
        """Extract routes from HTML/SHTML files"""
        routes = []
        try:
            content = path.read_text(encoding='utf-8', errors='ignore')
            
            # Extract form action
            form_actions = re.findall(r'action\s*=\s*["\']([^"\']+)["\']', content, re.I)
            for action in form_actions:
                if action and not action.startswith(('http://', 'https://', '#', 'javascript:')):
                    routes.append(StaticRouteInfo(
                        path=action,
                        method="POST",
                        source_file=str(path.relative_to(self.firmware_root))
                    ))
            
            # Extract goform routes (common in router firmware)
            goform_routes = re.findall(r'/goform/(\w+)', content)
            for route in goform_routes:
                goform_path = f"/goform/{route}"
                if not any(r.path == goform_path for r in routes):
                    routes.append(StaticRouteInfo(
                        path=goform_path,
                        method="POST",
                        source_file=str(path.relative_to(self.firmware_root))
                    ))
            
            # Extract AJAX URL and other API calls
            ajax_patterns = [
                r'(?:url|href)\s*[=:]\s*["\']([^"\']+\.(?:cgi|asp|php|lua))["\']',
                r'(?:url|api|action)\s*[=:]\s*["\'](/[^"\']+)["\']',
                r'location\.href\s*=\s*["\']([^"\']+)["\']',
            ]
            for pattern in ajax_patterns:
                matches = re.findall(pattern, content, re.I)
                for url in matches:
                    if url and not url.startswith(('http://', 'https://', '#', 'javascript:')):
                        if not any(r.path == url for r in routes):
                            routes.append(StaticRouteInfo(
                                path=url,
                                method="GET",
                                source_file=str(path.relative_to(self.firmware_root))
                            ))
            
        except Exception as e:
            pass
        
        return routes
    
    def _extract_routes_from_js(self, path: Path) -> List[StaticRouteInfo]:
        """Extract routes from JavaScript files"""
        routes = []
        try:
            content = path.read_text(encoding='utf-8', errors='ignore')
            
            # Extract API calls
            # $.ajax, fetch, XMLHttpRequest etc.
            api_patterns = [
                r'(?:url|api)\s*[=:]\s*["\']([^"\']+)["\']',
                r'\.(?:get|post|put|delete|ajax)\s*\(\s*["\']([^"\']+)["\']',
                r'fetch\s*\(\s*["\']([^"\']+)["\']',
                r'XMLHttpRequest.*?open\s*\([^,]+,\s*["\']([^"\']+)["\']',
            ]
            
            for pattern in api_patterns:
                matches = re.findall(pattern, content, re.I)
                for url in matches:
                    if url and not url.startswith(('http://', 'https://', '#')):
                        # Infer method
                        method = "POST" if ".post" in pattern.lower() else "GET"
                        routes.append(StaticRouteInfo(
                            path=url,
                            method=method,
                            source_file=str(path.relative_to(self.firmware_root))
                        ))
            
            # Extract UCI config file names (TP-Link/Mercury style)
            # These usually represent API modules
            uci_patterns = [
                r'fileName\s*:\s*["\'](\w+)["\']',
                r'uci(\w+)\s*=\s*\{',
            ]
            for pattern in uci_patterns:
                matches = re.findall(pattern, content)
                for module in matches:
                    if module and len(module) > 2:
                        # Record as API module hint
                        routes.append(StaticRouteInfo(
                            path=f"/api/module/{module}",
                            method="POST",
                            source_file=str(path.relative_to(self.firmware_root)),
                            auth_hint="UCI module"
                        ))
            
            # Extract dynData dynamic data names (represent API operations)
            dyn_patterns = [
                r'dynData\s*:\s*\{([^}]+)\}',
                r'actionName\s*:\s*\{([^}]+)\}',
            ]
            for pattern in dyn_patterns:
                matches = re.findall(pattern, content)
                for block in matches:
                    # Extract action names
                    actions = re.findall(r'(\w+)\s*:\s*["\'](\w+)["\']', block)
                    for action_key, action_value in actions:
                        routes.append(StaticRouteInfo(
                            path=f"/api/action/{action_value}",
                            method="POST",
                            source_file=str(path.relative_to(self.firmware_root)),
                            auth_hint=f"Dynamic action: {action_key}"
                        ))
            
        except Exception as e:
            pass
        
        return routes
    
    def _extract_routes_from_php(self, path: Path) -> List[StaticRouteInfo]:
        """Extract routes from PHP files"""
        routes = []
        try:
            content = path.read_text(encoding='utf-8', errors='ignore')
            
            # PHP file itself is a route endpoint
            routes.append(StaticRouteInfo(
                path="/" + str(path.relative_to(self.firmware_root)),
                method="GET",
                source_file=str(path.relative_to(self.firmware_root))
            ))
            
            # Extract include/require
            includes = re.findall(r'(?:include|require)(?:_once)?\s*["\']([^"\']+)["\']', content)
            for inc in includes:
                if inc.endswith('.php'):
                    routes.append(StaticRouteInfo(
                        path=inc,
                        method="GET",
                        source_file=str(path.relative_to(self.firmware_root))
                    ))
            
        except Exception as e:
            pass
        
        return routes
    
    def _extract_routes_from_lua(self, path: Path) -> List[StaticRouteInfo]:
        """Extract routes from Lua files"""
        routes = []
        try:
            content = path.read_text(encoding='utf-8', errors='ignore')
            
            # Extract luci route registration
            luci_entries = re.findall(r'entry\s*\(\s*\{([^}]+)\}', content)
            for entry in luci_entries:
                parts = [p.strip().strip('"\'') for p in entry.split(',')]
                if parts:
                    route_path = "/" + "/".join(parts)
                    routes.append(StaticRouteInfo(
                        path=route_path,
                        method="GET",
                        source_file=str(path.relative_to(self.firmware_root))
                    ))
            
        except Exception as e:
            pass
        
        return routes
    
    def _extract_python_wsgi_routes(self):
        """
        Extract routes from Python WSGI applications
        
        Applicable to devices using CherryPy/Flask/Django/WSGI and other Python Web frameworks
        Typical device: Zyxel NAS326 (using CherryPy + mod_wsgi)
        
        Route structure: /cmd,/{controller}/{action}
        """
        wsgi_routes_found = []
        
        # Search all partitions
        for search_root in self._get_all_search_roots():
            # Find web_framework/controllers directory
            controller_patterns = [
                "web_framework/controllers",
                "*/web_framework/controllers",
                "**/controllers",
                "www/cgi-bin/controllers",
            ]
            
            for pattern in controller_patterns:
                for controllers_dir in search_root.glob(pattern):
                    if not controllers_dir.is_dir():
                        continue
                    
                    self.log(f"  [+] Found Python controllers: {controllers_dir}")
                    
                    # Detect WSGI entry point
                    wsgi_entry = controllers_dir.parent / "main.wsgi"
                    if wsgi_entry.exists():
                        self.log(f"      WSGI entry: {wsgi_entry.name}")
                    
                    # Extract controllers and actions
                    routes = self._extract_cherrypy_routes(controllers_dir)
                    wsgi_routes_found.extend(routes)
        
        # Add to static route results
        if wsgi_routes_found:
            self.result.static_routes.extend(wsgi_routes_found)
            self.log(f"\n  [*] Extracted {len(wsgi_routes_found)} routes from Python WSGI controllers")
            
            # Add recommendation
            self.result.recommendations.append(
                f"Python WSGI framework detected with {len(wsgi_routes_found)} API endpoints. "
                f"These routes are in Python bytecode (.pyc) and cannot be analyzed with IDA."
            )
    
    def _extract_cherrypy_routes(self, controllers_dir: Path) -> List[StaticRouteInfo]:
        """
        Extract routes from CherryPy controller directory
        
        CherryPy route format: /cmd,/{controller}/{action}
        
        Args:
            controllers_dir: Controller directory path
            
        Returns:
            List of extracted routes
        """
        routes = []
        
        # Determine WSGI prefix from Apache config (default /cmd,)
        wsgi_prefix = "/cmd,"
        
        # Action method name patterns
        action_patterns = [
            r'^get_',    # get_xxx
            r'^set_',    # set_xxx
            r'^add_',    # add_xxx
            r'^del_',    # del_xxx
            r'^create_', # create_xxx
            r'^update_', # update_xxx
            r'^remove_', # remove_xxx
            r'^query_',  # query_xxx
            r'^check_',  # check_xxx
            r'^load_',   # load_xxx
            r'^save_',   # save_xxx
            r'^apply_',  # apply_xxx
            r'^start_',  # start_xxx
            r'^stop_',   # stop_xxx
            r'^enable_', # enable_xxx
            r'^disable_',# disable_xxx
        ]
        
        # Excluded built-in methods
        exclude_methods = {
            'index', 'default', '__init__', '__del__', '__str__', '__repr__',
            'exposed', 'json_in', 'json_out', 'tools', 'before_handler',
            'before_finalize', 'on_start', 'on_end', 'get_dict', 'get_list',
            'get_item', 'set_item', 'del_item'
        }
        
        for pyc_file in controllers_dir.glob("*.pyc"):
            if pyc_file.name == "__init__.pyc":
                continue
                
            # Get controller name
            controller_name = pyc_file.stem
            controller_name = controller_name.replace('_main', '').replace('_cgi', '')
            
            try:
                # Read pyc file to extract strings
                data = pyc_file.read_bytes()
                
                # Extract all strings that look like method names
                method_names = set(re.findall(rb'[a-z][a-z_0-9]{3,30}', data))
                method_names = {m.decode('latin1') for m in method_names}
                
                # Filter action methods
                actions = []
                for method in method_names:
                    if method in exclude_methods:
                        continue
                    # Check if matches action pattern
                    if any(re.match(pattern, method) for pattern in action_patterns):
                        actions.append(method)
                
                # Generate routes
                for action in sorted(actions):
                    route_path = f"{wsgi_prefix}/{controller_name}/{action}"
                    routes.append(StaticRouteInfo(
                        path=route_path,
                        method="POST",  # CherryPy typically uses POST
                        source_file=str(pyc_file.relative_to(self.firmware_root)) if self.firmware_root in pyc_file.parents else str(pyc_file),
                        auth_hint="Python WSGI - requires authentication (default)"
                    ))
                
                if actions:
                    self.log(f"      Controller '{controller_name}': {len(actions)} actions")
                    
            except Exception as e:
                pass
        
        return routes
    
    def _analyze_auth(self):
        """Analyze authentication mechanisms"""
        # Preserve auth info found during config parsing
        existing_findings = list(self.result.auth_findings)
        findings = []
        
        # Search auth-related files
        auth_patterns = ["*passwd*", "*shadow*", "*htpasswd*", "*auth*", "*session*", "*login*"]
        
        for pattern in auth_patterns:
            for match in self.firmware_root.glob(f"**/{pattern}"):
                if match.is_file():
                    findings.append(f"Auth-related file: {match.relative_to(self.firmware_root)}")
        
        # Search auth config in configuration files
        if self.result.webserver.config_file:
            try:
                config_content = Path(self.result.webserver.config_file).read_text(errors='ignore')
                
                if 'auth' in config_content.lower():
                    findings.append("Authentication configured in web server config")
                
                if 'htpasswd' in config_content.lower():
                    findings.append("HTTP Basic Auth (htpasswd) detected")
                
                if 'session' in config_content.lower():
                    findings.append("Session-based auth detected in config")
                    
            except:
                pass
        
        # Search default credentials
        for passwd_file in self.firmware_root.glob("**/passwd"):
            try:
                content = passwd_file.read_text(errors='ignore')
                if 'admin' in content or 'root' in content:
                    findings.append(f"Default users in: {passwd_file.relative_to(self.firmware_root)}")
            except:
                pass
        
        # Merge new and old findings, preserve whitelist info from config parsing
        self.result.auth_findings = existing_findings + findings
        
        for finding in findings[:5]:  # Only show first 5 new findings
            self.log(f"  [*] {finding}")
    
    def _generate_recommendations(self):
        """Generate analysis recommendations"""
        recommendations = []
        
        # Priority boost: if CGI is in Auth-Free whitelist, significantly increase priority
        # These no-auth-required CGIs are high-risk targets
        whitelist_paths = []
        for finding in self.result.auth_findings:
            if "Auth-Free (whitelist):" in finding:
                path = finding.replace("Auth-Free (whitelist):", "").strip()
                whitelist_paths.append(path)
        
        if whitelist_paths:
            for candidate in self.result.binary_candidates:
                cgi_name = candidate.name
                # Check if CGI is in whitelist
                for wl_path in whitelist_paths:
                    if cgi_name in wl_path or f"/{cgi_name}" in wl_path:
                        # CGI in whitelist gets significantly boosted priority
                        old_priority = candidate.priority
                        candidate.priority = max(candidate.priority, 50) + 20  # At least 70
                        candidate.reason = f"[Auth-Free WHITELIST] {candidate.reason}"
                        self.log(f"  [!] Boosted priority of {cgi_name}: {old_priority} -> {candidate.priority} (in whitelist)")
                        break
            
            # Re-sort candidate list
            self.result.binary_candidates.sort(key=lambda x: x.priority, reverse=True)
        
        # Recommendations based on web server type
        if self.result.webserver.server_type == "lighttpd":
            recommendations.append(
                "Web server is Lighttpd - a pure web server. "
                "Look for CGI/FastCGI binaries for route analysis."
            )
        elif self.result.webserver.server_type == "goahead":
            recommendations.append(
                "Web server is GoAhead - routes are embedded in the binary. "
                "Analyze the goahead binary directly."
            )
        
        # Recommendations based on candidate binaries
        if self.result.binary_candidates:
            top_candidates = self.result.binary_candidates[:3]
            for candidate in top_candidates:
                recommendations.append(
                    f"Recommend analyzing: {candidate.name} "
                    f"(Priority: {candidate.priority}, Type: {candidate.binary_type})"
                )
        
        # Recommendations based on static routes
        if self.result.static_routes:
            recommendations.append(
                f"Found {len(self.result.static_routes)} routes in static files. "
                "These can supplement binary analysis."
            )
        
        # Auth-related recommendations
        if self.result.auth_findings:
            recommendations.append(
                "Authentication mechanisms detected. "
                "Focus on auth bypass vulnerabilities."
            )
        
        self.result.recommendations = recommendations
        
        self.log("\n" + "-" * 60)
        self.log("  RECOMMENDATIONS:")
        self.log("-" * 60)
        for i, rec in enumerate(recommendations, 1):
            self.log(f"  {i}. {rec}")
    
    def save_result(self, output_path: str):
        """Save analysis result"""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.result.to_dict(), f, indent=2, ensure_ascii=False)
        self.log(f"\n[*] Analysis result saved to: {output_path}")
    
    def print_summary(self):
        """Print analysis summary"""
        print("\n" + "=" * 60)
        print("  FIRMWARE PRE-ANALYSIS SUMMARY")
        print("=" * 60)
        
        print(f"\n  Web Server: {self.result.webserver.server_type}")
        if self.result.webserver.config_file:
            print(f"  Config: {Path(self.result.webserver.config_file).name}")
        
        print(f"\n  Binary Candidates: {len(self.result.binary_candidates)}")
        if self.result.binary_candidates:
            print("  Top 3 recommended for analysis:")
            for c in self.result.binary_candidates[:3]:
                print(f"    - {c.name} (priority: {c.priority}, type: {c.binary_type})")
        
        print(f"\n  Static Routes Found: {len(self.result.static_routes)}")
        
        print(f"\n  Auth Findings: {len(self.result.auth_findings)}")
        
        print("\n" + "=" * 60)


def run_firmware_preanalysis(firmware_root: str, output_dir: str = "output", 
                             verbose: bool = True) -> Optional[FirmwareAnalysisResult]:
    """
    Run firmware pre-analysis (Phase 0)
    
    Args:
        firmware_root: Firmware filesystem root directory
        output_dir: Output directory
        verbose: Verbose output
    
    Returns:
        FirmwareAnalysisResult or None
    """
    analyzer = FirmwareAnalyzer(firmware_root, verbose)
    result = analyzer.analyze()
    
    # Save result
    os.makedirs(output_dir, exist_ok=True)
    firmware_name = Path(firmware_root).name
    output_path = os.path.join(output_dir, f"{firmware_name}_preanalysis.json")
    analyzer.save_result(output_path)
    
    # Print summary
    analyzer.print_summary()
    
    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        result = run_firmware_preanalysis(sys.argv[1])
    else:
        print("Usage: python firmware_analyzer.py <firmware_root>")
