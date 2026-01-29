# Copyright (c) 2026 The Pangu Project Authors. All rights reserved.
import os
import re
import json
import sys

# Configure the root directory for scanning (based on your screenshot path, this can be set to the extracted root)
# You can pass the path at runtime, or modify this value
DEFAULT_SCAN_DIR = "./" 

# Regex pattern definitions
PATTERNS = {
    # Match static webpage file references (e.g., "EditNetwork2.htm", "login.html")
    "static_file": re.compile(r'\b[\w-]+\.(htm|html|css|js|php|asp|jsp|json|xml)\b', re.IGNORECASE),
    
    # Match CGI program references (e.g., "ssi.cgi", "upload.cgi")
    "cgi_bin": re.compile(r'\b[\w-]+\.cgi\b', re.IGNORECASE),
    
    # Match LuCI/Lua module definitions (e.g., "luci.controller.admin.network")
    # This typically maps directly to route /cgi-bin/luci/admin/network
    "luci_module": re.compile(r'luci\.controller\.([\w\.]+)', re.IGNORECASE),
    
    # Match common API action keywords (used to infer handlers)
    "action_verb": re.compile(r'\b(set|get|add|del|update|upload|download)_[\w]+\b', re.IGNORECASE)
}

def get_strings(file_path, min_len=4):
    """
    Simulate the 'strings' command to extract printable strings from binary files.
    Filter out garbage, keeping only letters, numbers, underscores, dots, and slashes.
    """
    with open(file_path, "rb") as f:
        content = f.read()
    
    # Regex: match only 4+ consecutive [a-zA-Z0-9_./-] characters
    # This is cleaner than generic strings, filtering out bytecode noise like !G, @LL
    result = re.findall(b'[a-zA-Z0-9_./-]{4,}', content)
    
    # Decode to strings
    return [s.decode('utf-8', errors='ignore') for s in result]

def guess_root_handler(filename, ext_str):
    """Infer the root handler based on filename and extracted strings (e.g., ssi.cgi or /cgi-bin/luci)"""
    if "luci" in ext_str or filename.endswith(".lua"):
        return "/cgi-bin/luci"
    if ext_str.endswith(".cgi"):
        return ext_str # The file itself is the root
    if ext_str.endswith(".htm") or ext_str.endswith(".html"):
        return "ssi.cgi" # TP-Link common pattern: htm files are typically handled by ssi.cgi
    return "/" # Default to web root

def scan_file(file_path, results_list):
    filename = os.path.basename(file_path)
    
    try:
        # 1. Extract all clean strings
        strings = get_strings(file_path)
        
        # 2. Iterate through strings for regex matching
        for s in strings:
            
            # --- Strategy A: Discover static files (.htm, .cgi) ---
            if PATTERNS["static_file"].match(s) or PATTERNS["cgi_bin"].match(s):
                root = guess_root_handler(filename, s)
                item = {
                    "root": root,
                    "sub_path": s,
                    "full_path": f"{root}/{s}".replace("//", "/"),
                    "handler": "Static_Reference_Scan",
                    "mode": "static_scan_loose_v2"
                }
                results_list.append(item)

            # --- Strategy B: Discover LuCI controller definitions (for LuaQ files) ---
            # If luci.controller.admin.network is extracted, route /admin/network exists
            match_luci = PATTERNS["luci_module"].search(s)
            if match_luci:
                lua_path = match_luci.group(1) # e.g., "admin.network"
                url_path = lua_path.replace(".", "/") # e.g., "admin/network"
                item = {
                    "root": "/cgi-bin/luci",
                    "sub_path": url_path,
                    "full_path": f"/cgi-bin/luci/{url_path}",
                    "handler": "LuCI_Controller_Dispatch",
                    "mode": "static_scan_loose_v2"
                }
                results_list.append(item)

    except Exception as e:
        # Ignore read errors
        pass

def main():
    target_dir = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SCAN_DIR
    all_routes = []
    
    print(f"[*] Starting loose scan v2 on: {target_dir}")
    print(f"[*] Logic: Strings extraction -> Regex Filtering -> Heuristic Mapping")

    # Recursively traverse directories
    for root, dirs, files in os.walk(target_dir):
        for file in files:
            # Skip obviously irrelevant files to improve speed
            if file.endswith(('.jpg', '.png', '.gif', '.ko', '.o')):
                continue
            
            file_path = os.path.join(root, file)
            scan_file(file_path, all_routes)

    # Deduplication logic (dedupe by full_path)
    seen_paths = set()
    unique_routes = []
    for r in all_routes:
        if r["full_path"] not in seen_paths:
            seen_paths.add(r["full_path"])
            unique_routes.append(r)

    # Output results
    output_file = "extracted_routes_v2.json"
    with open(output_file, 'w') as f:
        json.dump(unique_routes, f, indent=4)

    print(f"[+] Scan complete. Found {len(unique_routes)} potential routes.")
    print(f"[+] Saved to {output_file}")
    
    # Print top 5 preview
    print("\n--- Preview (Top 5) ---")
    print(json.dumps(unique_routes[:5], indent=4))

if __name__ == "__main__":
    main()