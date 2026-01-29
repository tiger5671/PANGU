# Copyright (c) 2026 The Pangu Project Authors. All rights reserved.
# analysis/stage2_architect.py
import sys
import os
import json
import re
import time
from collections import defaultdict

# Path Hack: ensure core module can be imported
sys.path.append(os.getcwd())

from core.bridge.ida_client import IDAProClient
from core.llm import LLMProvider

class RouteArchitectAgent:
    def __init__(self):
        self.ida = IDAProClient()
        self.llm = LLMProvider()
        
        # Configuration directories
        self.out_dir = "output"
        self.input_file = self._find_latest_results()
        self.output_file = os.path.join(self.out_dir, "routes_v3_hierarchical.json")
        
        self.raw_data = []
        self.hub_groups = {}
        
        # Backtracking configuration
        self.MAX_DEPTH = 3  # Maximum 3 levels up

    def log(self, msg):
        print(f"[Architect] {msg}")

    def _find_latest_results(self):
        import glob
        if not os.path.exists(self.out_dir): return None
        list_of_files = glob.glob(os.path.join(self.out_dir, 'routes_v3_*.json'))
        list_of_files = [f for f in list_of_files if "hierarchical" not in f]
        if not list_of_files: return None
        return max(list_of_files, key=os.path.getctime)

    def load_data(self):
        if not self.input_file or not os.path.exists(self.input_file):
            self.log("[-] No input file found. Aborting.")
            return False

        self.log(f"[*] Loading raw data from: {self.input_file}")
        with open(self.input_file, 'r', encoding='utf-8') as f:
            self.raw_data = json.load(f)

        self.hub_groups = defaultdict(list)
        for entry in self.raw_data:
            hub = entry.get("source_hub", "").lower().strip()
            if hub:
                self.hub_groups[hub].append(entry)
        
        self.log(f"[*] Grouped {len(self.raw_data)} routes into {len(self.hub_groups)} unique Hubs.")
        return True

    def _extract_smart_snippet(self, full_code, target_keywords, window=20):
        """ Smart slicing: extract code around keywords (enlarged window) """
        lines = full_code.split('\n')
        relevant_lines = set()
        
        for i, line in enumerate(lines):
            for kw in target_keywords:
                if kw.lower() in line.lower():
                    start = max(0, i - window)
                    end = min(len(lines), i + window + 1)
                    for j in range(start, end):
                        relevant_lines.add(j)
        
        if not relevant_lines: return None
        
        sorted_indices = sorted(list(relevant_lines))
        snippet_parts = []
        last_idx = -1
        
        for idx in sorted_indices:
            if last_idx != -1 and idx > last_idx + 1:
                snippet_parts.append("    // ...")
            snippet_parts.append(lines[idx])
            last_idx = idx
            
        return "\n".join(snippet_parts)

    def get_caller_context(self, target_address):
        """
        Get context, return structured data instead of plain string
        """
        res = self.ida.get_xrefs(target_address, direction="to")
        if res.get("status") != "ok": return []
        
        refs = res.get("data", [])
        context_data = [] # List of dicts
        processed_callers = set()
        
        # Construct search keywords
        keywords = [target_address]
        if target_address.startswith("0x"):
            keywords.append(target_address.replace("0x", "sub_"))
            keywords.append(target_address.replace("0x", "off_")) 
            short_addr = target_address.replace("0x0", "0x")
            if short_addr != target_address:
                keywords.append(short_addr)

        for ref in refs:
            caller_addr = ref.get("from")
            caller_name = ref.get("func_name", "Unknown")
            
            if caller_addr in processed_callers: continue
            
            decomp_res = self.ida.decompile(caller_addr)
            if decomp_res.get("status") == "ok":
                code = decomp_res.get("data", {}).get("code", "")
                caller_func_name = decomp_res.get("data", {}).get("func_name", caller_name)
                
                snippet = self._extract_smart_snippet(code, keywords)
                if snippet:
                    context_data.append({
                        "caller_name": caller_func_name,
                        "caller_addr": caller_addr,
                        "snippet": snippet
                    })
                    processed_callers.add(caller_addr)
            
            if len(context_data) >= 3: break 
            
        return context_data

    def _ask_llm(self, current_target, context_data, depth):
        """ 
        Construct enhanced Prompt with explicit 'Container Trace' logic 
        """
        
        # Format Snippets, explicitly mark Container Function
        formatted_snippets = []
        for ctx in context_data:
            formatted_snippets.append(f"""
=== CONTEXT START: Inside Function '{ctx['caller_name']}' ===
{ctx['snippet']}
=== CONTEXT END ===
""")

        prompt = f"""
You are the "Routing Architect". Determine the **Mount Point (Root Path)** for a Route Hub.

**CURRENT TARGET**: `{current_target}` (Depth: {depth})

**CODE SNIPPETS**:
{chr(10).join(formatted_snippets)}

**TASK**:
Analyze how `{current_target}` is used inside the functions shown above.

**DECISION LOGIC (Strict Order)**:

1. **FOUND ROOT**: 
   If `{current_target}` (or its wrapper) is passed alongside a **String Literal** (e.g., `func("/api", {current_target})`), that string is the Root.
   -> OUTPUT: {{ "action": "decision", "root_path": "/found_string" }}

2. **FOUND WRAPPER (Target Passed)**: 
   If `{current_target}` is passed to another function `sub_XYZ` *without* a string (e.g., `sub_XYZ({current_target}, 0)`).
   -> OUTPUT: {{ "action": "trace_caller", "target_function": "sub_XYZ", "reasoning": "Target passed to sub_XYZ." }}

3. **CONTAINER TRACE (Target Used Locally)**: 
   If `{current_target}` is a global variable (like a table) used/iterated inside a function `sub_ABC`, AND no string path is present in `sub_ABC`.
   This means `sub_ABC` itself is likely the Handler. You must trace who calls `sub_ABC`.
   -> OUTPUT: {{ "action": "trace_caller", "target_function": "sub_ABC", "reasoning": "Target is used inside sub_ABC, tracing sub_ABC." }}

4. **IMPLICIT ROOT**: 
   If passed to `initWebs` or used in `main` with no path.
   -> OUTPUT: {{ "action": "decision", "root_path": "/" }}

**JSON OUTPUT ONLY**:
"""
        try:
            resp = self.llm.chat([{"role": "user", "content": prompt}], json_mode=True)
            if isinstance(resp, str):
                resp = re.sub(r'^```json\s*', '', resp, flags=re.MULTILINE)
                resp = re.sub(r'\s*```$', '', resp, flags=re.MULTILINE)
                return json.loads(resp.strip())
            return resp
        except Exception as e:
            self.log(f"[-] LLM Error: {e}")
            return {"action": "decision", "root_path": "/", "reasoning": "Error"}

    def analyze_with_backtrack(self, start_hub):
        current_target = start_hub
        depth = 0
        trace_history = []

        while depth < self.MAX_DEPTH:
            context_data = self.get_caller_context(current_target)
            
            if not context_data:
                if depth == 0: return "/", "No Xrefs found"
                else: return "/", f"Trace dead-end at {current_target}"

            self.log(f"   > [Depth {depth}] Analyzing target: {current_target} (Contexts: {len(context_data)})")
            
            result = self._ask_llm(current_target, context_data, depth)
            
            action = result.get("action", "decision")
            reason = result.get("reasoning", "")
            
            if action == "decision":
                root = result.get("root_path", "/")
                if not root or root == "null": root = "/"
                if root != "/" and not root.startswith("/"): root = "/" + root
                if root != "/" and root.endswith("/"): root = root.rstrip("/")
                
                full_reason = f"{reason} (Trace: {' -> '.join(trace_history + [root])})"
                return root, full_reason

            elif action == "trace_caller":
                next_target = result.get("target_function")
                
                # Special handling: If the LLM says to trace a function name that is the current context function name
                # This corresponds to "CONTAINER TRACE" logic
                # We need to ensure next_target is either an address or name, get_caller_context supports both
                
                if not next_target:
                    return "/", f"Trace error: empty target at {current_target}"

                # Simple cycle prevention
                if next_target in trace_history or next_target == current_target:
                     # Try to check if it's a "false loop" caused by name/address confusion
                     # Simple handling here: if the name is repeated, it means we've reached top-level recursion, terminate
                     return "/", f"Trace loop detected at {current_target} -> {next_target}"

                trace_history.append(current_target)
                current_target = next_target
                depth += 1
                self.log(f"   > [Trace] Switching focus to wrapper/container '{next_target}'...")
            
            else:
                return "/", f"Unknown action: {action}"

        return "/", "Max depth reached"

    def run(self):
        if not self.ida.connect():
            self.log("[-] Failed to connect to IDA Server.")
            return

        if not self.load_data():
            return

        self.log("\n=== STARTING ARCHITECTURE RECONSTRUCTION (TREE MODE v2.1) ===")
        
        total_hubs = len(self.hub_groups)

        for i, (hub_addr, routes) in enumerate(self.hub_groups.items()):
            self.log(f"\n[{i+1}/{total_hubs}] Analyzing Hub: {hub_addr} (Routes: {len(routes)})")
            
            final_root, reason = self.analyze_with_backtrack(hub_addr)
            self.log(f"   > [FINAL DECISION] Root: '{final_root}'")
            self.log(f"   > [Reason] {reason}")

            for r in routes:
                r['root'] = final_root
                sub = r.get('sub_path', '').strip()
                if final_root == "/":
                    full = "/" + sub.lstrip("/")
                else:
                    full = final_root + "/" + sub.lstrip("/")
                r['full_path'] = full
                r['architect_reason'] = reason

        self.save_results_as_tree()

    def save_results_as_tree(self):
        self.log(f"\n[*] Restructuring data into Tree format...")
        all_routes = []
        for routes in self.hub_groups.values():
            all_routes.extend(routes)
            
        tree = defaultdict(list)
        for r in all_routes:
            root_key = r.get('root', 'Unknown')
            clean_entry = {
                "path": r.get("sub_path"),
                "handler": r.get("handler"),
                "full_path": r.get("full_path"),
                "source_hub": r.get("source_hub"),
                # "mode": r.get("mode") # Optional, can be kept
            }
            tree[root_key].append(clean_entry)
            
        sorted_tree = {}
        if "/" in tree: sorted_tree["/"] = tree.pop("/")
        for k in sorted(tree.keys()):
            sorted_tree[k] = tree[k]

        try:
            with open(self.output_file, "w", encoding="utf-8") as f:
                json.dump(sorted_tree, f, indent=4, ensure_ascii=False)
            self.log(f"[+] Success! Tree saved to {self.output_file}")
            
        except Exception as e:
            self.log(f"[-] Save failed: {e}")

if __name__ == "__main__":
    architect = RouteArchitectAgent()
    architect.run()