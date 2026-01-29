# Copyright (c) 2026 The Pangu Project Authors. All rights reserved.
# analysis/smart_agent_v3.py
# [Version 3.7: FINAL MERGED - Phase 0 Filter + Full Tools + Robust Prompt]
import sys
import os
import json
import re
import glob
import traceback
from datetime import datetime

# Path Hack: ensure core module can be imported
sys.path.append(os.getcwd())

from core.bridge.ida_client import IDAProClient
from core.llm import LLMProvider

class RouteHunterAgentV3:
    def __init__(self):
        self.ida = IDAProClient()
        self.llm = LLMProvider()
        self.history = []
        self.max_steps = 3 
        self.scan_completed = False
        
        # Knowledge base
        self.knowledge_graph = []
        self.static_scan_data = {}
        self.api_knowledge = {} 
        self.static_table_whitelist = {} # {addr: {"class": str, "parent": str}}
        
        # Initialize directories
        self.log_dir = "logs"
        self.out_dir = "output"
        os.makedirs(self.log_dir, exist_ok=True)
        os.makedirs(self.out_dir, exist_ok=True)
        
        # Initialize log
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = os.path.join(self.log_dir, f"trace_v3_{timestamp}.md")
        self.result_file = os.path.join(self.out_dir, f"routes_v3_{timestamp}.json")
        self.api_know_file = os.path.join(self.out_dir, f"api_knowledge_{timestamp}.json")
        
        self.log(f"# Agent Trace Log V3.7 - {timestamp}\n")

    def log(self, content, print_to_console=True):
        if print_to_console:
            print(content)
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(content + "\n")

    def clean_json_block(self, text):
        if not text: return "{}"
        text = re.sub(r'^```json\s*', '', text, flags=re.MULTILINE)
        text = re.sub(r'^```\s*', '', text, flags=re.MULTILINE)
        text = re.sub(r'\s*```$', '', text, flags=re.MULTILINE)
        return text.strip()

    # ================= PHASE 0: STATIC TABLE TRIAGE (New Logic) =================
    def find_latest_llm_samples(self):
        """ Find the latest llm_samples_v3_4_*.json file """
        pattern = os.path.join(self.log_dir, "llm_samples_v3_4_*.json")
        list_of_files = glob.glob(pattern)
        if not list_of_files:
            return None
        return max(list_of_files, key=os.path.getctime)

    def run_static_table_filtering(self):
        """
        Read LLM Samples file, let LLM filter static tables and determine parent nodes.
        """
        self.log("\n=== PHASE 0: STATIC TABLE TRIAGE (LLM Filtering) ===")
        
        sample_file = self.find_latest_llm_samples()
        if not sample_file:
            self.log("[-] No 'llm_samples' file found. Skipping Phase 0.")
            return

        self.log(f"[*] Loading samples from: {sample_file}")
        try:
            with open(sample_file, 'r', encoding='utf-8') as f:
                payload = json.load(f)
            
            candidates = payload.get("candidates", [])
            if not candidates:
                self.log("[-] Sample file is empty. Skipping.")
                return
                
            # Build Prompt
            prompt = """
You are a Firmware Data Analyst. I will provide a list of "Candidate Memory Tables" found in a router's firmware.
Each candidate contains a "samples" list (first 5 entries).

**IMPORTANT**: Candidates may be of different types:
- **STATIC_ADAPTIVE**: Traditional [String, Handler] pairs
- **MIXED_TABLE**: String key + Multiple function handlers (e.g., ["ipgroup", clear_func, set_func, show_func])

**YOUR JOB**: Analyze the samples to determine if the table is a valid **HTTP Route/Action/Resource Table**.

**STEP 1: CLASSIFY**
1. `STANDARD_PATH`: Standard URL paths (contains `/` or `.ext`, e.g., `index.asp`).
2. `ACTION_MAP`: Function/Action mapping.
   - CamelCase verbs (e.g., `SetNetwork`, `Login`) -> Common in D-Link/HNAP.
   - snake_case keywords (e.g., `http_passwd`, `lan_ipaddr`, `wl_radio`) -> Common in GoAhead/GoForm.
3. `RESOURCE_MAP`: Resource identifiers with CRUD operations (for MIXED_TABLE).
   - Examples: `ipgroup`, `macfilter`, `urlfilter`, `qosrule`
   - Pattern: String key + multiple handlers (clear/set/show operations)
4. `NOISE`: 
   - Internal System Bindings (Specifically starting with `nvram_match`, `gpio_`, `mfcp_`).
   - MIME Types (e.g., `text/html`, `image/gif`).
   - Pure error messages.

**STEP 2: PARENT HINT**
- CamelCase Actions -> Hint: `/HNAP1`
- snake_case Actions (GoForm style) -> Hint: `/goform`
- Resource Map (MIXED_TABLE) -> Hint: `/resource` or analyze dispatcher_candidates
- UPnP style -> Hint: `/upnp/control`
- MIME Types or Noise -> Hint: `null`

**STEP 3: DISPATCHER ANALYSIS (for MIXED_TABLE)**
If `dispatcher_candidates` is provided, check function names for path hints:
- `sub_A8724` calling table -> likely a generic dispatcher
- `hnap_handler` -> hint `/HNAP1`
- `cgi_dispatcher` -> hint `/cgi-bin`

**INPUT DATA:**
"""
            prompt += json.dumps(candidates, indent=2)
            prompt += """
\n**OUTPUT FORMAT (Strict JSON):**
{
    "decisions": [
        {
            "id": "0x5acc0", 
            "verdict": "KEEP", 
            "class": "STANDARD_PATH", 
            "parent_hint": null,
            "reason": "Contains .asp paths"
        },
        {
            "id": "0x588d80", 
            "verdict": "KEEP", 
            "class": "ACTION_MAP", 
            "parent_hint": "/HNAP1",
            "reason": "HNAP style actions"
        },
        {
            "id": "0x5b320", 
            "verdict": "DISCARD", 
            "class": "NOISE", 
            "parent_hint": null,
            "reason": "NVRAM bindings"
        }
    ]
}
"""
            self.log(f"[*] Sending {len(candidates)} tables to LLM for triage...")
            
            response = self.llm.chat([{"role": "user", "content": prompt}], json_mode=True)
            
            # Parse response
            data = {}
            if isinstance(response, dict): data = response
            else: data = json.loads(self.clean_json_block(response))
            
            decisions = data.get("decisions", [])
            keep_count = 0
            
            for d in decisions:
                if d.get("verdict") == "KEEP":
                    addr = d.get("id")
                    self.static_table_whitelist[addr] = {
                        "class": d.get("class"),
                        "parent_hint": d.get("parent_hint"),
                        "reason": d.get("reason")
                    }
                    keep_count += 1
                    self.log(f"    [KEEP] {addr} ({d.get('class')}) Hint: {d.get('parent_hint')}")
                else:
                    self.log(f"    [DROP] {d.get('id')} ({d.get('reason')})")
            
            self.log(f"[+] Phase 0 Complete. Kept {keep_count}/{len(candidates)} tables.")

        except Exception as e:
            self.log(f"[-] Phase 0 Failed: {e}")
            traceback.print_exc()

    # ================= PHASE 1: API TRIAGE =================
    def run_phase_1_triage(self):
        """
        [Existing Logic] Identify Potential APIs
        """
        self.log("\n=== PHASE 1: API IDENTIFICATION (Snippets Analysis) ===")
        
        apis = self.static_scan_data.get("potential_apis", [])
        if not apis:
            self.log("[-] No Potential APIs found. Skipping.")
            return

        prompt_content = """
You are an expert Reverse Engineer. Classify these APIs.
ROLES:
1. `ROUTE_REGISTER`: func("string", &func_ptr). CRITICAL.
2. `INPUT_ACCESS`: Reading request vars.
3. `OTHER`: Logging, Memory, etc.

**TASK 2(Companion Discovery):**
If analyzing a `ROUTE_REGISTER` candidate, look deeply into its code snippet.
If you see **OTHER functions** being called in a "Registration" pattern (string + func_ptr) inside the snippet:
- EXTRACT them as `SECONDARY_REGISTER`.

**INPUT DATA:**
"""
        api_payload = []
        limit = 45 
        for api in apis[:limit]: 
            snippets = api.get("usage_snippets", [])
            snippet = snippets[0].get("code", "No code") if snippets else "No code"
            snippet = snippet[:600] 
            api_payload.append({
                "address": api["address"],
                "name": api["name"],
                "call_count": api["count"],
                "usage_snippet": snippet
            })
        
        prompt_content += json.dumps(api_payload, indent=2)
        prompt_content += """\n**OUTPUT FORMAT (JSON):**\n{"0xAddr": {"role": "ROUTE_REGISTER", "reason": "..."}}"""
        
        try:
            response = self.llm.chat([{"role": "user", "content": prompt_content}], json_mode=True)
            
            if isinstance(response, dict): self.api_knowledge = response
            else: self.api_knowledge = json.loads(self.clean_json_block(response))

            if not self.api_knowledge: return
            
            # Save debug info
            with open(self.api_know_file, "w") as f:
                json.dump(self.api_knowledge, f, indent=2)
                
            for addr, info in self.api_knowledge.items():
                if info.get("role") in ["ROUTE_REGISTER", "SECONDARY_REGISTER"]:
                    self.log(f"    [TARGET] {addr} -> {info['role']}")
                    
        except Exception as e:
            self.log(f"[-] Phase 1 Failed: {e}")

    # ================= CORE HELPERS & INGESTION =================
    
    # [Restored Robust System Prompt]
    def system_prompt(self):
        return """
You are "Hunter", a Firmware Data Harvester.
**MISSION**: Extract all potential routing data (Static Tables & Dynamic Registrations) and SAVE them to disk.
**DO NOT ANALYZE CONTEXT. DO NOT FIX ROOTS.**

### STANDARD OPERATING PROCEDURE

1. **PHASE 1: STATIC (Auto-Handled)**
   - The system has already scanned for Static Tables. 
   - If you see `[DETECTED STATIC TABLES]` in the report, simply acknowledge them. Do NOT try to extract them again.

2. **PHASE 2: DYNAMIC (Batch Scan)**
   - Check `[API INTELLIGENCE]` in the report.
   - If you see `ROUTE_REGISTER` APIs (e.g., `sub_171ec`), YOUR ONLY GOAL is to call `batch_scan_hubs`.
   - **Call `batch_scan_hubs` with the list of identified addresses.**
   - Once called, your job is done. The tool handles the rest.

### TOOLKIT
- `batch_scan_hubs(api_addresses=["hex", "hex"])`: 
  Scans the provided APIs for route registrations and SAVES them to `routes_v3_latest.json`.
  *Example:* `batch_scan_hubs(api_addresses=["0x402df4", "0x40a990"])`
  
- `report_discovery(root="/", handler="sub_xxx")`:
  Manually save a route if you find one in text.

### OUTPUT FORMAT
{
    "thought": "I see Register APIs 0x402df4 and 0x40a990. I will run the batch scan.",
    "action": { "tool": "batch_scan_hubs", "args": { "api_addresses": ["0x402df4", "0x40a990"] } }
}
"""

    def _ingest_static_data(self, memory_structures):
        """
        [Modified V3.7] Import LLM-verified static tables (including mixed tables)
        """
        import os, json
        
        # Separate different types of tables
        static_tables = [s for s in memory_structures if s['type'] == 'STATIC_ADAPTIVE']
        mixed_tables = [s for s in memory_structures if s['type'] == 'MIXED_TABLE']
        
        total_tables = len(static_tables) + len(mixed_tables)
        if total_tables == 0:
            return 0

        self.log(f"[*] Ingesting tables: {len(static_tables)} static, {len(mixed_tables)} mixed...")
        
        new_routes = []
        filtered_count = 0
        
        # Process traditional static tables
        for table in static_tables:
            table_addr = table['address']
            
            # === [FILTER] Whitelist Check ===
            if table_addr not in self.static_table_whitelist:
                filtered_count += 1
                continue
            
            # Get LLM-supplemented metadata
            meta = self.static_table_whitelist[table_addr]
            parent_hint = meta.get("parent_hint")
            table_class = meta.get("class")
            
            for entry in table.get('all_entries', []): 
                route_entry = {
                    "root": parent_hint if parent_hint else "Unknown",
                    "sub_path": entry.get('url'),
                    "full_path": entry.get('url'), 
                    "handler": entry.get('handler'),
                    "mode": "static_scan_llm_verified", 
                    "source_hub": table_addr,
                    "source_type": "static_table",
                    "table_class": table_class 
                }
                new_routes.append(route_entry)
        
        # Process mixed function pointer tables
        for table in mixed_tables:
            table_addr = table['address']
            
            # === [FILTER] Whitelist Check ===
            if table_addr not in self.static_table_whitelist:
                filtered_count += 1
                continue
            
            # Get LLM-supplemented metadata
            meta = self.static_table_whitelist[table_addr]
            parent_hint = meta.get("parent_hint", "Unknown")
            table_class = meta.get("class")
            
            # Each entry in mixed table contains: key + handlers[]
            for entry in table.get('entries', []):
                key = entry.get('key')
                handlers = entry.get('handlers', [])
                
                # Create route entry for each handler (or aggregate into a multi-handler entry)
                # Strategy 1: Aggregation mode (recommended, preserves resource+action semantics)
                route_entry = {
                    "root": parent_hint,
                    "sub_path": key,  # Resource name: ipgroup, macfilter, etc.
                    "full_path": f"{parent_hint}/{key}" if parent_hint != "Unknown" else key,
                    "handlers": {  # Multiple operations correspond to different handlers
                        f"handler_{i}": h['address'] for i, h in enumerate(handlers)
                    },
                    "mode": "mixed_table_multi_action",
                    "source_hub": table_addr,
                    "source_type": "mixed_table",
                    "pattern": table.get('pattern'),
                    "table_class": table_class
                }
                new_routes.append(route_entry)

        if filtered_count > 0:
            self.log(f"[-] Filtered out {filtered_count} noise tables based on LLM decision.")

        return self._save_routes_to_disk(new_routes)

    def _save_routes_to_disk(self, new_entries):
        import os, json
        filename = os.path.join(self.out_dir, "routes_v3_latest.json")
        
        existing_data = []
        if os.path.exists(filename):
            try:
                with open(filename, 'r') as f: existing_data = json.load(f)
            except: existing_data = []

        existing_fingerprints = set()
        for item in existing_data:
            h = str(item.get("source_hub", "")).lower().replace("0x", "")
            p = str(item.get("sub_path", ""))
            existing_fingerprints.add((h, p))

        added_count = 0
        for entry in new_entries:
            h = str(entry.get("source_hub", "")).lower().replace("0x", "")
            p = str(entry.get("sub_path", ""))
            
            if (h, p) not in existing_fingerprints:
                existing_data.append(entry)
                existing_fingerprints.add((h, p))
                added_count += 1
        
        if added_count > 0:
            with open(filename, 'w') as f:
                json.dump(existing_data, f, indent=4)
            return added_count
        return 0
    
    def get_initial_context(self):
        self.log("[*] Requesting Static Scan Data...")
        local_log_path = os.path.abspath(self.log_dir)
        scan_res = self.ida._send("run_static_scan", {"output_dir": local_log_path})
        
        if scan_res.get("status") != "ok": return "Static Analysis Failed."
        
        self.static_scan_data = scan_res.get("data", {})
        
        # === Step 1: LLM Filter Static Tables (Phase 0) ===
        self.run_static_table_filtering()
        
        # === Step 2: Ingest Verified Tables ===
        added = self._ingest_static_data(self.static_scan_data.get("memory_structures", []))
        if added > 0:
            self.log(f"[+] Archived {added} verified static routes to disk.")
            
        # === Step 3: Identify Dynamic APIs (Phase 1) ===
        self.run_phase_1_triage()
        
        # === Step 4: Generate Report ===
        report = []
        report.append("### INTELLIGENCE REPORT ###")
        
        # Report APIs
        registers = []
        for addr, info in self.api_knowledge.items():
            if info.get("role") in ["ROUTE_REGISTER", "SECONDARY_REGISTER"]:
                registers.append(f"{addr} ({info.get('reason')})")
        
        if registers:
            report.append(f"\n[API INTELLIGENCE] (High Confidence)")
            report.append(f"Identified ROUTE_REGISTER APIs: {', '.join(registers)}")
            report.append(f" -> ACTION: Call `batch_scan_hubs`.")
        else:
            report.append("\n[API INTELLIGENCE] No dynamic registration APIs found.")

        # Report Static Tables (Verified Only)
        verified_tables = len(self.static_table_whitelist)
        if verified_tables > 0:
            report.append(f"\n[STATIC TABLES] {verified_tables} tables verified and saved.")

        return "\n".join(report)

    # ================= TOOL EXECUTION (Restored Full Tools) =================
    def execute_tool(self, name, args):
        try:
            # [New Tool V3] Batch Scan
            if name == "batch_scan_hubs":
                return self.tool_batch_scan(args.get("api_addresses", []))
            
            # [Restored Tool] Scan Static Table
            if name == "scan_static_table":
                res = self.ida.scan_static_table(**args)
                if res.get("status") == "ok":
                    data = res.get("data", [])
                    table_addr = args.get("address")
                    new_routes = []
                    for entry in data:
                        if "url" in entry and ("handler" in entry or "handler_addr" in entry):
                            new_routes.append({
                                "root": "Unknown",
                                "sub_path": entry.get("url"),
                                "full_path": entry.get("url"),
                                "handler": entry.get("handler") or entry.get("handler_addr"),
                                "mode": "manual_static_tool",
                                "source_hub": table_addr,
                                "source_type": "static_table"
                            })
                    if new_routes:
                        count = self._save_routes_to_disk(new_routes)
                        return {
                            "status": "ok",
                            "msg": f"Scanned table at {table_addr}. Found {len(data)} entries. {count} NEW routes auto-saved.",
                            "entries_preview": data[:5]
                        }
                return res
            
            # [Restored Tool] Report Discovery (Manual Save)
            if name == "report_discovery":
                return self.tool_report_discovery(args)

            # [Restored Tool] Analyze Handler
            if name == "analyze_handler":
                res = self.ida.decompile(args.get("address"))
                if res.get("status") != "ok": return res
                code = res.get("data", {}).get("code", "")
                return {
                    "status": "ok", 
                    "code_snippet": code[:2000] + "..." if len(code)>2000 else code
                }

            # Standard Forwarding
            method = getattr(self.ida, name, None)
            if method: return method(**args) if args else method()
            if hasattr(self.ida, "_send"): return self.ida._send(name, args)

            return {"status": "error", "error": f"Unknown tool: {name}"}

        except Exception as e:
            return {"status": "error", "error": f"Tool execution failed: {str(e)}"}
    
    def tool_batch_scan(self, target_apis):
        """
        Stage 1: Dynamic Hub Scan
        """
        if not target_apis: return {"status": "error", "msg": "No APIs."}

        self.log(f"[*] Batch Scan for APIs: {target_apis}")
        targets = [t.lower() for t in target_apis]
        extracted_routes_buffer = [] 

        hubs = self.static_scan_data.get("memory_structures", [])
        
        for hub in hubs:
            if hub.get("type") != "REGISTRATION_HUB": continue
            
            traces = hub.get("raw_call_traces", [])
            for trace in traces:
                # [Fix] Add None filtering, ensure it's a string before calling lower()
                raw_callee = trace.get("callee_addr")
                if not raw_callee:
                    continue
                callee = str(raw_callee).lower()
                
                if callee in targets:
                    args = trace.get("args", [])
                    url = None; handler = None
                    for arg in args:
                        if arg.get("type") == "string" and not url: url = arg.get("val")
                        elif arg.get("type") == "obj" and not handler: handler = arg.get("val")
                    
                    if url and handler:
                        extracted_routes_buffer.append({
                            "root": "Unknown", 
                            "sub_path": url,
                            "full_path": url,
                            "handler": handler,
                            "mode": "batch_extracted",
                            "source_hub": hub["address"],
                            "source_api": callee
                        })

        saved_count = 0
        if extracted_routes_buffer:
            saved_count = self._save_routes_to_disk(extracted_routes_buffer)
        
        self.scan_completed = True
        return f"[MISSION COMPLETE] Batch scan saved {saved_count} new routes."

    def tool_report_discovery(self, args):
        """
        [Restored Tool] Manual Discovery with Instant Persistence
        """
        root = args.get("root")
        handler = args.get("handler")
        if "FINISHED" in str(root): return {"status": "ok", "msg": "Completion signaled."}

        self.knowledge_graph.append(args)
        self.log(f"[+] Route Saved (Memory): {root} -> {handler}")

        try:
            import os, json
            filename = os.path.join(self.out_dir, "routes_v3_latest.json")
            existing_data = []
            if os.path.exists(filename):
                try:
                    with open(filename, 'r') as f: existing_data = json.load(f)
                except: existing_data = []

            is_duplicate = False
            for entry in existing_data:
                if str(entry.get("root")) == str(root) and str(entry.get("handler")).lower() == str(handler).lower():
                    is_duplicate = True; break
            
            if not is_duplicate:
                if "mode" not in args: args["mode"] = "manual_discovery"
                existing_data.append(args)
                with open(filename, 'w') as f: json.dump(existing_data, f, indent=4)
                return {"status": "ok", "msg": f"Route '{root}' saved to disk."}
            else:
                return {"status": "ok", "msg": f"Route '{root}' already exists (Skipped)."}
        except Exception as e:
            return {"status": "warning", "msg": f"Disk write failed: {str(e)}"}

    # ================= MAIN LOOP (Restored Full Logic) =================
    def step_llm(self):
        response_raw = self.llm.chat(self.history, json_mode=False)
        if not response_raw: return False

        try:
            response_clean = self.clean_json_block(response_raw)
            response_json = json.loads(response_clean)
        except:
            self.history.append({"role": "user", "content": "Error: Output valid JSON."})
            return True

        thought = response_json.get("thought", "")
        action = response_json.get("action")
        self.log(f"**Brain**: {thought}")

        if not isinstance(action, dict):
            return True

        tool_name = action.get("tool")
        args = action.get("args", {})
        
        if tool_name:
            self.log(f"**Action**: `{tool_name}` Args: `{json.dumps(args)}`")
            result = self.execute_tool(tool_name, args)
            
            res_str = json.dumps(result)
            if len(res_str) > 500: res_str = res_str[:500] + "... (truncated)"
            self.log(f"**Observation**: {res_str}")

            if tool_name == "batch_scan_hubs":
                self.log("[*] Batch scan executed. Stage 1 Extraction Complete.")
                return False 
            
            self.history.append({"role": "assistant", "content": response_clean})
            self.history.append({"role": "user", "content": f"Tool Output: {result}"})
            return True
        return True

    def run_automated_rescue(self):
        if self.scan_completed: return
        targets = []
        for addr, info in self.api_knowledge.items():
            if info.get("role") in ["ROUTE_REGISTER", "SECONDARY_REGISTER"]:
                targets.append(addr)
        if targets:
            self.log(f"[!] Rescue: Force scanning {targets}")
            self.tool_batch_scan(targets)

    def run(self):
        if not self.ida.connect(): return
        self.log("\n=== AGENT START ===")
        self.history = [{"role": "system", "content": self.system_prompt()}]
        ctx = self.get_initial_context()
        self.log(f"[*] Context:\n{ctx}")
        self.history.append({"role": "user", "content": f"Start harvesting:\n{ctx}"})
        
        step = 0
        try: 
            while step < self.max_steps:
                step += 1
                self.log(f"\n## Step {step}")
                if not self.step_llm(): break
        except Exception as e:
            traceback.print_exc()
        
        self.run_automated_rescue()
        self.log("[*] Analysis Complete.")

if __name__ == "__main__":
    agent = RouteHunterAgentV3()
    agent.run()