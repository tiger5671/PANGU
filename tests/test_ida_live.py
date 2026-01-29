# tests/test_ida_live.py
# PANGU Real IDA Connection Test
# Module-by-module testing for easier debugging

import sys
import os
import json
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.bridge.ida_client import IDAProClient


class IDALiveTester:
    """IDA Pro Live Tester"""
    
    def __init__(self, host="localhost", port=18811):
        self.host = host
        self.port = port
        self.ida = None
        self.test_results = {}
    
    def banner(self, text):
        print("\n" + "=" * 60)
        print(f" {text}")
        print("=" * 60)
    
    def success(self, msg):
        print(f"  [OK] {msg}")
    
    def fail(self, msg):
        print(f"  [FAIL] {msg}")
    
    def info(self, msg):
        print(f"  [*] {msg}")
    
    def wait_input(self, prompt="Press Enter to continue, enter 'q' to quit: "):
        resp = input(prompt)
        if resp.lower() == 'q':
            print("\nTest aborted")
            sys.exit(0)
        return resp

    # ====================== Module 1: Basic Connection ======================
    
    def test_module1_connection(self):
        """Module 1: Test basic connection"""
        self.banner("Module 1: Basic Connection Test")
        
        self.ida = IDAProClient(self.host, self.port)
        
        # Test 1.0: Connection
        self.info("Test 1.0: Establishing connection...")
        try:
            if self.ida.connect():
                self.success("Connection successful")
            else:
                self.fail("Connection failed")
                return False
        except Exception as e:
            self.fail(f"Connection exception: {e}")
            return False
        
        # Test 1.1: Ping
        self.info("Test 1.1: Ping...")
        try:
            result = self.ida.ping()
            if result.get("status") == "ok":
                self.success(f"Ping successful: {result}")
                self.test_results["ping"] = True
            else:
                self.fail(f"Ping failed: {result}")
                self.test_results["ping"] = False
                return False
        except Exception as e:
            self.fail(f"Ping exception: {e}")
            self.test_results["ping"] = False
            return False
        
        # Test 1.2: Get status
        self.info("Test 1.2: Getting server status...")
        try:
            result = self.ida.get_status()
            if result.get("status") == "ok":
                data = result.get("data", {})
                self.success(f"Status retrieved successfully")
                self.info(f"  Binary: {data.get('binary_name', 'N/A')}")
                self.info(f"  Functions: {data.get('function_count', 'N/A')}")
                self.info(f"  Segments: {data.get('segment_count', 'N/A')}")
                self.test_results["status"] = True
            else:
                self.fail(f"Status retrieval failed: {result}")
                self.test_results["status"] = False
        except Exception as e:
            self.fail(f"Status retrieval exception: {e}")
            self.test_results["status"] = False
        
        return self.test_results.get("ping", False)

    # ====================== Module 2: Basic Read ======================
    
    def test_module2_basic_read(self):
        """Module 2: Test basic read functionality"""
        self.banner("Module 2: Basic Read Test")
        
        # Test 2.1: Get function list
        self.info("Test 2.1: Getting function list...")
        try:
            result = self.ida.get_functions()
            if result.get("status") == "ok":
                funcs = result.get("data", [])
                self.success(f"Retrieved {len(funcs)} functions")
                if funcs:
                    # Display first 5
                    for f in funcs[:5]:
                        self.info(f"  {f.get('address', 'N/A')}: {f.get('name', 'N/A')}")
                    if len(funcs) > 5:
                        self.info(f"  ... {len(funcs)-5} more functions")
                self.test_results["functions"] = funcs
            else:
                self.fail(f"Failed to get functions: {result.get('error')}")
        except Exception as e:
            self.fail(f"Get functions exception: {e}")
        
        # Test 2.2: Get segment info
        self.info("Test 2.2: Getting segment info...")
        try:
            result = self.ida.get_segments()
            if result.get("status") == "ok":
                segs = result.get("data", [])
                self.success(f"Retrieved {len(segs)} segments")
                for s in segs:
                    self.info(f"  {s.get('name', 'N/A')}: {s.get('start', 'N/A')} - {s.get('end', 'N/A')}")
                self.test_results["segments"] = segs
            else:
                self.fail(f"Failed to get segments: {result.get('error')}")
        except Exception as e:
            self.fail(f"Get segments exception: {e}")
        
        # Test 2.3: String search
        self.info("Test 2.3: String search (searching 'http')...")
        try:
            result = self.ida.search_strings("http")
            if result.get("status") == "ok":
                strings = result.get("data", [])
                self.success(f"Found {len(strings)} matching strings")
                for s in strings[:10]:
                    self.info(f"  {s.get('address', 'N/A')}: {s.get('value', 'N/A')[:50]}")
                if len(strings) > 10:
                    self.info(f"  ... {len(strings)-10} more")
                self.test_results["strings_http"] = strings
            else:
                self.fail(f"String search failed: {result.get('error')}")
        except Exception as e:
            self.fail(f"String search exception: {e}")
        
        return True

    # ====================== Module 3: Decompile ======================
    
    def test_module3_decompile(self, func_addr=None):
        """Module 3: Test decompilation functionality"""
        self.banner("Module 3: Decompilation Test")
        
        # If no address specified, let user choose or use first function
        if func_addr is None:
            funcs = self.test_results.get("functions", [])
            if funcs:
                self.info("Available test functions:")
                for i, f in enumerate(funcs[:10]):
                    self.info(f"  [{i}] {f.get('address')}: {f.get('name')}")
                
                choice = self.wait_input("Enter function number (default 0), or enter address: ")
                if choice.startswith("0x"):
                    func_addr = choice
                elif choice.isdigit():
                    idx = int(choice)
                    if idx < len(funcs):
                        func_addr = funcs[idx].get("address")
                else:
                    func_addr = funcs[0].get("address") if funcs else None
            
            if not func_addr:
                self.fail("No function available for testing")
                return False
        
        self.info(f"Test 3.1: Decompiling function {func_addr}...")
        try:
            result = self.ida.decompile(func_addr)
            if result.get("status") == "ok":
                data = result.get("data", {})
                pseudocode = data.get("code", data.get("pseudocode", ""))
                self.success(f"Decompilation successful ({len(pseudocode)} chars)")
                # Display first 10 lines
                lines = pseudocode.split('\n')[:10]
                for line in lines:
                    print(f"    {line}")
                if len(pseudocode.split('\n')) > 10:
                    self.info(f"  ... more code")
                self.test_results["decompile"] = data
            else:
                self.fail(f"Decompilation failed: {result.get('error')}")
        except Exception as e:
            self.fail(f"Decompilation exception: {e}")
        
        return True

    # ====================== Module 4: Static Scan ======================
    
    def test_module4_static_scan(self):
        """Module 4: Test static route scanning"""
        self.banner("Module 4: Static Route Scan Test")
        
        # Test 4.1: Basic static scan
        self.info("Test 4.1: Running static scan (may take some time)...")
        try:
            result = self.ida.run_static_scan()
            if result.get("status") == "ok":
                data = result.get("data", {})
                mem_structs = data.get("memory_structures", [])
                self.success(f"Scan complete, found {len(mem_structs)} memory structures")
                
                # Categorize display
                static_tables = [s for s in mem_structs if s.get('type') in ['STATIC_ADAPTIVE', 'MIXED_TABLE']]
                reg_hubs = [s for s in mem_structs if s.get('type') == 'REGISTRATION_HUB']
                
                self.info(f"  Static tables: {len(static_tables)}")
                self.info(f"  Registration hubs: {len(reg_hubs)}")
                
                # Display details
                for t in static_tables[:3]:
                    entries = t.get('all_entries', t.get('entries', []))
                    self.info(f"    Table {t.get('address')}: {len(entries)} entries")
                    for e in entries[:3]:
                        if 'url' in e:
                            self.info(f"      - {e.get('url')} -> {e.get('handler')}")
                        elif 'key' in e:
                            self.info(f"      - {e.get('key')} -> {len(e.get('handlers',[]))} handlers")
                
                self.test_results["static_scan"] = data
            else:
                self.fail(f"Static scan failed: {result.get('error')}")
        except Exception as e:
            self.fail(f"Static scan exception: {e}")
            import traceback
            traceback.print_exc()
        
        return True

    # ====================== Module 5: Enhanced Scan ======================
    
    def test_module5_enhanced_scan(self):
        """Module 5: Test enhanced static scanning"""
        self.banner("Module 5: Enhanced Static Scan Test")
        
        self.info("Test 5.1: Running enhanced scan...")
        try:
            result = self.ida.run_enhanced_scan(scan_type="all", min_entries=3)
            if result.get("status") == "ok":
                data = result.get("data", {})
                sh_tables = data.get("string_handler_tables", [])
                mixed_tables = data.get("mixed_tables", [])
                total = data.get("total_routes", 0)
                
                self.success(f"Enhanced scan complete")
                self.info(f"  String-Handler tables: {len(sh_tables)}")
                self.info(f"  Mixed tables: {len(mixed_tables)}")
                self.info(f"  Total routes: {total}")
                
                # Display details
                for t in sh_tables[:2]:
                    self.info(f"    Table {t.get('address')}: {t.get('entry_count')} entries, type: {t.get('dominant_class')}")
                    for e in t.get('all_entries', [])[:3]:
                        self.info(f"      - {e.get('url')} -> {e.get('handler')}")
                
                self.test_results["enhanced_scan"] = data
            else:
                self.fail(f"Enhanced scan failed: {result.get('error')}")
                if "traceback" in result:
                    print(result["traceback"])
        except Exception as e:
            self.fail(f"Enhanced scan exception: {e}")
            import traceback
            traceback.print_exc()
        
        return True

    # ====================== Module 6: CFG Analysis ======================
    
    def test_module6_cfg_analysis(self, func_addr=None):
        """Module 6: Test CFG analysis functionality"""
        self.banner("Module 6: CFG Analysis Test")
        
        # Select function
        if func_addr is None:
            funcs = self.test_results.get("functions", [])
            if funcs:
                # Prefer meaningful functions (not too small)
                good_funcs = [f for f in funcs if f.get('size', 0) > 100][:10]
                if not good_funcs:
                    good_funcs = funcs[:10]
                
                self.info("Select a function for CFG analysis:")
                for i, f in enumerate(good_funcs):
                    self.info(f"  [{i}] {f.get('address')}: {f.get('name')} (size: {f.get('size', 'N/A')})")
                
                choice = self.wait_input("Enter function number (default 0): ")
                if choice.isdigit() and int(choice) < len(good_funcs):
                    func_addr = good_funcs[int(choice)].get("address")
                else:
                    func_addr = good_funcs[0].get("address")
        
        if not func_addr:
            self.fail("No function available for testing")
            return False
        
        # Test 6.1: Get basic blocks
        self.info(f"Test 6.1: Getting basic blocks ({func_addr})...")
        try:
            result = self.ida.get_basic_blocks(func_addr)
            if result.get("status") == "ok":
                blocks = result.get("data", [])
                self.success(f"Retrieved {len(blocks)} basic blocks")
                for b in blocks[:5]:
                    self.info(f"  Block {b.get('id')}: {b.get('start')} - {b.get('end')}")
                self.test_results["basic_blocks"] = blocks
            else:
                self.fail(f"Failed to get basic blocks: {result.get('error')}")
        except Exception as e:
            self.fail(f"Get basic blocks exception: {e}")
        
        # Test 6.2: Build dominator tree
        self.info(f"Test 6.2: Building dominator tree...")
        try:
            result = self.ida.build_dominator_tree(func_addr)
            if result.get("status") == "ok":
                dom_tree = result.get("data", {})
                self.success(f"Dominator tree built successfully ({len(dom_tree)} nodes)")
                self.test_results["dominator_tree"] = dom_tree
            else:
                self.fail(f"Dominator tree build failed: {result.get('error')}")
        except Exception as e:
            self.fail(f"Dominator tree build exception: {e}")
        
        # Test 6.3: TIS calculation
        self.info(f"Test 6.3: Calculating TIS...")
        try:
            result = self.ida.calculate_tis(func_addr)
            if result.get("status") == "ok":
                tis_data = result.get("data", [])
                self.success(f"TIS calculation complete ({len(tis_data)} if statements)")
                for t in tis_data[:5]:
                    self.info(f"  {t.get('address')}: TIS={t.get('tis'):.2f}, pattern={t.get('pattern')}")
                self.test_results["tis"] = tis_data
            else:
                self.fail(f"TIS calculation failed: {result.get('error')}")
        except Exception as e:
            self.fail(f"TIS calculation exception: {e}")
        
        return True

    # ====================== Module 7: Handler Analysis ======================
    
    def test_module7_handler_analysis(self, handler_addr=None):
        """Module 7: Test handler analysis functionality"""
        self.banner("Module 7: Handler Analysis Test")
        
        # Get handler from static scan results
        if handler_addr is None:
            scan_data = self.test_results.get("static_scan", {})
            mem_structs = scan_data.get("memory_structures", [])
            
            handlers = []
            for s in mem_structs:
                if s.get('type') == 'STATIC_ADAPTIVE':
                    for e in s.get('all_entries', []):
                        if e.get('handler'):
                            handlers.append({
                                "address": e.get('handler'),
                                "url": e.get('url', 'N/A')
                            })
            
            if handlers:
                self.info("Select a handler for analysis:")
                for i, h in enumerate(handlers[:10]):
                    self.info(f"  [{i}] {h['address']}: {h['url']}")
                
                choice = self.wait_input("Enter number (default 0): ")
                if choice.isdigit() and int(choice) < len(handlers):
                    handler_addr = handlers[int(choice)]["address"]
                else:
                    handler_addr = handlers[0]["address"]
            else:
                self.fail("No handler found, please run static scan first")
                return False
        
        # Test 7.1: Get handler info
        self.info(f"Test 7.1: Getting handler info ({handler_addr})...")
        try:
            result = self.ida.get_handler_info(handler_addr)
            if result.get("status") == "ok":
                data = result.get("data", {})
                self.success(f"Handler info retrieved successfully")
                self.info(f"  Name: {data.get('name')}")
                self.info(f"  Size: {data.get('size')}")
                self.info(f"  Calls: {len(data.get('calls', []))}")
                self.info(f"  Strings: {len(data.get('strings', []))}")
                self.info(f"  Dangerous: {data.get('dangerous_calls', [])}")
                self.info(f"  Auth-related: {data.get('auth_related', [])}")
                self.test_results["handler_info"] = data
            else:
                self.fail(f"Failed to get handler info: {result.get('error')}")
        except Exception as e:
            self.fail(f"Get handler info exception: {e}")
        
        # Test 7.2: Scan authentication patterns
        self.info(f"Test 7.2: Scanning authentication patterns...")
        try:
            result = self.ida.scan_auth_patterns(handler_addr)
            if result.get("status") == "ok":
                data = result.get("data", {})
                self.success(f"Authentication pattern scan complete")
                self.info(f"  Auth calls: {data.get('auth_calls', [])}")
                self.info(f"  Auth strings: {data.get('auth_strings', [])[:5]}")
                self.info(f"  Blocking checks: {len(data.get('blocking_checks', []))}")
                self.test_results["auth_patterns"] = data
            else:
                self.fail(f"Authentication pattern scan failed: {result.get('error')}")
        except Exception as e:
            self.fail(f"Authentication pattern scan exception: {e}")
        
        return True

    # ====================== Complete Flow ======================
    
    def run_all_tests(self):
        """Run all tests"""
        self.banner("PANGU IDA Pro Live Test")
        print(f"Target server: {self.host}:{self.port}")
        print("Will test module by module, pausing after each module for confirmation")
        self.wait_input()
        
        # Module 1: Basic connection
        if not self.test_module1_connection():
            self.fail("Connection test failed, cannot continue")
            return
        self.wait_input()
        
        # Module 2: Basic read
        self.test_module2_basic_read()
        self.wait_input()
        
        # Module 3: Decompile
        self.test_module3_decompile()
        self.wait_input()
        
        # Module 4: Static scan
        self.test_module4_static_scan()
        self.wait_input()
        
        # Module 5: Enhanced scan
        self.test_module5_enhanced_scan()
        self.wait_input()
        
        # Module 6: CFG analysis
        self.test_module6_cfg_analysis()
        self.wait_input()
        
        # Module 7: Handler analysis
        self.test_module7_handler_analysis()
        
        # Summary
        self.banner("Test Summary")
        print(f"Completed tests: {len(self.test_results)}")
        for name, result in self.test_results.items():
            if isinstance(result, bool):
                status = "OK" if result else "FAIL"
            elif isinstance(result, list):
                status = f"OK ({len(result)} items)"
            elif isinstance(result, dict):
                status = f"OK (dict)"
            else:
                status = "OK"
            print(f"  {name}: {status}")

    def run_single_test(self, module_num):
        """Run a single test module"""
        if not self.ida:
            self.ida = IDAProClient(self.host, self.port)
            # Test connection first
            if not self.test_module1_connection():
                return
        
        test_map = {
            1: self.test_module1_connection,
            2: self.test_module2_basic_read,
            3: self.test_module3_decompile,
            4: self.test_module4_static_scan,
            5: self.test_module5_enhanced_scan,
            6: self.test_module6_cfg_analysis,
            7: self.test_module7_handler_analysis,
        }
        
        if module_num in test_map:
            test_map[module_num]()
        else:
            print(f"Unknown module number: {module_num}")
            print("Available modules: 1-7")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="PANGU IDA Pro Live Test")
    parser.add_argument("--host", default="localhost", help="IDA server address")
    parser.add_argument("--port", type=int, default=18811, help="IDA server port")
    parser.add_argument("--module", "-m", type=int, help="Test a specific module only (1-7)")
    parser.add_argument("--all", "-a", action="store_true", help="Run all tests")
    
    args = parser.parse_args()
    
    tester = IDALiveTester(args.host, args.port)
    
    if args.module:
        tester.run_single_test(args.module)
    elif args.all:
        tester.run_all_tests()
    else:
        # Interactive mode
        print("\nPANGU IDA Pro Live Test")
        print("=" * 40)
        print("Available modules:")
        print("  1. Basic connection test")
        print("  2. Basic read test")
        print("  3. Decompilation test")
        print("  4. Static route scan")
        print("  5. Enhanced static scan")
        print("  6. CFG analysis test")
        print("  7. Handler analysis")
        print("  a. Run all tests")
        print("  q. Quit")
        print()
        
        while True:
            choice = input("Select module (1-7, a, q): ").strip().lower()
            if choice == 'q':
                break
            elif choice == 'a':
                tester.run_all_tests()
            elif choice.isdigit():
                tester.run_single_test(int(choice))
            else:
                print("Invalid selection")


if __name__ == "__main__":
    main()
