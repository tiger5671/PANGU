# Copyright (c) 2026 The Pangu Project Authors. All rights reserved.
# core/bridge/cfg_analysis.py
# [CFG Analysis Module - Dominator Tree, TIS Calculation and other core algorithms]
# Called by ida_server.py

import idc
import idaapi
import idautils
import ida_funcs
import ida_gdl
import ida_bytes
from core.graph_analysis import ControlFlowGraph

try:
    import ida_hexrays
    HAS_HEXRAYS = ida_hexrays.init_hexrays_plugin()
except:
    HAS_HEXRAYS = False


class CFGAnalyzer:
    """Control Flow Graph Analyzer"""
    
    @staticmethod
    def get_basic_blocks(func_addr):
        """
        Get all basic blocks of a function
        Returns: [{"start": hex, "end": hex, "succs": [hex], "preds": [hex]}]
        """
        func = ida_funcs.get_func(func_addr)
        if not func:
            return []
        
        blocks = []
        flowchart = ida_gdl.FlowChart(func)
        
        for block in flowchart:
            block_info = {
                "id": block.id,
                "start": hex(block.start_ea),
                "end": hex(block.end_ea),
                "successors": [hex(succ.start_ea) for succ in block.succs()],
                "predecessors": [hex(pred.start_ea) for pred in block.preds()]
            }
            blocks.append(block_info)
        
        return blocks
    
    @staticmethod
    def build_dominator_tree(func_addr):
        """
        Build dominator tree
        Returns: {block_addr: immediate_dominator_addr}
        
        Dominance relation: If path from entry to B must go through A, then A dominates B
        """
        func = ida_funcs.get_func(func_addr)
        if not func:
            return {}
        
        flowchart = ida_gdl.FlowChart(func)
        blocks = list(flowchart)
        
        if not blocks:
            return {}
        
        return ControlFlowGraph(CFGAnalyzer.get_basic_blocks(func_addr),
                                hex(func.start_ea)).immediate_dominators()
    
    @staticmethod
    def _get_all_dominators(block_ea, dom_map):
        """Get all dominators of a block"""
        result = {block_ea}
        current = block_ea
        visited = set()
        
        while current in dom_map and current not in visited:
            visited.add(current)
            idom = dom_map[current]
            if idom == current:
                break
            result.add(idom)
            current = idom
        
        return result
    
    @staticmethod
    def _find_immediate_dominator(block_ea, dom_set, dom_map):
        """Find immediate dominator"""
        # Immediate dominator is the nearest one in the dominator set (dominates all other dominators)
        candidates = dom_set - {block_ea}
        if not candidates:
            return None
        
        for candidate in candidates:
            candidate_doms = CFGAnalyzer._get_all_dominators(candidate, dom_map)
            # If candidate dominates all other candidates, it is the immediate dominator
            if candidates <= candidate_doms:
                return candidate
        
        # Return any one (simplified handling)
        return min(candidates)
    
    @staticmethod
    def get_dominator_context(func_addr, target_addr):
        """
        Get dominator context of target address
        Returns all basic blocks that dominate the target address
        """
        dom_tree = CFGAnalyzer.build_dominator_tree(func_addr)
        
        target_hex = hex(target_addr)
        if target_hex not in dom_tree:
            # target_addr may not be block start, find block containing it
            func = ida_funcs.get_func(func_addr)
            if func:
                flowchart = ida_gdl.FlowChart(func)
                for block in flowchart:
                    if block.start_ea <= target_addr < block.end_ea:
                        target_hex = hex(block.start_ea)
                        break
        
        # Collect all dominators
        dominators = []
        current = target_hex
        visited = set()
        
        while current in dom_tree and current not in visited:
            visited.add(current)
            dominators.append(current)
            idom = dom_tree[current]
            if idom == current:
                break
            current = idom
        
        return dominators


class TISCalculator:
    """
    Terminating Imbalance Score (TIS) Calculator
    Paper formula: TIS(n) = max(|S_then|, |S_else|) / (min(|S_then|, |S_else|) + 1) * I(terminates)
    """
    
    @staticmethod
    def calculate_tis(func_addr):
        """
        Analyze TIS scores for all if statements in function
        Returns: [{"address": hex, "tis": float, "pattern": str, "condition_text": str}]
        """
        if not HAS_HEXRAYS:
            return []
        
        try:
            cfunc = ida_hexrays.decompile(func_addr)
            if not cfunc:
                return []
            # Hex-Rays assigns stable tree item indexes when rendering.
            cfunc.get_pseudocode()
        except:
            return []
        
        results = []
        
        class TISVisitor(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_PARENTS)
                self.tis_results = []
            
            def visit_insn(self, i):
                if i.op == ida_hexrays.cit_if:
                    tis_info = self._analyze_if(i)
                    if tis_info:
                        self.tis_results.append(tis_info)
                return 0
            
            def _analyze_if(self, if_stmt):
                """Analyze single if statement"""
                w_then = self._calc_weight(if_stmt.cif.ithen)
                w_else = self._calc_weight(if_stmt.cif.ielse)
                then_terminates = self._is_terminating(if_stmt.cif.ithen)
                else_terminates = self._is_terminating(if_stmt.cif.ielse)
                implicit_else = if_stmt.cif.ielse is None
                # if (reject) return; business(); has a real fall-through
                # continuation. Treating the omitted else as zero loses guards.
                if implicit_else and then_terminates:
                    w_else = self._fallthrough_weight(if_stmt)
                
                max_w = max(w_then, w_else)
                min_w = min(w_then, w_else)
                
                # Check if shorter branch terminates
                if w_then <= w_else:
                    terminates = then_terminates
                    short_branch = "then"
                else:
                    terminates = else_terminates
                    short_branch = "else"
                
                # Calculate TIS
                indicator = 1.0 if terminates else 0.0
                tis = (max_w / (min_w + 1)) * indicator
                
                # Determine pattern
                pattern = "None"
                if tis > 5.0:
                    if short_branch == "then" and terminates:
                        pattern = "Fail-Fast"  # if (fail) return;
                    elif short_branch == "else" and terminates:
                        pattern = "Success-Guard"  # if (success) {...} else return;
                
                return {
                    "address": hex(if_stmt.ea),
                    "tis": round(tis, 2),
                    "weight_then": w_then,
                    "weight_else": w_else,
                    "terminates": terminates,
                    "short_branch": short_branch,
                    "pattern": pattern,
                    "implicit_else": implicit_else,
                    "termination_scope": "function",
                    "analysis_method": "ctree_continuation",
                    "limitations": "Unresolved goto/break and indirect exits do not establish termination; cross-function request exit requires separate evidence"
                }

            def _fallthrough_weight(self, statement):
                # Only use an evidenced enclosing sequential block. Do not
                # guess continuations across loops or unresolved transfers.
                for parent in reversed(self.parents):
                    if parent.op == ida_hexrays.cit_block:
                        instructions = list(parent.cinsn.cblock)
                        for index, insn in enumerate(instructions):
                            if insn.index == statement.index:
                                return sum(self._calc_weight(s) for s in instructions[index + 1:])
                        return 0
                return 0
            
            def _calc_weight(self, stmt):
                """Calculate code block weight (statement count)"""
                if stmt is None:
                    return 0
                
                if stmt.op == ida_hexrays.cit_block:
                    # Recursively calculate statements in block
                    total = 0
                    for s in stmt.cblock:
                        total += self._calc_weight(s)
                    return max(total, 1)
                elif stmt.op == ida_hexrays.cit_if:
                    # if statement counts as 1, plus internal
                    return 1 + self._calc_weight(stmt.cif.ithen) + self._calc_weight(stmt.cif.ielse)
                elif stmt.op == ida_hexrays.cit_for:
                    return 3 + int(stmt.cfor.init.op != ida_hexrays.cot_empty) + int(stmt.cfor.step.op != ida_hexrays.cot_empty)
                elif stmt.op in [ida_hexrays.cit_while, ida_hexrays.cit_do]:
                    return 3  # Loops have higher weight
                else:
                    return 1
            
            def _is_terminating(self, stmt):
                """Require all paths to leave the current function.

                A goto or loop break alone is not evidence of request exit.
                """
                return self._termination_outcomes(stmt) == {"exit"}

            def _termination_outcomes(self, stmt):
                if stmt is None:
                    return {"fallthrough"}
                if stmt.op == ida_hexrays.cit_return:
                    return {"exit"}
                if stmt.op in [ida_hexrays.cit_goto, ida_hexrays.cit_break, ida_hexrays.cit_continue]:
                    return {"unknown"}
                if stmt.op == ida_hexrays.cit_if:
                    return self._termination_outcomes(stmt.cif.ithen) | self._termination_outcomes(stmt.cif.ielse)
                if stmt.op == ida_hexrays.cit_expr and stmt.cexpr.op == ida_hexrays.cot_call:
                    call = stmt.cexpr
                    if call.x.op == ida_hexrays.cot_obj:
                        callee = ida_funcs.get_func(call.x.obj_ea)
                        if callee and callee.flags & ida_funcs.FUNC_NORET:
                            return {"exit"}
                if stmt.op == ida_hexrays.cit_block:
                    outcomes = {"fallthrough"}
                    for instruction in stmt.cblock:
                        if "fallthrough" not in outcomes:
                            break
                        outcomes = (outcomes - {"fallthrough"}) | self._termination_outcomes(instruction)
                    return outcomes
                if stmt.op in [ida_hexrays.cit_for, ida_hexrays.cit_while, ida_hexrays.cit_do, ida_hexrays.cit_switch]:
                    return {"fallthrough", "unknown"}
                return {"fallthrough"}
        
        visitor = TISVisitor()
        visitor.apply_to(cfunc.body, None)
        
        return visitor.tis_results
    
    @staticmethod
    def find_blocking_checks(func_addr, tis_threshold=5.0):
        """
        Find checks with blocking characteristics in function (high TIS scores)
        Returns list of checks that meet the threshold
        """
        all_checks = TISCalculator.calculate_tis(func_addr)
        return [c for c in all_checks if c["tis"] > tis_threshold and c["terminates"]]


class AuthPatternDetector:
    """Authentication Pattern Detector"""
    
    # Authentication-related keywords
    AUTH_KEYWORDS = {
        "auth", "login", "session", "token", "cookie", "password", "passwd",
        "user", "admin", "uid", "gid", "credential", "verify", "check",
        "security", "permission", "access", "privilege", "level", "role"
    }
    
    @staticmethod
    def scan_auth_patterns_in_function(func_addr):
        """
        Scan authentication patterns in function
        Combining TIS and keyword analysis
        """
        if not HAS_HEXRAYS:
            return {"status": "error", "error": "No Hex-Rays"}
        
        try:
            cfunc = ida_hexrays.decompile(func_addr)
            if not cfunc:
                return {"status": "error", "error": "Decompile failed"}
        except:
            return {"status": "error", "error": "Exception"}
        
        results = {
            "func_addr": hex(func_addr),
            "func_name": idc.get_func_name(func_addr),
            "auth_calls": [],      # Calls that may be authentication functions
            "auth_strings": [],    # Referenced authentication-related strings
            "blocking_checks": [], # Blocking checks with high TIS
            "global_reads": [],    # Global variables read (may be auth flags)
        }
        
        class AuthVisitor(ida_hexrays.ctree_visitor_t):
            def __init__(self, keywords):
                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                self.keywords = keywords
                self.auth_calls = []
                self.auth_strings = []
                self.global_reads = []
            
            def visit_expr(self, e):
                # Check function call
                if e.op == ida_hexrays.cot_call:
                    callee_name = self._get_callee_name(e)
                    if callee_name and self._matches_auth_keyword(callee_name):
                        self.auth_calls.append({
                            "address": hex(e.ea),
                            "callee": callee_name
                        })
                
                # Check string reference
                elif e.op == ida_hexrays.cot_str:
                    if self._matches_auth_keyword(e.string):
                        self.auth_strings.append({
                            "address": hex(e.ea),
                            "string": e.string
                        })
                
                # Check global object reference
                elif e.op == ida_hexrays.cot_obj:
                    name = idc.get_name(e.obj_ea)
                    if name and self._matches_auth_keyword(name):
                        self.global_reads.append({
                            "address": hex(e.ea),
                            "global_addr": hex(e.obj_ea),
                            "global_name": name
                        })
                
                return 0
            
            def _get_callee_name(self, call_expr):
                if call_expr.x.op == ida_hexrays.cot_obj:
                    return idc.get_name(call_expr.x.obj_ea)
                elif call_expr.x.op == ida_hexrays.cot_helper:
                    return call_expr.x.helper
                return None
            
            def _matches_auth_keyword(self, text):
                text_lower = text.lower()
                return any(kw in text_lower for kw in self.keywords)
        
        visitor = AuthVisitor(AuthPatternDetector.AUTH_KEYWORDS)
        visitor.apply_to(cfunc.body, None)
        
        results["auth_calls"] = visitor.auth_calls
        results["auth_strings"] = visitor.auth_strings
        results["global_reads"] = visitor.global_reads
        
        # Get blocking checks
        results["blocking_checks"] = TISCalculator.find_blocking_checks(func_addr)
        
        return results


# Convenience functions for ida_server to call
def get_basic_blocks(func_addr):
    return CFGAnalyzer.get_basic_blocks(func_addr)

def build_dominator_tree(func_addr):
    return CFGAnalyzer.build_dominator_tree(func_addr)

def get_dominator_context(func_addr, target_addr):
    return CFGAnalyzer.get_dominator_context(func_addr, target_addr)

def calculate_tis(func_addr):
    return TISCalculator.calculate_tis(func_addr)

def find_blocking_checks(func_addr, threshold=5.0):
    return TISCalculator.find_blocking_checks(func_addr, threshold)

def scan_auth_patterns(func_addr):
    return AuthPatternDetector.scan_auth_patterns_in_function(func_addr)
