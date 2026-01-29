#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Test distributed CGI deep analysis"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.bridge.ida_client import IDAProClient
from analysis.distributed_cgi_extractor import DistributedCGIExtractor

def main():
    ida = IDAProClient()
    ida.connect()
    
    extractor = DistributedCGIExtractor(ida)
    cgi_info = extractor.analyze_current_binary()
    
    # Deep analyze all handlers
    print('\n' + '='*60)
    print('  DEEP VULNERABILITY ANALYSIS')
    print('='*60)
    results = extractor.deep_analyze_all_handlers()
    
    # Show high risk findings
    print('\n[Summary] High/Critical Risk Findings:')
    for r in results:
        if r['risk_level'] in ['HIGH', 'CRITICAL']:
            print(f"  🔴 {r['risk_level']}: {r['route']}")
            print(f"     Handler: {r['handler']}")
            print(f"     Bypass: {r['bypass_conditions']}")
            print(f"     Operations: {r['sensitive_operations']}")
            print()

if __name__ == "__main__":
    main()
