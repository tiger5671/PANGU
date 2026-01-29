#!/usr/bin/env python3
"""Test LLM connection"""

import sys
sys.path.insert(0, '.')

from core.llm import LLMProvider, LLM_TYPE, OPENAI_BASE_URL, OPENAI_MODEL

def test_llm():
    print("="*50)
    print("LLM Connection Test")
    print("="*50)
    
    print(f"\nConfig:")
    print(f"  Type: {LLM_TYPE}")
    print(f"  Base URL: {OPENAI_BASE_URL}")
    print(f"  Model: {OPENAI_MODEL}")
    
    print("\nInitializing LLM...")
    llm = LLMProvider()
    
    print("\nSending test message...")
    messages = [
        {"role": "user", "content": 'Reply with exactly this JSON: {"status": "ok", "message": "hello"}'}
    ]
    
    result = llm.chat(messages)
    
    print(f"\nResult: {result}")
    
    if result:
        print("\n✓ LLM connection successful!")
    else:
        print("\n✗ LLM connection failed!")

if __name__ == '__main__':
    test_llm()
