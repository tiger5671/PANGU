# Copyright (c) 2026 The Pangu Project Authors. All rights reserved.
# core/llm.py
"""
LLM Provider Module - Unified interface for OpenAI and Gemini APIs.
"""
import json
import os
import time
import random
import tiktoken
from openai import OpenAI
import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold
from google.api_core.exceptions import ResourceExhausted

# ================= Configuration =================

LLM_TYPE = os.environ.get("LLM_TYPE", "openai")

# --- Gemini Configuration ---
GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY", "")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash-exp")

# --- OpenAI/Compatible API Configuration ---
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o")

# ===========================================

# ================= Token Statistics Module =================
class TokenStats:
    """Global Token Statistics Tracker"""
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_stats()
        return cls._instance
    
    def _init_stats(self):
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.call_count = 0
        self.call_details = []  # Record details of each call
        try:
            self.encoder = tiktoken.encoding_for_model("gpt-4")
        except:
            self.encoder = tiktoken.get_encoding("cl100k_base")
    
    def count_tokens(self, text):
        """Count the number of tokens in text"""
        if isinstance(text, dict):
            text = json.dumps(text, ensure_ascii=False)
        elif not isinstance(text, str):
            text = str(text)
        return len(self.encoder.encode(text))
    
    def count_messages_tokens(self, messages):
        """Count the number of tokens in a message list"""
        total = 0
        for msg in messages:
            total += 4  # Overhead per message
            total += self.count_tokens(msg.get("content", ""))
            total += self.count_tokens(msg.get("role", ""))
        total += 2  # End overhead
        return total
    
    def record_call(self, input_tokens, output_tokens, caller="unknown"):
        """Record an LLM call"""
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens
        self.call_count += 1
        self.call_details.append({
            "call_id": self.call_count,
            "caller": caller,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "timestamp": time.strftime("%H:%M:%S")
        })
        print(f"  [Token] Call #{self.call_count}: +{input_tokens} in / +{output_tokens} out | Total: {self.total_input_tokens} in / {self.total_output_tokens} out")
    
    def get_summary(self):
        """Get statistics summary"""
        return {
            "total_calls": self.call_count,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_tokens": self.total_input_tokens + self.total_output_tokens,
            "avg_input_per_call": self.total_input_tokens / max(1, self.call_count),
            "avg_output_per_call": self.total_output_tokens / max(1, self.call_count),
        }
    
    def print_summary(self):
        """Print statistics summary"""
        s = self.get_summary()
        print("\n" + "=" * 60)
        print("TOKEN CONSUMPTION SUMMARY")
        print("=" * 60)
        print(f"  Total LLM Calls:     {s['total_calls']}")
        print(f"  Total Input Tokens:  {s['total_input_tokens']:,}")
        print(f"  Total Output Tokens: {s['total_output_tokens']:,}")
        print(f"  Total Tokens:        {s['total_tokens']:,}")
        print(f"  Avg Input/Call:      {s['avg_input_per_call']:.1f}")
        print(f"  Avg Output/Call:     {s['avg_output_per_call']:.1f}")
        # Cost estimation (GPT-4.1 pricing)
        cost_input = s['total_input_tokens'] * 2.00 / 1_000_000
        cost_output = s['total_output_tokens'] * 8.00 / 1_000_000
        print(f"  Estimated Cost:      ${cost_input + cost_output:.4f}")
        print(f"    - Input Cost:      ${cost_input:.4f}")
        print(f"    - Output Cost:     ${cost_output:.4f}")
        print("=" * 60)
        return s
    
    def reset(self):
        """Reset statistics"""
        self._init_stats()

# Global statistics instance
token_stats = TokenStats()

# ===========================================

class LLMProvider:
    def __init__(self):
        self.type = LLM_TYPE
        self.stats = token_stats  # Reference global statistics tracker
        if self.type == "gemini":
            genai.configure(api_key=GOOGLE_API_KEY)
            self.safety_settings = {
                HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
            }
            self.model = genai.GenerativeModel(GEMINI_MODEL)
            
        elif self.type == "openai":
            self.client = OpenAI(api_key=OPENAI_API_KEY, base_url=OPENAI_BASE_URL)

    def chat(self, messages, json_mode=True, caller="unknown"):
        """Conversation interface with retry mechanism"""
        max_retries = 3
        base_delay = 5  # Base wait time in seconds
        
        # Count input tokens
        input_tokens = self.stats.count_messages_tokens(messages)

        for attempt in range(max_retries):
            try:
                if self.type == "gemini":
                    result = self._chat_gemini(messages, json_mode)
                else:
                    result = self._chat_openai(messages, json_mode)
                
                # Count output tokens and record
                output_tokens = self.stats.count_tokens(result)
                self.stats.record_call(input_tokens, output_tokens, caller)
                
                return result
            
            except ResourceExhausted:
                # Specifically catch Google's 429 quota error
                wait_time = base_delay * (2 ** attempt) + random.uniform(0, 1)
                print(f"[Rate Limit] Quota exceeded. Retrying in {wait_time:.1f}s...")
                time.sleep(wait_time)
            
            except Exception as e:
                # Other errors: print and retry
                print(f"[-] LLM Error (Attempt {attempt+1}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(2)
                else:
                    return None
        return None

    def _chat_openai(self, messages, json_mode):
        response = self.client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=messages,
            response_format={"type": "json_object"} if json_mode else None
        )
        content = response.choices[0].message.content
        return json.loads(content) if json_mode else content

    def _chat_gemini(self, messages, json_mode):
        # Convert format
        gemini_history = []
        system_instruction = ""
        
        for msg in messages:
            role = msg["role"]
            content = msg["content"]
            if role == "system":
                system_instruction += content + "\n"
            elif role == "user":
                gemini_history.append({"role": "user", "parts": [content]})
            elif role == "assistant":
                gemini_history.append({"role": "model", "parts": [content]})

        # Concatenate System Prompt to the first user message
        if gemini_history:
            first_msg_content = gemini_history[0]['parts'][0]
            if system_instruction:
                gemini_history[0]['parts'][0] = f"System Instruction:\n{system_instruction}\n\nUser Query:\n{first_msg_content}"
        
        # When there's only one message (first turn), history is empty
        history_to_send = gemini_history[:-1] if len(gemini_history) > 1 else []
        last_msg = gemini_history[-1]['parts'][0]

        chat = self.model.start_chat(history=history_to_send)
        
        response = chat.send_message(
            last_msg,
            generation_config={"response_mime_type": "application/json"} if json_mode else None,
            safety_settings=self.safety_settings
        )
        
        return json.loads(response.text)