# Copyright (c) 2026 The Pangu Project Authors. All rights reserved.
# core/llm.py
"""
LLM Provider Module - Unified interface for OpenAI and Gemini APIs.
"""
import json
import os
import time
import random
import math

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
        # Importing PANGU, running Phase 0, and offline tests must never download
        # a tokenizer. Prefer API usage counts; optional exact local counting is
        # initialized only when explicitly requested.
        self.encoder = None
        self._encoder_attempted = False
    
    def count_tokens(self, text):
        """Count the number of tokens in text"""
        if isinstance(text, dict):
            text = json.dumps(text, ensure_ascii=False)
        elif not isinstance(text, str):
            text = str(text)
        if os.environ.get("PANGU_EXACT_TOKENS") == "1" and not self._encoder_attempted:
            self._encoder_attempted = True
            try:
                import tiktoken
                self.encoder = tiktoken.get_encoding("cl100k_base")
            except Exception:
                pass
        if self.encoder is not None:
            return len(self.encoder.encode(text))
        return math.ceil(len(text.encode("utf-8")) / 4)
    
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
        print("  Counts use API usage when available; otherwise estimated.")
        print("=" * 60)
        return s
    
    def reset(self):
        """Reset statistics"""
        self._init_stats()

# Global statistics instance
token_stats = TokenStats()

# ===========================================

class LLMProvider:
    def __init__(self, client=None, provider=None, model=None, max_attempts=3, timeout=60):
        self.type = provider or os.environ.get("LLM_TYPE", "openai")
        if self.type not in {"openai", "gemini"}:
            raise ValueError(f"Unsupported LLM_TYPE: {self.type}")
        if not 1 <= max_attempts <= 3 or timeout <= 0:
            raise ValueError("Use 1-3 attempts and a positive timeout")
        self.model_name = model or os.environ.get(
            "GEMINI_MODEL" if self.type == "gemini" else "OPENAI_MODEL",
            GEMINI_MODEL if self.type == "gemini" else OPENAI_MODEL)
        self.max_attempts = max_attempts
        self.timeout = timeout
        self.client = client
        self.last_usage = None
        self.last_error = None
        self.stats = token_stats  # Reference global statistics tracker
        if self.type == "gemini":
            import google.generativeai as genai
            from google.generativeai.types import HarmCategory, HarmBlockThreshold
            genai.configure(api_key=os.environ.get("GOOGLE_API_KEY", ""))
            self.safety_settings = {
                HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
            }
            self.model = genai.GenerativeModel(self.model_name)

    def validate_configuration(self):
        if self.type == "openai" and self.client is None and not os.environ.get("OPENAI_API_KEY"):
            raise ValueError("Set OPENAI_API_KEY, OPENAI_BASE_URL and OPENAI_MODEL before running LLM analysis")
        if self.type == "gemini" and not os.environ.get("GOOGLE_API_KEY"):
            raise ValueError("Set GOOGLE_API_KEY before running Gemini analysis")

    def chat(self, messages, json_mode=True, caller="unknown"):
        """Conversation interface with retry mechanism"""
        self.last_error = None
        
        # Count input tokens
        input_tokens = self.stats.count_messages_tokens(messages)

        for attempt in range(self.max_attempts):
            try:
                self.last_usage = None
                if self.type == "gemini":
                    result = self._chat_gemini(messages, json_mode)
                else:
                    result = self._chat_openai(messages, json_mode)
                
                # Count output tokens and record
                if json_mode and not isinstance(result, (dict, list)):
                    raise ValueError("Expected a JSON object or array")
                output_tokens = self.stats.count_tokens(result)
                if self.last_usage is not None:
                    input_tokens, output_tokens = self.last_usage
                self.stats.record_call(input_tokens, output_tokens, caller)
                
                return result
            
            except Exception as e:
                self.last_error = f"{type(e).__name__}: {e}"
                print(f"[-] LLM Error (Attempt {attempt+1}): {type(e).__name__}")
                # Authentication/configuration failures do not improve on retry.
                status = getattr(e, "status_code", None)
                if status in {400, 401, 403, 404}:
                    break
                if attempt < self.max_attempts - 1:
                    time.sleep(min(8, 2 ** attempt) + random.uniform(0, 0.25))
        return None

    def _chat_openai(self, messages, json_mode):
        self.validate_configuration()
        if self.client is None:
            from openai import OpenAI
            # Disable SDK retries so the outer three-attempt limit is real.
            self.client = OpenAI(
                api_key=os.environ.get("OPENAI_API_KEY", ""),
                base_url=os.environ.get("OPENAI_BASE_URL", OPENAI_BASE_URL),
                timeout=self.timeout, max_retries=0)
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            response_format={"type": "json_object"} if json_mode else None
        )
        content = response.choices[0].message.content
        usage = getattr(response, "usage", None)
        if usage is not None:
            self.last_usage = (usage.prompt_tokens, usage.completion_tokens)
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
            safety_settings=self.safety_settings,
            request_options={"timeout": self.timeout}
        )
        
        return json.loads(response.text) if json_mode else response.text
