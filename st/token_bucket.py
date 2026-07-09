import asyncio
import time
import json
import os
from pathlib import Path
from typing import Dict, Optional

class TokenBucket:
    """
    Dual-Gate Token Bucket Rate Limiter (RPM + TPM).
    Specifically tailored for OpenAI Tier-5 precision with V5.2 Cross-Script Persistence.
    """

    def __init__(self, max_rpm=10000, max_tpm=5000000, state_file=".token_state.json"):
        self.max_rpm = float(max_rpm)
        self.max_tpm = float(max_tpm)
        
        # Determine state file path (Global to the project)
        # Assuming st/ is in the project root
        self.state_file = Path(os.path.dirname(os.path.abspath(__file__))).parent / state_file
        
        self.tokens = self.max_tpm
        self.requests = self.max_rpm
        
        self.refill_rate_tokens = self.max_tpm / 60.0    # tokens per second
        self.refill_rate_requests = self.max_rpm / 60.0  # requests per second
        
        self.last_refill_tokens = time.time()
        self.last_refill_requests = time.time()
        
        self.lock = asyncio.Lock()
        self.max_file_tokens = self.max_tpm
        
        # V5.2: Load Shared Scent
        self._load_state()

    def _load_state(self):
        """Loads the shared scent of token debt from other scripts."""
        if self.state_file.exists():
            try:
                data = json.loads(self.state_file.read_text())
                ts = data.get("timestamp", 0)
                # If the state is older than 60s, it's irrelevant (OpenAI refilled)
                if time.time() - ts < 60:
                    self.tokens = float(data.get("tokens", self.tokens))
                    self.requests = float(data.get("requests", self.requests))
                    self.last_refill_tokens = ts
                    self.last_refill_requests = ts
            except: pass

    def _save_state(self):
        """Persists the current debt to the shared state file."""
        try:
            data = {
                "timestamp": time.time(),
                "tokens": self.tokens,
                "requests": self.requests
            }
            self.state_file.write_text(json.dumps(data))
        except: pass

    @staticmethod
    def auto_detect(api_key: str, model: str = "gpt-5.4-mini") -> 'TokenBucket':
        """
        Sends a 1-token probe to extract the absolute Tier limit properties from OpenAI headers.
        """
        import requests
        try:
            # V5.3.1: Reduced timeout to 3s to prevent hangs in firewalled/restricted environments
            resp = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={"model": model, "messages": [{"role": "user", "content": "ping"}], "max_tokens": 1},
                timeout=3
            )
            h = {k.lower(): v for k, v in resp.headers.items()}
            rpm = float(h.get("x-ratelimit-limit-requests", 10000))
            tpm = float(h.get("x-ratelimit-limit-tokens", 5000000))
            
            bucket = TokenBucket(max_rpm=rpm, max_tpm=tpm)
            
            # Immediately calibrate the remaining amounts
            rem_req = h.get("x-ratelimit-remaining-requests")
            rem_tok = h.get("x-ratelimit-remaining-tokens")
            if rem_req is not None:
                bucket.requests = float(rem_req)
            if rem_tok is not None:
                bucket.tokens = float(rem_tok)
                
            bucket._save_state()
            return bucket
        except Exception as e:
            # Fallback to theoretical maximums if the probe fails
            import sys
            sys.stdout.write(f" [FALLBACK: {str(e)[:40]}...] ")
            sys.stdout.flush()
            return TokenBucket(10000, 5000000)

    async def calibrate(self, headers: dict):
        """
        Force-sync internal clocks to absolute truth from OpenAI.
        Also dynamically updates the ceiling capacity if the user Tier shifts.
        """
        async with self.lock:
            h_map = {k.lower(): v for k, v in headers.items()}
            
            # Refresh absolute ceilings
            lim_tokens = h_map.get("x-ratelimit-limit-tokens")
            lim_reqs = h_map.get("x-ratelimit-limit-requests")
            if lim_tokens is not None:
                self.max_tpm = float(lim_tokens)
                self.refill_rate_tokens = self.max_tpm / 60.0
                self.max_file_tokens = self.max_tpm
            if lim_reqs is not None:
                self.max_rpm = float(lim_reqs)
                self.refill_rate_requests = self.max_rpm / 60.0
                
            # Refresh active balances
            rem_tokens = h_map.get("x-ratelimit-remaining-tokens")
            rem_reqs = h_map.get("x-ratelimit-remaining-requests")
            if rem_tokens is not None:
                self.tokens = min(self.max_tpm, float(rem_tokens))
                self.last_refill_tokens = time.time()
            if rem_reqs is not None:
                self.requests = min(self.max_rpm, float(rem_reqs))
                self.last_refill_requests = time.time()
            
            self._save_state()

    async def consume(self, requested_tokens: float, requested_requests: float = 1.0) -> float:
        """
        Consume resources. Returns exact micro-sleep required if locked.
        """
        async with self.lock:
            now = time.time()
            
            # Local Drift Refill
            elapsed_t = now - self.last_refill_tokens
            if elapsed_t > 0:
                self.tokens = min(self.max_tpm, self.tokens + (elapsed_t * self.refill_rate_tokens))
                self.last_refill_tokens = now
                
            elapsed_r = now - self.last_refill_requests
            if elapsed_r > 0:
                self.requests = min(self.max_rpm, self.requests + (elapsed_r * self.refill_rate_requests))
                self.last_refill_requests = now
                
            # Gate Check
            wait_tokens = 0.0
            wait_requests = 0.0
            
            if self.tokens < requested_tokens:
                wait_tokens = (requested_tokens - self.tokens) / self.refill_rate_tokens
                
            if self.requests < requested_requests:
                wait_requests = (requested_requests - self.requests) / self.refill_rate_requests
                
            wait_time = max(wait_tokens, wait_requests)
            
            # Mutate state
            self.tokens -= requested_tokens
            self.requests -= requested_requests
            
            # Persist state so other scripts know about this consumption
            self._save_state()
            
            return max(0.0, wait_time)
            
    async def consume_with_wait(self, tokens: float, requests: float = 1.0):
        """
        Wait for enough tokens and request capacity to be available.
        This is a convenience wrapper for consume() + sleep().
        """
        wait_time = await self.consume(tokens, requests)
        
        if wait_time > 0:
            import sys
            # Check if we can import hunter colors (best effort)
            try:
                from hunter import colored, Colors
                msg = colored(f"\n[RATE] Debt of {tokens:,.0f} tokens. Reserved slot, waiting {wait_time:.1f}s for refill...", Colors.YELLOW)
                sys.stdout.write(msg)
                sys.stdout.flush()
            except:
                print(f"\n[RATE] Waiting {wait_time:.1f}s for tokens...")
            
            await asyncio.sleep(wait_time)
            
        return True

    async def get_state(self) -> Dict:
        async with self.lock:
            return {
                "tpm_pct": int(max(0, min(100, (self.tokens / self.max_tpm) * 100))),
                "rpm_pct": int(max(0, min(100, (self.requests / self.max_rpm) * 100))),
                "tokens": self.tokens,
                "requests": self.requests
            }

