"""Model access: Ollama Cloud chat API with tool calling.

Settings come from config/settings.yaml (llm section); the API key comes from
OLLAMA_API_KEY in .env. Any object with the same chat() method can replace this
client (the tests use a scripted model).
"""
import json
import os
import time

import requests
from dotenv import load_dotenv

from src.config import REPO_ROOT, load_settings

load_dotenv(REPO_ROOT / ".env")


class LLMError(RuntimeError):
    pass


def to_ollama_tools(schemas):
    """registry-style {"name", "description", "parameters"} -> Ollama/OpenAI tool format."""
    return [{"type": "function", "function": s} for s in schemas]


class OllamaClient:
    def __init__(self, settings=None):
        cfg = (settings or load_settings()).get("llm", {})
        self.base_url = cfg.get("base_url", "https://ollama.com").rstrip("/")
        self.model = os.getenv("LLM_MODEL") or cfg.get("model", "gpt-oss:120b")
        self.options = cfg.get("options", {"temperature": 0})
        self.think = cfg.get("think")
        self.timeout = cfg.get("timeout_seconds", 120)
        self.retries = int(cfg.get("retries", 1))
        self.api_key = os.getenv("OLLAMA_API_KEY")

    def describe(self):
        return {"provider": "ollama-cloud", "base_url": self.base_url, "model": self.model,
                "options": self.options, "think": self.think, "timeout_seconds": self.timeout,
                "retries": self.retries}

    def chat(self, messages, tools=None, json_mode=False):
        """Send one chat turn. Returns the assistant message dict:
        {"role": "assistant", "content", "tool_calls": [{"function": {"name", "arguments"}}]}"""
        if not self.api_key:
            raise LLMError("OLLAMA_API_KEY is not set (copy .env.example to .env)")
        body = {"model": self.model, "messages": messages, "stream": False,
                "options": self.options}
        if tools:
            body["tools"] = to_ollama_tools(tools)
        if self.think is not None:
            body["think"] = self.think
        if json_mode:
            body["format"] = "json"
        reason = None
        for attempt in range(self.retries + 1):
            if attempt:
                time.sleep(5 * attempt)
            try:
                resp = requests.post(f"{self.base_url}/api/chat", json=body, timeout=self.timeout,
                                     headers={"Authorization": f"Bearer {self.api_key}"})
                if resp.status_code >= 400:
                    reason = f"HTTP {resp.status_code}: {resp.text[:300]}"
                    if resp.status_code in (401, 403, 404):
                        break  # retrying will not help
                    continue
                msg = resp.json().get("message") or {}
                for call in msg.get("tool_calls") or []:
                    args = call.get("function", {}).get("arguments")
                    if isinstance(args, str):  # some models return a JSON string
                        try:
                            call["function"]["arguments"] = json.loads(args)
                        except ValueError:
                            pass
                return msg
            except (requests.RequestException, ValueError) as exc:
                reason = f"{type(exc).__name__}: {exc}"
        raise LLMError(f"model call failed after {attempt + 1} attempt(s): {reason}")
