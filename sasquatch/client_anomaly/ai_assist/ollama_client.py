"""
ollama_client.py — Thin httpx wrapper for the Ollama local LLM API.

All configuration is via environment variables so the model and endpoint
can be changed without touching code:

  OLLAMA_BASE_URL   Base URL for the Ollama server  (default: http://localhost:11434)
  OLLAMA_MODEL      Model name to load/use           (default: llama3.2)
  OLLAMA_TIMEOUT    Request timeout in seconds       (default: 120)

Ollama must be running and the selected model must already be pulled:
  ollama serve
  ollama pull llama3.2
"""

import logging
import os

import httpx

log = logging.getLogger(__name__)

OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3.2")
OLLAMA_TIMEOUT: float = float(os.getenv("OLLAMA_TIMEOUT", "120"))


async def generate(system_prompt: str, user_prompt: str) -> str:
    """
    Send a system + user prompt to Ollama and return the assistant response text.

    Uses the /api/chat endpoint with stream=False so the full response is
    returned in a single HTTP reply.

    Raises RuntimeError with a human-readable message on connectivity or
    model errors so the FastAPI route can surface them as 502 responses.
    """
    url = f"{OLLAMA_BASE_URL}/api/chat"
    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ],
        "stream": False,
    }

    log.info(f"Sending prompt to Ollama model={OLLAMA_MODEL} url={url}")

    async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
        try:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
        except httpx.ConnectError:
            raise RuntimeError(
                f"Cannot connect to Ollama at {OLLAMA_BASE_URL}. "
                "Ensure Ollama is running (`ollama serve`)."
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                raise RuntimeError(
                    f"Model '{OLLAMA_MODEL}' is not pulled. "
                    f"Run: ollama pull {OLLAMA_MODEL}"
                )
            body = exc.response.text[:300]
            raise RuntimeError(
                f"Ollama returned HTTP {exc.response.status_code}: {body}"
            )
        except httpx.TimeoutException:
            raise RuntimeError(
                f"Ollama request timed out after {OLLAMA_TIMEOUT}s. "
                "Try increasing OLLAMA_TIMEOUT or using a smaller model."
            )

    data = resp.json()
    content = data.get("message", {}).get("content", "")
    if not content:
        raise RuntimeError(f"Ollama returned an empty response: {data}")

    log.info(f"Ollama response received ({len(content)} chars)")
    return content


async def health_check() -> dict:
    """
    Verify Ollama is reachable and return model availability info.
    Used by GET /api/v1/ai/status.
    """
    url = f"{OLLAMA_BASE_URL}/api/tags"
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            resp = await client.get(url)
            resp.raise_for_status()
        except (httpx.ConnectError, httpx.TimeoutException):
            return {"reachable": False, "model": OLLAMA_MODEL, "base_url": OLLAMA_BASE_URL}
        except httpx.HTTPStatusError:
            return {"reachable": False, "model": OLLAMA_MODEL, "base_url": OLLAMA_BASE_URL}

    tags = resp.json()
    available_models = [m.get("name", "") for m in tags.get("models", [])]
    model_available = any(OLLAMA_MODEL in m for m in available_models)

    return {
        "reachable": True,
        "base_url": OLLAMA_BASE_URL,
        "model": OLLAMA_MODEL,
        "model_available": model_available,
        "available_models": available_models,
    }
