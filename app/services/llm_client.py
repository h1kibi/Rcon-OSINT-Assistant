"""Unified LLM API client — shared by AI push, agent panel, and future features."""

import httpx
from loguru import logger


class LLMClientError(RuntimeError):
    pass


def call_chat_completion(
    agent_config,
    *,
    system_prompt: str,
    user_prompt: str,
    timeout: float = 60.0,
) -> str:
    base_url = agent_config.base_url.rstrip("/")
    url = f"{base_url}/chat/completions"

    headers = {
        "Authorization": f"Bearer {agent_config.api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": agent_config.model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
        "max_tokens": getattr(agent_config, "max_tokens", 2000),
    }

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as e:
        raise LLMClientError(f"LLM HTTP {e.response.status_code}: {e.response.text[:500]}") from e
    except Exception as e:
        raise LLMClientError(f"{type(e).__name__}: {e}") from e

    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError) as e:
        raise LLMClientError("LLM response missing choices[0].message.content") from e
