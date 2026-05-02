"""Agent service — LLM orchestration for Rcon AI panel."""

import json
from dataclasses import dataclass

from app.services.llm_client import call_chat_completion


@dataclass
class AgentResponse:
    content: str
    used_tool: bool = False


class AgentService:
    def __init__(self, config_getter, tools):
        self.config_getter = config_getter
        self.tools = tools

    def build_system_prompt(self) -> str:
        cfg = getattr(self.config_getter(), "agent", None)
        base = getattr(cfg, "prompt", "") if cfg else ""
        base = base or "你是 Rcon 的漏洞情报分析助手。"
        stats = self.tools.stats()
        return (
            f"{base}\n\n"
            "你可以基于本地漏洞数据库回答问题。"
            "回答必须面向防御和处置，不输出 exploit、payload 或攻击步骤。\n\n"
            f"当前数据库概览：总漏洞 {stats['total']}，KEV {stats['kev']}，"
            f"未读 {stats['unread']}，高危 {stats['high']}。"
        )

    def answer_with_llm(self, messages: list[dict]) -> str:
        cfg = getattr(self.config_getter(), "agent", None)
        if not cfg or not getattr(cfg, "api_key", ""):
            return "未配置 API Key，请在设置 → Agent 配置中设置。"

        user_prompt = json.dumps(messages[-10:], ensure_ascii=False, indent=2)
        return call_chat_completion(
            cfg,
            system_prompt=self.build_system_prompt(),
            user_prompt=user_prompt,
            timeout=120.0,
        )
