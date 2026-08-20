import os
from typing import Any, Dict

import httpx


class LLMService:

    def __init__(self):

        self.provider = os.getenv(
            "AI_PROVIDER",
            "none"
        ).lower()

        self.model = os.getenv(
            "AI_MODEL",
            ""
        )

        self.api_key = os.getenv(
            "AI_API_KEY",
            ""
        )

        self.api_url = os.getenv(
            "AI_API_URL",
            ""
        )

    async def analyze(
        self,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:

        if self.provider == "none":

            return {
                "status": "disabled",
                "provider": "none",
                "analysis": None,
            }

        if not self.api_url:

            return {
                "status": "error",
                "provider": self.provider,
                "analysis": None,
                "error": "AI_API_URL is not configured",
            }

        prompt = self._build_prompt(context)

        headers = {
            "Content-Type": "application/json"
        }

        if self.api_key:

            headers["Authorization"] = (
                f"Bearer {self.api_key}"
            )

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are SentinelX SOC Agent, "
                        "a cybersecurity SOC analyst. "
                        "Analyze security events carefully. "
                        "Do not invent evidence. "
                        "Provide concise defensive recommendations."
                    )
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.1
        }

        try:

            async with httpx.AsyncClient(
                timeout=30
            ) as client:

                response = await client.post(
                    self.api_url,
                    headers=headers,
                    json=payload
                )

                response.raise_for_status()

                data = response.json()

            return {
                "status": "success",
                "provider": self.provider,
                "analysis": self._extract_response(
                    data
                ),
            }

        except Exception as exc:

            return {
                "status": "error",
                "provider": self.provider,
                "analysis": None,
                "error": str(exc),
            }

    def _build_prompt(
        self,
        context: Dict[str, Any]
    ) -> str:

        return f"""
Analyze the following SentinelX security event.

EVENT:
{context.get("event", {})}

DETECTION:
{context.get("detection", {})}

THREAT INTELLIGENCE:
{context.get("threat_intelligence", [])}

Provide:

1. Executive summary
2. Why the activity is suspicious
3. Likely attack technique
4. Evidence supporting the verdict
5. Recommended SOC actions
6. Whether an incident should be created

Only use the evidence provided.
Do not invent facts.
"""

    def _extract_response(
        self,
        data: Dict[str, Any]
    ) -> str:

        try:

            choices = data.get(
                "choices",
                []
            )

            if choices:

                message = choices[0].get(
                    "message",
                    {}
                )

                content = message.get(
                    "content"
                )

                if content:
                    return content

        except Exception:
            pass

        return str(data)
