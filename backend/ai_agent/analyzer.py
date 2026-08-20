import os
from dotenv import load_dotenv
from openai import OpenAI

from ai_agent.prompts import SYSTEM_PROMPT, build_investigation_prompt


load_dotenv()


class SOCAnalyzer:

    def __init__(self):
        api_key = os.getenv("OPENAI_API_KEY")

        if not api_key:
            raise RuntimeError(
                "OPENAI_API_KEY is not configured"
            )

        self.client = OpenAI(api_key=api_key)

    def investigate(self, evidence: dict):

        prompt = build_investigation_prompt(evidence)

        response = self.client.responses.create(
            model="gpt-5-mini",
            instructions=SYSTEM_PROMPT,
            input=prompt,
        )

        return {
            "investigation": response.output_text
        }
