import json

from openai import OpenAI
from openai.types.chat import ChatCompletion

from .models import GPTClient


class ChatGPTClient(GPTClient):
    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4",
        temp: int = 0,
        max_tokens: int = 1000
    ) -> None:
        """OpenAI GPT Client for generating remediation plans."""
        super().__init__()
        self.client = OpenAI(api_key=api_key)
        self.model = model
        self.temp = temp
        self.max_tokens = max_tokens

    @staticmethod
    def process_response(response: ChatCompletion) -> list[str]:
        """Extract and clean the response content, returning it as a list."""
        content = response.choices[0].message.content

        if content is None:
            return []

        start = content.find("[")
        end = content.rfind("]") + 1
        list_str = content[start:end] if start != -1 and end != -1 else ""

        try:
            return json.loads(list_str) if list_str else []
        except json.JSONDecodeError:
            return []

    def chat(self, prompt: str) -> str:
        """Interact with ChatGPT textually."""
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=self.max_tokens,
            temperature=self.temp,
        )

        return response.choices[0].message.content

    def generate_plan(self, prompt: str) -> list[str]:
        """Generate remediation plan from prompt using OpenAI's GPT chat model."""
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=self.max_tokens,
            temperature=self.temp,
        )

        return self.process_response(response)
