
from .models import GPTClient


class ChatGPTClient(GPTClient):
    def __init__(self, api_key: str, model: str = "gpt-4o-mini") -> None:
        """OpenAI GPT Client for generating remediation plans."""
        super().__init__()
        self.api_key = api_key
        self.model = model

    @staticmethod
    def process_response(response: dict) -> str:
        """Extract and clena the response content."""
        plan = (
            response.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
            .strip()
        )
        start = plan.find("[")
        end = plan.rfind("]") + 1

        return plan[start:end] if start != -1 and end != -1 else plan

    async def generate_plan(self, prompt: str) -> str:
        """Generate remedation plan from prompt using OpenAI's GPT chat model."""
        response = self.openai.ChatCompletion.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1000,
            temperature=0.2,
        )

        return self.process_response(response)
