from abc import ABC, abstractmethod


class GPTClient(ABC):
    """Abstract base class for GPT client implementation."""

    @abstractmethod
    async def generate_plan(self, prompt: str) -> str:
        """Generate remediation plan from prompt."""
