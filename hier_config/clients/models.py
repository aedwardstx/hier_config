from abc import ABC, abstractmethod


class GPTClient(ABC):
    """Abstract base class for GPT client implementation."""

    @abstractmethod
    def generate_plan(self, prompt: str) -> list[str]:
        """Generate remediation plan from prompt."""
