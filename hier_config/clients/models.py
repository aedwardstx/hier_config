from abc import ABC, abstractmethod


class GPTClient(ABC):
    """Abstract base class for GPT client implementation."""

    @abstractmethod
    def chat(self, prompt: str) -> str:
        """Send a prompt to a GPT and recieve a textual response."""

    @abstractmethod
    def generate_plan(self, prompt: str) -> list[str]:
        """Generate remediation plan from prompt."""
