class DuplicateChildError(Exception):
    """Raised when attempting to add a duplicate child."""


class GPTClientInitializationError(Exception):
    """Raised when a GPT client is not initialized."""


class RemediationError(Exception):
    """Raised when a remediation config errors upon initialization."""
