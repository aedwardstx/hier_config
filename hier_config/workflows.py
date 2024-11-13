import ast
from collections.abc import AsyncIterator, Iterable
from logging import getLogger
from typing import Optional

from .clients import GPTClient
from .exceptions import GPTClientInitializationError, RemediationError
from .model import GPTRemediationContext, TagRule
from .root import HConfig

logger = getLogger(__name__)


class WorkflowRemediation:
    """Manages configuration workflows for a network device by comparing
    running and generated configurations and creating remediations to align
    the device with the intended configuration state.

    Attributes:
        running_config (HConfig): The current configuration of the network device.
        generated_config (HConfig): The target configuration for the network device.

    Raises:
        ValueError: If `running_config` and `generated_config` have different drivers.

    Example:
        Initialize `WorkflowRemediation` with the running and generated configurations
        and generate remediation and rollback configurations.

        ```python
        from hier_config import WorkflowRemediation, get_hconfig
        from hier_config.model import Platform

        # Create running and generated configurations as HConfig objects
        running_config = get_hconfig(Platform.CISCO_IOS, "running_config_text")
        generated_config = get_hconfig(Platform.CISCO_IOS, "generated_config_text")

        # Initialize WorkflowRemediation with running and generated configurations
        workflow = WorkflowRemediation(running_config, generated_config)

        # Generate the remediation configuration to apply the target configuration to the device
        remediation_config = workflow.remediation_config
        print("Remediation configuration:")
        for line in remediation_config.all_children_sorted():
            print(line.cisco_style_text())

        # Generate the rollback configuration to revert back to the running configuration
        rollback_config = workflow.rollback_config
        print("Rollback configuration:")
        for line in rollback_config.all_children_sorted():
            print(line.cisco_style_text())
        ```

    """

    def __init__(
        self,
        running_config: HConfig,
        generated_config: HConfig,
    ) -> None:
        self.running_config = running_config
        self.generated_config = generated_config

        if running_config.driver != generated_config.driver:
            message = "The running and generated configs must use the same driver."
            raise ValueError(message)

        self._remediation_config: Optional[HConfig] = None
        self._rollback_config: Optional[HConfig] = None
        self._gpt_remediation_config: Optional[HConfig] = None
        self._gpt_client: Optional[GPTClient] = None

    @property
    def remediation_config(self) -> HConfig:
        """Builds and returns the remediation configuration to bring the device
        in line with the generated configuration.

        Returns:
            HConfig: The configuration needed to remediate the device.

        Notes:
            The remediation configuration is cached after the first call.

        """
        if self._remediation_config:
            return self._remediation_config

        remediation_config = self.running_config.config_to_get_to(
            self.generated_config, HConfig(self.running_config.driver)
        ).set_order_weight()

        self._remediation_config = remediation_config

        return self._remediation_config

    @property
    def rollback_config(self) -> HConfig:
        """Builds and returns the rollback configuration to revert the device
        from the generated configuration back to the running configuration.

        Returns:
            HConfig: The configuration required to roll back to the original state.

        Notes:
            The rollback configuration is cached after the first call.

        """
        if self._rollback_config:
            return self._rollback_config

        rollback_config = self.generated_config.config_to_get_to(
            self.running_config, HConfig(self.running_config.driver)
        ).set_order_weight()

        self._rollback_config = rollback_config

        return rollback_config

    def apply_remediation_tag_rules(self, tag_rules: tuple[TagRule, ...]) -> None:
        """Applies tag rules to selectively label parts of the remediation configuration.

        Args:
            tag_rules (tuple[TagRule, ...]): A set of tag rules specifying sections to tag.

        Notes:
            This method is useful for managing configuration changes by marking specific
            parts of the config for conditional remediation.

        """
        for tag_rule in tag_rules:
            for child in self.remediation_config.get_children_deep(
                tag_rule.match_rules
            ):
                child.tags_add(tag_rule.apply_tags)

    def remediation_config_filtered_text(
        self,
        include_tags: Iterable[str] = (),
        exclude_tags: Iterable[str] = (),
    ) -> str:
        """Returns the remediation configuration as text, filtered by included and excluded tags.

        Args:
            include_tags (Iterable[str], optional): Tags to include in the output.
            exclude_tags (Iterable[str], optional): Tags to exclude from the output.

        Returns:
            str: The filtered remediation configuration in a text format.

        Notes:
            - If no tags are provided, the complete sorted remediation configuration is returned.
            - Sorting respects configuration hierarchy and specified tags.

        """
        children = (
            self.remediation_config.all_children_sorted_by_tags(
                include_tags, exclude_tags
            )
            if include_tags or exclude_tags
            else self.remediation_config.all_children_sorted()
        )
        return "\n".join(c.cisco_style_text() for c in children)

    def set_gpt_client(self, gpt_client: GPTClient) -> None:
        """Set GPT client for remediation planning."""
        self._gpt_client = gpt_client

    async def gpt_remediation_config(self) -> HConfig:
        """Generate GPT-based remediation plan.

        Returns:
            HConfig: The configuration created by an GPT to remediate the device.

        """
        if not self._gpt_client:
            msg = "No GPT client is initialized."
            raise GPTClientInitializationError(msg)

        self._gpt_remediation_config = HConfig(self.running_config.driver)

        async for context in self._build_remediation_context():
            try:
                prompt = self._build_gpt_prompt(context)
                response = await self._gpt_client.generate_plan(prompt)

                if isinstance(response, list) and all(
                    isinstance(cmd, str) for cmd in response
                ):
                    commands = "\n".join(response)
                else:
                    commands = "\n".join(ast.literal_eval(response))

                self._gpt_remediation_config.add_children_deep(commands)
            except Exception as e:
                msg = f"Failed to generate remediation plan: {e}"
                raise RemediationError(msg) from e

        return self._gpt_remediation_config

    async def _build_remediation_context(self) -> AsyncIterator[GPTRemediationContext]:
        """Generate context for GPT Prompt."""
        rules = self.running_config.driver.gpt_remediation_rules

        if not rules:
            RemediationError("no GPT remediation rules loaded.")

        for rule in rules:
            running_config = self.running_config.get_children_deep(rule.lineage)
            generated_config = self.generated_config.get_children_deep(rule.lineage)

            yield GPTRemediationContext(
                running_config=str(running_config),
                generated_config=str(generated_config),
                description=rule.description,
                example=rule.example
            )

    @staticmethod
    def _build_gpt_prompt(context: GPTRemediationContext) -> str:
        """Build GPT prompt from context."""
        return f"""
        Generate a network configuration remediation plan as a Python list of commands to be executed sequentially for remediation.

        Current Configuration:
        {context.running_config}

        Target Configuration:
        {context.generated_config}

        Remediation Rules:
        {context.description}

        Use the following Example as a guide for the format and structure of the commands:

        Example:
        running config:
        {context.example.running_config}

        remediation config:
        {context.example.remediation_config}

        Instructions:
        - Generate a Python list of commands for the remediation plan.
        - Follow the format and structure demonstrated in the Example context above.
        - Maintain the command hierarchy, using indentation to denote child commands under parent commands.
        - Each command should be a string in the list.
        - Do not include rollback or validation steps. The list should only contain the commands required to implement the target configuration.

        Example output format:
        [
            "command1",
            "parent_command",
            "    child_command1",
            "    child_command2",
            "command2"
        ]
        """
