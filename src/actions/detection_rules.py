# ============================================================================
# src/actions/detection_rules.py - Custom Rule Deployment
# ============================================================================

"""Deploy custom detection rules to Elasticsearch."""
from typing import Any
from src.ingestion.elastic_client import ElasticClient
from src.utils.logger import get_default_logger


class DetectionRuleDeployer:
    """Deploys custom detection rules to Elasticsearch."""

    def __init__(self, client: ElasticClient):
        """
        Initialize rule deployer.

        Args:
            client: ElasticClient instance
        """
        self.client = client
        self.logger = get_default_logger(level="INFO")

    def deploy_rule(self, rule_config: dict[str, Any]) -> bool:
        """
        Deploy a detection rule.

        Args:
            rule_config: Rule configuration dictionary

        Returns:
            True if successful
        """
        try:
            rule_body = {
                "name": rule_config.get("name", "Custom Rule"),
                "enabled": rule_config.get("enabled", True),
                "query": rule_config.get("query", ""),
                "actions": rule_config.get("actions", []),
                "description": rule_config.get("description", ""),
                "tags": rule_config.get("tags", ["custom"]),
            }

            # Index rule
            index = ".alerts-detection-rules"
            self.client.index_document(index, rule_body)

            self.logger.info(
                "Rule deployed",
                name=rule_config.get("name")
            )

            return True

        except Exception as e:
            self.logger.error(
                "Failed to deploy rule",
                error=str(e)
            )
            return False

    def deploy_rules_batch(
        self,
        rules: list[dict[str, Any]]
    ) -> int:
        """
        Deploy multiple rules.

        Args:
            rules: List of rule configurations

        Returns:
            Number of deployed rules
        """
        deployed = 0

        for rule in rules:
            if self.deploy_rule(rule):
                deployed += 1

        self.logger.info("Batch deployment complete", deployed=deployed)
        return deployed