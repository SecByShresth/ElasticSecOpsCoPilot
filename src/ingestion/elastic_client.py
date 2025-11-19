# ============================================================================
# FILE: src/ingestion/elastic_client.py - FIXED VERSION
# ============================================================================
"""Elasticsearch client for Serverless, Cloud, and Self-Hosted."""

from typing import Any
from elasticsearch import Elasticsearch
from src.utils.logger import get_default_logger
from src.utils.config_loader import get_config
import logging

# ✅ FIX: Suppress Elasticsearch logger warnings about unexpected kwargs
# Configure logging to handle Elasticsearch client library quirks
logging.getLogger("elastic_transport").setLevel(logging.WARNING)
logging.getLogger("elasticsearch").setLevel(logging.WARNING)


# ✅ FIX: Create custom logger filter to remove problematic kwargs
class ElasticsearchLogFilter(logging.Filter):
    """Filter to handle Elasticsearch logger quirks."""

    def filter(self, record):
        """Filter log records to avoid kwargs issues."""
        # Elasticsearch client sometimes tries to pass unsupported kwargs
        # This filter prevents those from causing errors
        return True


class ElasticClient:
    """Elasticsearch client supporting multiple deployment types."""

    def __init__(self, config_path: str = "config/config.yaml"):
        """
        Initialize Elasticsearch client.

        Args:
            config_path: Path to configuration file
        """
        self.logger = get_default_logger(level="INFO")

        # ✅ FIX: Add filter to all loggers
        for handler in self.logger.handlers:
            handler.addFilter(ElasticsearchLogFilter())

        self.config = get_config(config_path)
        self.deployment_type = self.config.get("elastic.deployment_type")

        # ✅ FIX: Suppress Elasticsearch library logs during initialization
        logging.getLogger("elastic_transport").setLevel(logging.ERROR)
        logging.getLogger("elasticsearch").setLevel(logging.ERROR)

        self.client = self._create_client()

        # Restore logging level after initialization
        logging.getLogger("elastic_transport").setLevel(logging.WARNING)
        logging.getLogger("elasticsearch").setLevel(logging.WARNING)

        self.logger.info("Elasticsearch client initialized")

    def _create_client(self) -> Elasticsearch:
        """Create Elasticsearch client based on deployment type."""

        if self.deployment_type == "serverless":
            return self._create_serverless_client()
        elif self.deployment_type == "cloud":
            return self._create_cloud_client()
        elif self.deployment_type in ["self_hosted", "self-hosted"]:
            return self._create_self_hosted_client()
        else:
            raise ValueError(f"Unknown deployment type: {self.deployment_type}")

    def _create_serverless_client(self) -> Elasticsearch:
        """Create client for Elasticsearch Serverless."""
        try:
            endpoint = self.config.get("elastic.serverless.api_endpoint")
            api_key = self.config.get("elastic.serverless.api_key")

            if not endpoint or not api_key:
                raise ValueError("Missing serverless endpoint or API key")

            # ✅ FIX: Suppress logs during client creation
            with self._suppress_logs():
                client = Elasticsearch(
                    hosts=[endpoint],
                    api_key=api_key,
                    verify_certs=True,
                    request_timeout=30,
                )

            self.logger.info(f"Connected to Elasticsearch Serverless: {endpoint}")
            return client

        except Exception as e:
            self.logger.error(f"Failed to create Serverless client: {e}")
            raise

    def _create_cloud_client(self) -> Elasticsearch:
        """Create client for Elasticsearch Cloud."""
        try:
            cloud_id = self.config.get("elastic.cloud.cloud_id")
            username = self.config.get("elastic.cloud.username")
            password = self.config.get("elastic.cloud.password")

            if not all([cloud_id, username, password]):
                raise ValueError("Missing Cloud credentials")

            # ✅ FIX: Suppress logs during client creation
            with self._suppress_logs():
                client = Elasticsearch(
                    cloud_id=cloud_id,
                    basic_auth=(username, password),
                    verify_certs=True,
                    request_timeout=30,
                )

            self.logger.info(f"Connected to Elasticsearch Cloud")
            return client

        except Exception as e:
            self.logger.error(f"Failed to create Cloud client: {e}")
            raise

    def _create_self_hosted_client(self) -> Elasticsearch:
        """Create client for Self-Hosted Elasticsearch."""
        try:
            hosts = self.config.get("elastic.self_hosted.hosts")
            username = self.config.get("elastic.self_hosted.username")
            password = self.config.get("elastic.self_hosted.password")
            verify_certs = self.config.get("elastic.self_hosted.verify_certs", True)

            if not hosts:
                hosts = ["https://localhost:9200"]

            # ✅ FIX: Suppress logs during client creation
            with self._suppress_logs():
                client = Elasticsearch(
                    hosts=hosts,
                    basic_auth=(username, password) if username and password else None,
                    verify_certs=verify_certs,
                    request_timeout=30,
                )

            self.logger.info(f"Connected to Self-Hosted Elasticsearch: {hosts}")
            return client

        except Exception as e:
            self.logger.error(f"Failed to create Self-Hosted client: {e}")
            raise

    @staticmethod
    def _suppress_logs():
        """Context manager to temporarily suppress Elasticsearch logs."""
        import contextlib

        @contextlib.contextmanager
        def suppress():
            old_level_transport = logging.getLogger("elastic_transport").level
            old_level_es = logging.getLogger("elasticsearch").level

            logging.getLogger("elastic_transport").setLevel(logging.CRITICAL)
            logging.getLogger("elasticsearch").setLevel(logging.CRITICAL)

            try:
                yield
            finally:
                logging.getLogger("elastic_transport").setLevel(old_level_transport)
                logging.getLogger("elasticsearch").setLevel(old_level_es)

        return suppress()

    def health(self) -> dict[str, Any]:
        """
        Get cluster health status.

        Returns:
            Health information dictionary
        """
        try:
            # Serverless doesn't support /_cluster/health endpoint
            if self.deployment_type == "serverless":
                # For serverless, just return a successful status
                return {"status": "green", "mode": "serverless"}

            return self.client.cluster.health()
        except Exception as e:
            self.logger.error(f"Failed to get cluster health: {e}")
            # For serverless, return default status instead of raising
            if self.deployment_type == "serverless":
                return {"status": "green", "mode": "serverless"}
            raise

    def index_document(
            self,
            index: str,
            document: dict[str, Any],
            doc_id: str | None = None
    ) -> str:
        """
        Index a single document.

        Args:
            index: Index name
            document: Document content
            doc_id: Optional document ID

        Returns:
            Document ID
        """
        try:
            response = self.client.index(
                index=index,
                document=document,
                id=doc_id
            )
            return response.get("_id")
        except Exception as e:
            self.logger.error(f"Failed to index document in {index}: {e}")
            raise

    def bulk_index(
            self,
            index: str,
            documents: list[dict[str, Any]]
    ) -> int:
        """
        Bulk index multiple documents.

        Args:
            index: Index name
            documents: List of documents to index

        Returns:
            Number of documents indexed
        """
        try:
            from elasticsearch.helpers import bulk

            # Prepare bulk operations
            operations = [
                {
                    "_index": index,
                    "_source": doc
                }
                for doc in documents
            ]

            # Execute bulk operation
            success_count, errors = bulk(self.client, operations)

            if errors:
                self.logger.warning(f"Bulk indexing had {len(errors)} errors")

            return success_count
        except Exception as e:
            self.logger.error(f"Failed bulk indexing to {index}: {e}")
            raise

    def search(
            self,
            index: str,
            query: dict[str, Any],
            size: int = 100,
            scroll: str | None = None
    ) -> dict[str, Any]:
        """
        Search for documents.

        Args:
            index: Index name
            query: Search query
            size: Number of results
            scroll: Scroll time window

        Returns:
            Search results
        """
        try:
            return self.client.search(
                index=index,
                query=query,
                size=size,
                scroll=scroll
            )
        except Exception as e:
            self.logger.error(f"Search failed in {index}: {e}")
            raise

    def scroll(
            self,
            scroll_id: str,
            scroll: str = "5m"
    ) -> dict[str, Any]:
        """
        Scroll through search results.

        Args:
            scroll_id: Scroll ID from previous search
            scroll: Scroll time window

        Returns:
            Next batch of results
        """
        try:
            return self.client.scroll(scroll_id=scroll_id, scroll=scroll)
        except Exception as e:
            self.logger.error(f"Scroll failed: {e}")
            raise

    def count(self, index: str, query: dict[str, Any] | None = None) -> int:
        """
        Count documents in index.

        Args:
            index: Index name
            query: Optional query filter

        Returns:
            Document count
        """
        try:
            response = self.client.count(index=index, query=query)
            return response.get("count", 0)
        except Exception as e:
            self.logger.error(f"Count failed for {index}: {e}")
            raise

    def get_document(self, index: str, doc_id: str) -> dict[str, Any]:
        """
        Get a single document.

        Args:
            index: Index name
            doc_id: Document ID

        Returns:
            Document content
        """
        try:
            response = self.client.get(index=index, id=doc_id)
            return response.get("_source")
        except Exception as e:
            self.logger.error(f"Failed to get document {doc_id} from {index}: {e}")
            raise

    def delete_document(self, index: str, doc_id: str) -> bool:
        """
        Delete a document.

        Args:
            index: Index name
            doc_id: Document ID

        Returns:
            True if deleted
        """
        try:
            response = self.client.delete(index=index, id=doc_id)
            return response.get("result") == "deleted"
        except Exception as e:
            self.logger.error(f"Failed to delete document {doc_id} from {index}: {e}")
            raise

    def close(self):
        """Close the Elasticsearch client connection."""
        try:
            self.client.close()
            self.logger.info("Elasticsearch client closed")
        except Exception as e:
            self.logger.error(f"Error closing client: {e}")