"""
Logging configuration for Elastic SecOps Copilot.
Updated so that:
- No logs go to console (prevents PowerShell termination)
- All logs go to logs/esc_service.log
- structlog JSON output stored in file only
- setup_logging() restored for backward compatibility
"""

import logging
from pathlib import Path
from typing import Any, Optional
import structlog
from pythonjsonlogger import jsonlogger

DEFAULT_LOG_PATH = "logs/esc_service.log"


class LoggerConfig:
    """Centralized logging configuration."""

    def __init__(
        self,
        name: str = "secops-copilot",
        level: str = "INFO",
        log_format: str = "json",
        log_file: Optional[str] = DEFAULT_LOG_PATH,
        max_bytes: int = 104857600,
        backup_count: int = 10,
        console_output: bool = False,   # FORCE OFF
    ):
        self.name = name
        self.level = getattr(logging, level.upper())
        self.log_format = log_format
        self.log_file = log_file or DEFAULT_LOG_PATH
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.console_output = False  # FORCE OFF ALWAYS

        self.logger = self._setup_logger()

    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger(self.name)
        logger.setLevel(self.level)
        logger.handlers.clear()

        # structlog JSON configuration
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.processors.JSONRenderer(),
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )

        # ----- FILE HANDLER ONLY -----
        log_path = Path(self.log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(self.level)

        if self.log_format == "json":
            formatter = jsonlogger.JsonFormatter()
        else:
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )

        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        return logger

    def get_logger(self) -> logging.Logger:
        return self.logger


# GLOBAL DEFAULT LOGGER
_default_logger: Optional[logging.Logger] = None


def get_default_logger(
    level: str = "INFO",
    log_file: Optional[str] = DEFAULT_LOG_PATH,
) -> logging.Logger:
    global _default_logger
    if _default_logger is None:
        config = LoggerConfig(
            level=level,
            log_file=log_file,
            console_output=False,
        )
        _default_logger = config.get_logger()
    return _default_logger


# -------------------------------
# RESTORED setup_logging() FOR COMPATIBILITY
# -------------------------------

def setup_logging(config_dict: dict) -> logging.Logger:
    """
    Project compatibility function — older modules import this.
    It now simply wraps LoggerConfig safely.
    """
    cfg = LoggerConfig(
        name=config_dict.get("name", "secops-copilot"),
        level=config_dict.get("level", "INFO"),
        log_format=config_dict.get("format", "json"),
        log_file=config_dict.get("file", DEFAULT_LOG_PATH),
        max_bytes=config_dict.get("max_file_size_mb", 100) * 1024 * 1024,
        backup_count=config_dict.get("backup_count", 10),
        console_output=False,   # ALWAYS OFF
    )
    return cfg.get_logger()


# -------------------------------
# Exception helper
# -------------------------------

def log_exception(logger: logging.Logger, exc: Exception, context: Optional[str] = None):
    msg = f"Exception occurred: {exc}"
    if context:
        msg = f"{context}: {msg}"
    logger.exception(msg)
