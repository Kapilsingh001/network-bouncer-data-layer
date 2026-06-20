"""Centralised logging configuration for the Network Bouncer data layer.

A single, consistently-formatted logger is used across every module so that
parsing, cleaning, profiling and aggregation steps all emit traceable,
greppable output. This is intentionally dependency-free (stdlib only) so it can
be dropped into any environment without extra installs.
"""

from __future__ import annotations

import logging
import sys
from typing import Optional

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Track configured loggers so we never attach duplicate handlers (which would
# otherwise produce repeated log lines when modules are re-imported).
_configured: set[str] = set()


def get_logger(name: str = "network_bouncer", level: int = logging.INFO) -> logging.Logger:
    """Return a configured, singleton logger for the given name.

    Parameters
    ----------
    name:
        Logical name of the logger, usually the module name.
    level:
        Logging threshold (defaults to ``logging.INFO``).

    Returns
    -------
    logging.Logger
        A logger that writes to stdout with a consistent format.
    """
    logger = logging.getLogger(name)

    if name not in _configured:
        logger.setLevel(level)
        handler = logging.StreamHandler(stream=sys.stdout)
        handler.setLevel(level)
        handler.setFormatter(logging.Formatter(fmt=_LOG_FORMAT, datefmt=_DATE_FORMAT))
        logger.addHandler(handler)
        # Prevent log records from bubbling up to the root logger and being
        # printed twice when the host application also configures logging.
        logger.propagate = False
        _configured.add(name)

    return logger


def set_global_level(level: int, name: Optional[str] = None) -> None:
    """Adjust the verbosity of an existing logger at runtime."""
    logger = logging.getLogger(name or "network_bouncer")
    logger.setLevel(level)
    for handler in logger.handlers:
        handler.setLevel(level)
