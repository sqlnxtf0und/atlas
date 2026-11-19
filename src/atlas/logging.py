"""Structured logging.

Two renderers share one redaction filter:

* ``json`` — one JSON object per line on stderr, for log shippers.
* ``console`` — human-readable ``ts level logger message`` lines on stderr.

Nothing is ever logged to stdout: stdout belongs to command output so that
``atlas --json ... | jq`` stays clean.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import time
from typing import Any, Final

from atlas.config import LoggingSettings, Settings

__all__ = [
    "configure_logging",
    "get_logger",
    "redact",
    "set_level",
]

_CONFIGURED: bool = False
_SECRET_PATTERNS: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    (
        re.compile(r"(?i)(\b(?:password|passwd|secret|token|api[_-]?key|apikey)\b\s*[=:]\s*)(\S+)"),
        r"\1***",
    ),
    (re.compile(r"(?i)((?:authorization|cookie)\s*[=:]\s*)([^\s,;]+)"), r"\1***"),
    (re.compile(r"(//[^/\s:@]+:)([^/\s@]+)(@)"), r"\1***\3"),
)


def redact(text: str) -> str:
    """Mask credential-shaped substrings in a free-form string."""

    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class _RedactionFilter(logging.Filter):
    def __init__(self, keys: tuple[str, ...]) -> None:
        super().__init__()
        self._keys = {key.lower() for key in keys}

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        if record.args:
            record.args = tuple(redact(arg) if isinstance(arg, str) else arg for arg in record.args)
        extra = getattr(record, "atlas", None)
        if isinstance(extra, dict):
            record.atlas = {
                key: ("***" if key.lower() in self._keys else value) for key, value in extra.items()
            }
        return True


class _JsonFormatter(logging.Formatter):
    def __init__(self, redact_keys: tuple[str, ...]) -> None:
        super().__init__()
        self._redact_keys = redact_keys

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": redact(record.getMessage()),
        }
        extra = getattr(record, "atlas", None)
        if isinstance(extra, dict):
            payload.update(
                {
                    key: ("***" if key.lower() in self._redact_keys else value)
                    for key, value in extra.items()
                }
            )
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=False)


class _ConsoleFormatter(logging.Formatter):
    def __init__(self, redact_keys: tuple[str, ...]) -> None:
        super().__init__()
        self._redact_keys = {key.lower() for key in redact_keys}

    def format(self, record: logging.LogRecord) -> str:
        stamp = time.strftime("%H:%M:%S", time.localtime(record.created))
        message = redact(record.getMessage())
        line = f"{stamp} {record.levelname.lower():<7} {record.name:<28} {message}"
        extra = getattr(record, "atlas", None)
        if isinstance(extra, dict) and extra:
            rendered = " ".join(
                f"{key}={'***' if key.lower() in self._redact_keys else value}"
                for key, value in extra.items()
            )
            line = f"{line}  [{rendered}]"
        if record.exc_info:
            line = f"{line}\n{self.formatException(record.exc_info)}"
        return line


def configure_logging(settings: Settings | LoggingSettings) -> None:
    """Install handlers on the ``atlas`` logger tree. Idempotent."""

    global _CONFIGURED

    log_settings = settings.logging if isinstance(settings, Settings) else settings
    root = logging.getLogger("atlas")
    level = getattr(logging, log_settings.level.upper(), logging.INFO)

    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(
        _JsonFormatter(log_settings.redact_keys)
        if log_settings.json
        else _ConsoleFormatter(log_settings.redact_keys)
    )
    handler.addFilter(_RedactionFilter(log_settings.redact_keys))
    root.addHandler(handler)
    root.setLevel(level)
    root.propagate = False

    # Third-party libraries stay at warning unless we are debugging.
    for noisy in ("httpx", "httpcore", "urllib3", "asyncio", "sqlalchemy.engine"):
        logging.getLogger(noisy).setLevel(
            logging.WARNING if level > logging.DEBUG else logging.INFO
        )

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced logger (``atlas.<name>``)."""

    if name.startswith("atlas."):
        return logging.getLogger(name)
    return logging.getLogger(f"atlas.{name}")


def set_level(level: str) -> None:
    """Change the level of the ``atlas`` logger tree at runtime."""

    logging.getLogger("atlas").setLevel(getattr(logging, level.upper(), logging.INFO))
