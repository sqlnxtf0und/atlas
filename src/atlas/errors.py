"""Typed error hierarchy.

Every error that can reach an operator carries a stable exit code so scripts and
automation can branch on outcome instead of parsing prose. Exit codes are part of
the CLI contract documented in ``docs/CLI.md``.
"""

from __future__ import annotations

from typing import Any, Final

__all__ = [
    "EXIT_CANCELLED",
    "EXIT_CONFIG",
    "EXIT_CONFLICT",
    "EXIT_DATABASE",
    "EXIT_ERROR",
    "EXIT_NOT_FOUND",
    "EXIT_OK",
    "EXIT_SCOPE_VIOLATION",
    "EXIT_USAGE",
    "AtlasError",
    "AuthorizationError",
    "ConfigurationError",
    "ConflictError",
    "DatabaseError",
    "NotFoundError",
    "OperationCancelled",
    "ScopeViolation",
    "ValidationError",
    "exit_code_for",
]

EXIT_OK: Final[int] = 0
EXIT_ERROR: Final[int] = 1
EXIT_USAGE: Final[int] = 2
EXIT_SCOPE_VIOLATION: Final[int] = 3
EXIT_NOT_FOUND: Final[int] = 4
EXIT_CONFLICT: Final[int] = 5
EXIT_CONFIG: Final[int] = 6
EXIT_DATABASE: Final[int] = 7
EXIT_CANCELLED: Final[int] = 8


class AtlasError(Exception):
    """Base class for all ATLAS-raised errors."""

    exit_code: int = EXIT_ERROR
    slug: str = "error"

    def __init__(self, message: str, *, context: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.context: dict[str, Any] = dict(context or {})

    def as_dict(self) -> dict[str, Any]:
        return {
            "error": self.slug,
            "message": self.message,
            "context": self.context,
            "exit_code": self.exit_code,
        }

    def __str__(self) -> str:
        return self.message


class ConfigurationError(AtlasError):
    """Configuration is missing, malformed, or internally inconsistent."""

    exit_code = EXIT_CONFIG
    slug = "configuration_error"


class ValidationError(AtlasError):
    """Operator input failed validation before any work was attempted."""

    exit_code = EXIT_USAGE
    slug = "validation_error"


class ScopeViolation(AtlasError):
    """A value is not covered by the project's active authorized scope.

    This is raised *before* any network operation. It is never a warning and
    never downgraded to a soft failure: callers must let it propagate.
    """

    exit_code = EXIT_SCOPE_VIOLATION
    slug = "scope_violation"


class AuthorizationError(AtlasError):
    """The caller is not permitted to perform this action (role/credential)."""

    exit_code = EXIT_SCOPE_VIOLATION
    slug = "authorization_error"


class NotFoundError(AtlasError):
    """A requested resource does not exist."""

    exit_code = EXIT_NOT_FOUND
    slug = "not_found"


class ConflictError(AtlasError):
    """A create would violate a uniqueness constraint."""

    exit_code = EXIT_CONFLICT
    slug = "conflict"


class DatabaseError(AtlasError):
    """Database connectivity or schema state prevents the operation."""

    exit_code = EXIT_DATABASE
    slug = "database_error"


class OperationCancelled(AtlasError):
    """The operator cancelled the operation."""

    exit_code = EXIT_CANCELLED
    slug = "cancelled"


def exit_code_for(error: BaseException) -> int:
    """Map any exception to the documented process exit code."""

    if isinstance(error, AtlasError):
        return error.exit_code
    return EXIT_ERROR
