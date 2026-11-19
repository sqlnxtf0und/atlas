"""Locally hosted operator console for ATLAS.

The console is a thin browser front end over the same services the CLI calls: it adds
no capability, and it cannot bypass the scope gate. See :mod:`atlas.web.app`.
"""

from __future__ import annotations

from atlas.web.app import build_api, create_app

__all__ = ["build_api", "create_app"]
