"""ASGI entry point for ``uvicorn atlas.web.main:app``.

The console is normally launched with ``atlas serve``, which passes a settings object
it has already resolved. This module exists for the reload path (uvicorn's supervisor
needs an import string) and for operators who want to point a process manager at the
app directly: settings are resolved from the environment and the standard config
search path, exactly as the CLI does.
"""

from __future__ import annotations

import os

from atlas.config import load_settings
from atlas.web.app import create_app

__all__ = ["app"]

app = create_app(load_settings(), project_slug=os.environ.get("ATLAS_PROJECT", "default"))
