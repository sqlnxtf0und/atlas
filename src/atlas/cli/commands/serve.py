"""``atlas serve`` — run the local operator console.

The binding rules are the whole safety story here, so they are enforced in one place
rather than trusted to whoever types the command:

* The default host is ``127.0.0.1``. There is no login on the console.
* Any non-loopback host requires ``--allow-remote``, and prints a warning explaining
  that every write endpoint is then reachable by anyone who can route to it.
* ``--open`` launches the browser once the server is actually accepting connections,
  not on a timer.
"""

from __future__ import annotations

import socket
import threading
import time
import webbrowser
from typing import Annotated, Any

import typer
from rich.console import Console

from atlas.cli.context import current_context
from atlas.errors import ConfigurationError

__all__ = ["LOOPBACK_HOSTS", "is_loopback", "serve"]

#: Hosts that keep the console local. Anything else is a deliberate exposure.
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

_READY_TIMEOUT_SECONDS = 15.0


def is_loopback(host: str) -> bool:
    return host.strip().lower() in LOOPBACK_HOSTS


def _base_url(host: str, port: int) -> str:
    display = "[::1]" if host in {"::1", "0:0:0:0:0:0:0:1"} else host
    return f"http://{display}:{port}/"


def _wait_until_ready(host: str, port: int, deadline: float) -> bool:
    """Poll a TCP connect on ``host``/``port`` until it accepts or ``deadline`` passes."""

    probe_host = "127.0.0.1" if host in {"0.0.0.0", "::", ""} else host
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((probe_host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def _open_when_ready(host: str, port: int, url: str, console: Console) -> None:
    if _wait_until_ready(host, port, time.monotonic() + _READY_TIMEOUT_SECONDS):
        webbrowser.open(url)
    else:  # pragma: no cover - only on a stalled bind
        console.print(f"[yellow]console did not answer in time; open {url} manually[/yellow]")


def serve(
    host: Annotated[
        str,
        typer.Option("--host", help="Bind address. Defaults to loopback only."),
    ] = "127.0.0.1",
    port: Annotated[
        int,
        typer.Option("--port", help="TCP port for the console.", min=1, max=65535),
    ] = 8000,
    open_browser: Annotated[
        bool,
        typer.Option("--open/--no-open", help="Open the console in a browser once it is up."),
    ] = True,
    allow_remote: Annotated[
        bool,
        typer.Option(
            "--allow-remote",
            help="Permit binding a non-loopback address. The console has no authentication.",
        ),
    ] = False,
    reload: Annotated[
        bool,
        typer.Option("--reload", help="Restart on source changes (development only)."),
    ] = False,
) -> None:
    """Serve the local console: scope, collect and read results in a browser."""

    context = current_context()
    if context is None:  # pragma: no cover - only if called outside the CLI
        raise ConfigurationError("serve requires the CLI context")
    console = context.console

    if not is_loopback(host) and not allow_remote:
        raise ConfigurationError(
            f"refusing to bind {host}: the console has no authentication. "
            "Use --host 127.0.0.1, or pass --allow-remote if that exposure is intended.",
            context={"host": host},
        )

    settings = context.settings
    project_slug = context.project_slug
    url = _base_url(host, port)

    if not is_loopback(host):
        console.print(
            f"[yellow]warning[/yellow] console bound to [bold]{host}[/bold]: every write "
            "endpoint (scope, collect) is reachable by anyone who can route here."
        )
    console.print(f"ATLAS console → [bold]{url}[/bold]  (project [bold]{project_slug}[/bold])")
    console.print(f"database: {settings.database.url.split('?', 1)[0]}")

    if open_browser and not reload:
        threading.Thread(
            target=_open_when_ready,
            args=(host, port, url, console),
            daemon=True,
        ).start()

    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover - dependency is pinned
        raise ConfigurationError("uvicorn is not installed; cannot serve the console") from exc

    from atlas.web.app import create_app

    target: Any = create_app(settings, project_slug=project_slug)
    if reload:
        # ``reload`` needs an import string so the supervisor can import the app
        # itself. Settings resolution in the child goes through the environment.
        uvicorn.run(
            "atlas.web.main:app",
            host=host,
            port=port,
            reload=True,
            log_config=None,
        )
        return
    uvicorn.run(target, host=host, port=port, log_config=None)
