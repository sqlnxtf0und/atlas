"""ATLAS command-line entry point.

Exit codes are part of the public contract (see ``docs/CLI.md``). Every failure
is rendered once, in the mode the operator asked for, and mapped to a stable code.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated

import click
import typer
from rich.console import Console

from atlas import __version__
from atlas.cli.commands import register
from atlas.cli.context import AppContext, current_context, set_context
from atlas.config import load_settings
from atlas.errors import (
    EXIT_CANCELLED,
    EXIT_ERROR,
    EXIT_OK,
    AtlasError,
    ConfigurationError,
)
from atlas.logging import configure_logging, get_logger

__all__ = ["app", "main"]

log = get_logger("cli")

app = typer.Typer(
    name="atlas",
    help="ATLAS — Advanced Threat & Infrastructure Intelligence System.",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
)


def _show_version(value: bool) -> None:
    if value:
        typer.echo(f"atlas {__version__}")
        raise typer.Exit()


@app.callback()
def root(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            help=(
                "YAML configuration file (default: ./atlas.yaml, then ~/.config/atlas/atlas.yaml)."
            ),
        ),
    ] = None,
    db_url: Annotated[
        str | None, typer.Option("--db-url", help="Override the database URL.")
    ] = None,
    project: Annotated[
        str, typer.Option("--project", "-p", help="Active project slug.")
    ] = "default",
    json_output: Annotated[
        bool, typer.Option("--json", help="Machine-readable output on stdout.")
    ] = False,
    log_level: Annotated[
        str | None, typer.Option("--log-level", help="debug|info|warning|error")
    ] = None,
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
    version: Annotated[
        bool,
        typer.Option("--version", callback=_show_version, is_eager=True, help="Print version."),
    ] = False,
) -> None:
    """Global options. Every command inherits them."""

    del version  # handled by the eager callback

    explicit = Path(config).expanduser() if config is not None else None
    if explicit is not None and not explicit.is_file() and ctx.invoked_subcommand != "init":
        raise ConfigurationError(f"configuration file not found: {explicit}")

    settings = load_settings(explicit if explicit and explicit.is_file() else None)

    overrides: dict[str, object] = {}
    if db_url:
        overrides["database"] = settings.database.model_copy(update={"url": db_url})
    if log_level:
        level = log_level.lower()
        if level not in {"debug", "info", "warning", "error"}:
            raise ConfigurationError(f"invalid log level: {log_level}")
        overrides["logging"] = settings.logging.model_copy(update={"level": level})
    if overrides:
        settings = settings.model_copy(update=overrides)

    configure_logging(settings)

    context = AppContext(
        settings=settings,
        console=Console(no_color=no_color, highlight=False),
        error_console=Console(stderr=True, no_color=no_color, highlight=False),
        json_output=json_output,
        project_slug=project,
        actor="cli",
        config_path=explicit,
    )
    set_context(context)
    ctx.obj = context
    ctx.call_on_close(context.close)


register(app)


def main(argv: list[str] | None = None) -> None:
    """Console entry point with a single error boundary.

    Click returns the exit code instead of raising when ``standalone_mode`` is
    disabled, so the returned value is honoured here — otherwise a command that
    exits non-zero would still look successful to the shell.
    """

    code = EXIT_OK
    try:
        result = app(args=argv, standalone_mode=False)
        if result is not None:
            code = int(result)
    except click.exceptions.Exit as exc:
        raise SystemExit(exc.exit_code) from None
    except click.exceptions.Abort:
        raise SystemExit(EXIT_CANCELLED) from None
    except click.ClickException as exc:
        exc.show()
        raise SystemExit(exc.exit_code) from None
    except AtlasError as exc:
        _render_atlas_error(exc)
        raise SystemExit(exc.exit_code) from None
    except KeyboardInterrupt:
        _render_line("cancelled", "operation cancelled by operator")
        raise SystemExit(EXIT_CANCELLED) from None
    except Exception as exc:
        log.exception("unhandled error")
        _render_line("internal error", f"{type(exc).__name__}: {exc}")
        raise SystemExit(EXIT_ERROR) from None
    finally:
        set_context(None)
    raise SystemExit(code)


def _render_atlas_error(error: AtlasError) -> None:
    context = current_context()
    if context is not None and context.json_output:
        sys.stdout.write(json.dumps(error.as_dict(), default=str) + "\n")
        sys.stdout.flush()
        return
    _render_line(error.slug.replace("_", " "), error.message)


def _render_line(label: str, message: str) -> None:
    context = current_context()
    console = context.error_console if context is not None else Console(stderr=True)
    console.print(f"[red]{label}[/red] {message}")


if __name__ == "__main__":  # pragma: no cover
    main()
