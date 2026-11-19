"""``atlas config`` — inspect effective configuration."""

from __future__ import annotations

import typer
import yaml

from atlas.cli.context import AppContext
from atlas.cli.ui import emit

__all__ = ["app"]

app = typer.Typer(help="Inspect effective configuration.", no_args_is_help=True)


@app.command("show")
def show(ctx: typer.Context) -> None:
    """Print the effective configuration with secrets redacted."""

    context: AppContext = ctx.obj
    payload = context.settings.redacted()

    emit(context, payload)
    if context.json_output:
        return
    context.console.print(
        yaml.safe_dump(payload, sort_keys=False, default_flow_style=False).rstrip()
    )
