"""``atlas init`` — first-run bootstrap."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from atlas.cli.context import AppContext
from atlas.cli.ui import emit, info, success
from atlas.services.bootstrap import init_workspace

__all__ = ["init"]


def init(
    ctx: typer.Context,
    force: Annotated[
        bool, typer.Option("--force", help="Overwrite an existing configuration file.")
    ] = False,
    config: Annotated[
        Path | None,
        typer.Option("--config", help="Where to write the configuration file."),
    ] = None,
) -> None:
    """Create configuration, apply migrations and create the default project."""

    context: AppContext = ctx.obj
    target = config or context.config_path or Path("atlas.yaml")

    summary = init_workspace(context.settings, config_path=target, force=force)

    emit(context, summary)
    if context.json_output:
        return

    if summary["config_path"]:
        success(context, f"configuration written: {summary['config_path']}")
    else:
        info(context, "configuration already present; left untouched")
    success(context, f"schema migrated ({summary['database_url']})")
    if summary["project"]:
        verb = "created" if summary["project_created"] else "present"
        success(context, f"project '{summary['project']}' {verb}")
    info(context, "next: atlas scope add <domain>, then atlas assets list")
