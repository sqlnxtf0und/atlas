"""CLI command registration."""

from __future__ import annotations

import typer

from atlas.cli.commands import (
    assets,
    audit,
    certs,
    collect,
    config,
    db,
    dns,
    http,
    init,
    project,
    scope,
    serve,
    sources,
    version,
)

__all__ = ["register"]


def register(app: typer.Typer) -> None:
    app.command("init")(init.init)
    app.command("version")(version.version)
    app.command("discover")(collect.discover_command)
    app.command("collect")(collect.collect_command)
    app.command("serve")(serve.serve)

    app.add_typer(project.app, name="project")
    app.add_typer(scope.app, name="scope")
    app.add_typer(assets.app, name="assets")
    app.add_typer(dns.app, name="dns")
    app.add_typer(certs.app, name="certs")
    app.add_typer(http.app, name="http")
    app.add_typer(sources.app, name="sources")
    app.add_typer(audit.app, name="audit")
    app.add_typer(db.app, name="db")
    app.add_typer(config.app, name="config")
