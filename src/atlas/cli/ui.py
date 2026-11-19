"""Rich rendering helpers. JSON mode is always available and always clean."""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable, Sequence
from typing import Any

from rich import box
from rich.table import Table
from rich.text import Text

from atlas.cli.context import AppContext
from atlas.db.enums import FindingSeverity

__all__ = [
    "emit",
    "info",
    "print_table",
    "severity_text",
    "success",
    "warn",
]

_SEVERITY_STYLES: dict[FindingSeverity, str] = {
    FindingSeverity.CRITICAL: "bold white on red",
    FindingSeverity.HIGH: "bold red",
    FindingSeverity.MEDIUM: "yellow",
    FindingSeverity.LOW: "cyan",
    FindingSeverity.INFO: "dim",
}


def emit(context: AppContext, payload: Any, *, title: str | None = None) -> None:
    """Write machine output (JSON mode) or nothing (the caller renders a table)."""

    if not context.json_output:
        if title:
            context.console.print(f"[bold]{title}[/bold]")
        return
    sys.stdout.write(json.dumps(payload, indent=2, default=str, sort_keys=False) + "\n")
    sys.stdout.flush()


def print_table(
    context: AppContext,
    *,
    title: str,
    columns: Sequence[str],
    rows: Iterable[Sequence[Any]],
    empty: str = "no rows",
) -> None:
    """Render a dense table. In JSON mode the caller must use :func:`emit` instead."""

    table = Table(
        title=title,
        box=box.SIMPLE_HEAD,
        show_edge=False,
        pad_edge=False,
        header_style="bold",
        title_justify="left",
    )
    for column in columns:
        table.add_column(column, overflow="fold")
    count = 0
    for row in rows:
        table.add_row(*[cell if isinstance(cell, Text) else str(cell) for cell in row])
        count += 1
    if count == 0:
        context.console.print(f"[dim]{empty}[/dim]")
        return
    context.console.print(table)


def severity_text(severity: FindingSeverity | str) -> Text:
    value = FindingSeverity(str(severity))
    return Text(value.value.upper(), style=_SEVERITY_STYLES[value])


def success(context: AppContext, message: str) -> None:
    context.console.print(f"[green]✓[/green] {message}")


def info(context: AppContext, message: str) -> None:
    context.console.print(f"[dim]·[/dim] {message}")


def warn(context: AppContext, message: str) -> None:
    context.error_console.print(f"[yellow]![/yellow] {message}")
