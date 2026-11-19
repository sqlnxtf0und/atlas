"""ATLAS command-line interface."""

from __future__ import annotations

__all__ = ["main"]


def main() -> None:
    from atlas.cli.main import main as _main

    _main()
