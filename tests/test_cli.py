"""End-to-end CLI behaviour through the real error boundary.

These tests drive ``atlas.cli.main.main`` exactly as a shell would, so exit codes
and the JSON/stdout contract are verified rather than assumed. DNS is replaced by
a zone-backed double — no test opens a socket.
"""

from __future__ import annotations

import io
import json
from collections.abc import Callable, Iterator
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from atlas.cli.main import main
from atlas.collect.dns import DnsCollector
from atlas.collect.registry import CollectorRegistry
from atlas.db.enums import JobType
from atlas.errors import (
    EXIT_ERROR,
    EXIT_OK,
    EXIT_SCOPE_VIOLATION,
    EXIT_USAGE,
)
from support import FakeResolver, zone_of

CliRunner = Callable[..., tuple[int, str]]


@pytest.fixture
def cli(tmp_path: Path) -> Iterator[CliRunner]:
    url = f"sqlite+pysqlite:///{tmp_path / 'atlas.db'}"

    def run(*args: str) -> tuple[int, str]:
        out = io.StringIO()
        with (
            redirect_stdout(out),
            redirect_stderr(io.StringIO()),
            pytest.raises(SystemExit) as excinfo,
        ):
            main(["--db-url", url, "--no-color", *args])
        return int(excinfo.value.code or 0), out.getvalue()

    run.url = url  # type: ignore[attr-defined]
    yield run


def json_of(output: str) -> object:
    return json.loads(output)


def bootstrap(cli: CliRunner, tmp_path: Path) -> None:
    code, _ = cli("init", "--config", str(tmp_path / "atlas.yaml"))
    assert code == EXIT_OK


def use_fake_dns(monkeypatch: pytest.MonkeyPatch, resolver: FakeResolver) -> None:
    def fake_registry(**_: object) -> CollectorRegistry:
        registry = CollectorRegistry()
        registry.register(
            DnsCollector.name,
            lambda settings: DnsCollector(settings=settings, resolver=resolver, follow_cnames=True),
            job_type=(JobType.DISCOVER, JobType.DNS),
        )
        return registry

    monkeypatch.setattr("atlas.services.discovery.default_registry", fake_registry)


def test_init_then_assets_list_is_empty(cli: CliRunner, tmp_path: Path) -> None:
    bootstrap(cli, tmp_path)
    code, output = cli("--json", "assets", "list")
    assert code == EXIT_OK
    assert json_of(output) == []


def test_init_is_idempotent_only_when_config_exists(cli: CliRunner, tmp_path: Path) -> None:
    bootstrap(cli, tmp_path)
    config = tmp_path / "atlas.yaml"
    code, _ = cli("init", "--config", str(config))
    assert code == 6  # refuses to overwrite the configuration without --force

    code, _ = cli("init", "--config", str(config), "--force")
    assert code == EXIT_OK
    assert config.is_file()


def test_scope_add_and_list(cli: CliRunner, tmp_path: Path) -> None:
    bootstrap(cli, tmp_path)

    code, output = cli("--json", "scope", "add", "example.com")
    assert code == EXIT_OK
    payload = json_of(output)
    assert isinstance(payload, dict)
    assert payload["pattern"] == "example.com"
    assert payload["mode"] == "include"

    code, output = cli("--json", "scope", "list")
    assert code == EXIT_OK
    rules = json_of(output)
    assert isinstance(rules, list) and len(rules) == 1


def test_duplicate_scope_rule_is_a_conflict(cli: CliRunner, tmp_path: Path) -> None:
    bootstrap(cli, tmp_path)
    cli("scope", "add", "example.com")
    code, output = cli("--json", "scope", "add", "example.com")
    assert code == 5
    assert json_of(output)["error"] == "conflict"


def test_discovery_outside_scope_exits_with_scope_violation(cli: CliRunner, tmp_path: Path) -> None:
    bootstrap(cli, tmp_path)
    code, output = cli("--json", "discover", "example.com")
    assert code == EXIT_SCOPE_VIOLATION
    payload = json_of(output)
    assert payload["error"] == "scope_violation"
    assert "outside the authorized scope" in payload["message"]


def test_collect_dry_run_reports_the_decision(cli: CliRunner, tmp_path: Path) -> None:
    bootstrap(cli, tmp_path)
    cli("scope", "add", "example.com")

    code, output = cli("--json", "collect", "example.com", "--dry-run")
    assert code == EXIT_OK
    payload = json_of(output)
    assert payload["permitted"] is True
    assert payload["collection_value"] == "example.com"

    code, output = cli("--json", "collect", "outside.example", "--dry-run")
    assert code == EXIT_ERROR
    assert json_of(output)["permitted"] is False


def test_discover_persists_and_renders(
    cli: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bootstrap(cli, tmp_path)
    cli("scope", "add", "example.com")
    use_fake_dns(
        monkeypatch,
        zone_of(
            {
                "example.com": {
                    "A": ["203.0.113.10"],
                    "NS": ["ns1.registrar.example."],
                    "TXT": ['"v=spf1 -all"'],
                }
            }
        ),
    )

    code, output = cli("--json", "discover", "example.com")
    assert code == EXIT_OK
    payload = json_of(output)
    assert payload["status"] == "succeeded"
    assert payload["target"] == "example.com"
    assert payload["observations"] == 3
    assert payload["dns"]["active_records"] == 3
    assert payload["dns"]["addresses"] == ["203.0.113.10"]

    code, output = cli("--json", "assets", "list")
    kinds = {asset["kind"] for asset in json_of(output)}
    assert kinds == {"domain", "ip"}


def test_dns_show_and_history(
    cli: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bootstrap(cli, tmp_path)
    cli("scope", "add", "example.com")
    use_fake_dns(monkeypatch, zone_of({"example.com": {"A": ["203.0.113.10"]}}))
    cli("discover", "example.com")

    code, output = cli("--json", "dns", "show", "example.com")
    assert code == EXIT_OK
    records = json_of(output)["records"]
    assert [(r["record_type"], r["value"]) for r in records] == [("A", "203.0.113.10")]

    code, output = cli("--json", "dns", "history", "example.com")
    assert code == EXIT_OK
    history = json_of(output)
    assert history["active"] == 1
    assert history["retired"] == 0


def test_dns_history_for_unknown_name_is_usage_error(cli: CliRunner, tmp_path: Path) -> None:
    bootstrap(cli, tmp_path)
    code, output = cli("--json", "dns", "history", "ghost.example.com")
    assert code == EXIT_USAGE
    assert json_of(output)["error"] == "validation_error"


def test_dns_dangling_reports_evidence(
    cli: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bootstrap(cli, tmp_path)
    cli("scope", "add", "example.com")
    cli("scope", "add", "www.example.com")
    use_fake_dns(monkeypatch, zone_of({"www.example.com": {"CNAME": ["gone.example.net."]}}))
    cli("discover", "www.example.com")

    code, output = cli("--json", "dns", "dangling")
    assert code == EXIT_OK
    findings = json_of(output)
    assert len(findings) == 1
    assert findings[0]["target"] == "gone.example.net"
    assert findings[0]["indicator"] == "cname_target_nxdomain"


def test_asset_show_reports_domain_detail(
    cli: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bootstrap(cli, tmp_path)
    cli("scope", "add", "example.com")
    use_fake_dns(monkeypatch, zone_of({"example.com": {"A": ["203.0.113.10"]}}))
    cli("discover", "example.com")

    code, output = cli("--json", "assets", "show", "example.com")
    assert code == EXIT_OK
    payload = json_of(output)
    assert payload["domain"]["fqdn"] == "example.com"
    assert payload["domain"]["record_count"] == 1
    assert payload["relationships"]["out"] == 1


def test_unknown_asset_is_not_found(cli: CliRunner, tmp_path: Path) -> None:
    bootstrap(cli, tmp_path)
    code, output = cli("--json", "assets", "show", "ghost.example.com")
    assert code == 4
    assert json_of(output)["error"] == "not_found"


def test_bad_option_is_a_usage_error(cli: CliRunner, tmp_path: Path) -> None:
    bootstrap(cli, tmp_path)
    code, _ = cli("collect", "example.com", "--type", "nonsense")
    assert code == EXIT_USAGE


def test_audit_trail_records_denial(
    cli: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bootstrap(cli, tmp_path)
    use_fake_dns(monkeypatch, FakeResolver())
    cli("discover", "denied.example.com")

    code, output = cli("--json", "audit", "list")
    assert code == EXIT_OK
    actions = {event["action"] for event in json_of(output)}
    assert "discovery.denied" in actions
