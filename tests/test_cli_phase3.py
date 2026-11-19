"""``atlas certs``, ``atlas http`` and ``atlas sources urlscan`` through the real CLI.

The collectors are replaced at the registry boundary, so the commands, persistence
and rendering are all exercised while nothing opens a socket. Every assertion runs
against the JSON contract the commands emit under ``--json``.
"""

from __future__ import annotations

import datetime as dt
import io
import json
from collections.abc import Callable, Iterator
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

import httpx
import pytest

from atlas.cli.main import main
from atlas.collect.http import HttpCollector
from atlas.collect.registry import CollectorRegistry
from atlas.collect.tls import CertCollector
from atlas.db.enums import JobType
from atlas.errors import EXIT_CONFIG, EXIT_OK, EXIT_SCOPE_VIOLATION, EXIT_USAGE
from support import make_context  # noqa: F401  (import keeps support importable first)
from test_tls import build_certificate, handshake_for
from test_urlscan import SCAN_ID, result_transport, scan_payload

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


def json_of(output: str) -> Any:
    return json.loads(output)


def bootstrap(cli: CliRunner, tmp_path: Path) -> None:
    code, _ = cli("init", "--config", str(tmp_path / "atlas.yaml"))
    assert code == EXIT_OK


def fake_registry(
    monkeypatch: pytest.MonkeyPatch,
    *,
    certificate=None,
    body: bytes = b"<html><head><title>Acme</title></head>" + b"x" * 64 + b"</html>",
) -> None:
    """Swap the default registry for one whose collectors answer from fakes."""

    cert = certificate or build_certificate()

    def build(**_: object) -> CollectorRegistry:
        registry = CollectorRegistry()

        class Resolver:
            def resolve(self, host: str) -> list[str]:
                del host
                return ["203.0.113.10"]

        registry.register(
            CertCollector.name,
            lambda settings: CertCollector(
                settings=settings,
                address_resolver=Resolver(),
                handshake=lambda host, port, address, timeout: handshake_for(cert),
            ),
            job_type=JobType.CERTIFICATES,
        )

        def client_factory(_settings: object) -> httpx.Client:
            return httpx.Client(
                transport=httpx.MockTransport(
                    lambda request: httpx.Response(
                        200,
                        headers={
                            "Server": "nginx/1.24.0",
                            "Set-Cookie": "sid=1; Secure; HttpOnly; SameSite=Lax",
                        },
                        content=body,
                    )
                ),
                follow_redirects=True,
            )

        registry.register(
            HttpCollector.name,
            lambda settings: HttpCollector(settings=settings, client_factory=client_factory),
            job_type=JobType.HTTP,
        )
        return registry

    monkeypatch.setattr("atlas.services.discovery.default_registry", build)


# --------------------------------------------------------------------------- #
# Certificates                                                                 #
# --------------------------------------------------------------------------- #


def test_collect_certificates_then_list_and_show(
    cli: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bootstrap(cli, tmp_path)
    cli("scope", "add", "example.com")
    cli("scope", "add", "203.0.113.0/24")
    certificate = build_certificate()
    fake_registry(monkeypatch, certificate=certificate)

    code, output = cli("--json", "collect", "example.com", "--type", "certificates")
    assert code == EXIT_OK
    payload = json_of(output)
    assert payload["status"] == "succeeded"
    assert payload["certs"]["certificate_created"] is True
    assert payload["certs"]["subject_cn"] == "example.com"

    code, output = cli("--json", "certs", "list")
    assert code == EXIT_OK
    rows = json_of(output)["certificates"]
    assert [row["subject_cn"] for row in rows] == ["example.com"]
    assert rows[0]["issuer_cn"] == "Test Intermediate CA"

    fingerprint = rows[0]["fingerprint_sha256"]
    code, output = cli("--json", "certs", "show", fingerprint)
    assert code == EXIT_OK
    detail = json_of(output)
    assert detail["fingerprint_sha256"] == fingerprint
    assert [entry["host"] for entry in detail["presented_by"]] == ["example.com"]
    # A single host is not shared infrastructure, so no shared-certificate note.
    assert detail["shared_note"] is None


def test_certs_expiring_reports_the_window(
    cli: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bootstrap(cli, tmp_path)
    cli("scope", "add", "example.com")
    cli("scope", "add", "203.0.113.0/24")
    soon = build_certificate(not_after=dt.datetime.now(dt.UTC) + dt.timedelta(days=3))
    fake_registry(monkeypatch, certificate=soon)
    cli("collect", "example.com", "--type", "certs")

    code, output = cli("--json", "certs", "expiring", "--days", "7")
    assert code == EXIT_OK
    windowed = json_of(output)
    assert windowed["days"] == 7
    assert [row["subject_cn"] for row in windowed["certificates"]] == ["example.com"]
    assert windowed["certificates"][0]["days_until_expiry"] == 2

    code, output = cli("--json", "certs", "expiring", "--days", "0")
    assert code == EXIT_OK
    assert json_of(output) == {"days": 0, "certificates": []}


def test_certs_show_for_an_unknown_fingerprint_is_a_usage_error(
    cli: CliRunner, tmp_path: Path
) -> None:
    bootstrap(cli, tmp_path)
    code, output = cli("--json", "certs", "show", "00" * 32)
    assert code == 4
    assert json_of(output)["error"] == "not_found"


# --------------------------------------------------------------------------- #
# HTTP                                                                         #
# --------------------------------------------------------------------------- #


def test_collect_http_then_show_and_list(
    cli: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bootstrap(cli, tmp_path)
    cli("scope", "add", "example.com")
    fake_registry(monkeypatch)

    code, output = cli("--json", "collect", "example.com", "--type", "http")
    assert code == EXIT_OK
    payload = json_of(output)
    assert payload["status"] == "succeeded"
    assert payload["http"]["status"] == 200
    assert payload["http"]["port"] == 443
    assert [tech["name"] for tech in payload["http"]["technologies"]] == ["nginx"]

    code, output = cli("--json", "http", "show", "example.com")
    assert code == EXIT_OK
    snapshot = json_of(output)
    assert snapshot["http"]["host"] == "example.com"
    assert snapshot["http"]["title"] == "Acme"
    assert [cookie["name"] for cookie in snapshot["http"]["cookies"]] == ["sid"]
    assert snapshot["http"]["cookies"][0]["secure"] is True
    assert [(svc["port"], svc["protocol"]) for svc in snapshot["services"]] == [(443, "https")]

    code, output = cli("--json", "http", "list")
    assert code == EXIT_OK
    rows = json_of(output)["observations"]
    assert [row["host"] for row in rows] == ["example.com"]


def test_http_show_for_a_host_without_observations_is_a_usage_error(
    cli: CliRunner, tmp_path: Path
) -> None:
    bootstrap(cli, tmp_path)
    code, output = cli("--json", "http", "show", "nothing.test")
    assert code == EXIT_USAGE
    assert json_of(output)["error"] == "validation_error"


# --------------------------------------------------------------------------- #
# urlscan source                                                               #
# --------------------------------------------------------------------------- #


def patch_urlscan(monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any]) -> None:
    """Replace the collector class so ingestion works without a network or a key."""

    from atlas.collect.urlscan import UrlscanCollector
    from atlas.config import Settings

    def factory(settings: Settings, scan_id: str | None = None) -> UrlscanCollector:
        return UrlscanCollector(
            settings=settings,
            client_factory=lambda _settings: httpx.Client(
                base_url="https://urlscan.io", transport=result_transport(payload)
            ),
            scan_id=scan_id,
        )

    class Patched(UrlscanCollector):  # type: ignore[misc]
        def __init__(self, *, settings: Settings, scan_id: str | None = None, **_: object) -> None:
            built = factory(settings, scan_id)
            self.settings = built.settings
            self.client_factory = built.client_factory
            self.scan_id = built.scan_id
            self._host_budget = 0
            self._seen_hosts = set()

        def available(self, settings: Settings) -> tuple[bool, str]:
            del settings
            return True, ""

    monkeypatch.setattr("atlas.collect.urlscan.UrlscanCollector", Patched)


def test_sources_urlscan_ingests_and_then_shows(
    cli: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bootstrap(cli, tmp_path)
    cli("scope", "add", "example.com")
    patch_urlscan(monkeypatch, scan_payload())

    code, output = cli("--json", "sources", "urlscan", SCAN_ID)
    assert code == EXIT_OK
    ingestion = json_of(output)
    assert ingestion["status"] == "succeeded"
    assert ingestion["urlscan"]["scan_id"] == SCAN_ID
    assert ingestion["urlscan"]["hosts_in_scope"] == 1
    # ``cdn.thirdparty.test`` and the page address are both outside the rule, which
    # covers only ``example.com``: both are archived and neither is promoted.
    assert ingestion["urlscan"]["hosts_out_of_scope"] == 2

    code, output = cli("--json", "sources", "urlscan", SCAN_ID, "--show")
    assert code == EXIT_OK
    payload = json_of(output)
    assert payload["scan_id"] == SCAN_ID
    assert payload["page_domain"] == "example.com"
    assert payload["verdict_score"] == 12
    assert {host["host"] for host in payload["hosts"]} == {
        "example.com",
        "cdn.thirdparty.test",
        "203.0.113.10",
    }
    in_scope = {host["host"] for host in payload["hosts"] if host["in_scope"]}
    assert in_scope == {"example.com"}


def test_sources_urlscan_refuses_a_scan_of_an_out_of_scope_page(
    cli: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bootstrap(cli, tmp_path)
    cli("scope", "add", "example.com")
    patch_urlscan(monkeypatch, scan_payload(domain="someone-else.test"))

    code, output = cli("--json", "sources", "urlscan", SCAN_ID)
    assert code == EXIT_SCOPE_VIOLATION
    assert json_of(output)["error"] == "scope_violation"


def test_sources_urlscan_without_an_api_key_is_a_configuration_error(
    cli: CliRunner, tmp_path: Path
) -> None:
    bootstrap(cli, tmp_path)
    cli("scope", "add", "example.com")

    code, output = cli("--json", "sources", "urlscan", SCAN_ID)
    assert code == EXIT_CONFIG
    payload = json_of(output)
    assert payload["error"] == "configuration_error"
    assert "urlscan_api_key" in payload["message"]

    # A missing key is a configuration gap, so no scan job is created for it.
    url = cli.url  # type: ignore[attr-defined]
    from sqlalchemy import create_engine, text

    engine = create_engine(url)
    with engine.connect() as connection:
        count = connection.execute(
            text("SELECT COUNT(*) FROM scan_jobs WHERE job_type = 'urlscan'")
        ).scalar_one()
    engine.dispose()
    assert count == 0


def test_sources_urlscan_rejects_a_malformed_id(cli: CliRunner, tmp_path: Path) -> None:
    bootstrap(cli, tmp_path)
    code, output = cli("--json", "sources", "urlscan", "not-a-scan-id")
    assert code == EXIT_USAGE
    assert json_of(output)["error"] == "validation_error"
