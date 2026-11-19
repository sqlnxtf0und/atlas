"""The local console: routes, gate parity and the ``atlas serve`` binding rules.

Every test here drives the real FastAPI app built by :func:`atlas.web.app.create_app`
against a real SQLite database. The network boundary is replaced with a stub collector,
so no test performs a lookup.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar

import pytest
from fastapi.testclient import TestClient

from atlas.cli.commands.serve import is_loopback
from atlas.cli.main import main
from atlas.collect.base import (
    CollectionTarget,
    Collector,
    CollectorContext,
    CollectorResult,
    DnsAnswerObservation,
)
from atlas.collect.registry import CollectorRegistry
from atlas.config import Settings
from atlas.db.base import Base
from atlas.db.enums import DnsRecordType, JobType
from atlas.db.session import build_engine, build_session_factory
from atlas.services.projects import create_project
from atlas.web.app import JOB_TYPES, create_app

SCAN_ID = "0a1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5d"


class StubDns(Collector):
    """A DNS collector that records the target it was handed and answers fixed A records."""

    name = "dns"
    job_type = JobType.DISCOVER
    produces = ("dns.record",)

    calls: ClassVar[list[str]] = []

    def collect(self, target: CollectionTarget, context: CollectorContext) -> CollectorResult:
        StubDns.calls.append(target.value)
        return CollectorResult(
            collector=self.name,
            target=target,
            observations=[
                DnsAnswerObservation(
                    source=self.name,
                    observed_at=datetime(2026, 1, 1, 12, 0, 0),
                    query_name=target.value,
                    record_type=DnsRecordType.A,
                    value="203.0.113.10",
                    ttl=300,
                )
            ],
        )


def _run_cli(settings: Settings, *args: str) -> tuple[int, str]:
    """Drive the real entry point; ``main`` exits through ``SystemExit``."""

    out = io.StringIO()
    with (
        redirect_stdout(out),
        redirect_stderr(io.StringIO()),
        pytest.raises(SystemExit) as excinfo,
    ):
        main(["--db-url", settings.database.url, "--no-color", *args])
    return int(excinfo.value.code or 0), out.getvalue()


def _settings(db_path: Path) -> Settings:
    return Settings.model_validate(
        {
            "environment": "test",
            "database": {"url": f"sqlite+pysqlite:///{db_path}"},
            "security": {"allow_private_addresses": False},
            "collector": {"requests_per_second": 50},
        }
    )


def _bootstrap(db_path: Path, *, slug: str = "default", name: str = "Default") -> Settings:
    """Apply the schema and create the project the console serves."""

    settings = _settings(db_path)
    engine = build_engine(settings)
    Base.metadata.create_all(engine)
    with build_session_factory(engine)() as session:
        create_project(session, name=name, slug=slug)
        session.commit()
    engine.dispose()
    return settings


@pytest.fixture()
def seeded(tmp_path: Path) -> Settings:
    return _bootstrap(tmp_path / "console.db")


@pytest.fixture()
def client(seeded: Settings) -> TestClient:
    with TestClient(create_app(seeded)) as test_client:
        yield test_client


@pytest.fixture()
def stub_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the shipped registry with one holding only the stub collector."""

    from atlas.services import discovery

    def registry() -> CollectorRegistry:
        built = CollectorRegistry()
        built.register(
            StubDns.name,
            lambda _settings: StubDns(),
            job_type=(JobType.DISCOVER, JobType.DNS),
        )
        return built

    StubDns.calls = []
    monkeypatch.setattr(discovery, "default_registry", registry)


# --------------------------------------------------------------------------- #
# Shell and state
# --------------------------------------------------------------------------- #


def test_index_serves_the_console_shell(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    body = response.text
    assert "<title>ATLAS console</title>" in body
    for view in ("overview", "scope", "collect", "assets", "dns", "certs", "http", "jobs"):
        assert f'id="view-{view}"' in body
    # The shell must not pull anything from a third-party origin.
    for attribute in ('src="http', "src='http", 'href="http', "href='http"):
        assert attribute not in body, attribute


def test_static_assets_are_served_from_the_package(client: TestClient) -> None:
    for name, marker in (("style.css", "--accent"), ("app.js", "VIEW_LOADERS")):
        response = client.get(f"/static/{name}")
        assert response.status_code == 200, name
        assert marker in response.text, name


def test_console_javascript_talks_only_to_this_origin(client: TestClient) -> None:
    script = client.get("/static/app.js").text
    assert "fetch(" in script
    assert "https://" not in script
    assert "http://" not in script


def test_state_reports_an_empty_project_without_inventing_scope(client: TestClient) -> None:
    payload = client.get("/api/state").json()
    assert payload["project"]["slug"] == "default"
    assert payload["scope"] == []
    assert payload["scope_configured"] is False
    assert payload["counts"]["assets"] == 0
    assert payload["settings"]["database_backend"] == "sqlite+pysqlite"
    assert {entry["value"] for entry in payload["job_types"]} == set(JOB_TYPES)


def test_state_lists_projects_and_marks_the_served_one(client: TestClient) -> None:
    payload = client.get("/api/state").json()
    assert payload["projects"] == [{"slug": "default", "name": "Default", "active": True}]
    assert payload["cli"] == "atlas --project default"


def test_projects_endpoint_reports_every_project(client: TestClient) -> None:
    payload = client.get("/api/projects").json()
    assert payload["active"] == "default"
    assert [entry["slug"] for entry in payload["projects"]] == ["default"]
    assert payload["projects"][0]["active"] is True


def test_state_reports_urlscan_unavailable_without_a_key(client: TestClient) -> None:
    collectors = {entry["name"]: entry for entry in client.get("/api/state").json()["collectors"]}
    assert collectors["urlscan"]["ready"] is False
    assert "urlscan_api_key" in collectors["urlscan"]["reason"]
    assert collectors["dns"]["ready"] is True


def test_state_never_echoes_a_database_password(tmp_path: Path) -> None:
    settings = _bootstrap(tmp_path / "console.db")
    secret = f"{settings.database.url}?password=hunter2"
    settings = settings.model_copy(
        update={"database": settings.database.model_copy(update={"url": secret})}
    )
    with TestClient(create_app(settings)) as test_client:
        response = test_client.get("/api/state")
    assert response.status_code == 200
    assert "hunter2" not in response.text
    assert response.json()["settings"]["database_backend"] == "sqlite+pysqlite"


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #


def test_scope_rule_can_be_added_listed_and_removed(client: TestClient) -> None:
    created = client.post("/api/scope", json={"pattern": "example.com"})
    assert created.status_code == 200, created.text
    rule = created.json()["rule"]
    assert rule["pattern"] == "example.com"
    assert rule["mode"] == "include"
    assert rule["include_subdomains"] is True

    listed = client.get("/api/scope").json()["scope"]
    assert [entry["pattern"] for entry in listed] == ["example.com"]
    assert client.get("/api/state").json()["scope_configured"] is True

    removed = client.delete(f"/api/scope/{rule['id']}")
    assert removed.status_code == 200
    assert client.get("/api/scope").json()["scope"] == []


def test_scope_add_rejects_a_duplicate_rule(client: TestClient) -> None:
    client.post("/api/scope", json={"pattern": "example.com"})
    response = client.post("/api/scope", json={"pattern": "example.com"})
    assert response.status_code == 409
    assert response.json()["error"] == "conflict"


def test_scope_add_rejects_a_pattern_the_matcher_cannot_use(client: TestClient) -> None:
    response = client.post("/api/scope", json={"pattern": "not a domain!!"})
    assert response.status_code == 400
    assert response.json()["error"] == "validation_error"


def test_scope_add_requires_a_pattern(client: TestClient) -> None:
    assert client.post("/api/scope", json={"pattern": "   "}).status_code == 400


def test_scope_add_rejects_an_unknown_kind(client: TestClient) -> None:
    response = client.post("/api/scope", json={"pattern": "example.com", "kind": "planet"})
    assert response.status_code == 400
    assert "planet" in response.json()["detail"]


def test_scope_remove_unknown_rule_is_404(client: TestClient) -> None:
    response = client.delete(f"/api/scope/{SCAN_ID}")
    assert response.status_code == 404
    assert response.json()["error"] == "not_found"


def test_scope_remove_rejects_a_non_uuid(client: TestClient) -> None:
    assert client.delete("/api/scope/nope").status_code == 400


def test_scope_check_explains_a_denial(client: TestClient) -> None:
    payload = client.get("/api/scope/check", params={"value": "example.com"}).json()
    assert payload["permitted"] is False
    assert payload["collection_value"] == "example.com"
    assert payload["reason"]


def test_scope_check_admits_an_authorized_name_and_its_subdomains(client: TestClient) -> None:
    client.post("/api/scope", json={"pattern": "example.com"})
    for value in ("example.com", "www.example.com", "deep.www.example.com"):
        payload = client.get("/api/scope/check", params={"value": value}).json()
        assert payload["permitted"] is True, value


def test_scope_check_refuses_an_unrelated_name(client: TestClient) -> None:
    client.post("/api/scope", json={"pattern": "example.com"})
    payload = client.get("/api/scope/check", params={"value": "example.org"}).json()
    assert payload["permitted"] is False


def test_scope_check_reports_bad_input_as_a_validation_error(client: TestClient) -> None:
    response = client.get("/api/scope/check", params={"value": ""})
    assert response.status_code == 400
    assert response.json()["error"] == "validation_error"


# --------------------------------------------------------------------------- #
# Collection — the gate is the point
# --------------------------------------------------------------------------- #


def test_collect_refuses_a_target_outside_the_scope(client: TestClient, stub_dns: None) -> None:
    response = client.post("/api/collect", json={"target": "example.com", "job_type": "dns"})
    assert response.status_code == 403
    payload = response.json()
    assert payload["error"] == "scope_violation"
    assert payload["exit_code"] == 3
    assert StubDns.calls == [], "a denied collection must never reach a collector"


def test_collect_denial_is_audited(client: TestClient, stub_dns: None) -> None:
    client.post("/api/collect", json={"target": "example.com", "job_type": "dns"})
    events = client.get("/api/audit", params={"action": "discovery.denied"}).json()["events"]
    assert events, "a refused collection must leave an audit trail"
    assert events[0]["outcome"] == "denied"


def test_collect_requires_a_target(client: TestClient) -> None:
    assert client.post("/api/collect", json={"target": ""}).status_code == 400


def test_collect_rejects_an_unknown_job_type(client: TestClient) -> None:
    response = client.post("/api/collect", json={"target": "example.com", "job_type": "telepathy"})
    assert response.status_code == 400
    assert "telepathy" in response.json()["detail"]


def test_collect_runs_the_authorized_pass_through_the_real_pipeline(
    client: TestClient, stub_dns: None
) -> None:
    client.post("/api/scope", json={"pattern": "example.com"})
    response = client.post("/api/collect", json={"target": "example.com", "job_type": "dns"})
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["target"] == "example.com"
    assert payload["job_type"] == "dns"
    assert payload["status"] in {"succeeded", "partial"}
    assert StubDns.calls == ["example.com"]

    jobs = client.get("/api/jobs").json()["jobs"]
    assert len(jobs) == 1
    assert jobs[0]["job_type"] == "dns"

    # The observation the stub produced is persisted and readable back.
    names = client.get("/api/dns").json()["names"]
    assert [entry["fqdn"] for entry in names] == ["example.com"]


def test_collect_urlscan_without_a_key_is_reported_as_a_configuration_gap(
    client: TestClient,
) -> None:
    """An explicitly named source that cannot run is an error entry, not a crash."""

    client.post("/api/scope", json={"pattern": "example.com"})
    response = client.post("/api/collect", json={"target": "example.com", "job_type": "urlscan"})
    assert response.status_code == 200, response.text
    payload = response.json()
    # Only the urlscan collector ran, and it could not: a configuration gap.
    assert payload["status"] == "partial"
    assert [error["error_type"] for error in payload["errors"]] == ["not_configured"]
    assert "urlscan_api_key" in payload["errors"][0]["message"]


# --------------------------------------------------------------------------- #
# Read views on an empty project
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("path", "key"),
    [
        ("/api/assets", "assets"),
        ("/api/dns", "names"),
        ("/api/certs", "certificates"),
        ("/api/http", "observations"),
        ("/api/jobs", "jobs"),
        ("/api/urlscan", "scans"),
    ],
)
def test_empty_views_return_empty_collections(client: TestClient, path: str, key: str) -> None:
    response = client.get(path)
    assert response.status_code == 200, path
    assert response.json()[key] == []


def test_audit_holds_the_events_the_app_itself_wrote(client: TestClient) -> None:
    """A fresh project already has its creation event; the view must show it."""

    events = client.get("/api/audit").json()["events"]
    assert events
    assert events[0]["action"] == "project.create"
    assert events[0]["outcome"] == "success"


def test_dangling_cnames_is_empty_without_evidence(client: TestClient) -> None:
    assert client.get("/api/dns-dangling").json()["dangling"] == []


def test_assets_rejects_an_unknown_kind(client: TestClient) -> None:
    assert client.get("/api/assets", params={"kind": "ghost"}).status_code == 400


def test_asset_detail_for_a_missing_key_is_404(client: TestClient) -> None:
    response = client.get("/api/assets/example.com")
    assert response.status_code == 404
    assert response.json()["error"] == "not_found"


def test_dns_history_for_an_uncollected_name_is_404(client: TestClient) -> None:
    response = client.get("/api/dns/missing.example.com")
    assert response.status_code == 404


def test_http_snapshot_for_an_uncollected_host_is_404(client: TestClient) -> None:
    response = client.get("/api/http/missing.example.com")
    assert response.status_code == 404
    assert "collect" in response.json()["message"]


def test_certificate_detail_for_an_unknown_fingerprint_is_404(client: TestClient) -> None:
    assert client.get("/api/certs/deadbeef").status_code == 404


def test_certificate_window_is_echoed_back(client: TestClient) -> None:
    payload = client.get("/api/certs", params={"days": 30}).json()
    assert payload["window_days"] == 30
    assert payload["certificates"] == []


def test_export_is_a_complete_document_even_when_empty(client: TestClient) -> None:
    payload = client.get("/api/export").json()
    assert payload["project"]["slug"] == "default"
    for key in ("assets", "certificates", "http", "jobs", "scope"):
        assert payload[key] == [], key


def test_export_carries_the_scope_rules(client: TestClient) -> None:
    client.post("/api/scope", json={"pattern": "example.com"})
    payload = client.get("/api/export").json()
    assert [rule["pattern"] for rule in payload["scope"]] == ["example.com"]


def test_urlscan_ingest_requires_an_id(client: TestClient) -> None:
    assert client.post("/api/urlscan", json={"scan_id": ""}).status_code == 400


def test_urlscan_ingest_without_a_key_is_a_configuration_error(client: TestClient) -> None:
    response = client.post("/api/urlscan", json={"scan_id": SCAN_ID})
    assert response.status_code == 500
    payload = response.json()
    assert payload["error"] == "configuration_error"
    assert "urlscan_api_key" in payload["message"]


# --------------------------------------------------------------------------- #
# atlas serve — the binding rules
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", "127.0.0.1 "])
def test_is_loopback_accepts_loopback_spellings(host: str) -> None:
    assert is_loopback(host) is True


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "10.0.0.5", "example.com"])
def test_is_loopback_rejects_everything_routable(host: str) -> None:
    assert is_loopback(host) is False


def test_serve_refuses_a_routable_bind_without_allow_remote(
    seeded: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _explode(*_args: Any, **_kwargs: Any) -> None:  # pragma: no cover - must not run
        raise AssertionError("uvicorn must not be started for a refused bind")

    monkeypatch.setattr("uvicorn.run", _explode)
    code, output = _run_cli(seeded, "--json", "serve", "--host", "0.0.0.0", "--no-open")
    assert code == 6
    payload = json.loads(output)
    assert payload["error"] == "configuration_error"
    assert "refusing to bind" in payload["message"]


def test_serve_accepts_allow_remote_but_says_what_it_means(
    seeded: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    started: list[dict[str, Any]] = []

    def _capture(app: Any, **kwargs: Any) -> None:
        started.append(kwargs)

    monkeypatch.setattr("uvicorn.run", _capture)
    code, output = _run_cli(
        seeded, "serve", "--host", "0.0.0.0", "--port", "8123", "--no-open", "--allow-remote"
    )
    assert code == 0, output
    assert "no authentication" in output or "reachable" in output
    assert started and started[0]["host"] == "0.0.0.0"
    assert started[0]["port"] == 8123


def test_serve_binds_loopback_by_default(seeded: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    started: list[dict[str, Any]] = []

    def _capture(app: Any, **kwargs: Any) -> None:
        started.append(kwargs)

    monkeypatch.setattr("uvicorn.run", _capture)
    code, output = _run_cli(seeded, "serve", "--no-open", "--port", "8124")
    assert code == 0, output
    assert started[0]["host"] == "127.0.0.1"


def test_serve_rejects_a_port_out_of_range(seeded: Settings) -> None:
    code, _output = _run_cli(seeded, "serve", "--port", "70000")
    assert code == 2


def test_project_slug_selects_the_served_project(tmp_path: Path) -> None:
    _bootstrap(tmp_path / "console.db")
    alpha = _bootstrap(tmp_path / "console.db", slug="alpha", name="Alpha")

    with TestClient(create_app(alpha, project_slug="alpha")) as test_client:
        payload = test_client.get("/api/state").json()
    assert payload["project"]["slug"] == "alpha"
    assert payload["project"]["name"] == "Alpha"


def test_console_reports_a_missing_project_rather_than_serving_a_blank_one(
    seeded: Settings,
) -> None:
    """A wrong ``--project`` fails at boot, so no request can reach an empty shell."""

    from atlas.errors import ConfigurationError

    with (
        pytest.raises(ConfigurationError) as excinfo,
        TestClient(create_app(seeded, project_slug="missing")),
    ):
        pass
    assert "missing" in excinfo.value.message
    assert excinfo.value.context["projects"] == ["default"]


# --------------------------------------------------------------------------- #
# Embedding
# --------------------------------------------------------------------------- #


def test_build_api_matches_create_app(seeded: Settings) -> None:
    from atlas.web import build_api

    with TestClient(build_api(seeded)) as test_client:
        assert test_client.get("/api/state").status_code == 200


def test_openapi_document_describes_the_routes(client: TestClient) -> None:
    schema = client.get("/api/openapi.json").json()
    paths = set(schema["paths"])
    for path in ("/api/state", "/api/scope", "/api/collect", "/api/assets", "/api/export"):
        assert path in paths, path


def test_export_json_is_serialisable_after_collection(client: TestClient, stub_dns: None) -> None:
    client.post("/api/scope", json={"pattern": "example.com"})
    client.post("/api/collect", json={"target": "example.com", "job_type": "dns"})
    payload = client.get("/api/export").json()
    assert json.dumps(payload)  # no datetime leaks that FastAPI cannot encode
    assert payload["jobs"]
