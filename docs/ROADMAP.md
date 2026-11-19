# ATLAS — Development Roadmap

Each phase ends with: tests run, errors fixed, functionality documented, remaining work listed,
previous modules still green. Nothing is marked done until it runs.

---

## Phase 1 — Foundation ✅ (this delivery)

**Delivered**

- Architecture, module boundaries, ERD, dependency graph, CLI and API specifications.
- `pyproject.toml` with pinned dependency ranges, src layout, entry point `atlas`.
- Configuration: `pydantic-settings` + optional YAML file + env overrides, validated at load.
- Structured logging with JSON or console rendering and a secret-redaction filter.
- Typed exception hierarchy mapped to stable CLI exit codes.
- SQLAlchemy 2.0 schema for all 21 entities with naming conventions, indexes and constraints.
- Alembic migration environment and initial migration.
- Scope engine: domain/wildcard/IP/CIDR/URL matching, exclusion precedence, private and
  reserved address filtering, `ScopeSet.require_permitted()` raising `ScopeViolation`.
- Audit trail service (append-only `audit_events`).
- CLI: `init`, `config`, `project`, `scope`, `assets`, `audit`, `db`, `version`, `--json` mode.
- Test suite: unit tests for config, scope, models, CLI exit codes; SQLite integration tests.

**Remaining (by design, later phases)**

- Network collectors (Phase 2/3), correlation (Phase 4), graph (Phase 5), analysis (Phase 6),
  history (Phase 7), API/UI (Phase 8), reporting/deployment (Phase 9).

---

## Phase 2 — Asset discovery and DNS intelligence ✅ (this delivery)

**Delivered**

- `atlas.collect` package: `Collector` ABC, `CollectorContext` (scope + rate limiter + deadline),
  `CollectorResult` with per-operation `CollectionError` records, and a name → factory
  `CollectorRegistry` with job-type grouping (`default_registry()`).
- `DnsCollector`: A, AAAA, CNAME, MX, NS, TXT, SOA, CAA for names, PTR for addresses; bounded
  CNAME following (32 hops) with an explicit `NameStatusObservation` for every followed target;
  the scope gate is re-asserted before the first query and NXDOMAIN is recorded as evidence
  rather than treated as an error.
- `atlas.collect.ratelimit`: token bucket with injectable clock/sleeper, plus a composite
  limiter that enforces a global budget and a per-key budget.
- `atlas.collect.retry`: bounded retry with exponential backoff, a delay ceiling, jitter and
  `on_retry` callbacks; exhaustion re-raises the original exception unchanged.
- `atlas.services.observations`: asset/domain/IP upsert with first-seen, last-seen and
  confidence-monotonic semantics; DNS record upsert; retirement of records that are no longer
  observed (retire, never delete).
- `atlas.services.dns`: `persist_dns_result` (assets → records → relationships, then the
  added/removed diff), `dns_records`, `dns_history`, `nameserver_summary`, `dangling_cnames`.
  A record type is only retired when it was actually queried (`checked_types`), and a dangling
  CNAME is reported only when a stored `ScanResult` recorded NXDOMAIN for its target.
- `atlas.services.relationships`: relationship upsert carrying type, evidence source,
  first/last observed and confidence; shared nameservers are stored as
  `SHARES_NAMESERVER` at confidence **0.3** with a "shared infrastructure, not shared
  ownership" attribution.
- `atlas.services.targets` + `atlas.services.discovery`: target resolution/normalization, the
  scope gate (audited denial, no job row created), a committed `ScanJob` before collection
  starts, every observation archived as a `ScanResult` (`dns.answer` / `dns.status`), job
  finalization to `SUCCEEDED` / `PARTIAL` / `FAILED`.
- CLI: `atlas discover <target> [--full]`, `atlas collect <target> [--type dns|discover|full]
  [--dry-run]`, `atlas dns show|history|nameservers|dangling`, all supporting `--json`.
- Tests: **145 passing**, no network. DNS runs against a zone-backed fake resolver returning
  real dnspython rdata; CLI tests drive the real entry point and assert exit codes.

**Fixed while delivering**

- RFC 5737 / RFC 3849 documentation ranges were classified `PRIVATE` by Python 3.12 and
  therefore denied by `NetworkPolicy`; they now have their own `AddressClass.DOCUMENTATION`
  and are permitted (unroutable, so no SSRF surface).
- `ScopeSet.check()` leaked a Pydantic `ValidationError` for malformed values instead of
  returning a denial.
- CLI exit codes were swallowed (`main` always returned 0 with `standalone_mode=False`).
- Console log formatter was constructed without its required redaction argument.
- `typer` 0.15 + click 8.5 was an incompatible pair; pinned to `typer>=0.19,<0.20` and
  `click>=8.3.1,<9` (Celery's requirement).

**Remaining (later phases)**

- Certificate and HTTP collectors — delivered in Phase 3; `collect --full` now runs DNS, TLS,
  HTTP and (when keyed) urlscan.
- No CIDR sweep: a CIDR target resolves but yields no per-address work.
- Celery task wrappers: discovery runs in-process today; the service signature is ready for a
  queue since it takes only `session`, `project`, `settings`, `value`.
- `dns.answer` / `dns.status` were the only archived result types until Phase 3 added
  `tls.certificate`, `http.response` and the `urlscan.*` records.


## Phase 3 — Certificate and HTTP intelligence ✅ (this delivery)

**Delivered**

- `CertCollector` (`atlas.collect.tls`): a raw `ssl` handshake per (host, port) rather than an
  `httpx` fetch, because an invalid certificate is an observation, not a transport failure.
  Verification is off, TLS 1.2 is the floor, SNI is the host and the socket is pinned to a
  scope-approved address (DNS rebinding is checked before dialling). `parse_certificate`
  extracts subject/issuer RDNs, every SAN (DNS and IP), validity, key algorithm and bits,
  signature algorithm, CA and self-signed flags, and both fingerprints. 443 then 80 are tried;
  a handshake failure is a recorded `tls_error`, never an invented certificate.
- `HttpCollector` (`atlas.collect.http`): bounded GET with redirects captured as a chain, a
  body read capped at `collector.max_body_bytes` before hashing, `Server`/`X-Powered-By`/
  `X-Generator`/CDN header fingerprints and CMS/framework body markers (generator strings win
  the deduplication race so the version survives), every `Set-Cookie` attribute preserved as
  sent, title and content type extraction, HTTPS with a plain-HTTP fallback when the TLS
  connection cannot be made.
- `UrlscanCollector` (`atlas.collect.urlscan`): read-only ingestion of an existing urlscan.io
  scan by UUID or result URL, or the most recent scan for a page domain via the search API.
  There is no submission code path anywhere in the module — the test suite asserts every
  request is a `GET`. Scope is applied to *returned* hosts, and each host carries an `in_scope`
  flag into persistence so an out-of-scope host is archived but never promoted to an asset.
  A scan whose captured page domain is outside the project raises `ScopeViolation`.
- `Collector.available(settings)`: an unconfigured collector (today: urlscan without an API
  key) reports itself unavailable. A `FULL` job skips it and lists it in
  `outcome.skipped_collectors`; an explicit job type records a `not_configured` error and the
  job closes `PARTIAL` rather than `FAILED`, because a missing key is a gap the operator can fix.
- Persistence: `atlas.services.certificates` (one `Certificate` row per project+fingerprint,
  one `CertificateBinding` per presenting asset, a `PRESENTS_CERTIFICATE` edge at confidence
  **0.9**), `atlas.services.http` (a `Service` per endpoint, technologies and cookie warnings on
  the archived `http.response`, `REDIRECTS_TO` only to an already-known asset), and
  `atlas.services.urlscan` (hosts, requests, services, `RESOLVES_TO` at **0.6**, verdicts kept
  as third-party opinion). A urlscan certificate name never creates a `Certificate` row: there
  is no fingerprint to key it on.
- Expiry monitor feed: `atlas certs expiring --days N`, windowed against the current clock.
- CLI: `certs list`, `certs expiring`, `certs show <fingerprint>`, `http show <host>`,
  `http list`, `sources urlscan <scan-id> [--show]`; `collect --type certs|http|urlscan` plus
  `--scan-id`. All support `--json`.
- Tests: **232 passing**, no network (console tests are counted in Phase 3b). TLS runs against certificates minted in-test with
  `cryptography` and an injected handshake; HTTP and urlscan run through
  `httpx.MockTransport`; the CLI tests drive the real entry point. A live run against
  `example.com` verified the real handshake, real HTTP fetch and the cert/http CLI views.

**Fixed while delivering**

- A live smoke run against `example.com` exposed the address gate: the TLS collector
  required every resolved address to be covered by a rule in its own right, so a domain
  rule could never reach the addresses its own name resolves to and every certificate
  pass ended `address_out_of_scope`. `CollectorContext.permits_address()` now applies
  both gates explicitly — `NetworkPolicy` (which is what still forbids loopback, private
  and metadata ranges) and scope, where an authorized name authorizes its own answers.
  The HTTP collector gained the same gate: a pre-flight resolution check before the
  request, and a remote-address check after it, so a redirect cannot land the client on
  a private address. Loopback, link-local and cloud-metadata targets stay refused even
  for an authorized name — that is the SSRF boundary, not a scope question.
- `certs list` printed the certificate asset key (a fingerprint hash) in the `host`
  column, because `Certificate.asset_id` is keyed by fingerprint rather than by
  presenting host. Rows now carry `presented_by` / `presenting_host`, the CLI shows the
  host with a `(+N)` count for shared certificates, and the expiry column is rendered as
  a date instead of an overflowing timestamp.
- `sources urlscan` without an API key failed the job it had already created. The
  missing key is now a `ConfigurationError` raised before any job row exists (exit 6,
  `configuration_error`), so it is a configuration gap rather than a scan that found
  nothing.
- `urlscan_max_hosts` was applied per list, so a scan with N domains and N addresses could
  return 2N hosts. It is now a single per-scan budget.
- A scan-id target was being run through the scope matcher as if it were a hostname, which
  denied every explicit `--scan-id` ingestion. The gate now uses the host named alongside the
  id, and falls back to the captured page domain, which `_ingest` enforces.
- `ingest_urlscan_scan` let a `ScopeViolation` escape with the `ScanJob` still `RUNNING`; the
  row is now closed as `FAILED` with the refusal recorded as a `denied` audit event.
- Technology evidence lower-cased the header name (`server: nginx/1.24.0`), losing the exact
  casing an operator compares against a raw capture.
- HTTP transport failures were classified through the generic `AtlasError` mapper, so every
  connection refused surfaced as `ConnectError` instead of `connection_error`.
- Redirect count included the initial request rather than the hops.

**Remaining (by design, later phases)**

- Certificate/HTTP observations feed correlation (Phase 4) and the detectors (Phase 6); nothing
  scores them yet.
- urlscan needs `ATLAS_SOURCES__URLSCAN_API_KEY`; without it the source is skipped. Live calls
  are unverified against the real API — the parser is tested against recorded response shapes.
- No CIDR sweep yet: a CIDR target still yields no per-address work.
- Celery task wrappers remain unwired; discovery still runs in-process.

## Phase 3b — Local operator console ✅ (this delivery)

**Delivered**

- `atlas serve` (`cli/commands/serve.py`): browser console on loopback. Non-loopback binds
  require `--allow-remote` and print what that means; the browser is opened only after a TCP
  probe confirms the socket is accepting, not on a timer.
- `atlas.web.app`: the console API. Every route is a thin call into the same services the CLI
  uses — `discover()` for collection, `add_rule`/`remove_rules` for scope, the read services for
  views. **No route can bypass the scope gate**, because the gate is inside `discover()`, which
  audits the denial and raises before a socket opens.
- `atlas.web.main`: ASGI entry point for `uvicorn atlas.web.main:app` and the `--reload` path.
- Static console (`web/static/index.html`, `style.css`, `app.js`): no build step, no bundler, no
  CDN — it renders with the machine's network unplugged. Ten views: Overview, Scope, Collect,
  Assets, DNS, Certificates, HTTP, Jobs, Audit, Export.
- Lifespan resolves the configured project at boot: a wrong `--project` or an unmigrated database
  fails with `configuration_error` naming the projects that do exist, instead of serving an empty
  shell.
- Error mapping: ATLAS slugs to HTTP statuses (`scope_violation` 403, `not_found` 404,
  `conflict` 409, `configuration_error` 500, `database_error` 503) with the CLI's `exit_code`
  preserved in the body.
- Tests: **60 passing** for the console — routes, gate parity (a denied POST never reaches a
  collector), 404s for uncollected artifacts, binding rules, project selection, export.

**Fixed while delivering**

- `/api/dns/{fqdn}` surfaced `dns_history`'s "the name was never collected" as a **400**, which
  reads as a malformed request. It is a missing resource: 404 with the command that would
  produce it, same for `/api/http/{host}`.
- The certificate and HTTP renderers initially read field names the collectors do not emit
  (`status_code`, `remote_address`). They now read the archived payload verbatim (`status`,
  `remote_ip`), verified against a live response.
- `/api/state` echoed the full database URL, which can embed a password. It now reports only the
  backend scheme.

**Remaining (by design, later phases)**

- The console is unauthenticated and loopback-only by design. Multi-user access belongs with
  Phase 8's API, behind real auth.
- Collection runs in the request thread, so a slow target holds the request open. Moving it to
  Celery is Phase 7's queue work, not a console change.
- No write endpoints for projects: `atlas project create` remains the way to add one.

## Phase 4 — Infrastructure correlation

- `CorrelationService`: relationship rules per type, evidence source, confidence model
  (observed-direct 0.95, inferred-from-DNS 0.8, inferred-from-cert 0.5).
- Shared-hosting guard: shared IP or shared certificate is never emitted as ownership.
- CLI: `relationships list`, `relationships explain <id>`.
- Tests: fixture graph → expected edge set.

## Phase 5 — Graph intelligence

- `GraphBackend` ABC, NetworkX implementation, optional Neo4j adapter.
- Build from `assets` + `relationships`; clustering (connected components, shared-infra groups).
- Snapshot diff → added/removed/edge-change sets.
- Export JSON + GraphML; CLI: `graph build`, `graph export`, `graph stats`.
- Tests: golden-file comparisons for exports.

## Phase 6 — Security analysis and risk

- Detector set: security headers, cookie flags, TLS version/cipher, certificate expiry,
  administrative interface exposure, unexpected service exposure, suspicious DNS, version match.
- `RiskScorer`: documented formula, severity and confidence independent, exposure and business
  relevance as inputs, no opaque magic numbers.
- `findings` CLI with severity filters and `--json`.
- Tests: detector fixtures with positive and negative cases.

## Phase 7 — Historical monitoring

- Celery beat schedules per project (`monitor start|stop|status`).
- Snapshot capture on every scheduled run, change events, new-asset and disappeared-asset feeds.
- `history compare <from> <to>`, retention pruning job.
- Tests: time-travel fixtures with frozen clock.

## Phase 8 — API and dashboard

- FastAPI routers: projects, scope, targets, assets, dns, certs, http, findings, graph, history,
  jobs, reports, settings. OpenAPI generated, problem+json errors, pagination, filtering.
- React + TypeScript + Tailwind dashboard, Cytoscape.js graph, 11 pages as specified.
- Auth: API key + session, RBAC (viewer/analyst/admin).
- Tests: API integration with transactional test DB, UI smoke tests.

## Phase 9 — Reporting and deployment

- Renderers: HTML (Jinja2), JSON, CSV, PDF (WeasyPrint), executive summary + technical sections.
- Docker images (api, worker, beat, ui), compose stack with Postgres/Redis, health checks.
- Backup/restore runbook, retention policy wiring.

## Phase 10 — Hardening

- Security review: scope bypass attempts, SSRF corpus, header injection, path traversal in reports.
- Performance: index review, query plans, graph build at 50k nodes.
- Fuzz scope matcher and DNS parser.
- Documentation pass, operator runbook, contribution guide.
