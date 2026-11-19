# ATLAS — System Architecture

**Advanced Threat & Infrastructure Intelligence System**
Version 0.1.0 · Architecture baseline for Phase 1

---

## 1. Purpose

ATLAS is an attack-surface intelligence platform. It discovers external infrastructure,
records what it observed and when, links observations into a graph, evaluates security
posture against evidence, and tracks how all of it changes over time.

It is not a scanner wrapper. The collection, correlation, storage, scoring and
presentation layers are owned by ATLAS itself and share one data model.

### Non-goals

- Exploitation, credential attacks, authentication bypass, destructive testing.
- Acting on targets that are not covered by an explicit, active, authorized scope rule.
- Claiming exploitability from a version string alone.

---

## 2. Design principles

| Principle | Consequence in the codebase |
|---|---|
| **Evidence over assertion** | Every `Finding` references `Evidence` rows; every `Relationship` carries `evidence_source`, `confidence`, `first_observed`, `last_observed`. |
| **Scope is a hard gate** | All collection passes through `atlas.scope.ScopeSet.require_permitted()` before a socket is opened. Discovered assets never widen scope. |
| **Observations are immutable facts** | Rows are appended; state changes are expressed as new `ScanResult` / `AssetChange` / `Snapshot` rows, not by overwriting history. |
| **Modules are replaceable** | Collection adapters implement `Collector`; storage is behind repositories; the graph engine is behind `GraphBackend`. |
| **Fail closed** | Unreadable input yields *no* result, never a guessed one. Private/reserved address space is refused by default. |
| **Bounded everything** | Timeouts, concurrency ceilings, response-size caps, redirect caps, retry budgets are configuration, not magic numbers. |

---

## 3. Layered architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  PRESENTATION                                                                │
│  ┌───────────────────┐  ┌───────────────────┐  ┌───────────────────────────┐  │
│  │  CLI (Typer/Rich) │  │ Web UI (React/TS) │  │ Reports (HTML/JSON/CSV/PDF)│  │
│  └─────────┬─────────┘  └─────────┬─────────┘  └─────────────┬─────────────┘  │
└────────────┼──────────────────────┼──────────────────────────┼────────────────┘
             │                      │                          │
┌────────────▼──────────────────────▼──────────────────────────▼────────────────┐
│  INTERFACE LAYER                                                              │
│  REST API (FastAPI, /api/v1)   ·   CLI service façade   ·   Report builders    │
│  Pydantic schemas in / Pydantic schemas out / problem+json errors             │
└────────────┬──────────────────────────────────────────────────────────────────┘
             │
┌────────────▼──────────────────────────────────────────────────────────────────┐
│  DOMAIN SERVICES                                                              │
│  DiscoveryService · DnsService · CertificateService · HttpService             │
│  CorrelationService · GraphService · AnalysisService · RiskService            │
│  HistoryService · ReportService · ScopeService · AuditService                 │
└───────┬───────────────────┬──────────────────┬──────────────────┬─────────────┘
        │                   │                  │                  │
┌───────▼────────┐  ┌───────▼────────┐  ┌──────▼───────┐  ┌───────▼────────────┐
│ COLLECTION     │  │ ANALYSIS       │  │ GRAPH        │  │ PERSISTENCE        │
│                │  │                │  │              │  │                    │
│ Collector ABC  │  │ Detector ABC   │  │ GraphBackend │  │ Repositories       │
│ DnsCollector   │  │ HeaderDetector │  │  ├ NetworkX  │  │  (SQLAlchemy 2.0)  │
│ CertCollector  │  │ TlsDetector    │  │  └ Neo4j     │  │ Unit of Work       │
│ HttpCollector  │  │ ExposureDetect │  │ Snapshots    │  │ Alembic migrations │
│ UrlscanCollect │  │ VersionDetect  │  │ Differ       │  │ PostgreSQL         │
│ ServiceCollect │  │ VersionDetect  │  │ Differ       │  │ PostgreSQL         │
│ (Celery tasks) │  │ RiskScorer     │  │ Exporters    │  │                    │
└───────┬────────┘  └───────┬────────┘  └──────┬───────┘  └───────┬────────────┘
        │                   │                  │                  │
┌───────▼───────────────────▼──────────────────▼──────────────────▼────────────┐
│  PLATFORM FOUNDATION                                                          │
│  Config (pydantic-settings + YAML) · Structured logging · Audit · Scope gate   │
│  Rate limiter · HTTP client policy · Retry/timeout policy · Task queue (Celery)│
└───────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Module dependency graph

Dependencies point downward only. No cycles.

```
                    ┌──────────────┐
                    │  cli / api   │
                    └──────┬───────┘
                           │
              ┌────────────▼────────────┐
              │  services (domain)      │
              └───┬────────┬────────┬───┘
                  │        │        │
      ┌───────────▼──┐ ┌───▼────┐ ┌─▼──────────┐
      │  collectors  │ │analysis│ │   graph    │
      └───────┬──────┘ └───┬────┘ └─────┬──────┘
              │            │            │
              └────────────┼────────────┘
                           │
                    ┌──────▼──────┐
                    │ repositories│
                    └──────┬──────┘
                           │
        ┌──────────────────┼───────────────────┐
        │                  │                   │
  ┌─────▼─────┐     ┌──────▼──────┐     ┌──────▼──────┐
  │    db     │     │   scope     │     │  platform   │
  │  models   │     │  validator  │     │ config/log  │
  └───────────┘     └─────────────┘     └─────────────┘
```

Hard rules:

- `atlas.db` imports nothing from `atlas.services`, `atlas.collect`, `atlas.graph`.
- `atlas.scope` is dependency-free (stdlib only) so it can be unit-tested and reused by workers.
- Collectors never write to the database directly; they return typed `Observation` objects that the
  calling service persists. This keeps collection pure and testable.
- Services never construct SQL; they call repositories.

---

## 5. Data flow — one collection run

What is implemented today (Phase 3) is steps 1–4 for DNS, TLS certificates, HTTP and the
urlscan source; steps 5–7 are the documented target for Phases 4–7 and are not wired yet.

```
CLI: atlas discover example.com
   │
   ├─ 1. resolve_target("example.com")  → kind + collection value
   │      ScopeSet.check(value)                              → ScopeViolation (exit 3)
   │      └─ denial is audited (discovery.denied) before raising; no job row
   │
   ├─ 2. upsert Target + ScanJob(status=running) committed before collection
   │      AuditEvent(discovery.start)
   │
   ├─ 3. collectors selected from CollectorRegistry by JobType
   │      ├─ available(settings) gate: an unconfigured source is skipped (FULL)
   │      │  or reported not_configured (explicit type) — never silently empty
   │      └─ DnsCollector / CertCollector / HttpCollector / UrlscanCollector
   │         .collect(target, CollectorContext) → CollectorResult
   │         (scope re-asserted at the collector boundary and per request;
   │          each request takes a token from the rate limiter)
   │
   ├─ 4. persistence (services, inside the caller's transaction)
   │      ├─ persist_dns_result         → Domain/IpAddress assets, DnsRecord history,
   │      │                               Relationships, added/removed diff
   │      ├─ persist_certificate_result → Certificate (per fingerprint) +
   │      │                               CertificateBinding + PRESENTS_CERTIFICATE
   │      ├─ persist_http_result        → Service, technologies/cookies on the
   │      │                               ScanResult, REDIRECTS_TO to known assets only
   │      ├─ persist_urlscan_result     → in-scope hosts only, RESOLVES_TO at 0.6,
   │      │                               verdicts archived as third-party opinion
   │      └─ record_scan_results → one immutable ScanResult per observation
   │                               (dns.answer, dns.status, tls.certificate,
   │                                http.response, urlscan.{scan,host,request,certificate})
   │
   ├─ 5. Correlate + analyse + score                        (Phase 4–6, not yet)
   │
   ├─ 6. Snapshot capture                                   (Phase 7, not yet)
   │
   └─ 7. ScanJob(status=SUCCEEDED|PARTIAL|FAILED, stats, error) + AuditEvent
```

Collectors never touch the database; the discovery service is the only writer.

**The console is another front end, not another engine.** `atlas.web.app` holds no
logic of its own: every route is a call into `atlas.services`, and collection goes
through `discover()`, which owns the scope gate and the audit record. That is why the
browser cannot collect something the CLI would refuse — there is one gate, and both
callers are behind it. The console binds loopback because it has no authentication;
`atlas serve` refuses a routable address unless the operator passes `--allow-remote`.

**The address gate.** Opening a socket to an address requires two independent gates,
applied together by `CollectorContext.permits_address()`:

1. **Network policy** classifies the address and refuses loopback, private, link-local,
   reserved and multicast targets unless `security.allow_private_addresses` is enabled.
   This is the SSRF boundary, and it outranks scope: an authorized name that resolves to
   `127.0.0.1` or a cloud metadata address is still refused.
2. **Scope** admits the address when a rule covers it directly, or when it is the answer
   for a host that is covered — otherwise a domain rule could never reach its own name.

**Scope at a source boundary.** A third-party source returns hosts ATLAS never chose. The
collector applies the scope set to every returned value and stamps each observation with an
`in_scope` flag; persistence creates an asset only for a flagged host. The page a scan captured
is the scan's authorization: when it is outside the project the collector raises
`ScopeViolation` before any of it is written. A source is never used to expand authorized
scope — a discovered host is recorded as evidence, not as a new permission.

---

## 6. Storage design

PostgreSQL in production (SQLite supported for local development and tests).
All timestamps are timezone-aware UTC. All primary keys are UUIDv4.

### 6.1 Entity-relationship overview

```
Project 1───* ScopeRule
Project 1───* Target 1───* ScanJob
Project 1───* Asset
Project 1───* Relationship
Project 1───* Finding 1───* Evidence
Project 1───* Snapshot 1───* SnapshotAsset
Project 1───* AuditEvent
Project 1───* AssetChange

Asset 1───0..1 Domain
Asset 1───0..1 IpAddress *───0..1 Asn
Asset 1───0..1 Certificate
Asset 1───* Service *───* Technology

Domain *───* DnsRecord          (records belong to the owning domain)
Domain 1───* Domain             (parent/child subdomain tree)
Certificate *───* Asset         (via CertificateBinding, with observation window)

Relationship: (src_asset) ──type──> (dst_asset)
Finding: (asset?) ── evidence ──> Evidence
ScanJob 1───* ScanResult
```

### 6.2 Table catalogue

| Table | Purpose | Key constraints |
|---|---|---|
| `projects` | Tenant boundary | `slug` unique |
| `scope_rules` | Authorization model | unique `(project_id, kind, pattern, mode)` |
| `targets` | Named roots submitted for collection | unique `(project_id, kind, value)` |
| `assets` | Canonical graph node | unique `(project_id, kind, key)` |
| `domains` | Domain detail | `fqdn` unique per project, self-FK `parent_id` |
| `ip_addresses` | IP detail | `address` unique per project, FK `asn_id` |
| `asns` | Autonomous system detail | `number` unique per project |
| `certificates` | X.509 detail | `fingerprint_sha256` unique per project |
| `certificate_bindings` | cert ↔ asset observation | unique `(certificate_id, asset_id)` |
| `services` | Port/protocol exposure | unique `(asset_id, port, transport)` |
| `technologies` | Fingerprint catalogue | unique `(name, version)` |
| `service_technologies` | service ↔ tech | unique `(service_id, technology_id)` |
| `dns_records` | Record observation history | index `(domain_id, record_type)` |
| `relationships` | Edges with provenance | unique `(project_id, src, dst, rel_type)` |
| `findings` | Scored issues | unique `(project_id, dedup_key)` |
| `evidence` | Raw proof | index `(finding_id)`, `content_hash` |
| `scan_jobs` | Execution record | index `(project_id, status)` |
| `scan_results` | Immutable raw observations | index `(scan_job_id, result_type)` |
| `snapshots` | Point-in-time asset set | index `(project_id, created_at)` |
| `snapshot_assets` | Membership + digest | unique `(snapshot_id, asset_id)` |
| `asset_changes` | Diff events | index `(project_id, detected_at)` |
| `audit_events` | Who did what | index `(project_id, created_at)` |

### 6.3 Provenance contract

Every observation-bearing row carries:

- `first_seen` / `last_seen` (Asset, Relationship, Service, DnsRecord, CertificateBinding)
- `source` (collector identifier, e.g. `dns`, `ct`, `http`, `tls`)
- `scan_job_id` where the observation originated from a job

No row is deleted to represent disappearance. Disappearance is an `AssetChange`
(`change_type = removed`) plus `Asset.is_active = false`.

---

## 7. Scope and authorization model

Scope is **default-deny**. A project with no active include rule can collect nothing.

Rule kinds:

| Kind | Example | Matches |
|---|---|---|
| `domain` | `example.com` | the apex and, when `include_subdomains`, all descendants |
| `domain` | `*.example.com` | descendants only |
| `ip` | `203.0.113.10` | that address |
| `cidr` | `203.0.113.0/24` | any address inside |
| `asn` | `AS64500` | only used for enrichment; never expands collection scope |
| `url` | `https://example.com/app` | exact host + path prefix |

Exclusion rules always win over inclusion rules.

Enforcement points:

1. `Target` creation — a target that is not permitted is rejected at write time.
2. Before every network operation — `ScopeSet.require_permitted(host_or_ip)`.
3. After resolution — a hostname resolving to an address outside scope is **reported, not scanned**.
4. SSRF guard — resolved addresses in private/reserved/loopback/link-local ranges are refused
   unless `ATLAS_SECURITY__ALLOW_PRIVATE_ADDRESSES=true` (explicit, documented, audited).
5. DNS rebinding — the address set validated before the request is the address set used for the
   request (the HTTP client is pinned to the vetted IP with the original `Host`/SNI header).

Every scope decision that denies is written to `audit_events` with the offending value.

---

## 8. Safety controls

| Control | Implementation |
|---|---|
| Rate limiting | Token bucket per `(project, host)` and global ceiling; `ATLAS_COLLECTOR__REQUESTS_PER_SECOND` |
| Timeouts | Connect/read/total per request; hard job deadline |
| Concurrency | Bounded `asyncio.Semaphore` / worker pool, per-host and global |
| Response caps | Max body bytes, max headers, max redirects |
| Retry policy | Exponential backoff with jitter, capped attempts, no retry on 4xx except 429 |
| SSRF | Scheme allowlist, address class check, redirect re-validation, no `file://`, `gopher://` |
| Cancellation | Cooperative cancellation token checked between units of work; job → `cancelled` |
| Secrets | Env/YAML only, never persisted in DB; redaction filter in the log formatter |
| Retention | Per-project `retention_days`; `atlas maintenance prune` deletes expired evidence/results |
| Audit | All mutating CLI/API actions append `audit_events` |

---

## 9. Extension points

- **New collector** — subclass `atlas.collect.base.Collector`, declare `name` and `job_type`,
  implement `collect(target, context) -> CollectorResult`. Register in
  `atlas.collect.registry` and expose it from `default_registry()`.
- **New detector** — subclass `atlas.analysis.base.Detector`, declare `finding_category`,
  implement `evaluate(asset) -> list[CandidateFinding]`. Register in the detector registry.
- **New graph backend** — implement `atlas.graph.backend.GraphBackend`.
- **New report format** — implement `atlas.reporting.base.Renderer`.

---

## 10. Deployment topology

```
            ┌────────────┐
  browser ──▶  nginx/caddy │
            └─────┬──────┘
                  │
        ┌─────────▼──────────┐        ┌───────────────┐
        │  api (uvicorn)     │───────▶│  PostgreSQL   │
        └─────────┬──────────┘        └───────────────┘
                  │                   ┌───────────────┐
                  ├──────────────────▶│    Redis      │
                  │                   └───────┬───────┘
        ┌─────────▼──────────┐                │
        │  worker (celery)   │◀───────────────┘
        └─────────┬──────────┘
                  │
        ┌─────────▼──────────┐
        │ beat (scheduler)   │
        └────────────────────┘
```

The CLI talks to the database directly (operator mode) or to the API (`--api-url`, planned
in Phase 8). The web UI talks only to the API.

---

## 11. Phase map

See `docs/ROADMAP.md`. Phase 1 delivers configuration, logging, errors, database schema,
migrations, scope enforcement, audit trail, CLI foundation and tests. Phase 2 adds the
collector runtime and DNS intelligence. Phase 3 adds certificate, HTTP and urlscan.io
collection with their persistence and CLI surfaces.
