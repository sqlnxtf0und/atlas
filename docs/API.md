# ATLAS — API Specification (v1)

Status: **specification**. The FastAPI application lands in Phase 8. This document fixes the
contract now so collectors, CLI and UI agree on shapes.

Base path: `/api/v1`. Content type: `application/json`. Errors: `application/problem+json`.

```
{
  "type": "https://atlas.local/errors/scope-violation",
  "title": "Scope violation",
  "status": 403,
  "detail": "203.0.113.9 is not covered by any active include rule",
  "instance": "/api/v1/targets"
}
```

Authentication: `Authorization: Bearer <api-key>` (machine) or session cookie (UI).
Roles: `viewer` (read), `analyst` (read + collect), `admin` (everything + scope changes).

Pagination: `?limit=50&cursor=<opaque>`; responses carry
`{"items": [...], "next_cursor": "...", "total": 1234}`.

Common query filters: `?q=`, `?kind=`, `?active=true`, `?severity=`, `?from=&to=`.

---

## Projects

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/projects` | viewer | list projects |
| POST | `/projects` | admin | create project |
| GET | `/projects/{slug}` | viewer | project detail + counters |
| PATCH | `/projects/{slug}` | admin | rename, description, retention |
| DELETE | `/projects/{slug}` | admin | delete (requires `?confirm=<slug>`) |

## Scope

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/projects/{slug}/scope` | viewer | effective include/exclude rules |
| POST | `/projects/{slug}/scope` | admin | add rule |
| DELETE | `/projects/{slug}/scope/{rule_id}` | admin | remove rule |
| POST | `/projects/{slug}/scope/check` | analyst | evaluate a value → `{permitted, matched_rule, reason}` |

## Targets

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/projects/{slug}/targets` | viewer | list |
| POST | `/projects/{slug}/targets` | analyst | add target (scope-checked) |
| DELETE | `/projects/{slug}/targets/{id}` | analyst | remove |

## Collection jobs

| Method | Path | Role | Purpose |
|---|---|---|---|
| POST | `/projects/{slug}/jobs` | analyst | `{target, modules[], profile}` → job |
| GET | `/projects/{slug}/jobs` | viewer | list with status |
| GET | `/jobs/{id}` | viewer | job detail + stats |
| POST | `/jobs/{id}/cancel` | analyst | cooperative cancel |
| GET | `/jobs/{id}/results` | viewer | raw observation stream |

## Assets

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/projects/{slug}/assets` | viewer | filter by kind/active/q |
| GET | `/assets/{id}` | viewer | detail (domain/ip/cert/service payload included) |
| GET | `/assets/{id}/relationships` | viewer | incident edges with provenance |
| GET | `/assets/{id}/findings` | viewer | findings for asset |
| GET | `/assets/{id}/history` | viewer | first/last seen + change events |

## DNS

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/projects/{slug}/dns` | viewer | record inventory |
| GET | `/dns/{domain_id}` | viewer | records grouped by type |
| GET | `/dns/{domain_id}/history` | viewer | change timeline |
| GET | `/projects/{slug}/dns/anomalies` | viewer | dangling / inconsistent records |

## Certificates

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/projects/{slug}/certificates` | viewer | inventory |
| GET | `/certificates/{id}` | viewer | subject, SAN, issuer, validity, fingerprint |
| GET | `/certificates/expiring?days=30` | viewer | expiry feed |
| GET | `/certificates/{id}/shared` | viewer | hosts presenting the same cert |

## HTTP

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/projects/{slug}/http` | viewer | per-host HTTP profile |
| GET | `/http/{service_id}` | viewer | headers, redirect chain, cookies, tech |
| GET | `/http/{service_id}/diff?against=<scan_id>` | viewer | response difference |

## Findings

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/projects/{slug}/findings` | viewer | filter severity/confidence/status |
| GET | `/findings/{id}` | viewer | finding + evidence + reasoning |
| PATCH | `/findings/{id}` | analyst | status, note |
| GET | `/findings/{id}/evidence` | viewer | evidence blobs / references |
| GET | `/projects/{slug}/findings/summary` | viewer | counts by severity/category |

## Graph

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/projects/{slug}/graph` | viewer | nodes + edges (filterable by kind/rel) |
| GET | `/projects/{slug}/graph/clusters` | viewer | connected components / shared infra |
| GET | `/projects/{slug}/graph/neighbours/{asset_id}?depth=2` | viewer | subgraph |
| POST | `/projects/{slug}/graph/snapshot` | analyst | capture snapshot |
| GET | `/projects/{slug}/graph/snapshots` | viewer | snapshot list |
| GET | `/projects/{slug}/graph/diff?from=&to=` | viewer | added/removed/changed |
| GET | `/projects/{slug}/graph/export?format=json|graphml` | viewer | download |

## History and monitoring

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/projects/{slug}/history/changes` | viewer | change feed |
| GET | `/projects/{slug}/history/compare?from=&to=` | viewer | diff detail |
| GET | `/projects/{slug}/monitor` | viewer | schedule + last runs |
| POST | `/projects/{slug}/monitor` | admin | set schedule (cron, profile) |
| POST | `/projects/{slug}/monitor/run` | analyst | trigger now |
| DELETE | `/projects/{slug}/monitor` | admin | disable |

## Reports

| Method | Path | Role | Purpose |
|---|---|---|---|
| POST | `/projects/{slug}/reports` | analyst | `{format, scope, sections[]}` |
| GET | `/reports/{id}` | viewer | status + metadata |
| GET | `/reports/{id}/download` | viewer | artifact |

## Settings and health

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/settings` | admin | effective config (redacted) |
| PATCH | `/settings` | admin | runtime-tunable knobs |
| GET | `/health` | public | liveness |
| GET | `/ready` | public | DB + Redis reachability |
| GET | `/audit` | admin | audit feed |

---

## Response shapes (excerpt)

`GET /api/v1/assets/{id}`

```json
{
  "id": "0f0c2f7e-...",
  "kind": "domain",
  "key": "api.example.com",
  "first_seen": "2026-11-01T09:12:44Z",
  "last_seen": "2026-11-19T06:00:11Z",
  "is_active": true,
  "confidence": 1.0,
  "source": "dns",
  "attributes": {"registrable_domain": "example.com", "is_apex": false},
  "domain": {"fqdn": "api.example.com", "parent": "example.com", "record_count": 4},
  "relationships": {"out": 3, "in": 1},
  "findings": {"critical": 0, "high": 1, "medium": 2, "low": 4, "info": 7}
}
```

`GET /api/v1/findings/{id}`

```json
{
  "id": "9a1e...",
  "title": "Missing Content-Security-Policy",
  "category": "http.headers",
  "severity": "medium",
  "confidence": 0.95,
  "exposure": "public",
  "business_relevance": "unknown",
  "detection_method": "http.header_presence",
  "evidence": [{"kind": "header_set", "source": "http", "collected_at": "2026-11-19T06:00:11Z"}],
  "remediation": "Serve a Content-Security-Policy header with a restrictive default-src.",
  "reasoning": "Header absent in 3/3 observations over 14 days."
}
```

Severity and confidence are independent fields. Severity reflects impact class;
confidence reflects evidence strength. A high-severity, low-confidence finding is valid and
must render as such.
