# The local console

`atlas serve` starts a browser console on loopback. It is the same engine the CLI
drives — same scope gate, same collectors, same persistence — with the first-run
friction removed: declare scope, run a pass, read the results without memorising
command names.

It is **not** an API server for external clients and it has **no authentication**. It
binds `127.0.0.1` and refuses any other address unless you pass `--allow-remote`, which
prints what that means before starting.

## Start it

```bash
cd atlas
.venv/bin/atlas init                       # once: config, schema, default project
.venv/bin/atlas serve                      # http://127.0.0.1:8000/  (opens a browser)
```

| Flag | Default | Meaning |
|---|---|---|
| `--host` | `127.0.0.1` | Bind address. Non-loopback needs `--allow-remote`. |
| `--port` | `8000` | TCP port. |
| `--open/--no-open` | `--open` | Open a browser once the socket is actually accepting. |
| `--allow-remote` | off | Permit a routable bind. The console has no login. |
| `--reload` | off | Restart on source changes (development; in-process settings are not carried into the reloader). |

Use `--project <slug>` (a global flag, so before the subcommand) to serve a different
project, and a second port for a second project:

```bash
.venv/bin/atlas --project alpha serve --port 8001
```

## What the views do

| View | Backed by | Notes |
|---|---|---|
| Overview | `/api/state`, `/api/jobs` | Counters, collector readiness, projects, recent jobs. |
| Scope | `add_rule` / `remove_rules` / `ScopeSet.check` | Add or remove rules; the check strip shows the matcher's own reason. |
| Collect | `services.discovery.discover` | Runs in the server process, so a `full` pass holds the request open until it finishes (seconds, not minutes, at default rate limits). |
| Assets | `services.assets` | Filter by kind, search by key, expand one asset's detail. |
| DNS | `services.dns` | Records with first/last seen, NS summary, dangling-CNAME indicators, full history. |
| Certificates | `services.certificates` | Expiry window, presenting hosts, key and signature facts. |
| HTTP | `services.http` | Status, TLS, remote address, headers, redirect chain, technology evidence. |
| Jobs | `services.discovery` | Status per run, including `partial` and its errors. |
| Audit | `services.audit` | Scope changes, collection starts/finishes, denials. |
| Export | assembled in `web/app.py` | One JSON document for the active project. |

## Boundaries

- **Scope is enforced in the service layer, not the route.** A POST to
  `/api/collect` cannot bypass it, because the route calls `discover()`, which audits
  the denial and raises before any socket opens. There is no override, no dry-run flag
  and no "run anyway".
- **Read views never fabricate.** An empty project renders empty tables; a missing
  artifact returns 404 with the command that would produce it.
- **A `partial` job is a fixable gap.** An unconfigured source (urlscan without a key)
  makes the job `partial` for a `full` pass and reports `not_configured` for an
  explicit one. `failed` means nothing ran.
- **All routes are `GET` except scope add/remove, collect and urlscan ingest.** The
  console writes exactly what the CLI writes.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | The console shell. |
| GET | `/api/state` | Project, counters, scope, collectors, job types, runtime settings. |
| GET | `/api/projects` | Every project, with the served one marked. |
| GET/POST | `/api/scope` | List / add a rule. |
| DELETE | `/api/scope/{id}` | Remove a rule. |
| GET | `/api/scope/check?value=` | Evaluate a value without collecting. |
| POST | `/api/collect` | `{target, job_type, scan_id?}` → the discovery outcome. |
| POST | `/api/urlscan` | `{scan_id}` → an ingestion summary. |
| GET | `/api/assets?kind=&search=&limit=` | Asset list. |
| GET | `/api/assets/{key}` | Asset detail. |
| GET | `/api/dns` | Collected names, for the picker. |
| GET | `/api/dns/{fqdn}` | Records, history, nameservers (404 when never collected). |
| GET | `/api/dns-dangling` | Dangling-CNAME indicators backed by stored NXDOMAIN evidence. |
| GET | `/api/certs?days=&limit=` | Certificates, ordered by expiry. |
| GET | `/api/certs/{fingerprint}` | One certificate and its presenting hosts. |
| GET | `/api/http?limit=` | Archived HTTP observations, newest first. |
| GET | `/api/http/{host}` | Latest observation plus services (404 when never fetched). |
| GET | `/api/jobs?limit=` | Recent runs. |
| GET | `/api/audit?limit=&action=` | Audit events. |
| GET | `/api/urlscan?limit=` | Ingested scans. |
| GET | `/api/export` | Everything the project holds, as one document. |
| GET | `/api/openapi.json`, `/api/docs` | Generated schema and interactive docs. |

Errors use the same slugs and exit codes as the CLI, mapped to HTTP status:
`validation_error` 400, `scope_violation` 403, `not_found` 404, `conflict` 409,
`configuration_error` 500, `database_error` 503.

## Files

```
src/atlas/web/app.py          routes, error mapping, lifespan
src/atlas/web/main.py         ASGI entry point for uvicorn / --reload
src/atlas/web/static/         index.html, style.css, app.js (no build step, no CDN)
src/atlas/cli/commands/serve.py   binding rules, readiness probe, browser hand-off
tests/test_console.py         routes, gate parity, binding rules
```

The front end is three static files served from the package. There is no npm, no
bundler and no third-party origin — the console works with the network unplugged
except for the targets you ask it to collect.
