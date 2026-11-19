# ATLAS — CLI Specification

Global invocation:

```
atlas [GLOBAL OPTIONS] COMMAND [ARGS]
```

Global options:

| Option | Default | Meaning |
|---|---|---|
| `--config PATH` | `./atlas.yaml`, then `~/.config/atlas/atlas.yaml` | YAML configuration file |
| `--db-url URL` | from config | Override database URL |
| `--project SLUG` | `default` | Active project for project-scoped commands |
| `--json` | off | Machine-readable output on stdout; logs stay on stderr |
| `--log-level LEVEL` | `info` | `debug|info|warning|error` |
| `--no-color` | off | Disable ANSI colour |
| `--version` | — | Print version and exit |

Exit codes (stable contract):

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | unexpected internal error |
| 2 | usage error (Typer/Click) |
| 3 | scope violation / authorization refusal |
| 4 | resource not found |
| 5 | conflict (duplicate, already exists) |
| 6 | configuration error |
| 7 | database error / migration required |
| 8 | cancelled by operator |

---

## Implemented in Phase 1

### `atlas init`

Create the configuration file and the database schema, then create the default project.

```
atlas init [--force] [--config PATH] [--db-url URL]
```

- Writes `atlas.yaml` if absent (never overwrites without `--force`).
- Runs `alembic upgrade head` against the configured database.
- Creates project `default` if absent.
- Emits an `audit_events` row (`action = project.init`).

### `atlas version`

```
atlas version [--json]
```

Prints ATLAS version, Python version, database backend and schema revision.

### `atlas config show`

```
atlas config show [--json]
```

Prints effective configuration with secrets redacted.

### `atlas project create NAME [--slug SLUG] [--description TEXT]`

Creates a project. Slug is derived from the name when omitted. Duplicate slug → exit 5.

### `atlas project list`

Table of projects: slug, name, assets, findings, created.

### `atlas project show [SLUG]`

Detail view: scope rule count, target count, asset count, open findings, retention.

### `atlas project delete SLUG --yes`

Deletes a project and all dependent rows (cascade). Refuses without `--yes`.

---

### `atlas scope add PATTERN`

```
atlas scope add PATTERN [--kind domain|ip|cidr|asn|url] [--mode include|exclude]
                        [--no-subdomains] [--note TEXT] [--expires YYYY-MM-DD]
```

- Kind is inferred when omitted (`10.0.0.0/8` → cidr, `AS64500` → asn, `https://…` → url,
  bare address → ip, otherwise domain).
- Pattern is normalized and validated; invalid input → exit 2.
- Duplicate `(kind, pattern, mode)` → exit 5.

### `atlas scope list`

Table: kind, pattern, mode, subdomains, active, expires, note.

### `atlas scope remove PATTERN [--kind KIND] [--mode MODE]`

Deletes matching rule(s). Not found → exit 4.

### `atlas scope check VALUE`

Evaluates a hostname, IP or URL against the project scope and prints the decision plus the
rule that decided it. Denied → exit 3. This is the same code path collectors use.

### `atlas scope export [--json]`

Emits the effective scope as JSON (`{include: [...], exclude: [...]}`).

---

### `atlas assets list`

```
atlas assets list [--kind domain|ip|asn|certificate|service] [--active|--inactive]
                  [--search TEXT] [--limit N] [--json]
```

### `atlas assets show KEY`

Detail view for an asset by its canonical key (`example.com`, `203.0.113.10`,
`sha256:ab12…`, `203.0.113.10:443/tcp`).

---

### `atlas audit list [--limit N] [--action ACTION] [--json]`

Append-only audit feed, newest first.

### `atlas db upgrade|current|revision -m MESSAGE`

Alembic wrappers. `upgrade` applies migrations; `current` prints the schema revision;
`revision` autogenerates a migration (developer use).

---

## Implemented in Phase 2

### `atlas discover TARGET`

Run a scoped collection pass over a target. `TARGET` may be a domain, IP, CIDR or URL; it is
normalized and must be covered by an active include rule (otherwise exit 3, audited as
`discovery.denied`, no job row created).

```
atlas discover TARGET [--full]
```

- Default (`discover`) runs the collectors registered for the `discover` job type (DNS today).
- `--full` runs every registered collector: DNS, TLS certificates, HTTP, and urlscan when a key
  is configured. An unavailable source is skipped and listed in `skipped_collectors`.
- Creates a committed `ScanJob` before collection, archives each observation as a `ScanResult`,
  persists DNS assets/records/relationships, and finalizes the job to
  `succeeded` / `partial` / `failed`.
- Exit 0 on success, 1 when the job did not fully succeed.

### `atlas collect TARGET`

Long form of the same pipeline with an explicit collector selection.

```
atlas collect TARGET [--type discover|dns|certificates|certs|http|urlscan|full]
                     [--scan-id UUID] [--dry-run]
```

- `--dry-run` prints the scope decision (`permitted`, `reason`, `collection_value`) without
  collecting; exits 1 when not permitted.
- Any other run behaves like `discover` with the chosen job type.
- `--scan-id` reads one existing urlscan.io scan; it is only valid with `--type urlscan`.
- An explicitly named source that is not configured (urlscan without a key) records
  `not_configured` and closes the job `partial` rather than `failed`.

### `atlas dns show FQDN`

```
atlas dns show FQDN [--types A,AAAA,CNAME,MX,NS,TXT,SOA,CAA,PTR] [--all]
```

Current records with TTL, priority and active flag. `--all` includes retired records.

### `atlas dns history FQDN`

Every record ever observed for the name, grouped by type, with first/last seen and the
observation window. Exit 2 (`validation_error`) for a name never collected.

### `atlas dns nameservers FQDN`

Nameservers for the name plus other collected names sharing them. Shared nameservers are
labelled as shared DNS infrastructure, **not** shared ownership.

### `atlas dns dangling`

CNAME targets that a stored `ScanResult` recorded as NXDOMAIN. Each finding carries its
evidence (query name, target, status, observation timestamp, scan job id). Absence of a name is
never used as evidence on its own.

## `atlas serve`

```bash
atlas serve [--host 127.0.0.1] [--port 8000] [--open/--no-open] [--allow-remote] [--reload]
```

Serves the local browser console. Non-loopback binds are refused without
`--allow-remote`; the browser opens only once the port is accepting. See `docs/WEB.md`.

## Implemented in Phase 3

### `atlas certs list`

```
atlas certs list [--days N] [--include-expired/--hide-expired] [--limit N]
```

One row per certificate, soonest expiry first: presenting host, subject CN, issuer CN, expiry,
days remaining (or `expired`), and the self-signed flag.

### `atlas certs expiring`

```
atlas certs expiring [--days 30] [--include-expired/--hide-expired]
```

The expiry monitor feed, windowed against the current clock. Expiry is reported as a date and a
day count — no severity is assigned here, because whether nine days is a problem is an operator
call.

### `atlas certs show FINGERPRINT`

A certificate plus every host that has presented it. When more than one host is listed, the
output carries an explicit note that a shared certificate is shared infrastructure, **not**
shared ownership.

### `atlas http show HOST`

```
atlas http show HOST
```

The most recent observation for a host: URL, status, final URL after redirects, scheme and port,
TLS version, server, title, remote address, response headers, technology markers with their
evidence and confidence, each `Set-Cookie` as sent, and the services recorded for the host.
Technologies are evidence of what answered — never a claim of exploitability.

### `atlas http list`

```
atlas http list [--limit 50]
```

Archived HTTP observations, newest first.

### `atlas sources urlscan SCAN_ID`

```
atlas sources urlscan SCAN_ID [--show]
```

Ingests an existing urlscan.io scan (UUID or result URL) into the project: the page, in-scope
hosts, archived requests, services and relationships. Out-of-scope hosts are archived with
`in_scope: false` and never promoted to assets. A scan whose captured page is outside the
project raises `scope_violation` (exit 3) and closes the job `failed`.

`--show` prints a previously ingested scan without touching the network.

ATLAS never submits a URL to urlscan.io. The source is read-only by construction.

---

## Planned (documented, not yet implemented)

Registered in the roadmap, **not** present in the CLI until they work:

```
atlas graph build              # Phase 5
atlas graph export --format json|graphml
atlas findings list --severity high
atlas history compare FROM TO
atlas report generate --format html|json|csv|pdf
atlas monitor start|stop|status
atlas maintenance prune --older-than 90d
```

Invoking one of these before its phase lands prints:

```
ollie: not on the bench yet — <command> lands in phase <N>.
```

and exits 2. No command ever pretends to run.
