# ATLAS

**Attack Surface Intelligence System** — a self-contained, local-first tool for external attack surface mapping. Discover infrastructure, track certificates, observe HTTP posture, detect dangling CNAMEs, and get an AI-powered security summary — all from a browser running on your own machine.

No cloud. No accounts. No data leaves your machine (except to the targets you explicitly authorize and to AI/urlscan.io APIs if you configure them).

---

## What it does

- **DNS intelligence** — resolves targets, records history, detects dangling CNAMEs
- **TLS certificates** — grabs and tracks certificates, expiry, self-signed flags, key strength
- **HTTP observation** — headers, redirects, technology fingerprinting, security header gaps
- **urlscan.io integration** — ingest existing scans for passive enrichment (free API key)
- **Red flags** — automatic detection of expired certs, missing HSTS/CSP/X-Content-Type-Options, plaintext HTTP, weak keys, dangling CNAMEs
- **AI chat** — built-in chat panel that loads your collected data as context; works with any OpenAI-compatible API (OpenAI, DeepSeek, local Ollama, etc.)
- **Scope gate** — nothing is collected unless you explicitly declare the target as authorized
- **Auto-purge** — all collected data is wiped when you close the browser tab (optional, on by default)

---

## Quick start

**Requirements:** Python 3.12+

```bash
git clone https://github.com/YOUR_USERNAME/atlas.git
cd atlas

python3 -m venv .venv
.venv/bin/pip install -e .

.venv/bin/atlas init       # creates atlas.db and default project
.venv/bin/atlas serve      # opens http://127.0.0.1:8000/
```

Then in the browser:

1. **Scope tab** — add a domain you are authorized to test (e.g. `example.com`)
2. **Collect tab** — select the target, pick `Full pass`, click Collect
3. **Overview tab** — see red flags and chat with the AI about what was found

---

## urlscan.io (optional, free)

Get a free API key at https://urlscan.io/user/profile/ and add it to `atlas.yaml`:

```yaml
sources:
  urlscan_api_key: "your-key-here"
```

This enables the urlscan.io collector, which ingests existing scans for passive enrichment without touching the target directly.

---

## AI chat (optional)

The Overview tab has a built-in AI chat panel. It works with any OpenAI-compatible API:

| Provider | Endpoint | Model |
|---|---|---|
| OpenAI | `https://api.openai.com/v1/chat/completions` | `gpt-4o-mini` |
| DeepSeek | `https://api.deepseek.com/v1/chat/completions` | `deepseek-chat` |
| Ollama (local) | `http://localhost:11434/v1/chat/completions` | `llama3` |

Enter your key and endpoint in the panel, click **Save**. The key is stored in browser `localStorage` only — it is never sent to the ATLAS server.

---

## CLI usage

```bash
# initialize
.venv/bin/atlas init

# scope
.venv/bin/atlas scope add example.com
.venv/bin/atlas scope list

# collect
.venv/bin/atlas collect example.com --type full
.venv/bin/atlas collect example.com --type dns
.venv/bin/atlas collect example.com --type certificates
.venv/bin/atlas collect example.com --type http

# read results
.venv/bin/atlas assets list
.venv/bin/atlas dns show example.com
.venv/bin/atlas certs expiring --days 30
.venv/bin/atlas http show example.com

# web console
.venv/bin/atlas serve
.venv/bin/atlas serve --port 8001   # second project on a different port
```

---

## Configuration

Copy `atlas.yaml` to your project directory and edit as needed. All settings can also be overridden with environment variables using the `ATLAS_` prefix:

```bash
ATLAS_API__PORT=9000 .venv/bin/atlas serve
ATLAS_SOURCES__URLSCAN_API_KEY=your-key .venv/bin/atlas serve
```

---

## Security model

- **Loopback only by default** — binds `127.0.0.1`. Use `atlas serve --allow-remote` to expose on a routable interface (prints a warning).
- **No authentication** — acceptable because it is loopback-only. Do not expose publicly.
- **Scope is a hard gate** — collection is refused before a socket is opened if the target is not in scope. There is no override in the web console.
- **Read-only collection** — ATLAS does not exploit anything. It observes and records.
- **Auto-purge on close** — by default, all collected data (assets, DNS, certs, jobs, scope rules) is deleted when you close the browser tab, leaving no trace.

---

## License

MIT — see `LICENSE`.
