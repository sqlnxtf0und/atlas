/* ATLAS local console — vanilla JS, no build step, no network calls beyond this origin. */

"use strict";

const state = {
  meta: null,
  view: "overview",
  dnsNames: [],
};

/* ------------------------------------------------------------------ */
/* utilities                                                          */
/* ------------------------------------------------------------------ */

const $ = (id) => document.getElementById(id);

function esc(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function dash(value) {
  return value === null || value === undefined || value === "" ? "—" : value;
}

function toast(message, ok) {
  const el = $("toast");
  el.textContent = message;
  el.className = "toast" + (ok ? " ok" : "");
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => el.classList.add("hidden"), 7000);
}

function footStatus(message) {
  $("foot-status").textContent = message || "";
}

async function api(path, options) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  let payload = null;
  const text = await response.text();
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = { error: "bad_response", message: text.slice(0, 400) };
    }
  }
  if (!response.ok) {
    const detail = payload && payload.message ? payload.message : `HTTP ${response.status}`;
    const error = new Error(detail);
    error.slug = payload && payload.error ? payload.error : "http_error";
    error.status = response.status;
    throw error;
  }
  return payload;
}

function table(columns, rows, renderRow) {
  if (!rows.length) return `<p class="empty">nothing collected yet</p>`;
  const head = columns.map((c) => `<th class="${esc(c.cls || "")}">${esc(c.label)}</th>`).join("");
  const body = rows.map((row) => `<tr>${renderRow(row)}</tr>`).join("");
  return `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

function cell(value, cls) {
  return `<td class="${cls || ""}">${esc(dash(value))}</td>`;
}

/* ------------------------------------------------------------------ */
/* boot                                                               */
/* ------------------------------------------------------------------ */

async function loadState() {
  const meta = await api("/api/state");
  state.meta = meta;
  $("project-chip").textContent = meta.project.slug;
  $("db-chip").textContent = meta.settings.database_backend;
  $("version-chip").textContent = "v" + meta.version;
  renderOverview(meta);
  renderScope(meta.scope);
  renderJobTypes(meta.job_types);
  renderProjects(meta);
  $("setup-banner").classList.toggle("hidden", meta.scope_configured);
  return meta;
}

function renderOverview(meta) {
  const counts = meta.counts;
  const cards = [
    ["scope rules", counts.scope_rules],
    ["targets", counts.targets],
    ["assets", counts.assets],
    ["findings", counts.findings],
    ["open findings", counts.open_findings],
  ];
  $("stat-cards").innerHTML = cards
    .map(
      ([label, value]) => `
      <div class="card">
        <div class="label">${esc(label)}</div>
        <div class="value">${esc(value)}</div>
      </div>`
    )
    .join("");

  $("collector-list").innerHTML = meta.collectors
    .map(
      (collector) => `
      <div class="collector">
        <span>${esc(collector.label)}</span>
        ${
          collector.ready
            ? '<span class="tag ok">ready</span>'
            : `<span class="tag off" title="${esc(collector.reason)}">${esc(collector.reason)}</span>`
        }
      </div>`
    )
    .join("");

  const settings = meta.settings;
  $("runtime-list").innerHTML = `
    <dt>database</dt><dd>${esc(settings.database_backend)}</dd>
    <dt>rate</dt><dd>${esc(settings.requests_per_second)} req/s</dd>
    <dt>job deadline</dt><dd>${esc(settings.job_deadline_seconds)} s</dd>
    <dt>max body</dt><dd>${esc(settings.max_body_bytes)} bytes</dd>
    <dt>private addresses</dt>
    <dd>${settings.allow_private_addresses ? "allowed" : "refused (SSRF guard)"}</dd>`;
}

function renderProjects(meta) {
  const projects = meta.projects || [];
  $("project-list").innerHTML = table(
    [{ label: "slug" }, { label: "name" }, { label: "" }],
    projects,
    (project) =>
      cell(project.slug, "mono") +
      cell(project.name) +
      `<td>${
        project.active
          ? '<span class="tag ok">serving</span>'
          : `<code>atlas serve --project ${esc(project.slug)} --port ${esc(8001)}</code>`
      }</td>`
  );
}

function renderJobTypes(jobTypes) {
  const select = $("collect-type");
  select.innerHTML = jobTypes
    .map((entry) => `<option value="${esc(entry.value)}">${esc(entry.label)}</option>`)
    .join("");
  select.value = "full";
}

/* ------------------------------------------------------------------ */
/* overview jobs                                                      */
/* ------------------------------------------------------------------ */

function jobTags(job) {
  const tone =
    job.status === "succeeded" ? "ok" : job.status === "partial" ? "warn" : job.status === "running" ? "" : "bad";
  return `<span class="tag ${tone}">${esc(job.status)}</span>`;
}

async function loadOverviewJobs() {
  try {
    const payload = await api("/api/jobs?limit=6");
    $("overview-jobs").innerHTML = table(
      [
        { label: "job" },
        { label: "type" },
        { label: "status" },
        { label: "target" },
        { label: "started" },
      ],
      payload.jobs,
      (job) =>
        cell(String(job.id).slice(0, 8), "mono nowrap") +
        cell(job.job_type) +
        `<td>${jobTags(job)}</td>` +
        cell(job.params && job.params.target ? job.params.target : "", "mono wrap") +
        cell(job.started_at || job.created_at, "mono nowrap")
    );
  } catch (error) {
    $("overview-jobs").innerHTML = `<p class="empty">${esc(error.message)}</p>`;
  }
}

/* ------------------------------------------------------------------ */
/* scope                                                              */
/* ------------------------------------------------------------------ */

function renderScope(rules) {
  const rows = rules || [];
  $("scope-table").innerHTML = table(
    [
      { label: "mode" },
      { label: "kind" },
      { label: "pattern", cls: "mono" },
      { label: "subdomains" },
      { label: "note" },
      { label: "" },
    ],
    rows,
    (rule) => `
      <td><span class="tag ${rule.mode === "include" ? "ok" : "bad"}">${esc(rule.mode)}</span></td>
      ${cell(rule.kind)}
      <td class="mono wrap">${esc(rule.pattern)}</td>
      <td>${rule.include_subdomains ? "yes" : "no"}</td>
      ${cell(rule.note)}
      <td><button class="danger" data-remove-rule="${esc(rule.id)}" data-pattern="${esc(rule.pattern)}">remove</button></td>`
  );
}

async function addScope(event) {
  event.preventDefault();
  const pattern = $("scope-pattern").value.trim();
  if (!pattern) return;
  const body = {
    pattern,
    kind: $("scope-kind").value || null,
    note: $("scope-note").value.trim() || null,
  };
  try {
    await api("/api/scope", { method: "POST", body: JSON.stringify(body) });
    $("scope-pattern").value = "";
    $("scope-note").value = "";
    toast(`scope rule added: ${pattern}`, true);
    const meta = await loadState();
    renderScope(meta.scope);
  } catch (error) {
    toast(error.message);
  }
}

async function removeScope(ruleId, pattern) {
  if (!confirm(`Remove the scope rule for ${pattern}?`)) return;
  try {
    await api(`/api/scope/${encodeURIComponent(ruleId)}`, { method: "DELETE" });
    toast(`removed ${pattern}`, true);
    const meta = await loadState();
    renderScope(meta.scope);
  } catch (error) {
    toast(error.message);
  }
}

async function checkScope(value) {
  const strip = $("scope-check");
  if (!value.trim()) {
    strip.classList.add("hidden");
    return;
  }
  try {
    const result = await api(`/api/scope/check?value=${encodeURIComponent(value.trim())}`);
    strip.className = "check-strip " + (result.permitted ? "ok" : "bad");
    strip.textContent = `${result.permitted ? "permitted" : "denied"} · ${result.normalized} (${result.kind}) — ${result.reason}`;
  } catch (error) {
    strip.className = "check-strip bad";
    strip.textContent = error.message;
  }
}

/* ------------------------------------------------------------------ */
/* collect                                                            */
/* ------------------------------------------------------------------ */

async function runCollect(event) {
  event.preventDefault();
  const target = $("collect-target").value.trim();
  if (!target) return;
  const jobType = $("collect-type").value;
  const scanId = $("collect-scan").value.trim();
  const status = $("collect-status");
  const button = $("collect-submit");

  if (jobType === "urlscan" && !scanId) {
    status.className = "status bad";
    status.textContent = "urlscan needs a scan id (UUID or result URL) — set it in the third field.";
    status.classList.remove("hidden");
    return;
  }

  button.disabled = true;
  status.className = "status running";
  status.textContent = `running ${jobType} against ${target}… (scope check, then collection)`;
  status.classList.remove("hidden");
  $("collect-result").innerHTML = "";
  footStatus("collecting…");

  const started = performance.now();
  try {
    const outcome = await api("/api/collect", {
      method: "POST",
      body: JSON.stringify({
        target,
        job_type: jobType,
        scan_id: scanId || null,
      }),
    });
    const seconds = ((performance.now() - started) / 1000).toFixed(1);
    status.className = "status " + (outcome.status === "succeeded" ? "ok" : "bad");
    status.textContent = `${outcome.status} · ${outcome.observations} observation(s) · ${seconds}s · job ${String(outcome.job_id).slice(0, 8)}`;
    renderCollectResult(outcome);
    footStatus(`last: ${jobType} ${target} → ${outcome.status}`);
    await loadState();
    await loadOverviewJobs();
  } catch (error) {
    status.className = "status bad";
    status.textContent =
      error.slug === "scope_violation"
        ? `denied: ${error.message}`
        : `failed: ${error.message}`;
    footStatus("last collection failed");
    if (error.slug === "scope_violation") {
      $("collect-result").innerHTML =
        '<p class="hint">The scope gate refused this before any socket was opened. ' +
        'Add the target under <button class="link" data-goto="scope">Scope</button> if it is authorized.</p>';
    }
  } finally {
    button.disabled = false;
  }
}

function renderCollectResult(outcome) {
  const collectors = outcome.collectors || [];
  const errors = outcome.errors || [];
  const skipped = outcome.skipped_collectors || [];

  let html = "";

  html += `<div class="subpanel"><h3>Collectors</h3>`;
  if (!collectors.length) {
    html += `<p class="empty">no collector ran</p>`;
  } else {
    html += table(
      [{ label: "collector" }, { label: "result" }, { label: "observations", cls: "num" }, { label: "errors", cls: "num" }, { label: "duration", cls: "num" }],
      collectors,
      (entry) =>
        cell(entry.collector, "mono") +
        `<td>${
          entry.ok
            ? '<span class="tag ok">ok</span>'
            : entry.partial
              ? '<span class="tag warn">partial</span>'
              : '<span class="tag bad">failed</span>'
        }</td>` +
        `<td class="num">${esc(entry.observations)}</td>` +
        `<td class="num">${esc(entry.errors)}</td>` +
        `<td class="num">${esc(entry.duration_seconds)}s</td>`
    );
  }
  html += `</div>`;

  if (errors.length) {
    html += `<div class="subpanel"><h3>Errors</h3>`;
    html += table(
      [{ label: "operation" }, { label: "type" }, { label: "message" }],
      errors,
      (error) =>
        cell(error.operation, "mono") +
        `<td><span class="tag bad">${esc(error.type || error.error_type)}</span></td>` +
        `<td class="wrap">${esc(error.message)}</td>`
    );
    html += `</div>`;
  }

  if (skipped.length) {
    html += `<div class="subpanel"><h3>Skipped</h3>`;
    html += table(
      [{ label: "collector" }, { label: "reason" }],
      skipped,
      (entry) => cell(entry.collector || entry.name, "mono") + `<td class="wrap">${esc(entry.reason)}</td>`
    );
    html += `</div>`;
  }

  html += `<div class="subpanel"><h3>Raw outcome</h3>
    <details><summary>show JSON</summary><pre>${esc(JSON.stringify(outcome, null, 2))}</pre></details></div>`;

  $("collect-result").innerHTML = html;
}

/* ------------------------------------------------------------------ */
/* assets                                                             */
/* ------------------------------------------------------------------ */

async function loadAssets() {
  const kind = $("asset-kind").value;
  const search = $("asset-search").value.trim();
  const params = new URLSearchParams({ limit: "300" });
  if (kind) params.set("kind", kind);
  if (search) params.set("search", search);
  try {
    const payload = await api(`/api/assets?${params}`);
    $("assets-table").innerHTML = table(
      [
        { label: "kind" },
        { label: "key" },
        { label: "source" },
        { label: "conf", cls: "num" },
        { label: "active" },
        { label: "last seen" },
        { label: "" },
      ],
      payload.assets,
      (asset) => `
        <td>${esc(asset.kind)}</td>
        <td class="mono wrap">${esc(asset.key)}</td>
        ${cell(asset.source)}
        <td class="num">${esc(asset.confidence.toFixed(2))}</td>
        <td>${asset.is_active ? '<span class="tag ok">active</span>' : '<span class="tag off">retired</span>'}</td>
        ${cell(asset.last_seen, "mono nowrap")}
        <td><button class="ghost" data-asset="${esc(asset.key)}">detail</button></td>`
    );
  } catch (error) {
    $("assets-table").innerHTML = `<p class="empty">${esc(error.message)}</p>`;
  }
}

async function showAsset(key) {
  try {
    const detail = await api(`/api/assets/${encodeURIComponent(key)}`);
    $("assets-table").insertAdjacentHTML(
      "afterbegin",
      `<div class="panel" id="asset-detail">
        <h2>${esc(detail.kind)} · ${esc(detail.key)}</h2>
        <dl class="kv">
          <dt>asset id</dt><dd>${esc(detail.id)}</dd>
          <dt>source</dt><dd>${esc(dash(detail.source))}</dd>
          <dt>confidence</dt><dd>${esc(detail.confidence)}</dd>
          <dt>first seen</dt><dd>${esc(dash(detail.first_seen))}</dd>
          <dt>last seen</dt><dd>${esc(dash(detail.last_seen))}</dd>
        </dl>
        <details><summary>attributes and relationships</summary>
          <pre>${esc(JSON.stringify(detail, null, 2))}</pre>
        </details>
        <button class="ghost" onclick="document.getElementById('asset-detail').remove()">close</button>
      </div>`
    );
  } catch (error) {
    toast(error.message);
  }
}

/* ------------------------------------------------------------------ */
/* DNS                                                                */
/* ------------------------------------------------------------------ */

async function loadDnsNames() {
  try {
    const payload = await api("/api/dns");
    state.dnsNames = payload.names;
    $("dns-picker").innerHTML =
      '<option value="">collected names…</option>' +
      payload.names
        .map((entry) => `<option value="${esc(entry.fqdn)}">${esc(entry.fqdn)}</option>`)
        .join("");
  } catch (error) {
    footStatus(error.message);
  }
}

async function loadDns(fqdn) {
  const name = (fqdn || $("dns-input").value).trim();
  if (!name) return;
  $("dns-input").value = name;
  try {
    const payload = await api(`/api/dns/${encodeURIComponent(name)}`);
    let html = `<div class="subpanel"><h3>records for ${esc(payload.fqdn)}</h3>`;
    html += table(
      [
        { label: "type" },
        { label: "value" },
        { label: "ttl", cls: "num" },
        { label: "prio", cls: "num" },
        { label: "state" },
        { label: "first seen" },
        { label: "last seen" },
      ],
      payload.records,
      (record) =>
        cell(record.record_type, "mono nowrap") +
        cell(record.value, "mono wrap") +
        `<td class="num">${esc(dash(record.ttl))}</td>` +
        `<td class="num">${esc(dash(record.priority))}</td>` +
        `<td>${record.is_active ? '<span class="tag ok">active</span>' : '<span class="tag off">retired</span>'}</td>` +
        cell(record.first_seen, "mono nowrap") +
        cell(record.last_seen, "mono nowrap")
    );
    html += `</div>`;

    const nameservers = payload.nameservers || {};
    html += `<div class="subpanel"><h3>nameservers</h3>`;
    html += nameservers.nameservers && nameservers.nameservers.length
      ? `<p class="mono">${nameservers.nameservers.map(esc).join("<br>")}</p>`
      : `<p class="empty">no NS records observed</p>`;
    if (nameservers.shared_with && nameservers.shared_with.length) {
      html += `<p class="hint">shared nameserver infrastructure (not proof of common ownership): ${nameservers.shared_with.map(esc).join(", ")}</p>`;
    }
    html += `</div>`;

    html += `<div class="subpanel"><h3>history</h3>
      <details><summary>every record ever observed</summary>
      <pre>${esc(JSON.stringify(payload.history, null, 2))}</pre></details></div>`;

    $("dns-body").innerHTML = html;
  } catch (error) {
    $("dns-body").innerHTML = `<p class="empty">${esc(error.message)}</p>`;
  }
}

async function loadDangling() {
  try {
    const payload = await api("/api/dns-dangling");
    $("dangling-table").innerHTML = payload.dangling.length
      ? table(
          [{ label: "cname" }, { label: "target" }, { label: "evidence" }],
          payload.dangling,
          (entry) =>
            cell(entry.fqdn || entry.name, "mono wrap") +
            cell(entry.target, "mono wrap") +
            cell(entry.reason || entry.observed_at, "wrap")
        )
      : `<p class="empty">no dangling CNAME evidence recorded</p>`;
  } catch (error) {
    $("dangling-table").innerHTML = `<p class="empty">${esc(error.message)}</p>`;
  }
}

/* ------------------------------------------------------------------ */
/* certificates                                                       */
/* ------------------------------------------------------------------ */

async function loadCerts() {
  const days = $("cert-window").value;
  const query = days ? `?days=${encodeURIComponent(days)}` : "";
  try {
    const payload = await api(`/api/certs${query}`);
    $("certs-table").innerHTML = table(
      [
        { label: "presented by" },
        { label: "subject" },
        { label: "issuer" },
        { label: "expires" },
        { label: "days", cls: "num" },
        { label: "key" },
        { label: "self-signed" },
      ],
      payload.certificates,
      (cert) => {
        const hosts = cert.presented_by || [];
        const host = hosts.length ? hosts[0] + (hosts.length > 1 ? ` (+${hosts.length - 1})` : "") : "—";
        const daysLeft = cert.days_until_expiry;
        const tone = cert.expired ? "bad" : daysLeft !== null && daysLeft <= 14 ? "warn" : "ok";
        return (
          cell(host, "mono wrap") +
          cell(cert.subject_cn, "wrap") +
          cell(cert.issuer_cn, "wrap") +
          cell(cert.not_after ? String(cert.not_after).slice(0, 10) : "—", "mono nowrap") +
          `<td class="num"><span class="tag ${tone}">${cert.expired ? "expired" : esc(daysLeft)}</span></td>` +
          cell(`${dash(cert.key_algorithm)} ${cert.key_bits ? cert.key_bits : ""}`.trim()) +
          cell(cert.is_self_signed ? "yes" : "no")
        );
      }
    );
  } catch (error) {
    $("certs-table").innerHTML = `<p class="empty">${esc(error.message)}</p>`;
  }
}

/* ------------------------------------------------------------------ */
/* HTTP                                                               */
/* ------------------------------------------------------------------ */

async function loadHttp() {
  try {
    const payload = await api("/api/http?limit=100");
    const rows = payload.observations || [];
    if (!rows.length) {
      $("http-list").innerHTML = `<p class="empty">no HTTP observations recorded</p>`;
      return;
    }
    $("http-list").innerHTML = rows
      .map((entry) => {
        // The payload is the archived observation verbatim, so field names are the
        // collector's: status, remote_ip, redirect_chain includes the initial URL.
        const chain = (entry.redirect_chain || []).filter(Boolean);
        const headers = entry.headers || {};
        const tech = (entry.technologies || []).filter((t) => t.name);
        const cookies = entry.cookies || [];
        const status = entry.status ?? entry.status_code;
        return `<div class="subpanel">
          <h3>${esc(entry.host)} · ${esc(dash(entry.final_url || entry.url))}</h3>
          <dl class="kv">
            <dt>status</dt><dd>${esc(dash(status))} ${esc(dash(entry.reason))}</dd>
            <dt>observed</dt><dd>${esc(dash(entry.observed_at))}</dd>
            <dt>TLS</dt><dd>${esc(dash(entry.tls_version))}</dd>
            <dt>remote</dt><dd>${esc(dash(entry.remote_ip || entry.remote_address))}</dd>
            <dt>server</dt><dd>${esc(dash(entry.server || headers["server"] || headers["Server"]))}</dd>
            <dt>title</dt><dd>${esc(dash(entry.title))}</dd>
            <dt>cookies</dt><dd>${esc(cookies.length)}</dd>
            <dt>redirects</dt><dd>${esc(Math.max(0, chain.length - 1))}</dd>
          </dl>
          ${
            tech.length
              ? `<p class="hint">technology markers (evidence, not exploitability): ${tech
                  .map((t) => esc(`${t.name}${t.version ? " " + t.version : ""} (${t.evidence || t.category})`))
                  .join(", ")}</p>`
              : ""
          }
          <details><summary>headers</summary><pre>${esc(JSON.stringify(headers, null, 2))}</pre></details>
          ${chain.length ? `<details><summary>redirect chain</summary><pre>${esc(chain.join("\n"))}</pre></details>` : ""}
        </div>`;
      })
      .join("");
  } catch (error) {
    $("http-list").innerHTML = `<p class="empty">${esc(error.message)}</p>`;
  }
}

/* ------------------------------------------------------------------ */
/* jobs + audit                                                       */
/* ------------------------------------------------------------------ */

async function loadJobs() {
  try {
    const payload = await api("/api/jobs?limit=50");
    $("jobs-table").innerHTML = payload.jobs.length
      ? table(
          [
            { label: "job" },
            { label: "type" },
            { label: "status" },
            { label: "target" },
            { label: "started" },
            { label: "finished" },
            { label: "error" },
          ],
          payload.jobs,
          (job) =>
            cell(String(job.id).slice(0, 8), "mono nowrap") +
            cell(job.job_type) +
            `<td>${jobTags(job)}</td>` +
            cell(job.params && job.params.target ? job.params.target : "", "mono wrap") +
            cell(job.started_at, "mono nowrap") +
            cell(job.finished_at, "mono nowrap") +
            cell(job.error || "", "wrap")
        )
      : `<p class="empty">no jobs yet</p>`;
  } catch (error) {
    $("jobs-table").innerHTML = `<p class="empty">${esc(error.message)}</p>`;
  }
}

async function loadAudit() {
  try {
    const payload = await api("/api/audit?limit=200");
    $("audit-table").innerHTML = payload.events.length
      ? table(
          [
            { label: "when" },
            { label: "action" },
            { label: "outcome" },
            { label: "actor" },
            { label: "object" },
            { label: "detail" },
          ],
          payload.events,
          (event) =>
            cell(event.created_at, "mono nowrap") +
            cell(event.action, "mono") +
            `<td><span class="tag ${event.outcome === "denied" ? "bad" : event.outcome === "failure" ? "warn" : "ok"}">${esc(event.outcome)}</span></td>` +
            cell(event.actor) +
            cell(event.object_type, "wrap") +
            `<td class="wrap"><code>${esc(JSON.stringify(event.detail))}</code></td>`
        )
      : `<p class="empty">no audit events yet</p>`;
  } catch (error) {
    $("audit-table").innerHTML = `<p class="empty">${esc(error.message)}</p>`;
  }
}

async function exportProject() {
  try {
    const payload = await api("/api/export");
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `atlas-${payload.project.slug}-${new Date().toISOString().slice(0, 10)}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
    toast("export downloaded", true);
  } catch (error) {
    toast(error.message);
  }
}

/* ------------------------------------------------------------------ */
/* routing                                                            */
/* ------------------------------------------------------------------ */

const VIEW_LOADERS = {
  overview: async () => {
    await loadState();
    await loadOverviewJobs();
    await loadRedFlags();
  },
  scope: async () => {
    const meta = await loadState();
    renderScope(meta.scope);
  },
  collect: async () => {
    await loadState();
  },
  assets: loadAssets,
  dns: async () => {
    await loadDnsNames();
    await loadDangling();
  },
  certs: loadCerts,
  http: loadHttp,
  jobs: loadJobs,
  audit: loadAudit,
};

function showView(name) {
  if (!VIEW_LOADERS[name]) name = "overview";
  state.view = name;
  document.querySelectorAll(".view").forEach((section) => {
    section.classList.toggle("active", section.id === `view-${name}`);
  });
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.classList.toggle("active", tab.dataset.view === name);
  });
  if (location.hash.slice(1) !== name) {
    history.replaceState(null, "", `#${name}`);
  }
  footStatus(`view: ${name}`);
  Promise.resolve(VIEW_LOADERS[name]()).catch((error) => toast(error.message));
}

/* ------------------------------------------------------------------ */
/* wiring                                                             */
/* ------------------------------------------------------------------ */

document.addEventListener("click", (event) => {
  const goto = event.target.closest("[data-goto]");
  if (goto) {
    showView(goto.dataset.goto);
    return;
  }
  const remove = event.target.closest("[data-remove-rule]");
  if (remove) {
    removeScope(remove.dataset.removeRule, remove.dataset.pattern);
    return;
  }
  const asset = event.target.closest("[data-asset]");
  if (asset) {
    const existing = $("asset-detail");
    if (existing) existing.remove();
    showAsset(asset.dataset.asset);
  }
});

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => showView(tab.dataset.view));
});

window.addEventListener("hashchange", () => showView(location.hash.slice(1)));

$("scope-form").addEventListener("submit", addScope);
$("scope-pattern").addEventListener("input", (event) => {
  clearTimeout(checkScope._timer);
  checkScope._timer = setTimeout(() => checkScope(event.target.value), 350);
});
$("collect-form").addEventListener("submit", runCollect);
$("asset-refresh").addEventListener("click", loadAssets);
$("asset-kind").addEventListener("change", loadAssets);
$("dns-load").addEventListener("click", () => loadDns());
$("dns-input").addEventListener("keydown", (event) => {
  if (event.key === "Enter") loadDns();
});
$("dns-picker").addEventListener("change", (event) => {
  if (event.target.value) loadDns(event.target.value);
});
$("cert-refresh").addEventListener("click", loadCerts);
$("cert-window").addEventListener("change", loadCerts);
$("jobs-refresh").addEventListener("click", loadJobs);

window.addEventListener("beforeunload", () => {
  // always purge everything on close — no manual button, no checkbox
  navigator.sendBeacon("/api/purge-beacon");
});

$("audit-refresh").addEventListener("click", loadAudit);
$("export-btn").addEventListener("click", exportProject);

showView(location.hash.slice(1) || "overview");

/* ------------------------------------------------------------------ */
/* red flags                                                           */
/* ------------------------------------------------------------------ */

async function loadRedFlags() {
  const el = $("redflags-body");
  el.innerHTML = `<p class="empty">loading…</p>`;

  const flags = [];

  try {
    // expired / expiring certs
    const certsAll = await api("/api/certs");
    for (const cert of certsAll.certificates || []) {
      const hosts = (cert.presented_by || []).join(", ") || cert.subject_cn || "unknown";
      if (cert.expired) {
        flags.push({ severity: "bad", category: "Certificate", message: `Expired certificate on ${hosts} (expired ${String(cert.not_after || "").slice(0, 10)})` });
      } else if (cert.days_until_expiry !== null && cert.days_until_expiry <= 14) {
        flags.push({ severity: "warn", category: "Certificate", message: `Certificate expiring in ${cert.days_until_expiry} day(s) on ${hosts}` });
      }
      if (cert.is_self_signed) {
        flags.push({ severity: "warn", category: "Certificate", message: `Self-signed certificate on ${hosts}` });
      }
      if (cert.key_bits && cert.key_algorithm === "RSA" && cert.key_bits < 2048) {
        flags.push({ severity: "bad", category: "Certificate", message: `Weak RSA key (${cert.key_bits}-bit) on ${hosts}` });
      }
    }
  } catch (_) { /* certs unavailable — skip */ }

  try {
    // dangling CNAMEs
    const dangling = await api("/api/dns-dangling");
    for (const entry of dangling.dangling || []) {
      flags.push({ severity: "bad", category: "DNS", message: `Dangling CNAME: ${entry.fqdn || entry.name} → ${entry.target} (potential subdomain takeover)` });
    }
  } catch (_) { /* skip */ }

  try {
    // HTTP issues
    const httpData = await api("/api/http?limit=100");
    for (const obs of httpData.observations || []) {
      const url = obs.final_url || obs.url || obs.host || "";
      const isHttp = url.startsWith("http://");
      if (isHttp) {
        flags.push({ severity: "warn", category: "HTTP", message: `Plaintext HTTP (no TLS) observed on ${obs.host || url}` });
      }
      const headers = obs.headers || {};
      const headerKeys = Object.keys(headers).map((k) => k.toLowerCase());
      if (!headerKeys.includes("strict-transport-security") && !isHttp) {
        flags.push({ severity: "warn", category: "HTTP", message: `Missing HSTS header on ${obs.host || url}` });
      }
      if (!headerKeys.includes("x-content-type-options")) {
        flags.push({ severity: "warn", category: "HTTP", message: `Missing X-Content-Type-Options on ${obs.host || url}` });
      }
      if (!headerKeys.includes("x-frame-options") && !headerKeys.includes("content-security-policy")) {
        flags.push({ severity: "warn", category: "HTTP", message: `No clickjacking protection (X-Frame-Options / CSP) on ${obs.host || url}` });
      }
      const server = headers["server"] || headers["Server"] || "";
      if (server && /[0-9]/.test(server)) {
        flags.push({ severity: "warn", category: "HTTP", message: `Server header leaks version info on ${obs.host || url}: "${server}"` });
      }
      const status = obs.status ?? obs.status_code;
      if (status && status >= 500) {
        flags.push({ severity: "bad", category: "HTTP", message: `Server error (${status}) observed on ${obs.host || url}` });
      }
    }
  } catch (_) { /* skip */ }

  try {
    // retired assets still in scope
    const assetsData = await api("/api/assets?limit=300");
    const retired = (assetsData.assets || []).filter((a) => !a.is_active);
    if (retired.length) {
      flags.push({ severity: "warn", category: "Assets", message: `${retired.length} retired asset(s) still tracked — verify they are intentionally decommissioned` });
    }
  } catch (_) { /* skip */ }

  try {
    // recent job failures
    const jobsData = await api("/api/jobs?limit=20");
    const failed = (jobsData.jobs || []).filter((j) => j.status === "failed");
    if (failed.length) {
      const targets = [...new Set(failed.map((j) => j.params && j.params.target ? j.params.target : "unknown"))].slice(0, 3).join(", ");
      flags.push({ severity: "warn", category: "Jobs", message: `${failed.length} recent job(s) failed — collection may be incomplete (targets: ${targets})` });
    }
  } catch (_) { /* skip */ }

  if (!flags.length) {
    el.innerHTML = `<p class="empty">no red flags found in collected data</p>`;
    return;
  }

  // sort: bad first, then warn
  flags.sort((a, b) => (a.severity === "bad" ? -1 : 1) - (b.severity === "bad" ? -1 : 1));

  el.innerHTML = table(
    [{ label: "severity" }, { label: "category" }, { label: "finding" }],
    flags,
    (flag) =>
      `<td><span class="tag ${flag.severity === "bad" ? "bad" : "warn"}">${esc(flag.severity === "bad" ? "high" : "medium")}</span></td>` +
      cell(flag.category) +
      `<td class="wrap">${esc(flag.message)}</td>`
  );

  // stash for AI context
  window._atlasFlags = flags;
}

/* ------------------------------------------------------------------ */
/* AI summary                                                          */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* AI chat                                                             */
/* ------------------------------------------------------------------ */

// conversation history — system prompt injected once per session load
const _aiMessages = [];
let _aiContextBuilt = false;

(function initAiKey() {
  const saved = localStorage.getItem("atlas-ai-key") || "";
  if (saved) $("ai-key").value = saved;
  const savedEndpoint = localStorage.getItem("atlas-ai-endpoint") || "";
  if (savedEndpoint) $("ai-endpoint").value = savedEndpoint;
  const savedModel = localStorage.getItem("atlas-ai-model") || "";
  if (savedModel) $("ai-model-input").value = savedModel;
})();

$("ai-save-key").addEventListener("click", () => {
  const key      = $("ai-key").value.trim();
  const endpoint = $("ai-endpoint").value.trim();
  const model    = $("ai-model-input").value.trim();
  if (key)      localStorage.setItem("atlas-ai-key",      key);
  if (endpoint) localStorage.setItem("atlas-ai-endpoint", endpoint);
  if (model)    localStorage.setItem("atlas-ai-model",    model);
  toast("AI settings saved", true);
});

$("ai-clear-chat").addEventListener("click", () => {
  _aiMessages.length = 0;
  _aiContextBuilt = false;
  $("ai-chat-log").innerHTML = "";
  $("ai-status").classList.add("hidden");
});

function aiAppendMessage(role, text) {
  const log = $("ai-chat-log");
  const isUser = role === "user";
  const div = document.createElement("div");
  div.style.cssText = `margin:4px 0;padding:4px 8px;border-left:3px solid ${isUser ? "var(--navy)" : "var(--line)"};background:var(--bg)`;
  div.innerHTML = `<span style="font:bold 8pt 'Segoe UI',Tahoma,sans-serif;color:${isUser ? "var(--navy)" : "var(--grey)"}">${isUser ? "you" : "AI"}</span><br>`
    + text.split("\n").map((l) => esc(l)).join("<br>");
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
}

async function aiBuildContext() {
  let ctx = "You are a security analyst assistant with access to ATLAS attack surface data.\n";
  ctx += "Answer questions specifically using the data below. Be direct and technical.\n\n";

  try {
    const st = state.meta;
    if (st) {
      const c = st.counts;
      ctx += `Project: ${st.project.slug}\n`;
      ctx += `Stats: ${c.scope_rules} scope rules, ${c.targets} targets, ${c.assets} assets, ${c.findings} findings (${c.open_findings} open)\n\n`;
    }
  } catch (_) {}

  try {
    const flags = window._atlasFlags || [];
    if (flags.length) {
      ctx += `Red flags (${flags.length}):\n`;
      flags.forEach((f) => { ctx += `  [${f.severity}] ${f.category}: ${f.message}\n`; });
    } else {
      ctx += "Red flags: none\n";
    }
    ctx += "\n";
  } catch (_) {}

  try {
    const certsData = await api("/api/certs");
    const certs = certsData.certificates || [];
    ctx += `Certificates (${certs.length}):\n`;
    certs.slice(0, 15).forEach((cert) => {
      const hosts = (cert.presented_by || []).join(", ") || cert.subject_cn || "unknown";
      ctx += `  ${hosts} — issuer: ${cert.issuer_cn} — expires: ${String(cert.not_after || "").slice(0, 10)} — self-signed: ${cert.is_self_signed}\n`;
    });
    ctx += "\n";
  } catch (_) {}

  try {
    const httpData = await api("/api/http?limit=20");
    const obs = httpData.observations || [];
    ctx += `HTTP observations (${obs.length}):\n`;
    obs.slice(0, 10).forEach((o) => {
      const tech = (o.technologies || []).filter((t) => t.name).map((t) => `${t.name}${t.version ? " " + t.version : ""}`).join(", ");
      const headers = Object.keys(o.headers || {}).join(", ");
      ctx += `  ${o.host} — status ${o.status ?? o.status_code} — TLS: ${o.tls_version || "none"} — tech: ${tech || "unknown"} — headers: ${headers || "none"}\n`;
    });
    ctx += "\n";
  } catch (_) {}

  try {
    const assetsData = await api("/api/assets?limit=100");
    const assets = assetsData.assets || [];
    ctx += `Assets (${assets.length}):\n`;
    assets.slice(0, 20).forEach((a) => {
      ctx += `  [${a.kind}] ${a.key} — active: ${a.is_active} — last seen: ${a.last_seen || "unknown"}\n`;
    });
    ctx += "\n";
  } catch (_) {}

  try {
    const dnsData = await api("/api/dns-dangling");
    const dangling = dnsData.dangling || [];
    if (dangling.length) {
      ctx += `Dangling CNAMEs (${dangling.length}):\n`;
      dangling.forEach((d) => { ctx += `  ${d.fqdn || d.name} → ${d.target}\n`; });
      ctx += "\n";
    }
  } catch (_) {}

  return ctx;
}

async function aiSend() {
  const key = $("ai-key").value.trim() || localStorage.getItem("atlas-ai-key") || "";
  if (!key) { toast("Enter an API key and click Save first"); return; }

  const input = $("ai-input");
  const userMsg = input.value.trim();
  if (!userMsg) return;

  input.value = "";
  aiAppendMessage("user", userMsg);

  const statusEl = $("ai-status");
  statusEl.className = "status running";
  statusEl.textContent = "thinking…";
  statusEl.classList.remove("hidden");
  $("ai-send").disabled = true;

  // build system context once per session
  if (!_aiContextBuilt) {
    statusEl.textContent = "building context…";
    const ctx = await aiBuildContext();
    _aiMessages.push({ role: "system", content: ctx });
    _aiContextBuilt = true;
  }

  _aiMessages.push({ role: "user", content: userMsg });

  const endpoint = $("ai-endpoint").value.trim() || localStorage.getItem("atlas-ai-endpoint") || "https://api.openai.com/v1/chat/completions";
  const model    = $("ai-model-input").value.trim() || localStorage.getItem("atlas-ai-model") || "gpt-4o-mini";

  statusEl.textContent = "waiting for response…";

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${key}`,
      },
      body: JSON.stringify({
        model,
        messages: _aiMessages,
        temperature: 0.4,
        max_tokens: 1200,
      }),
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error((err.error && err.error.message) ? err.error.message : `HTTP ${response.status}`);
    }

    const data = await response.json();
    const reply = data.choices && data.choices[0] && data.choices[0].message
      ? data.choices[0].message.content
      : "(no response)";

    _aiMessages.push({ role: "assistant", content: reply });
    aiAppendMessage("assistant", reply);

    statusEl.className = "status ok";
    statusEl.textContent = `${data.model} · ${data.usage ? data.usage.total_tokens + " tokens used" : ""}`;
  } catch (error) {
    statusEl.className = "status bad";
    statusEl.textContent = `failed: ${error.message}`;
  } finally {
    $("ai-send").disabled = false;
    input.focus();
  }
}

$("ai-send").addEventListener("click", aiSend);
$("ai-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); aiSend(); }
});
