const state = {
  stats: null,
  programs: [],
  scans: [],
  findings: [],
  selectedProgramId: "",
  autoTimer: null,
};

const $ = (id) => document.getElementById(id);

document.addEventListener("DOMContentLoaded", () => {
  $("refreshButton").addEventListener("click", () => loadAll());
  $("autoRefresh").addEventListener("change", () => configureAutoRefresh());
  $("programSearch").addEventListener("input", () => renderPrograms());
  $("programFilter").addEventListener("change", () => renderPrograms());
  configureAutoRefresh();
  loadAll();
});

function configureAutoRefresh() {
  if (state.autoTimer) {
    clearInterval(state.autoTimer);
    state.autoTimer = null;
  }
  if ($("autoRefresh").checked) {
    state.autoTimer = setInterval(() => loadAll(false), 30000);
  }
}

async function loadAll(showLoading = true) {
  if (showLoading) {
    setStatus("Refreshing...");
  }
  try {
    const [stats, programs, scans, findings] = await Promise.all([
      getJSON("/api/v1/stats"),
      getJSON("/api/v1/programs"),
      getJSON("/api/v1/scans/latest"),
      getJSON("/api/v1/findings?limit=100"),
    ]);
    state.stats = stats;
    state.programs = Array.isArray(programs) ? programs : [];
    state.scans = Array.isArray(scans) ? scans : [];
    state.findings = Array.isArray(findings) ? findings : [];
    renderGlobalStats();
    renderPrograms();
    renderScans();
    renderFindings();
    if (state.selectedProgramId) {
      await loadProgramDetail(state.selectedProgramId);
    }
    setStatus(`Updated ${new Date().toLocaleTimeString()}`);
  } catch (error) {
    setStatus(`Error: ${error.message}`);
  }
}

async function getJSON(path) {
  const response = await fetch(path, { headers: { Accept: "application/json" } });
  const text = await response.text();
  let payload = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = text;
  }
  if (!response.ok) {
    const message = payload && payload.error ? payload.error : response.statusText;
    throw new Error(message);
  }
  return payload;
}

function renderGlobalStats() {
  const stats = state.stats || {};
  const programs = stats.programs || {};
  const assets = stats.assets || {};
  const findings = stats.findings || {};
  const scanRuns = stats.scan_runs || {};

  setText("programsActive", fmt(programs.active));
  setText("programsTotal", `${fmt(programs.total)} total`);
  setText("programsScanned", fmt(programs.scanned));
  setText("programsRemaining", `${fmt(programs.never_scanned)} never scanned, ${fmt(programs.due)} due`);
  setText("httpServices", fmt(assets.active_http_services));
  setText("subdomains", `${fmt(assets.active_subdomains)} subdomains`);
  setText("findingsTotal", fmt(findings.total));
  setText("findingsSplit", `${fmt(findings.nuclei_confirmed)} confirmed, ${fmt(findings.passive_unconfirmed)} passive`);
  setText("scansRunning", fmt(scanRuns.running));
  setText("scansFailed", `${fmt(scanRuns.failed)} failed`);

  const active = Number(programs.active || 0);
  const scanned = Number(programs.scanned || 0);
  const coverage = active > 0 ? Math.round((scanned / active) * 100) : 0;
  $("coverageBar").style.width = `${Math.max(0, Math.min(coverage, 100))}%`;
  setText("coverageLabel", `${coverage}% of active programs scanned`);
}

function renderPrograms() {
  const query = $("programSearch").value.trim().toLowerCase();
  const filter = $("programFilter").value;
  const rows = state.programs
    .filter((program) => {
      const haystack = `${program.handle || ""} ${program.platform || ""} ${program.program_url || ""}`.toLowerCase();
      if (query && !haystack.includes(query)) {
        return false;
      }
      const never = !program.last_scan_finished_at;
      const due = isDue(program);
      if (filter === "due") return due;
      if (filter === "scanned") return !never;
      if (filter === "never") return never;
      if (filter === "active") return Boolean(program.active);
      if (filter === "inactive") return !program.active;
      return true;
    })
    .sort((a, b) => {
      const ad = isDue(a) ? 0 : 1;
      const bd = isDue(b) ? 0 : 1;
      if (ad !== bd) return ad - bd;
      return String(a.handle || "").localeCompare(String(b.handle || ""));
    });

  setText("programCount", `${rows.length} shown`);
  const tbody = $("programRows");
  tbody.innerHTML = "";
  for (const program of rows) {
    const tr = document.createElement("tr");
    if (program.id === state.selectedProgramId) {
      tr.className = "selected";
    }
    tr.addEventListener("click", () => {
      state.selectedProgramId = program.id;
      renderPrograms();
      loadProgramDetail(program.id);
    });
    tr.innerHTML = `
      <td><strong>${escapeHTML(program.handle || "unknown")}</strong><small>${escapeHTML(program.platform || "")}</small></td>
      <td>${statusPill(program)}</td>
      <td>${fmt(program.scan_interval_hours)}h</td>
      <td>${timeAgo(program.last_scan_finished_at)}</td>
    `;
    tbody.appendChild(tr);
  }
  if (rows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="muted">No programs match the current filter.</td></tr>`;
  }
}

async function loadProgramDetail(programID) {
  setText("detailState", "Loading");
  try {
    const stats = await getJSON(`/api/v1/programs/${encodeURIComponent(programID)}/stats`);
    const program = stats.program || {};
    const assets = stats.assets || {};
    const findings = stats.findings || {};
    setText("detailTitle", program.handle || "Program Detail");
    setText("detailState", program.is_due ? "Due" : "Current");
    setText("detailScope", fmt(assets.active_scope_assets));
    setText("detailSubdomains", fmt(assets.active_subdomains));
    setText("detailServices", fmt(assets.active_http_services));
    setText("detailTech", fmt(assets.active_technologies));
    setText("detailFindings", `${fmt(findings.total)} total`);
    setText("detailNuclei", fmt(stats.nuclei_results));
    $("latestScan").textContent = formatLatestScan(stats.latest_scan);
  } catch (error) {
    setText("detailState", "Error");
    $("latestScan").textContent = error.message;
  }
}

function renderScans() {
  setText("scanCount", `${state.scans.length} rows`);
  const tbody = $("scanRows");
  tbody.innerHTML = "";
  for (const scan of state.scans) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><strong>${escapeHTML(scan.run_type || "unknown")}</strong><small>${escapeHTML(shortID(scan.program_id))}</small></td>
      <td>${scanStatusPill(scan.status)}</td>
      <td>${timeAgo(scan.started_at)}</td>
      <td>${escapeHTML(scanSummary(scan))}</td>
    `;
    tbody.appendChild(tr);
  }
  if (state.scans.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="muted">No scans yet.</td></tr>`;
  }
}

function renderFindings() {
  setText("findingCount", `${state.findings.length} rows`);
  const tbody = $("findingRows");
  tbody.innerHTML = "";
  for (const finding of state.findings) {
    const evidence = finding.evidence || {};
    const validation = finding.nuclei_result_id
      ? "confirmed"
      : evidence.nuclei_validation_reason || evidence.nuclei_validation || "passive";
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${severityPill(finding.severity)}</td>
      <td>${fmt(finding.confidence)}</td>
      <td><strong>${escapeHTML(validation)}</strong><small>${escapeHTML((evidence.cves || []).join(", "))}</small></td>
      <td>${timeAgo(finding.first_seen_at)}</td>
    `;
    tbody.appendChild(tr);
  }
  if (state.findings.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="muted">No findings available.</td></tr>`;
  }
}

function statusPill(program) {
  if (!program.active) return `<span class="pill">Inactive</span>`;
  if (!program.last_scan_finished_at) return `<span class="pill warn">Never scanned</span>`;
  if (isDue(program)) return `<span class="pill warn">Due</span>`;
  return `<span class="pill good">Current</span>`;
}

function scanStatusPill(status) {
  const clean = String(status || "unknown").toLowerCase();
  if (clean === "succeeded") return `<span class="pill good">Succeeded</span>`;
  if (clean === "running") return `<span class="pill info">Running</span>`;
  if (clean === "failed") return `<span class="pill danger">Failed</span>`;
  return `<span class="pill">${escapeHTML(clean)}</span>`;
}

function severityPill(severity) {
  const clean = String(severity || "unknown").toLowerCase();
  if (clean === "critical" || clean === "high") return `<span class="pill danger">${escapeHTML(clean)}</span>`;
  if (clean === "medium") return `<span class="pill warn">${escapeHTML(clean)}</span>`;
  return `<span class="pill">${escapeHTML(clean)}</span>`;
}

function isDue(program) {
  if (!program.active) return false;
  if (!program.last_scan_finished_at) return true;
  const intervalHours = Number(program.scan_interval_hours || 72);
  const last = new Date(program.last_scan_finished_at).getTime();
  if (!Number.isFinite(last)) return true;
  return Date.now() - last > intervalHours * 60 * 60 * 1000;
}

function formatLatestScan(scan) {
  if (!scan) return "No scan run recorded for this program.";
  const payload = {
    id: scan.id,
    type: scan.run_type,
    status: scan.status,
    started: scan.started_at,
    finished: scan.finished_at,
    error: scan.error || "",
    stats: scan.stats || {},
  };
  return JSON.stringify(payload, null, 2);
}

function scanSummary(scan) {
  const stats = scan.stats || {};
  const parts = [];
  if (scan.input_count !== undefined) parts.push(`in ${scan.input_count}`);
  if (scan.inserted_count !== undefined) parts.push(`new ${scan.inserted_count}`);
  if (stats.tool) parts.push(stats.tool);
  if (stats.skipped) parts.push(`skipped: ${stats.skipped}`);
  if (scan.error) parts.push(`error`);
  return parts.join(" | ") || "-";
}

function timeAgo(value) {
  if (!value) return "never";
  const ts = new Date(value).getTime();
  if (!Number.isFinite(ts)) return String(value);
  const diff = Date.now() - ts;
  const abs = Math.abs(diff);
  const minutes = Math.round(abs / 60000);
  if (minutes < 1) return "now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  return `${days}d ago`;
}

function setText(id, value) {
  $(id).textContent = value;
}

function setStatus(value) {
  setText("statusLine", value);
}

function fmt(value) {
  const number = Number(value || 0);
  return new Intl.NumberFormat().format(number);
}

function shortID(value) {
  if (!value) return "";
  return String(value).slice(0, 8);
}

function escapeHTML(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
