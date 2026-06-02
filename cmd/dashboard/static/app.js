const state = {
  stats: null,
  programs: [],
  scans: [],
  campaigns: [],
  findings: [],
  selectedProgramId: "",
  selectedCampaignId: "",
  selectedCampaignDetail: null,
  selectedFindingId: "",
  autoTimer: null,
};

const $ = (id) => document.getElementById(id);

document.addEventListener("DOMContentLoaded", () => {
  $("refreshButton").addEventListener("click", () => loadAll());
  $("autoRefresh").addEventListener("change", () => configureAutoRefresh());
  $("programSearch").addEventListener("input", () => renderPrograms());
  $("programFilter").addEventListener("change", () => renderPrograms());
  $("closeCampaignDetail").addEventListener("click", () => clearCampaignDetail());
  $("cancelCampaignButton").addEventListener("click", () => cancelSelectedCampaign());
  $("closeFindingDetail").addEventListener("click", () => clearFindingDetail());
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
    const [stats, programs, scans, campaigns, findings] = await Promise.all([
      getJSON("/api/v1/stats"),
      getJSON("/api/v1/programs"),
      getJSON("/api/v1/scans/latest?run_type=full"),
      getJSON("/api/v1/scan-campaigns"),
      getJSON("/api/v1/findings?limit=100"),
    ]);
    state.stats = stats;
    state.programs = Array.isArray(programs) ? programs : [];
    state.scans = Array.isArray(scans) ? scans : [];
    state.campaigns = Array.isArray(campaigns) ? campaigns : [];
    state.findings = Array.isArray(findings) ? findings : [];
    renderGlobalStats();
    renderPrograms();
    renderScans();
    renderCampaigns();
    renderFindings();
    if (state.selectedProgramId) {
      await loadProgramDetail(state.selectedProgramId);
    }
    if (state.selectedCampaignId) {
      await loadCampaignDetail(state.selectedCampaignId, false);
    }
    if (state.selectedFindingId) {
      const finding = state.findings.find((item) => item.id === state.selectedFindingId);
      if (finding) {
        renderFindingDetail(finding);
      } else {
        clearFindingDetail();
      }
    }
    setStatus(`Updated ${new Date().toLocaleTimeString()}`);
  } catch (error) {
    setStatus(`Error: ${error.message}`);
  }
}

async function getJSON(path) {
  return apiJSON(path, { method: "GET" });
}

async function postJSON(path) {
  return apiJSON(path, { method: "POST" });
}

async function apiJSON(path, options = {}) {
  const response = await fetch(path, {
    method: options.method || "GET",
    headers: { Accept: "application/json", ...(options.headers || {}) },
    body: options.body,
  });
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
  const campaigns = stats.scan_campaigns || {};

  setText("programsActive", fmt(programs.active));
  setText("programsTotal", `${fmt(programs.total)} total`);
  setText("programsScanned", fmt(programs.scanned));
  setText("programsRemaining", `${fmt(programs.never_scanned)} never scanned, ${fmt(programs.due)} due`);
  setText("httpServices", fmt(assets.active_http_services));
  setText("subdomains", `${fmt(assets.active_subdomains)} subdomains`);
  setText("findingsTotal", fmt(findings.total));
  setText("findingsSplit", `${fmt(findings.nuclei_confirmed)} confirmed, ${fmt(findings.passive_unconfirmed)} passive`);
  setText("scansRunning", fmt(scanRuns.running_programs || scanRuns.running));
  setText("scansFailed", `${fmt(scanRuns.failed)} failed program scans, ${fmt((scanRuns.task_runs || {}).running)} tool tasks running`);
  setText("campaignsRunning", fmt(campaigns.running));
  setText("campaignsSplit", `${fmt(campaigns.queued)} queued, ${fmt(campaigns.failed)} failed`);

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
      const running = isRunning(program);
      if (filter === "running") return running;
      if (filter === "due") return due;
      if (filter === "scanned") return !never;
      if (filter === "never") return never;
      if (filter === "active") return Boolean(program.active);
      if (filter === "inactive") return !program.active;
      return true;
    })
    .sort((a, b) => {
      const ar = isRunning(a) ? 0 : 1;
      const br = isRunning(b) ? 0 : 1;
      if (ar !== br) return ar - br;
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
      <td>${programScanTime(program)}</td>
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
    setText("detailState", isRunning(program) ? "Running" : program.is_due ? "Due" : "Current");
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
      <td><strong>${escapeHTML(scan.program_handle || shortID(scan.program_id) || "unknown")}</strong><small>${escapeHTML(scan.program_platform || scan.run_type || "")}</small></td>
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

function renderCampaigns() {
  setText("campaignCount", `${state.campaigns.length} rows`);
  const tbody = $("campaignRows");
  tbody.innerHTML = "";
  for (const campaign of state.campaigns) {
    const tr = document.createElement("tr");
    if (campaign.id === state.selectedCampaignId) {
      tr.className = "selected";
    }
    tr.addEventListener("click", () => loadCampaignDetail(campaign.id));
    const canCancel = campaign.status === "queued" || campaign.status === "running";
    tr.innerHTML = `
      <td><strong>${escapeHTML(campaign.name || shortID(campaign.id) || "custom scan")}</strong><small>${escapeHTML(shortID(campaign.id))}</small></td>
      <td>${scanStatusPill(campaign.status)}</td>
      <td>${escapeHTML(campaignProgress(campaign))}</td>
      <td>${fmt(campaign.parallelism)}</td>
      <td>${timeAgo(campaign.updated_at || campaign.created_at)}</td>
      <td>${canCancel ? `<button class="danger-button row-action" type="button" data-cancel-campaign="${escapeHTML(campaign.id)}">Cancel</button>` : `<span class="muted">-</span>`}</td>
    `;
    const cancelButton = tr.querySelector("[data-cancel-campaign]");
    if (cancelButton) {
      cancelButton.addEventListener("click", (event) => {
        event.stopPropagation();
        cancelCampaign(campaign.id, campaign.name || shortID(campaign.id));
      });
    }
    tbody.appendChild(tr);
  }
  if (state.campaigns.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="muted">No custom scan campaigns yet.</td></tr>`;
  }
}

async function loadCampaignDetail(campaignID, showLoading = true) {
  if (!campaignID) return;
  state.selectedCampaignId = campaignID;
  renderCampaigns();
  const panel = $("campaignDetailPanel");
  panel.classList.remove("hidden");
  if (showLoading) {
    setText("campaignDetailTitle", "Campaign Detail");
    setText("campaignDetailMeta", "Loading...");
    $("campaignDetailBody").innerHTML = "";
  }
  try {
    const detail = await getJSON(`/api/v1/scan-campaigns/${encodeURIComponent(campaignID)}`);
    state.selectedCampaignDetail = detail;
    renderCampaignDetail(detail);
  } catch (error) {
    setText("campaignDetailMeta", `Error: ${error.message}`);
    $("campaignDetailBody").innerHTML = "";
  }
}

function renderCampaignDetail(detail) {
  const campaign = detail.campaign || {};
  const counts = detail.request_counts || {};
  const findings = Array.isArray(detail.findings) ? detail.findings : [];
  const requests = Array.isArray(detail.recent_requests) ? detail.recent_requests : [];
  const nuclei = Array.isArray(detail.nuclei_results) ? detail.nuclei_results : [];
  const canCancel = campaign.status === "queued" || campaign.status === "running";

  setText("campaignDetailTitle", campaign.name || shortID(campaign.id) || "Campaign Detail");
  setText("campaignDetailMeta", `${shortID(campaign.id)} | ${campaignProgress(campaign)} | ${timeAgo(campaign.updated_at || campaign.created_at)}`);
  $("cancelCampaignButton").disabled = !canCancel;
  $("cancelCampaignButton").textContent = canCancel ? "Cancel Campaign" : "Cancel Unavailable";

  $("campaignDetailBody").innerHTML = `
    <div class="drawer-grid">
      ${detailCard("Status", scanStatusPill(campaign.status), campaign.error || "")}
      ${detailCard("Requests", `${fmt(campaign.succeeded_requests)} succeeded`, `${fmt(campaign.running_requests)} running, ${fmt(campaign.queued_requests)} queued, ${fmt(campaign.failed_requests)} failed`)}
      ${detailCard("Findings", fmt(findings.length), "new since campaign start")}
      ${detailCard("Nuclei", fmt(nuclei.length), "recent validation results")}
    </div>
    <div class="drawer-section">
      <h4>Request Counts</h4>
      <div class="inline-pills">${renderCountPills(counts)}</div>
    </div>
    <div class="drawer-section">
      <h4>Recent Requests</h4>
      ${renderCampaignRequests(requests)}
    </div>
    <div class="drawer-section">
      <h4>Campaign Findings</h4>
      ${renderCampaignFindings(findings)}
    </div>
    <div class="drawer-section">
      <h4>Nuclei Results</h4>
      ${renderCampaignNuclei(nuclei)}
    </div>
    <div class="drawer-section">
      <h4>Parameters</h4>
      <pre class="json-box">${escapeHTML(JSON.stringify(campaign.params || {}, null, 2))}</pre>
    </div>
  `;
}

function renderCampaignRequests(requests) {
  if (requests.length === 0) {
    return `<p class="muted">No child requests available.</p>`;
  }
  return `
    <div class="mini-list">
      ${requests.map((request) => `
        <div class="mini-row">
          <div>
            <strong>${escapeHTML(request.program_handle || shortID(request.program_id) || "unknown")}</strong>
            <small>${escapeHTML(request.error || `${request.attempt_count || 0} attempt(s)`)}</small>
          </div>
          <div>${scanStatusPill(request.status)}<small>${timeAgo(request.updated_at || request.started_at)}</small></div>
        </div>
      `).join("")}
    </div>
  `;
}

function renderCampaignFindings(findings) {
  if (findings.length === 0) {
    return `<p class="muted">No findings have been associated with this campaign window yet.</p>`;
  }
  return `
    <div class="mini-list">
      ${findings.map((finding) => {
        const evidence = finding.evidence || {};
        const validation = finding.nuclei_result_id ? "confirmed by Nuclei" : evidence.nuclei_validation_reason || evidence.nuclei_validation || "passive";
        return `
          <div class="mini-row">
            <div>
              <strong>${escapeHTML(finding.program_handle || shortID(finding.program_id) || "unknown")}</strong>
              <small>${escapeHTML(firstNonEmpty(finding.service_url, evidence.url, evidence.technology_name, finding.vulnerability_id, shortID(finding.id)))}</small>
            </div>
            <div>${severityPill(finding.severity)}<small>${escapeHTML(validation)}</small></div>
          </div>
        `;
      }).join("")}
    </div>
  `;
}

function renderCampaignNuclei(results) {
  if (results.length === 0) {
    return `<p class="muted">No Nuclei results have been associated with this campaign window yet.</p>`;
  }
  return `
    <div class="mini-list">
      ${results.map((result) => `
        <div class="mini-row">
          <div>
            <strong>${escapeHTML(result.template_id || shortID(result.id))}</strong>
            <small>${escapeHTML(firstNonEmpty(result.service_url, result.program_handle, result.matched_at))}</small>
          </div>
          <div>${severityPill(result.severity)}<small>${timeAgo(result.first_seen_at)}</small></div>
        </div>
      `).join("")}
    </div>
  `;
}

async function cancelSelectedCampaign() {
  const campaign = (state.selectedCampaignDetail || {}).campaign || state.campaigns.find((item) => item.id === state.selectedCampaignId);
  if (!campaign || !campaign.id) return;
  await cancelCampaign(campaign.id, campaign.name || shortID(campaign.id));
}

async function cancelCampaign(campaignID, name) {
  if (!campaignID) return;
  const ok = window.confirm(`Cancel campaign "${name || shortID(campaignID)}"? Queued and running child requests will be marked canceled.`);
  if (!ok) return;
  try {
    setStatus("Canceling campaign...");
    await postJSON(`/api/v1/scan-campaigns/${encodeURIComponent(campaignID)}/cancel`);
    await loadAll(false);
    await loadCampaignDetail(campaignID, false);
    setStatus("Campaign canceled");
  } catch (error) {
    setStatus(`Cancel failed: ${error.message}`);
  }
}

function clearCampaignDetail() {
  state.selectedCampaignId = "";
  state.selectedCampaignDetail = null;
  $("campaignDetailPanel").classList.add("hidden");
  renderCampaigns();
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
    if (finding.id === state.selectedFindingId) {
      tr.className = "selected";
    }
    tr.addEventListener("click", () => renderFindingDetail(finding));
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

function renderFindingDetail(finding) {
  state.selectedFindingId = finding.id;
  renderFindings();
  const evidence = finding.evidence || {};
  const validation = finding.nuclei_result_id
    ? "confirmed by Nuclei"
    : evidence.nuclei_validation_reason || evidence.nuclei_validation || "passive/unconfirmed";
  $("findingDetailPanel").classList.remove("hidden");
  setText("findingDetailTitle", `${String(finding.severity || "unknown").toUpperCase()} finding`);
  setText("findingDetailMeta", `${shortID(finding.id)} | confidence ${fmt(finding.confidence)} | ${timeAgo(finding.first_seen_at)}`);
  $("findingDetailBody").innerHTML = `
    <div class="drawer-grid">
      ${detailCard("Validation", escapeHTML(validation), finding.nuclei_result_id ? "active evidence linked" : "passive or not confirmed")}
      ${detailCard("Status", escapeHTML(finding.status || "unknown"), finding.report_id ? `report ${shortID(finding.report_id)}` : "not reported")}
      ${detailCard("Technology", escapeHTML(firstNonEmpty(evidence.technology_name, evidence.technology, "-")), escapeHTML(firstNonEmpty(evidence.technology_version, evidence.version, "")))}
      ${detailCard("CVEs", escapeHTML(asList(evidence.cves).join(", ") || evidence.vulnerability_id || "-"), escapeHTML(firstNonEmpty(evidence.nuclei_template_id, "")))}
    </div>
    <div class="drawer-section">
      <h4>Summary</h4>
      <p>${escapeHTML(firstNonEmpty(evidence.summary, evidence.cve_summary, evidence.description, "No summary stored."))}</p>
    </div>
    <div class="drawer-section">
      <h4>Timing</h4>
      <dl class="compact-kv">
        <div><dt>First Seen</dt><dd>${escapeHTML(finding.first_seen_at || "-")}</dd></div>
        <div><dt>Last Seen</dt><dd>${escapeHTML(finding.last_seen_at || "-")}</dd></div>
        <div><dt>Service ID</dt><dd>${escapeHTML(shortID(finding.http_service_id) || "-")}</dd></div>
        <div><dt>Nuclei Result</dt><dd>${escapeHTML(shortID(finding.nuclei_result_id) || "-")}</dd></div>
      </dl>
    </div>
    <div class="drawer-section">
      <h4>Evidence</h4>
      <pre class="json-box">${escapeHTML(JSON.stringify(evidence, null, 2))}</pre>
    </div>
  `;
}

function clearFindingDetail() {
  state.selectedFindingId = "";
  $("findingDetailPanel").classList.add("hidden");
  renderFindings();
}

function campaignProgress(campaign) {
  const total = Number(campaign.total_requests || 0);
  const succeeded = Number(campaign.succeeded_requests || 0);
  const failed = Number(campaign.failed_requests || 0);
  const running = Number(campaign.running_requests || 0);
  const queued = Number(campaign.queued_requests || 0);
  if (total <= 0) return "no programs";
  return `${fmt(succeeded + failed)}/${fmt(total)} done, ${fmt(running)} running, ${fmt(queued)} queued`;
}

function statusPill(program) {
  if (!program.active) return `<span class="pill">Inactive</span>`;
  if (isRunning(program)) return `<span class="pill info">Running</span>`;
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

function isRunning(program) {
  return Boolean(program && (program.is_running || program.latest_scan_status === "running"));
}

function programScanTime(program) {
  if (isRunning(program)) {
    return `started ${timeAgo(program.running_scan_started_at || program.last_scan_started_at)}`;
  }
  return timeAgo(program.last_scan_finished_at);
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

function detailCard(label, value, note = "") {
  return `
    <div class="detail-card">
      <span>${escapeHTML(label)}</span>
      <strong>${value || "-"}</strong>
      <small>${escapeHTML(note || "")}</small>
    </div>
  `;
}

function renderCountPills(counts) {
  const keys = ["queued", "running", "succeeded", "failed", "canceled"];
  const rendered = keys
    .filter((key) => Number(counts[key] || 0) > 0)
    .map((key) => `<span class="pill">${escapeHTML(key)} ${fmt(counts[key])}</span>`);
  return rendered.length > 0 ? rendered.join("") : `<span class="muted">No request counts available.</span>`;
}

function scanSummary(scan) {
  const stats = scan.stats || {};
  const parts = [];
  if (scan.finished_at) parts.push(`finished ${timeAgo(scan.finished_at)}`);
  if (stats.steps) parts.push(`${stats.steps} steps`);
  if (stats.stale_http_services) parts.push(`${stats.stale_http_services} stale services`);
  if (stats.handle) parts.push(stats.handle);
  if (!scan.finished_at && scan.status === "running") parts.push("program pipeline in progress");
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

function firstNonEmpty(...values) {
  for (const value of values) {
    if (value === null || value === undefined) continue;
    const clean = String(value).trim();
    if (clean !== "") return clean;
  }
  return "";
}

function asList(value) {
  if (Array.isArray(value)) return value.filter((item) => item !== null && item !== undefined).map(String);
  if (value === null || value === undefined || value === "") return [];
  return [String(value)];
}

function escapeHTML(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
