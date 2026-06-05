const state = {
  stats: null,
  programs: [],
  defaultScans: [],
  scans: [],
  campaigns: [],
  findings: [],
  selectedProgramId: "",
  selectedDefaultScanId: "",
  selectedDefaultScanDetail: null,
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
  $("closeDefaultScanDetail").addEventListener("click", () => clearDefaultScanDetail());
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
    const [stats, programs, defaultScans, scans, campaigns, findings] = await Promise.all([
      getJSON("/api/v1/stats"),
      getJSON("/api/v1/programs"),
      getJSON("/api/v1/default-scans?limit=100"),
      getJSON("/api/v1/scans/latest?run_type=full&limit=250"),
      getJSON("/api/v1/scan-campaigns"),
      getJSON("/api/v1/findings?limit=100"),
    ]);
    state.stats = stats;
    state.programs = Array.isArray(programs) ? programs : [];
    state.defaultScans = Array.isArray(defaultScans) ? defaultScans : [];
    state.scans = Array.isArray(scans) ? scans : [];
    state.campaigns = Array.isArray(campaigns) ? campaigns : [];
    state.findings = Array.isArray(findings) ? findings : [];
    renderGlobalStats();
    renderPrograms();
    renderScans();
    renderDefaultScanProgress();
    renderCampaigns();
    renderFindings();
    if (state.selectedDefaultScanId) {
      const scan = state.defaultScans.find((item) => item.id === state.selectedDefaultScanId);
      if (scan) {
        await loadDefaultScanDetail(scan.id, false);
      } else {
        clearDefaultScanDetail();
      }
    }
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
  setText("campaignsSplit", `${fmt(campaigns.queued)} queued, ${fmt(campaigns.partial)} partial, ${fmt(campaigns.failed)} failed`);

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

function renderDefaultScanProgress() {
  const scans = [...state.defaultScans];
  const running = scans.filter((scan) => scan.status === "running").length;
  setText("defaultScanCount", `${fmt(running)} running, ${fmt(scans.length)} cycles`);
  const tbody = $("defaultScanRows");
  tbody.innerHTML = "";
  for (const scan of scans) {
    const tr = document.createElement("tr");
    if (scan.id === state.selectedDefaultScanId) {
      tr.className = "selected";
    }
    tr.addEventListener("click", () => loadDefaultScanDetail(scan.id));
    tr.innerHTML = `
      <td><strong>${escapeHTML(scan.name || shortID(scan.id) || "default scan")}</strong><small>${escapeHTML(shortID(scan.id))}</small></td>
      <td>${scanStatusPill(scan.status)}</td>
      <td>${escapeHTML(campaignProgress(scan))}</td>
      <td>${escapeHTML(defaultScanParallelism(scan))}</td>
      <td><strong>${timeAgo(scan.updated_at || scan.finished_at || scan.started_at)}</strong><small>${escapeHTML(scanDuration(scan))}</small></td>
      <td><button class="ghost-button row-action" type="button" data-scan-detail="${escapeHTML(scan.id)}">View</button></td>
    `;
    const detailButton = tr.querySelector("[data-scan-detail]");
    if (detailButton) {
      detailButton.addEventListener("click", (event) => {
        event.stopPropagation();
        loadDefaultScanDetail(scan.id);
      });
    }
    tbody.appendChild(tr);
  }
  if (scans.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="muted">No default scan cycles yet.</td></tr>`;
  }
}

async function loadDefaultScanDetail(scanID, showLoading = true) {
  if (!scanID) return;
  state.selectedDefaultScanId = scanID;
  renderDefaultScanProgress();
  const panel = $("defaultScanDetailPanel");
  panel.classList.remove("hidden");
  if (showLoading) {
    setText("defaultScanDetailTitle", "Default Scan Detail");
    setText("defaultScanDetailMeta", "Loading...");
    $("defaultScanDetailBody").innerHTML = "";
  }
  try {
    const detail = await getJSON(`/api/v1/default-scans/${encodeURIComponent(scanID)}`);
    state.selectedDefaultScanDetail = detail;
    renderDefaultScanDetail(detail);
  } catch (error) {
    setText("defaultScanDetailMeta", `Error: ${error.message}`);
    $("defaultScanDetailBody").innerHTML = "";
  }
}

function renderDefaultScanDetail(detail) {
  const scan = detail.scan || {};
  const counts = detail.request_counts || {};
  const requests = Array.isArray(detail.recent_requests) ? detail.recent_requests : [];
  const runningRequests = Array.isArray(detail.running_requests) ? detail.running_requests : [];
  const findingCounts = detail.finding_counts || {};
  const findings = Array.isArray(detail.findings) ? detail.findings : [];
  const nuclei = Array.isArray(detail.nuclei_results) ? detail.nuclei_results : [];
  const stats = scan.stats || {};

  setText("defaultScanDetailTitle", scan.name || shortID(scan.id) || "Default Scan Detail");
  setText("defaultScanDetailMeta", `${shortID(scan.id)} | ${campaignProgress(scan)} | ${timeAgo(scan.updated_at || scan.started_at)}`);
  $("defaultScanDetailBody").innerHTML = `
    <div class="drawer-grid">
      ${detailCard("Status", scanStatusPill(scan.status), scan.error || "")}
      ${detailCard("Program Scans", `${fmt(scan.succeeded_requests)} succeeded`, `${fmt(scan.running_requests)} running, ${fmt(scan.queued_requests)} queued, ${fmt(scan.failed_requests)} failed`)}
      ${detailCard("Parallelism", escapeHTML(defaultScanParallelism(scan)), "default scheduler")}
      ${detailCard("Findings", fmt(findingCounts.total), `${fmt(findingCounts.nuclei_confirmed)} confirmed, ${fmt(findingCounts.passive_unconfirmed)} passive`)}
      ${detailCard("Nuclei", fmt(nuclei.length), "recent validation results")}
    </div>
    <div class="drawer-section">
      <h4>Scan Timing</h4>
      <dl class="compact-kv">
        <div><dt>Started</dt><dd>${escapeHTML(scan.started_at || "-")}</dd></div>
        <div><dt>Finished</dt><dd>${escapeHTML(scan.finished_at || "-")}</dd></div>
        <div><dt>Duration</dt><dd>${escapeHTML(scanDuration(scan))}</dd></div>
        <div><dt>Cycle ID</dt><dd>${escapeHTML(shortID(scan.id) || "-")}</dd></div>
      </dl>
    </div>
    <div class="drawer-section">
      <h4>Program Counts</h4>
      <div class="inline-pills">${renderCountPills(counts)}</div>
    </div>
    <div class="drawer-section">
      <h4>Running Programs</h4>
      ${renderDefaultProgramRuns(runningRequests, "No programs are currently running in this default scan.")}
    </div>
    <div class="drawer-section">
      <h4>Program Runs</h4>
      ${renderDefaultProgramRuns(requests, "No program runs are linked to this default scan.")}
    </div>
    <div class="drawer-section">
      <h4>Scan Findings</h4>
      ${renderCampaignFindings(findings, "No findings have been associated with this scan.")}
    </div>
    <div class="drawer-section">
      <h4>Nuclei Results</h4>
      ${renderCampaignNuclei(nuclei, "No Nuclei results have been associated with this scan.")}
    </div>
    <div class="drawer-section">
      <h4>Stats</h4>
      <pre class="json-box">${escapeHTML(JSON.stringify(stats, null, 2))}</pre>
    </div>
  `;
}

function renderDefaultProgramRuns(runs, emptyMessage) {
  if (runs.length === 0) {
    return `<p class="muted">${escapeHTML(emptyMessage)}</p>`;
  }
  return `
    <div class="mini-list">
      ${runs.map((run) => `
        <div class="mini-row">
          <div>
            <strong>${escapeHTML(run.program_handle || shortID(run.program_id) || "unknown")}</strong>
            <small>${escapeHTML(scanStepSummary(run))}</small>
          </div>
          <div>${scanStatusPill(run.status)}<small>${escapeHTML(scanDuration(run))}</small></div>
        </div>
      `).join("")}
    </div>
  `;
}

function clearDefaultScanDetail() {
  state.selectedDefaultScanId = "";
  state.selectedDefaultScanDetail = null;
  $("defaultScanDetailPanel").classList.add("hidden");
  renderDefaultScanProgress();
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
  const findingCounts = detail.finding_counts || {};
  const findings = Array.isArray(detail.findings) ? detail.findings : [];
  const requests = Array.isArray(detail.recent_requests) ? detail.recent_requests : [];
  const runningRequests = Array.isArray(detail.running_requests) ? detail.running_requests : [];
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
      ${detailCard("Parallelism", fmt(campaign.parallelism), "campaign configured")}
      ${detailCard("Findings", fmt(findingCounts.total), `${fmt(findingCounts.nuclei_confirmed)} confirmed, ${fmt(findingCounts.passive_unconfirmed)} passive`)}
      ${detailCard("Nuclei", fmt(nuclei.length), "recent validation results")}
    </div>
    <div class="drawer-section">
      <h4>Request Counts</h4>
      <div class="inline-pills">${renderCountPills(counts)}</div>
    </div>
    <div class="drawer-section">
      <h4>Running Work</h4>
      ${renderRunningCampaignRequests(runningRequests)}
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
            <small>${escapeHTML(requestProgressSummary(request) || request.error || `${request.attempt_count || 0} attempt(s)`)}</small>
          </div>
          <div>${scanStatusPill(request.status)}<small>${timeAgo(request.progress_updated_at || request.locked_at || request.updated_at || request.started_at)}</small></div>
        </div>
      `).join("")}
    </div>
  `;
}

function renderRunningCampaignRequests(requests) {
  if (requests.length === 0) {
    return `<p class="muted">No running child requests.</p>`;
  }
  return `
    <div class="work-list">
      ${requests.map((request) => {
        const progress = requestProgressPercent(request);
        return `
          <div class="work-row">
            <div class="work-head">
              <div>
                <strong>${escapeHTML(request.program_handle || shortID(request.program_id) || "unknown")}</strong>
                <small>${escapeHTML(requestProgressSummary(request))}</small>
              </div>
              <div>
                ${scanStatusPill(request.status)}
                <small>${timeAgo(request.progress_updated_at || request.locked_at || request.updated_at || request.started_at)}</small>
              </div>
            </div>
            <div class="thin-progress"><span style="width: ${progress}%"></span></div>
            <div class="work-meta">
              <span>${fmt(request.active_http_services)} services</span>
              <span>${fmt(request.estimated_webanalyze_urls)} expanded URLs</span>
              <span>${fmt(request.estimated_webanalyze_batches)} est. batches</span>
              <span>started ${timeAgo(request.started_at)}</span>
            </div>
          </div>
        `;
      }).join("")}
    </div>
  `;
}

function requestProgressSummary(request) {
  const stage = firstNonEmpty(request.progress_stage, request.progress_message, "queued work");
  const current = Number(request.progress_current || 0);
  const total = Number(request.progress_total || 0);
  const meta = request.progress_meta || {};
  if (total > 0) {
    return `${stage}: ${fmt(current)}/${fmt(total)}`;
  }
  if (Number(request.estimated_webanalyze_urls || 0) > 0) {
    return `${stage}: ${fmt(request.estimated_webanalyze_urls)} estimated Webanalyze URLs`;
  }
  if (meta.total_batches) {
    return `${stage}: batch ${fmt(meta.batch)}/${fmt(meta.total_batches)}`;
  }
  return stage;
}

function requestProgressPercent(request) {
  const current = Number(request.progress_current || 0);
  const total = Number(request.progress_total || 0);
  if (total <= 0) return 0;
  return Math.max(0, Math.min(100, Math.round((current / total) * 100)));
}

function renderCampaignFindings(findings, emptyMessage = "No findings have been associated with this campaign window yet.") {
  if (findings.length === 0) {
    return `<p class="muted">${escapeHTML(emptyMessage)}</p>`;
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
                <small>${escapeHTML(findingTargetLabel(finding))}</small>
            </div>
            <div>${severityPill(finding.severity)}<small>${escapeHTML(validation)}</small></div>
          </div>
        `;
      }).join("")}
    </div>
  `;
}

function renderCampaignNuclei(results, emptyMessage = "No Nuclei results have been associated with this campaign window yet.") {
  if (results.length === 0) {
    return `<p class="muted">${escapeHTML(emptyMessage)}</p>`;
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
  const targetURL = findingTargetLabel(finding);
  const targetMeta = [
    finding.service_host,
    finding.service_status_code ? `HTTP ${finding.service_status_code}` : "",
    finding.service_title,
    finding.service_webserver,
  ].filter((item) => firstNonEmpty(item)).join(" | ");
  $("findingDetailPanel").classList.remove("hidden");
  setText("findingDetailTitle", `${String(finding.severity || "unknown").toUpperCase()} finding`);
  setText("findingDetailMeta", `${shortID(finding.id)} | confidence ${fmt(finding.confidence)} | ${timeAgo(finding.first_seen_at)}`);
  $("findingDetailBody").innerHTML = `
    <div class="target-asset">
      <span>Target Asset</span>
      <strong>${escapeHTML(targetURL)}</strong>
      <small>${escapeHTML(targetMeta || "No HTTP service metadata stored.")}</small>
    </div>
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

function findingTargetLabel(finding) {
  const evidence = finding.evidence || {};
  const target = evidence.target && typeof evidence.target === "object" ? evidence.target : {};
  return firstNonEmpty(
    finding.service_url,
    evidence.url,
    evidence.matched_at,
    evidence.target_input,
    target.input,
    target.source && target.id ? `${target.source}:${shortID(target.id)}` : "",
    evidence.technology_name,
    finding.vulnerability_id,
    shortID(finding.id),
    "-"
  );
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
  const canceled = Number(campaign.canceled_requests || 0);
  if (total <= 0) return "no programs";
  const final = succeeded + failed + canceled;
  const issues = [];
  if (failed > 0) issues.push(`${fmt(failed)} failed`);
  if (canceled > 0) issues.push(`${fmt(canceled)} canceled`);
  const issueText = issues.length > 0 ? ` (${issues.join(", ")})` : "";
  return `${fmt(final)}/${fmt(total)} finished${issueText}, ${fmt(running)} running, ${fmt(queued)} queued`;
}

function defaultScanParallelism(scan) {
  const configured = Number(scan.parallelism || 0);
  if (configured > 0) return fmt(configured);
  return "default";
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
  if (clean === "partial") return `<span class="pill warn">Partial</span>`;
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
  if (scan.status === "running") parts.push(scanCurrentStep(scan));
  if (stats.steps) parts.push(`${stats.steps} steps`);
  if (stats.stale_http_services) parts.push(`${stats.stale_http_services} stale services`);
  if (stats.handle) parts.push(stats.handle);
  if (!scan.finished_at && scan.status === "running") parts.push("program pipeline in progress");
  if (scan.error) parts.push(`error`);
  return parts.join(" | ") || "-";
}

function scanStatsSummary(scan) {
  const stats = scan.stats || {};
  const findings = Number(stats.findings || 0);
  const reports = Number(stats.reports || 0);
  if (findings > 0 || reports > 0) {
    return `${fmt(findings)} findings, ${fmt(reports)} reports`;
  }
  const inserted = Number(scan.inserted_count || stats.inserted || 0);
  const updated = Number(scan.updated_count || stats.updated || 0);
  const unchanged = Number(scan.unchanged_count || stats.unchanged || 0);
  const changes = inserted + updated;
  if (changes > 0 || unchanged > 0) {
    return `${fmt(changes)} changes, ${fmt(unchanged)} unchanged`;
  }
  if (Number(scan.input_count || 0) > 0) {
    return `${fmt(scan.input_count)} inputs`;
  }
  return "no stored changes";
}

function scanStaleSummary(scan) {
  const stats = scan.stats || {};
  const staleServices = Number(stats.stale_http_services || 0);
  const staleSubdomains = Number(stats.stale_subdomains || 0);
  const staleTech = Number(stats.stale_technologies || 0);
  const stale = staleServices + staleSubdomains + staleTech;
  if (stale > 0) {
    return `${fmt(staleServices)} stale services, ${fmt(staleSubdomains)} stale subdomains, ${fmt(staleTech)} stale tech`;
  }
  if (stats.steps) {
    return `${fmt(stats.steps)} configured steps`;
  }
  return scan.error ? "scan stored an error" : "no stale cleanup";
}

function scanStepSummary(scan) {
  const progress = scan.progress || {};
  const stats = scan.stats || {};
  const total = Number(stats.steps || progress.steps_total || 8);
  const childRuns = Number(progress.child_scan_runs || 0);
  const succeeded = Number(progress.child_succeeded || 0);
  const failed = Number(progress.child_failed || 0);
  const running = Number(progress.child_running || 0);
  if (scan.status === "succeeded") {
    return `${fmt(total)} steps`;
  }
  return `${fmt(childRuns)} step runs, ${fmt(succeeded + failed)} done, ${fmt(running)} running`;
}

function stepStatsSummary(step) {
  const stats = step.stats || {};
  const parts = [];
  if (Number(step.input_count || 0) > 0) parts.push(`${fmt(step.input_count)} inputs`);
  if (Number(step.inserted_count || 0) > 0) parts.push(`${fmt(step.inserted_count)} inserted`);
  if (Number(step.updated_count || 0) > 0) parts.push(`${fmt(step.updated_count)} updated`);
  if (Number(stats.findings || 0) > 0) parts.push(`${fmt(stats.findings)} findings`);
  if (Number(stats.reports || 0) > 0) parts.push(`${fmt(stats.reports)} reports`);
  if (step.error) parts.push("error");
  return parts.join(", ") || scanDuration(step);
}

function scanDuration(scan) {
  if (!scan || !scan.started_at) return "-";
  const start = new Date(scan.started_at).getTime();
  const end = scan.finished_at ? new Date(scan.finished_at).getTime() : Date.now();
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return "-";
  const seconds = Math.round((end - start) / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.round(minutes / 60);
  return `${hours}h`;
}

function scanCurrentStep(scan) {
  if (scan.status === "succeeded") {
    return "pipeline completed";
  }
  if (scan.status === "failed") {
    return "pipeline failed";
  }
  if (scan.status === "canceled") {
    return "pipeline canceled";
  }
  const progress = scan.progress || {};
  const current = progress.current_step || {};
  const runType = firstNonEmpty(current.run_type, "planning");
  const status = firstNonEmpty(current.status, "running");
  const childRuns = Number(progress.child_scan_runs || 0);
  const total = Number(progress.steps_total || 8);
  if (childRuns <= 0) {
    return "waiting for first pipeline step";
  }
  return `${runType} ${status}: ${fmt(Math.min(childRuns + 1, total))}/${fmt(total)} pipeline steps`;
}

function scanProgressPercent(scan) {
  if (scan.status === "succeeded") {
    return 100;
  }
  const progress = scan.progress || {};
  const total = Number(progress.steps_total || 8);
  if (total <= 0) return 0;
  const childRuns = Number(progress.child_scan_runs || 0);
  const current = progress.current_step || {};
  const completed = Number(progress.child_succeeded || 0) + Number(progress.child_failed || 0);
  let effective = completed;
  if (current.status === "running") {
    effective += 0.5;
  } else if (childRuns > completed) {
    effective = childRuns;
  }
  return Math.max(0, Math.min(100, Math.round((effective / total) * 100)));
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
