// gridscan-ui / dashboard.js

const RUNNING_STATES = new Set(["active", "activating"]);
const POLL_INTERVAL_MS = 5000;
const LOG_POLL_INTERVAL_MS = 4000;
const LOG_SCROLL_NEAR_BOTTOM_PX = 40;

const statusEl = document.getElementById("scan-status");
const statusTextEl = document.getElementById("scan-status-text");
const triggerBtn = document.getElementById("trigger-btn");
const stopBtn = document.getElementById("stop-btn");
const triggerMsgEl = document.getElementById("trigger-msg");
const runsBody = document.getElementById("runs-body");
const logToggleBtn = document.getElementById("log-toggle-btn");
const logPanel = document.getElementById("log-panel");
const logContentEl = document.getElementById("log-content");

const runPanelOverlay = document.getElementById("run-panel-overlay");
const runPanel = document.getElementById("run-panel");
const runPanelClose = document.getElementById("run-panel-close");
const runPanelStarted = document.getElementById("run-panel-started");
const runPanelFinished = document.getElementById("run-panel-finished");
const runPanelTriggeredBy = document.getElementById("run-panel-triggered-by");
const runPanelSummary = document.getElementById("run-panel-summary");
const runPanelReportContent = document.getElementById("run-panel-report-content");
const runPanelOpenFull = document.getElementById("run-panel-open-full");

// discover-then-select-then-scan workflow (additional to trigger/stop above)
const discoverStatusEl = document.getElementById("discover-status");
const discoverStatusTextEl = document.getElementById("discover-status-text");
const discoverBtn = document.getElementById("discover-btn");
const discoverMsgEl = document.getElementById("discover-msg");
const discoveryEmptyEl = document.getElementById("discovery-empty");
const discoveryPanelEl = document.getElementById("discovery-panel");
const discoveryBodyEl = document.getElementById("discovery-body");
const discoveryGeneratedEl = document.getElementById("discovery-generated");
const selectAllBtn = document.getElementById("select-all-btn");
const deselectAllBtn = document.getElementById("deselect-all-btn");
const scanSelectedBtn = document.getElementById("scan-selected-btn");

let pollHandle = null;
let logPollHandle = null;
let scanRunning = false;
let logPanelOpen = false;

let discoverPollHandle = null;
let discoverRunning = false;
let runSelectedPollHandle = null;
let runSelectedRunning = false;
let isAdminUser = false;

function updateStopButtonVisibility(running) {
  stopBtn.hidden = !running;
  // Same data-requires-admin convention as trigger-btn (see auth.js
  // applyRoleRestrictions()): for a viewer it inserts a ".admin-hint" span
  // right after the button. Keep that hint in sync with the button's own
  // running-state visibility so a viewer doesn't see a stray "Requires admin
  // role" hint with no button next to it while idle.
  const hint = stopBtn.nextElementSibling;
  if (hint && hint.classList.contains("admin-hint")) {
    hint.hidden = !running;
  }
}

function isNearBottom(el) {
  return el.scrollHeight - el.scrollTop - el.clientHeight <= LOG_SCROLL_NEAR_BOTTOM_PX;
}

async function fetchAndRenderLog() {
  try {
    const data = await api.scanLogs();
    const wasNearBottom = isNearBottom(logContentEl);
    logContentEl.textContent = data && data.exists && data.content
      ? data.content
      : "(no log content yet)";
    if (wasNearBottom) {
      logContentEl.scrollTop = logContentEl.scrollHeight;
    }
  } catch (e) {
    // transient failure (e.g. backend briefly unreachable) - leave whatever
    // was already rendered in place rather than blanking it out.
  }
}

function syncLogPolling() {
  const shouldPoll = scanRunning || logPanelOpen;
  if (shouldPoll && !logPollHandle) {
    fetchAndRenderLog();
    logPollHandle = setInterval(fetchAndRenderLog, LOG_POLL_INTERVAL_MS);
  } else if (!shouldPoll && logPollHandle) {
    clearInterval(logPollHandle);
    logPollHandle = null;
  }
}

function renderStatus(state) {
  const running = RUNNING_STATES.has(state);
  statusEl.classList.remove("idle", "running", "error");

  if (state === "inactive") {
    statusEl.classList.add("idle");
    statusTextEl.textContent = "idle";
  } else if (running) {
    statusEl.classList.add("running");
    statusTextEl.textContent = state === "activating" ? "starting..." : "scan running...";
  } else {
    statusEl.classList.add("error");
    statusTextEl.textContent = state || "unknown";
  }

  scanRunning = running;
  updateStopButtonVisibility(running);
  syncLogPolling();

  return running;
}

function stopPolling() {
  if (pollHandle) {
    clearInterval(pollHandle);
    pollHandle = null;
  }
}

async function checkStatusOnce() {
  try {
    const data = await api.scanStatus();
    const running = renderStatus(data.status);
    return running;
  } catch (e) {
    statusEl.classList.remove("idle", "running");
    statusEl.classList.add("error");
    statusTextEl.textContent = "status unavailable";
    scanRunning = false;
    updateStopButtonVisibility(false);
    syncLogPolling();
    return false;
  }
}

function startPolling() {
  if (pollHandle) return; // already polling
  pollHandle = setInterval(async () => {
    const running = await checkStatusOnce();
    if (!running) {
      stopPolling();
    }
  }, POLL_INTERVAL_MS);
}

function formatSummary(summaryRaw) {
  if (!summaryRaw) {
    return { new: "-", reappeared: "-", resolved: "-", total_seen: "-" };
  }
  try {
    const parsed = typeof summaryRaw === "string" ? JSON.parse(summaryRaw) : summaryRaw;
    return {
      new: parsed.new ?? "-",
      reappeared: parsed.reappeared ?? "-",
      resolved: parsed.resolved ?? "-",
      total_seen: parsed.total_seen ?? "-",
    };
  } catch (e) {
    return { new: "-", reappeared: "-", resolved: "-", total_seen: "-" };
  }
}

function formatDate(value) {
  if (!value) return "-";
  const d = new Date(value);
  if (isNaN(d.getTime())) return value;
  return d.toLocaleString();
}

function formatTargets(targets) {
  if (Array.isArray(targets)) return targets.join(", ");
  if (targets == null) return "-";
  return String(targets);
}

function renderRuns(runs) {
  runsBody.innerHTML = "";

  if (!runs || runs.length === 0) {
    runsBody.innerHTML = `<tr class="empty-row"><td colspan="8">No runs yet.</td></tr>`;
    return;
  }

  runs.forEach((run) => {
    const s = formatSummary(run.summary);
    const tr = document.createElement("tr");
    tr.className = "run-row";
    tr.title = "Click to view this run's report";
    tr.innerHTML = `
      <td>${formatDate(run.started_at)}</td>
      <td>${formatDate(run.finished_at)}</td>
      <td>${run.triggered_by || "scheduler"}</td>
      <td>${formatTargets(run.targets)}</td>
      <td>${s.new}</td>
      <td>${s.reappeared}</td>
      <td>${s.resolved}</td>
      <td>${s.total_seen}</td>
    `;
    tr.addEventListener("click", () => openRunPanel(run));
    runsBody.appendChild(tr);
  });
}

function closeRunPanel() {
  runPanel.hidden = true;
  runPanelOverlay.hidden = true;
}

async function openRunPanel(run) {
  const s = formatSummary(run.summary);

  runPanelStarted.textContent = formatDate(run.started_at);
  runPanelFinished.textContent = formatDate(run.finished_at);
  runPanelTriggeredBy.textContent = run.triggered_by || "scheduler";
  runPanelSummary.textContent =
    `${s.new} new, ${s.reappeared} reappeared, ${s.resolved} resolved, ${s.total_seen} total seen`;
  runPanelOpenFull.href = `report.html?run_id=${encodeURIComponent(run.run_id)}`;

  runPanelReportContent.className = "loading";
  runPanelReportContent.textContent = "Loading report...";

  runPanel.hidden = false;
  runPanelOverlay.hidden = false;

  try {
    const data = await api.runReport(run.run_id);
    if (data && data.not_found) {
      runPanelReportContent.className = "text-dim";
      runPanelReportContent.textContent = "Run not found.";
    } else if (data && data.available) {
      const pre = document.createElement("pre");
      pre.className = "report-content";
      pre.textContent = data.report_md;
      runPanelReportContent.className = "";
      runPanelReportContent.innerHTML = "";
      runPanelReportContent.appendChild(pre);
    } else {
      runPanelReportContent.className = "text-dim";
      runPanelReportContent.textContent =
        "No detailed report snapshot available for this run (recorded before this feature was added).";
    }
  } catch (e) {
    runPanelReportContent.className = "text-dim";
    runPanelReportContent.textContent = "Failed to load report.";
  }
}

runPanelClose.addEventListener("click", closeRunPanel);
runPanelOverlay.addEventListener("click", closeRunPanel);

async function loadRuns() {
  try {
    const runs = await api.runs({ scope: "prod", limit: 20 });
    renderRuns(runs);
  } catch (e) {
    runsBody.innerHTML = `<tr class="empty-row"><td colspan="7">Failed to load runs.</td></tr>`;
  }
}

triggerBtn.addEventListener("click", async () => {
  triggerBtn.disabled = true;
  triggerMsgEl.innerHTML = "";

  try {
    const resp = await api.triggerScan();
    const data = await resp.json().catch(() => null);

    if (resp.ok && data && data.status === "triggered") {
      triggerMsgEl.innerHTML = `<div class="msg msg-success">Scan triggered.</div>`;
      await checkStatusOnce();
      startPolling();
    } else {
      const errText = (data && (data.detail || data.error)) || `Trigger failed (${resp.status}).`;
      triggerMsgEl.innerHTML = `<div class="msg msg-error">${errText}</div>`;
    }
  } catch (e) {
    triggerMsgEl.innerHTML = `<div class="msg msg-error">Could not reach gridscan backend.</div>`;
  } finally {
    triggerBtn.disabled = false;
  }
});

logToggleBtn.addEventListener("click", () => {
  logPanelOpen = !logPanelOpen;
  logPanel.hidden = !logPanelOpen;
  logToggleBtn.setAttribute("aria-expanded", String(logPanelOpen));
  logToggleBtn.textContent = logPanelOpen ? "Hide log" : "View log";
  syncLogPolling();
});

stopBtn.addEventListener("click", async () => {
  const confirmed = window.confirm(
    "Are you sure? This will terminate the in-progress scan."
  );
  if (!confirmed) return;

  stopBtn.disabled = true;
  triggerMsgEl.innerHTML = "";

  try {
    const resp = await api.stopScan();
    const data = await resp.json().catch(() => null);

    if (resp.ok && data && data.status === "stopped") {
      triggerMsgEl.innerHTML = `<div class="msg msg-success">Scan stop requested.</div>`;
      await checkStatusOnce();
    } else {
      const errText = (data && (data.detail || data.error)) || `Stop failed (${resp.status}).`;
      triggerMsgEl.innerHTML = `<div class="msg msg-error">${errText}</div>`;
    }
  } catch (e) {
    triggerMsgEl.innerHTML = `<div class="msg msg-error">Could not reach gridscan backend.</div>`;
  } finally {
    stopBtn.disabled = false;
  }
});

// ---------------------------------------------------------------------------
// discover-then-select-then-scan workflow
// ---------------------------------------------------------------------------

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str == null ? "" : String(str);
  return div.innerHTML;
}

function renderTechChips(tech) {
  const list = Array.isArray(tech) ? tech : [];
  if (list.length === 0) return `<span class="text-dim">-</span>`;
  return list.map((t) => `<span class="chip">${escapeHtml(t)}</span>`).join("");
}

function formatDateTime(value) {
  if (!value) return "-";
  const d = new Date(value);
  if (isNaN(d.getTime())) return value;
  return d.toLocaleString();
}

function renderDiscoverStatus(state) {
  const running = RUNNING_STATES.has(state);
  discoverStatusEl.classList.remove("idle", "running", "error");

  if (state === "inactive") {
    discoverStatusEl.classList.add("idle");
    discoverStatusTextEl.textContent = "idle";
  } else if (running) {
    discoverStatusEl.classList.add("running");
    discoverStatusTextEl.textContent = state === "activating" ? "starting..." : "discovering...";
  } else {
    discoverStatusEl.classList.add("error");
    discoverStatusTextEl.textContent = state || "unknown";
  }

  const wasRunning = discoverRunning;
  discoverRunning = running;
  if (wasRunning && !running) {
    // discovery just finished (or errored out) - refresh the results table
    loadDiscovery();
  }
  return running;
}

function stopDiscoverPolling() {
  if (discoverPollHandle) {
    clearInterval(discoverPollHandle);
    discoverPollHandle = null;
  }
}

async function checkDiscoverStatusOnce() {
  try {
    const data = await api.discoverStatus();
    return renderDiscoverStatus(data.status);
  } catch (e) {
    discoverStatusEl.classList.remove("idle", "running");
    discoverStatusEl.classList.add("error");
    discoverStatusTextEl.textContent = "status unavailable";
    discoverRunning = false;
    return false;
  }
}

function startDiscoverPolling() {
  if (discoverPollHandle) return;
  discoverPollHandle = setInterval(async () => {
    const running = await checkDiscoverStatusOnce();
    if (!running) stopDiscoverPolling();
  }, POLL_INTERVAL_MS);
}

function stopRunSelectedPolling() {
  if (runSelectedPollHandle) {
    clearInterval(runSelectedPollHandle);
    runSelectedPollHandle = null;
  }
}

function updateScanSelectedButtonLabel() {
  const count = discoveryBodyEl.querySelectorAll('input[type="checkbox"]:checked').length;
  scanSelectedBtn.textContent = `Scan selected (${count})`;
  // data-requires-admin already disables this for viewers (see auth.js
  // applyRoleRestrictions()) - for admins, additionally require at least one
  // selected item and no scan-selected run already in flight.
  if (isAdminUser) {
    scanSelectedBtn.disabled = count === 0 || runSelectedRunning;
  }
}

async function checkRunSelectedStatusOnce() {
  try {
    const data = await api.runSelectedStatus();
    const running = RUNNING_STATES.has(data.status);
    runSelectedRunning = running;
    updateScanSelectedButtonLabel();
    if (running) {
      discoverMsgEl.innerHTML = `<div class="msg msg-success">Scan of selected targets is running...</div>`;
    } else if (discoverMsgEl.dataset.runSelectedPending === "1") {
      discoverMsgEl.innerHTML = `<div class="msg msg-success">Scan of selected targets finished. See Recent runs below.</div>`;
      discoverMsgEl.dataset.runSelectedPending = "0";
      loadRuns();
    }
    return running;
  } catch (e) {
    runSelectedRunning = false;
    updateScanSelectedButtonLabel();
    return false;
  }
}

function startRunSelectedPolling() {
  if (runSelectedPollHandle) return;
  runSelectedPollHandle = setInterval(async () => {
    const running = await checkRunSelectedStatusOnce();
    if (!running) stopRunSelectedPolling();
  }, POLL_INTERVAL_MS);
}

function renderDiscovery(data) {
  const items = (data && Array.isArray(data.items)) ? data.items : [];

  if (!data || !data.available || items.length === 0) {
    discoveryEmptyEl.hidden = false;
    discoveryPanelEl.hidden = true;
    return;
  }

  discoveryEmptyEl.hidden = true;
  discoveryPanelEl.hidden = false;
  discoveryGeneratedEl.textContent = data.generated
    ? `Generated ${formatDateTime(data.generated)}`
    : "";

  discoveryBodyEl.innerHTML = "";
  items.forEach((item) => {
    const tr = document.createElement("tr");
    const disabled = isAdminUser ? "" : "disabled";
    tr.innerHTML = `
      <td><input type="checkbox" class="discovery-checkbox" value="${escapeHtml(item.url)}" ${disabled}></td>
      <td><a href="${escapeHtml(item.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(item.url)}</a></td>
      <td>${escapeHtml(item.host)}</td>
      <td class="tech-cell">${renderTechChips(item.tech)}</td>
      <td>${escapeHtml(item.status_code)}</td>
      <td>${escapeHtml(item.title)}</td>
    `;
    discoveryBodyEl.appendChild(tr);
  });

  updateScanSelectedButtonLabel();
}

async function loadDiscovery() {
  try {
    const data = await api.getDiscovery();
    renderDiscovery(data);
  } catch (e) {
    discoveryEmptyEl.hidden = false;
    discoveryEmptyEl.textContent = "Failed to load discovery results.";
    discoveryPanelEl.hidden = true;
  }
}

discoverBtn.addEventListener("click", async () => {
  discoverBtn.disabled = true;
  discoverMsgEl.innerHTML = "";

  try {
    const resp = await api.triggerDiscover();
    const data = await resp.json().catch(() => null);

    if (resp.ok && data && data.status === "triggered") {
      discoverMsgEl.innerHTML = `<div class="msg msg-success">Discovery triggered.</div>`;
      await checkDiscoverStatusOnce();
      startDiscoverPolling();
    } else {
      const errText = (data && (data.detail || data.error)) || `Discover failed (${resp.status}).`;
      discoverMsgEl.innerHTML = `<div class="msg msg-error">${errText}</div>`;
    }
  } catch (e) {
    discoverMsgEl.innerHTML = `<div class="msg msg-error">Could not reach gridscan backend.</div>`;
  } finally {
    discoverBtn.disabled = false;
  }
});

selectAllBtn.addEventListener("click", () => {
  discoveryBodyEl.querySelectorAll('input[type="checkbox"]').forEach((cb) => {
    cb.checked = true;
  });
  updateScanSelectedButtonLabel();
});

deselectAllBtn.addEventListener("click", () => {
  discoveryBodyEl.querySelectorAll('input[type="checkbox"]').forEach((cb) => {
    cb.checked = false;
  });
  updateScanSelectedButtonLabel();
});

discoveryBodyEl.addEventListener("change", (evt) => {
  if (evt.target.classList.contains("discovery-checkbox")) {
    updateScanSelectedButtonLabel();
  }
});

scanSelectedBtn.addEventListener("click", async () => {
  const urls = Array.from(
    discoveryBodyEl.querySelectorAll('input[type="checkbox"]:checked')
  ).map((cb) => cb.value);
  if (urls.length === 0) return;

  scanSelectedBtn.disabled = true;
  discoverMsgEl.innerHTML = "";

  try {
    const resp = await api.runSelected(urls);
    const data = await resp.json().catch(() => null);

    if (resp.ok && data && data.status === "triggered") {
      discoverMsgEl.innerHTML = `<div class="msg msg-success">Scan of ${data.count} selected target(s) triggered.</div>`;
      discoverMsgEl.dataset.runSelectedPending = "1";
      await checkRunSelectedStatusOnce();
      startRunSelectedPolling();
    } else {
      const errText = (data && (data.detail || data.error)) || `Scan-selected failed (${resp.status}).`;
      discoverMsgEl.innerHTML = `<div class="msg msg-error">${errText}</div>`;
    }
  } catch (e) {
    discoverMsgEl.innerHTML = `<div class="msg msg-error">Could not reach gridscan backend.</div>`;
  } finally {
    updateScanSelectedButtonLabel();
  }
});

(async () => {
  const session = await requireAuth();
  if (!session) return;
  isAdminUser = session.role === "admin";

  const running = await checkStatusOnce();
  if (running) {
    startPolling();
  }

  const discoverRunningNow = await checkDiscoverStatusOnce();
  if (discoverRunningNow) {
    startDiscoverPolling();
  }
  await checkRunSelectedStatusOnce();

  await loadRuns();
  await loadDiscovery();
})();
