// gridscan-ui / findings.js

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const SEVERITY_LABELS = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

const byScanContainer = document.getElementById("by-scan-container");
const expandAllBtn = document.getElementById("expand-all-btn");
const collapseAllBtn = document.getElementById("collapse-all-btn");
const byScanPageSizeSelect = document.getElementById("by-scan-page-size");
const byScanPrevBtn = document.getElementById("by-scan-prev-btn");
const byScanNextBtn = document.getElementById("by-scan-next-btn");
const byScanPageLabel = document.getElementById("by-scan-page-label");
let byScanPage = 0; // 0-indexed
let byScanHasNextPage = false;
const container = document.getElementById("findings-container");
const severityGroup = document.getElementById("filter-severity");
const statusGroup = document.getElementById("filter-status");
const hostInput = document.getElementById("filter-host");
const runIdInput = document.getElementById("filter-run-id");
const filtersForm = document.getElementById("filters-form");

// Returns the checked values from a checkbox-group field (see
// filter-severity/filter-status in findings.html). If every box is checked
// (or none are), the caller omits the param entirely - both cases mean
// "all" under the backend's "empty/omitted means all" contract, same as
// the old single-select "All" option did.
function getCheckedValues(groupEl) {
  return Array.from(groupEl.querySelectorAll('input[type="checkbox"]:checked')).map((cb) => cb.value);
}

function formatDate(value) {
  if (!value) return "-";
  const d = new Date(value);
  if (isNaN(d.getTime())) return value;
  return d.toLocaleString();
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str == null ? "" : String(str);
  return div.innerHTML;
}

function groupBySeverity(findings) {
  const groups = {};
  SEVERITY_ORDER.forEach((sev) => (groups[sev] = []));
  const other = [];

  findings.forEach((f) => {
    const sev = (f.severity || "").toLowerCase();
    if (groups[sev]) {
      groups[sev].push(f);
    } else {
      other.push(f);
    }
  });

  return { groups, other };
}

// Shared "extra detail" body for a finding, used both in the main flat list
// below and in the By-scan lists above - same finding shape everywhere.
function renderFindingDetail(f) {
  let extracted = [];
  try {
    extracted = JSON.parse(f.extracted || "[]");
  } catch (e) {
    extracted = [];
  }
  const extractedHtml = extracted.length
    ? `<dt>Extracted</dt><dd><ul>${extracted.map((x) => `<li class="mono">${escapeHtml(x)}</li>`).join("")}</ul></dd>`
    : "";
  return `
    <dl class="finding-detail">
      <dt>Matched at</dt><dd class="mono">${escapeHtml(f.matched_at)}</dd>
      <dt>Matcher</dt><dd class="mono">${escapeHtml(f.matcher_name) || "-"}</dd>
      <dt>Type</dt><dd>${escapeHtml(f.type) || "-"}</dd>
      <dt>First seen</dt><dd>${formatDate(f.first_seen)}</dd>
      <dt>Last seen</dt><dd>${formatDate(f.last_seen)}</dd>
      ${f.resolved_at ? `<dt>Resolved at</dt><dd>${formatDate(f.resolved_at)}</dd>` : ""}
      ${extractedHtml}
    </dl>
  `;
}

function renderFindingsTable(list) {
  const rows = list
    .map((f) => {
      const sev = (f.severity || "info").toLowerCase();
      const statusClass = f.status === "resolved" ? "badge-status-resolved" : "badge-status-open";
      return `
        <details class="finding-row sev-row-${sev}">
          <summary>
            <span class="finding-summary-main">${escapeHtml(f.name)}
              <span class="mono text-dim">${escapeHtml(f.template_id)}</span></span>
            <span class="finding-summary-host">${escapeHtml(f.host)}</span>
            <span class="badge ${statusClass}">${escapeHtml(f.status)}</span>
            <span class="text-dim">${formatDate(f.first_seen)}</span>
          </summary>
          ${renderFindingDetail(f)}
        </details>
      `;
    })
    .join("");

  return `<div class="finding-list">${rows}</div>`;
}

function renderFindings(findings) {
  if (!findings || findings.length === 0) {
    // A scan-ID filter with zero rows is ambiguous: it might genuinely have
    // found nothing, or (for runs before per-run snapshots shipped) there's
    // just no snapshot file to read at all. Don't claim more than we know.
    const msg = runIdInput.value.trim()
      ? "No findings for that scan ID (or it predates per-run scan history)."
      : "No findings match these filters.";
    container.innerHTML = `<div class="loading">${msg}</div>`;
    return;
  }

  const { groups, other } = groupBySeverity(findings);

  let html = "";

  SEVERITY_ORDER.forEach((sev) => {
    const list = groups[sev];
    if (list.length === 0) return;
    html += `
      <div class="sev-group">
        <div class="sev-group-title">
          <span class="badge badge-${sev} sev-toggle" title="Click to expand/collapse">${SEVERITY_LABELS[sev]}</span>
          <span class="count">${list.length} finding${list.length === 1 ? "" : "s"}</span>
        </div>
        ${renderFindingsTable(list)}
      </div>
    `;
  });

  if (other.length > 0) {
    html += `
      <div class="sev-group">
        <div class="sev-group-title">
          <span class="badge badge-info sev-toggle" title="Click to expand/collapse">Unknown severity</span>
          <span class="count">${other.length} finding${other.length === 1 ? "" : "s"}</span>
        </div>
        ${renderFindingsTable(other)}
      </div>
    `;
  }

  container.innerHTML = html;
}

function renderDeltaList(title, items) {
  if (!items || items.length === 0) return "";
  const rows = items
    .map(
      (f) => `
        <details class="finding-row">
          <summary>
            <span class="badge badge-${(f.severity || "info").toLowerCase()}">${escapeHtml(f.severity)}</span>
            ${escapeHtml(f.name)} <span class="text-dim mono">${escapeHtml(f.host)}</span>
          </summary>
          ${renderFindingDetail(f)}
        </details>
      `
    )
    .join("");
  return `<div class="mt-14"><strong>${title}</strong><div class="finding-list">${rows}</div></div>`;
}

function renderDownloadLinks(runId) {
  return `
    <div class="actions-row mt-14">
      <a href="/api/runs/${runId}/report/download" download>Download report (.md)</a>
      <a href="/api/runs/${runId}/findings/download" download>Download findings (.json)</a>
    </div>
  `;
}

// Native <details>/<summary> handles expand/collapse; the delta itself is
// fetched lazily on first expand (via the "toggle" event, which fires
// whenever a <details> opens OR closes) rather than upfront for every run.
async function onScanToggle(evt) {
  const details = evt.target;
  if (!details.open || details.dataset.loaded) return;
  const runId = details.dataset.runId;
  const body = details.querySelector(".scan-delta-body");
  try {
    const d = await api.runFindingsDelta(runId);
    if (!d.available) {
      body.innerHTML = `<p class="text-dim">No detail available for this run.</p>`;
    } else {
      const changes =
        renderDeltaList("New", d.new_items) +
        renderDeltaList("Reappeared", d.reappeared_items) +
        renderDeltaList("Resolved", d.resolved_items);
      const all = renderDeltaList(
        `All findings open as of this scan (${(d.open_findings || []).length})`,
        d.open_findings
      );
      body.innerHTML =
        (changes || `<p class="text-dim">Nothing changed this scan.</p>`) +
        all +
        renderDownloadLinks(runId);
    }
    details.dataset.loaded = "1";
  } catch (e) {
    body.innerHTML = `<p class="msg msg-error">Failed to load this run's findings.</p>`;
  }
}

function renderByScan(runs) {
  if (!runs || runs.length === 0) {
    byScanContainer.innerHTML = `<div class="loading">No scans yet.</div>`;
    return;
  }
  byScanContainer.innerHTML = runs
    .map((run) => {
      let s;
      try {
        s = JSON.parse(run.summary || "{}");
      } catch (e) {
        s = {};
      }
      return `
        <details class="scan-entry" data-run-id="${run.run_id}">
          <summary>
            <span class="mono text-dim">#${run.run_id}</span>
            ${formatDate(run.started_at)} &middot; ${escapeHtml(run.triggered_by || "scheduler")}
            &middot; ${s.new || 0} new, ${s.reappeared || 0} reappeared, ${s.resolved || 0} resolved
          </summary>
          <div class="scan-delta-body mt-14 text-dim">Loading...</div>
        </details>
      `;
    })
    .join("");
  byScanContainer.querySelectorAll(".scan-entry").forEach((el) => el.addEventListener("toggle", onScanToggle));
}

async function loadByScan() {
  const pageSize = Number(byScanPageSizeSelect.value);
  try {
    // Fetch one extra row to detect a next page without a separate count query.
    const runs = await api.runs({ scope: "prod", limit: pageSize + 1, offset: byScanPage * pageSize });
    byScanHasNextPage = runs.length > pageSize;
    renderByScan(runs.slice(0, pageSize));
    byScanPageLabel.textContent = `Page ${byScanPage + 1}`;
    byScanPrevBtn.disabled = byScanPage === 0;
    byScanNextBtn.disabled = !byScanHasNextPage;
  } catch (e) {
    byScanContainer.innerHTML = `<div class="msg msg-error">Failed to load scans.</div>`;
  }
}

async function loadFindings() {
  container.innerHTML = `<div class="loading">Loading findings...</div>`;
  try {
    const findings = await api.findings({
      scope: "prod",
      severity: getCheckedValues(severityGroup),
      status: getCheckedValues(statusGroup),
      host: hostInput.value.trim(),
      runId: runIdInput.value.trim(),
    });
    renderFindings(findings);
  } catch (e) {
    const notFound = String(e && e.message).includes("404");
    container.innerHTML = notFound
      ? `<div class="msg msg-error">No scan with that ID.</div>`
      : `<div class="msg msg-error">Failed to load findings.</div>`;
  }
}

expandAllBtn.addEventListener("click", () => {
  byScanContainer.querySelectorAll(".scan-entry").forEach((el) => (el.open = true));
});
collapseAllBtn.addEventListener("click", () => {
  byScanContainer.querySelectorAll(".scan-entry").forEach((el) => (el.open = false));
});

byScanPageSizeSelect.addEventListener("change", () => {
  byScanPage = 0;
  loadByScan();
});
byScanPrevBtn.addEventListener("click", () => {
  if (byScanPage === 0) return;
  byScanPage -= 1;
  loadByScan();
});
byScanNextBtn.addEventListener("click", () => {
  if (!byScanHasNextPage) return;
  byScanPage += 1;
  loadByScan();
});

filtersForm.addEventListener("submit", (evt) => {
  evt.preventDefault();
  loadFindings();
});

container.addEventListener("click", (evt) => {
  const toggle = evt.target.closest(".sev-toggle");
  if (!toggle) return;
  const list = toggle.closest(".sev-group-title").nextElementSibling;
  if (list) list.classList.toggle("collapsed");
});

(async () => {
  const session = await requireAuth();
  if (!session) return;
  await loadByScan();
  await loadFindings();
})();
