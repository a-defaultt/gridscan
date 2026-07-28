// gridscan-ui / review.js
// Vulnerability triage queue: open findings only, with a per-finding triage
// control. Findings.html stays the pure scan-history/browsing view; this
// page is the "what do we need to decide on" workflow, keyed to finding_key
// (not (scope,url) like the old, now-removed, asset triage was).

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const SEVERITY_LABELS = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

const TRIAGE_STATUSES = ["unreviewed", "confirmed", "false_positive", "accepted_risk", "remediating"];
const TRIAGE_LABELS = {
  unreviewed: "Unreviewed",
  confirmed: "Confirmed",
  false_positive: "False Positive",
  accepted_risk: "Accepted Risk",
  remediating: "Remediating",
};

const VERIFY_LABELS = {
  confirmed: "✓ Verified",
  unconfirmed: "Unconfirmed",
  insufficient_data: "Insufficient data",
};
function renderVerifyBadge(status) {
  if (!status || status === "not_run") return "";
  return `<span class="badge badge-verify-${status}">${VERIFY_LABELS[status] || status}</span>`;
}

const reviewContainer = document.getElementById("review-container");
const severityGroup = document.getElementById("filter-severity");
const triageGroup = document.getElementById("filter-triage");
const hostInput = document.getElementById("filter-host");
const filtersForm = document.getElementById("filters-form");
const toast = document.getElementById("toast");

function showToast(text) {
  toast.textContent = text;
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), 2500);
}

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

function errorTextFromResponse(data, resp) {
  const detail = data && data.detail;
  if (typeof detail === "string") return detail;
  return `Request failed (${resp.status}).`;
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

// Same shape as findings.js's renderFindingDetail - kept as its own copy
// here per this codebase's existing convention (assets.js/findings.js
// already duplicate small page-scoped helpers rather than share a module).
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

function renderTriageBadge(status) {
  const s = TRIAGE_STATUSES.includes(status) ? status : "unreviewed";
  return `<span class="badge triage-badge badge-triage-${s}">${TRIAGE_LABELS[s]}</span>`;
}

function renderTriageSelect(findingKey, status) {
  const s = TRIAGE_STATUSES.includes(status) ? status : "unreviewed";
  const options = TRIAGE_STATUSES.map(
    (opt) => `<option value="${opt}" ${opt === s ? "selected" : ""}>${TRIAGE_LABELS[opt]}</option>`
  ).join("");
  return `
    <select class="triage-select" data-finding-key="${escapeHtml(findingKey)}" data-current="${s}">
      ${options}
    </select>
  `;
}

function renderFindingsList(list) {
  const rows = list
    .map((f) => {
      const sev = (f.severity || "info").toLowerCase();
      return `
        <details class="finding-row sev-row-${sev}">
          <summary>
            <span class="finding-summary-main">${escapeHtml(f.name)}
              <span class="mono text-dim">${escapeHtml(f.template_id)}</span></span>
            <span class="finding-summary-host">${escapeHtml(f.host)}</span>
            ${renderTriageBadge(f.triage_status)}
            ${renderTriageSelect(f.finding_key, f.triage_status)}
            ${renderVerifyBadge(f.verification_status)}
          </summary>
          ${renderFindingDetail(f)}
        </details>
      `;
    })
    .join("");
  return `<div class="finding-list">${rows}</div>`;
}

function renderReview(findings) {
  if (!findings || findings.length === 0) {
    reviewContainer.innerHTML = `<div class="loading">No findings match these filters.</div>`;
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
        ${renderFindingsList(list)}
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
        ${renderFindingsList(other)}
      </div>
    `;
  }

  reviewContainer.innerHTML = html;
}

async function loadReview() {
  reviewContainer.innerHTML = `<div class="loading">Loading findings...</div>`;
  try {
    const findings = await api.findings({
      scope: "prod",
      severity: getCheckedValues(severityGroup),
      status: ["open"], // Review is a "needs a decision" queue - resolved findings don't.
      triageStatus: getCheckedValues(triageGroup),
      host: hostInput.value.trim(),
    });
    renderReview(findings);
  } catch (e) {
    reviewContainer.innerHTML = `<div class="msg msg-error">Failed to load findings.</div>`;
  }
}

filtersForm.addEventListener("submit", (evt) => {
  evt.preventDefault();
  loadReview();
});

reviewContainer.addEventListener("click", (evt) => {
  const toggle = evt.target.closest(".sev-toggle");
  if (!toggle) return;
  const list = toggle.closest(".sev-group-title").nextElementSibling;
  if (list) list.classList.toggle("collapsed");
});

reviewContainer.addEventListener("change", async (evt) => {
  const select = evt.target.closest(".triage-select");
  if (!select) return;

  const findingKey = select.getAttribute("data-finding-key");
  const previous = select.getAttribute("data-current");
  const newStatus = select.value;
  const summary = select.closest("summary");
  const badge = summary ? summary.querySelector(".triage-badge") : null;

  select.disabled = true;
  try {
    const resp = await api.setFindingTriage(findingKey, newStatus);
    if (resp.ok) {
      select.setAttribute("data-current", newStatus);
      if (badge) badge.outerHTML = renderTriageBadge(newStatus);
      showToast(`Triage set to ${TRIAGE_LABELS[newStatus] || newStatus}.`);
    } else {
      const data = await resp.json().catch(() => null);
      showToast(errorTextFromResponse(data, resp));
      select.value = previous; // revert the dropdown on failure
    }
  } catch (e) {
    showToast("Could not reach gridscan backend.");
    select.value = previous;
  } finally {
    select.disabled = false;
  }
});

(async () => {
  const session = await requireAuth();
  if (!session) return;
  await loadReview();
})();
