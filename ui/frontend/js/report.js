// gridscan-ui / report.js
// Full-page view of a single run's report snapshot. Reached from the
// dashboard's run detail side panel via "Open full report" -> report.html?run_id=N.

const reportTitleEl = document.getElementById("report-title");
const reportBodyEl = document.getElementById("report-body");

function getRunIdFromQuery() {
  const params = new URLSearchParams(window.location.search);
  return params.get("run_id");
}

async function loadReport() {
  const runId = getRunIdFromQuery();
  if (!runId) {
    reportBodyEl.className = "msg msg-error";
    reportBodyEl.textContent = "No run_id given in the URL.";
    return;
  }

  reportTitleEl.textContent = `Run #${runId} report`;

  try {
    const data = await api.runReport(runId);

    if (data && data.not_found) {
      reportBodyEl.className = "msg msg-error";
      reportBodyEl.textContent = `Run #${runId} does not exist.`;
      return;
    }

    if (data && data.scope) {
      reportTitleEl.textContent = `Run #${runId} report · ${data.scope}`;
    }

    if (data && data.available) {
      const pre = document.createElement("pre");
      pre.className = "report-content report-content-full";
      pre.textContent = data.report_md;
      reportBodyEl.className = "";
      reportBodyEl.innerHTML = "";
      reportBodyEl.appendChild(pre);
    } else {
      reportBodyEl.className = "text-dim";
      reportBodyEl.textContent =
        "No detailed report snapshot available for this run (recorded before this feature was added).";
    }
  } catch (e) {
    reportBodyEl.className = "msg msg-error";
    reportBodyEl.textContent = "Failed to load report.";
  }
}

(async () => {
  const session = await requireAuth();
  if (!session) return;
  await loadReport();
})();
