// gridscan-ui / scope.js

const textarea = document.getElementById("scope-text");
const saveBtn = document.getElementById("save-btn");
const scopeStatus = document.getElementById("scope-status");
const scopeMsg = document.getElementById("scope-msg");

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str == null ? "" : String(str);
  return div.innerHTML;
}

function clearMsg() {
  scopeMsg.innerHTML = "";
}

async function loadScope(canSave) {
  try {
    const data = await api.getScope();
    textarea.value = data.content || "";
    textarea.disabled = false;
    // Only re-enable the save button for admins - applyRoleRestrictions()
    // (called from requireAuth(), before this runs) already disabled it for
    // viewers, and this must not undo that.
    saveBtn.disabled = !canSave;
  } catch (e) {
    textarea.value = "";
    textarea.placeholder = "Failed to load scope.";
    scopeMsg.innerHTML = `<div class="msg msg-error">Failed to load scope.txt.</div>`;
  }
}

async function saveScope() {
  clearMsg();

  // Consequential action: this controls what gridscan scans against real
  // infrastructure, so require an explicit confirmation before it fires.
  const confirmed = window.confirm(
    "Are you sure? This changes what gets scanned against real infrastructure."
  );
  if (!confirmed) return;

  saveBtn.disabled = true;
  scopeStatus.textContent = "Saving...";

  try {
    const resp = await api.putScope(textarea.value);

    if (resp.ok) {
      scopeMsg.innerHTML = `<div class="msg msg-success">Scope saved.</div>`;
    } else if (resp.status === 400) {
      const data = await resp.json().catch(() => null);
      // FastAPI wraps HTTPException(detail=...) bodies under "detail"; the
      // backend puts {error, invalid_lines: [{line_number, content}]} there.
      const detail = data && data.detail;
      const badLines = (detail && detail.invalid_lines) || [];
      const errorText = (detail && detail.error) || "Scope validation failed.";
      const listHtml = badLines.length
        ? `<ul class="bad-lines">${badLines
            .map((l) => `<li>Line ${escapeHtml(l.line_number)}: ${escapeHtml(l.content)}</li>`)
            .join("")}</ul>`
        : "";
      scopeMsg.innerHTML = `<div class="msg msg-error">${escapeHtml(errorText)}${listHtml}</div>`;
    } else {
      scopeMsg.innerHTML = `<div class="msg msg-error">Save failed (${resp.status}).</div>`;
    }
  } catch (e) {
    scopeMsg.innerHTML = `<div class="msg msg-error">Could not reach gridscan backend.</div>`;
  } finally {
    saveBtn.disabled = false;
    scopeStatus.textContent = "";
  }
}

saveBtn.addEventListener("click", saveScope);

(async () => {
  const session = await requireAuth();
  if (!session) return;
  await loadScope(session.role === "admin");
})();
