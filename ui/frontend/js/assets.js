// gridscan-ui / assets.js

const assetsBody = document.getElementById("assets-body");
const assetsMsg = document.getElementById("assets-msg");

const techInput = document.getElementById("filter-tech");
const statusCodeInput = document.getElementById("filter-status-code");
const hostInput = document.getElementById("filter-host");
const filtersForm = document.getElementById("filters-form");

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

function renderTechChips(techRaw) {
  let list = [];
  if (Array.isArray(techRaw)) {
    list = techRaw;
  } else if (typeof techRaw === "string" && techRaw.trim() !== "") {
    try {
      const parsed = JSON.parse(techRaw);
      if (Array.isArray(parsed)) list = parsed;
    } catch (e) {
      // not JSON, fall back to a single chip with the raw string
      list = [techRaw];
    }
  }

  if (list.length === 0) return `<span class="text-dim">-</span>`;
  return list.map((t) => `<span class="chip">${escapeHtml(t)}</span>`).join("");
}

function renderAssets(assets) {
  assetsBody.innerHTML = "";

  if (!assets || assets.length === 0) {
    assetsBody.innerHTML = `<tr class="empty-row"><td colspan="6">No assets match these filters.</td></tr>`;
    return;
  }

  assets.forEach((a) => {
    const tr = document.createElement("tr");
    tr.setAttribute("data-asset-row", "");
    tr.setAttribute("data-scope", a.scope);
    tr.setAttribute("data-url", a.url);
    tr.innerHTML = `
      <td><a href="${escapeHtml(a.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(a.url)}</a></td>
      <td class="tech-cell">${renderTechChips(a.tech)}</td>
      <td>${escapeHtml(a.status_code)}</td>
      <td>${escapeHtml(a.title)}</td>
      <td>${formatDate(a.first_seen)}</td>
      <td>${formatDate(a.last_seen)}</td>
    `;
    assetsBody.appendChild(tr);
  });
}

async function loadAssets() {
  assetsMsg.innerHTML = "";
  try {
    const assets = await api.assets({
      scope: "prod",
      tech: techInput.value.trim(),
      statusCode: statusCodeInput.value.trim(),
      host: hostInput.value.trim(),
    });
    renderAssets(assets);
  } catch (e) {
    assetsBody.innerHTML = `<tr class="empty-row"><td colspan="6">Failed to load assets.</td></tr>`;
  }
}

filtersForm.addEventListener("submit", (evt) => {
  evt.preventDefault();
  loadAssets();
});

(async () => {
  const session = await requireAuth();
  if (!session) return;
  await loadAssets();
})();
