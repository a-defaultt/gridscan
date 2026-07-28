// gridscan-ui / users.js
// Admin-only user management page. The nav link and this page's own
// redirect-away-if-not-admin check are UX only - GET/POST/PUT/DELETE
// /api/users are what actually enforce require_admin server-side.

const createForm = document.getElementById("create-user-form");
const createBtn = document.getElementById("create-user-btn");
const createMsg = document.getElementById("create-user-msg");
const usersBody = document.getElementById("users-body");
const usersMsg = document.getElementById("users-msg");
const toast = document.getElementById("toast");

let currentUsername = null;

function showToast(text) {
  toast.textContent = text;
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), 2500);
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str == null ? "" : String(str);
  return div.innerHTML;
}

function formatDate(value) {
  if (!value) return "-";
  const d = new Date(value);
  if (isNaN(d.getTime())) return value;
  return d.toLocaleString();
}

function errorTextFromResponse(data, resp) {
  const detail = data && data.detail;
  if (typeof detail === "string") return detail;
  return `Request failed (${resp.status}).`;
}

function renderUsers(users) {
  usersBody.innerHTML = "";

  if (!users || users.length === 0) {
    usersBody.innerHTML = `<tr class="empty-row"><td colspan="6">No users.</td></tr>`;
    return;
  }

  users.forEach((u) => {
    const tr = document.createElement("tr");
    const isSelf = u.username === currentUsername;
    tr.innerHTML = `
      <td class="mono">${escapeHtml(u.username)}</td>
      <td>${escapeHtml(u.name || "-")}</td>
      <td>${escapeHtml(u.email || "-")}</td>
      <td>
        <select class="role-select" data-username="${escapeHtml(u.username)}">
          <option value="viewer" ${u.role === "viewer" ? "selected" : ""}>viewer</option>
          <option value="admin" ${u.role === "admin" ? "selected" : ""}>admin</option>
        </select>
      </td>
      <td>${formatDate(u.created_at)}</td>
      <td>
        <button
          class="danger"
          data-delete-username="${escapeHtml(u.username)}"
          ${isSelf ? "disabled title=\"Cannot delete your own account here\"" : ""}
        >Delete</button>
      </td>
    `;
    usersBody.appendChild(tr);
  });
}

async function loadUsers() {
  usersMsg.innerHTML = "";
  try {
    const users = await api.listUsers();
    renderUsers(users);
  } catch (e) {
    usersBody.innerHTML = `<tr class="empty-row"><td colspan="6">Failed to load users.</td></tr>`;
  }
}

createForm.addEventListener("submit", async (evt) => {
  evt.preventDefault();
  createMsg.innerHTML = "";

  const body = {
    username: document.getElementById("new-username").value.trim(),
    password: document.getElementById("new-password").value,
    name: document.getElementById("new-name").value.trim() || null,
    email: document.getElementById("new-email").value.trim() || null,
    role: document.getElementById("new-role").value,
  };

  if (!body.username || !body.password) {
    createMsg.innerHTML = `<div class="msg msg-error">Username and password are required.</div>`;
    return;
  }

  createBtn.disabled = true;
  try {
    const resp = await api.createUser(body);
    if (resp.ok) {
      showToast(`User "${body.username}" created.`);
      createForm.reset();
      await loadUsers();
    } else {
      const data = await resp.json().catch(() => null);
      createMsg.innerHTML = `<div class="msg msg-error">${escapeHtml(errorTextFromResponse(data, resp))}</div>`;
    }
  } catch (e) {
    createMsg.innerHTML = `<div class="msg msg-error">Could not reach gridscan backend.</div>`;
  } finally {
    createBtn.disabled = false;
  }
});

usersBody.addEventListener("change", async (evt) => {
  const select = evt.target.closest(".role-select");
  if (!select) return;

  const username = select.getAttribute("data-username");
  const newRole = select.value;

  const confirmed = window.confirm(`Change ${username}'s role to "${newRole}"?`);
  if (!confirmed) {
    await loadUsers(); // revert the dropdown to the actual stored value
    return;
  }

  select.disabled = true;
  try {
    const resp = await api.updateUser(username, { role: newRole });
    if (resp.ok) {
      showToast(`${username} is now ${newRole}.`);
      await loadUsers();
    } else {
      const data = await resp.json().catch(() => null);
      usersMsg.innerHTML = `<div class="msg msg-error">${escapeHtml(errorTextFromResponse(data, resp))}</div>`;
      await loadUsers(); // revert dropdown on failure (e.g. last-admin lockout)
    }
  } catch (e) {
    usersMsg.innerHTML = `<div class="msg msg-error">Could not reach gridscan backend.</div>`;
    await loadUsers();
  } finally {
    select.disabled = false;
  }
});

usersBody.addEventListener("click", async (evt) => {
  const btn = evt.target.closest("[data-delete-username]");
  if (!btn || btn.disabled) return;

  const username = btn.getAttribute("data-delete-username");
  const confirmed = window.confirm(`Delete user "${username}"? This cannot be undone.`);
  if (!confirmed) return;

  btn.disabled = true;
  try {
    const resp = await api.deleteUser(username);
    if (resp.ok) {
      showToast(`User "${username}" deleted.`);
      await loadUsers();
    } else {
      const data = await resp.json().catch(() => null);
      usersMsg.innerHTML = `<div class="msg msg-error">${escapeHtml(errorTextFromResponse(data, resp))}</div>`;
      btn.disabled = false;
    }
  } catch (e) {
    usersMsg.innerHTML = `<div class="msg msg-error">Could not reach gridscan backend.</div>`;
    btn.disabled = false;
  }
});

(async () => {
  const session = await requireAuth();
  if (!session) return;

  if (session.role !== "admin") {
    // Server-enforced already (require_admin on every /api/users* route) -
    // this redirect is just so a viewer hitting this URL directly doesn't
    // sit on a page full of 403s.
    window.location.href = "dashboard.html";
    return;
  }

  currentUsername = session.username;
  await loadUsers();
})();
