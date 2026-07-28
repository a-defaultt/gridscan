// gridscan-ui / auth.js
// Auth guard used by every page except login.html.
// Frontend-side check so the UX doesn't sit on a page full of 401s while
// waiting for the backend to reject each request individually.

/**
 * Checks /api/session, then /api/account for the user's current role (looked
 * up fresh from the backend on every page load - never trusted from a cookie
 * or cached value). Redirects to login.html if not authenticated, or if the
 * account lookup itself 401s (e.g. the account was deleted after the session
 * cookie was issued - same rejection the backend enforces on every request).
 * Resolves with the session object ({authenticated, username, role, name,
 * email}) if ok.
 */
async function requireAuth() {
  let session;
  try {
    session = await api.session();
  } catch (e) {
    session = { authenticated: false, username: null };
  }

  if (!session || !session.authenticated) {
    window.location.href = "login.html";
    return null;
  }

  let account;
  try {
    account = await api.account();
  } catch (e) {
    // Account lookup failed (e.g. 401 - user deleted mid-session). Backend
    // enforcement is the real boundary; this just gets the user off a stale
    // page promptly instead of leaving them looking at 403s.
    window.location.href = "login.html";
    return null;
  }

  session.role = account.role;
  session.name = account.name;
  session.email = account.email;

  const tag = document.querySelector("[data-user-tag]");
  if (tag) {
    tag.textContent = session.username ? `${session.username} · ${session.role}` : "";
  }

  applyRoleRestrictions(session.role);

  return session;
}

/**
 * Frontend-only UX: hides the admin-only "Users" nav link and disables
 * write-action controls for viewers, so they aren't shown buttons that would
 * just come back 403. The backend (require_admin) is the actual security
 * boundary - this is not it.
 */
function applyRoleRestrictions(role) {
  const isAdmin = role === "admin";

  const usersLink = document.querySelector('nav.mainnav a[data-nav="users.html"]');
  if (usersLink) {
    usersLink.style.display = isAdmin ? "" : "none";
  }

  if (!isAdmin) {
    document.querySelectorAll("[data-requires-admin]").forEach((el) => {
      el.disabled = true;
      el.title = "Requires admin role";
      if (!el.nextElementSibling || !el.nextElementSibling.classList.contains("admin-hint")) {
        const hint = document.createElement("span");
        hint.className = "text-dim admin-hint";
        hint.textContent = " Requires admin role.";
        el.insertAdjacentElement("afterend", hint);
      }
    });
  }
}

/**
 * Marks the current page's nav link as active based on data-nav attribute
 * matching the current file name, and wires up the logout button if present.
 */
function initNav() {
  const current = window.location.pathname.split("/").pop() || "dashboard.html";
  document.querySelectorAll("nav.mainnav a[data-nav]").forEach((link) => {
    if (link.getAttribute("data-nav") === current) {
      link.classList.add("active");
    }
  });

  const logoutBtn = document.querySelector("[data-logout]");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", async () => {
      try {
        await api.logout();
      } catch (e) {
        // ignore network errors on logout, still send the user back
      }
      window.location.href = "login.html";
    });
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initNav();
});
