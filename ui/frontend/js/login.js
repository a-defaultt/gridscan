// gridscan-ui / login.js

const form = document.getElementById("login-form");
const btn = document.getElementById("login-btn");
const msgEl = document.getElementById("login-msg");

let lastAttemptAt = 0;
const MIN_RETRY_MS = 1500; // avoid hammering the backend on repeated submits

function showError(text) {
  msgEl.innerHTML = `<div class="msg msg-error">${text}</div>`;
}

function clearMsg() {
  msgEl.innerHTML = "";
}

// If already logged in, skip straight to the dashboard.
(async () => {
  try {
    const session = await api.session();
    if (session && session.authenticated) {
      window.location.href = "dashboard.html";
    }
  } catch (e) {
    // not authenticated / backend unreachable - stay on login
  }
})();

form.addEventListener("submit", async (evt) => {
  evt.preventDefault();
  clearMsg();

  const now = Date.now();
  if (now - lastAttemptAt < MIN_RETRY_MS) {
    // silently ignore rapid re-submits (e.g. double-click / enter spam)
    return;
  }
  lastAttemptAt = now;

  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;

  if (!username || !password) {
    showError("Username and password are required.");
    return;
  }

  btn.disabled = true;
  btn.textContent = "Signing in...";

  try {
    const resp = await api.login(username, password);

    if (resp.ok) {
      window.location.href = "dashboard.html";
      return;
    }

    if (resp.status === 401) {
      showError("Invalid username or password.");
    } else if (resp.status === 429) {
      showError("Too many attempts. Please wait before trying again.");
    } else {
      showError(`Login failed (${resp.status}).`);
    }
  } catch (e) {
    showError("Could not reach the gridscan backend.");
  } finally {
    btn.disabled = false;
    btn.textContent = "Sign in";
  }
});
