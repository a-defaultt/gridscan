// gridscan-ui / settings.js
//
// NOTE: the "set new webhook" input below is a write-only control (same as
// before) - it must never be pre-filled from any API response. The current
// value is shown separately, masked by default, via slack-masked-value /
// slack-reveal-btn (see loadSlackSettings() / the reveal handler below).

const webhookForm = document.getElementById("webhook-form");
const webhookInput = document.getElementById("webhook-url");
const webhookMsg = document.getElementById("webhook-msg");
const slackTestBtn = document.getElementById("slack-test-btn");
const slackMaskedValueEl = document.getElementById("slack-masked-value");
const slackRevealBtn = document.getElementById("slack-reveal-btn");
const toast = document.getElementById("toast");

// Client-side reveal/hide state for the current page session. Hiding is a
// pure display toggle back to the masked text already fetched - it must
// NOT trigger another call to the reveal endpoint (that endpoint is the
// sensitive, audit-logged action; toggling visibility of an already-
// revealed value in this same session is not).
let slackMaskedText = null;
let slackRealValue = null;
let slackRevealed = false;

const smtpForm = document.getElementById("smtp-form");
const smtpHostInput = document.getElementById("smtp-host");
const smtpPortInput = document.getElementById("smtp-port");
const smtpUsernameInput = document.getElementById("smtp-username");
const smtpPasswordInput = document.getElementById("smtp-password");
const smtpFromInput = document.getElementById("smtp-from");
const smtpToInput = document.getElementById("smtp-to");
const smtpPasswordStatus = document.getElementById("smtp-password-status");
const smtpTestBtn = document.getElementById("smtp-test-btn");
const smtpMsg = document.getElementById("smtp-msg");

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str == null ? "" : String(str);
  return div.innerHTML;
}

const accountRoleEl = document.getElementById("account-role");
const profileForm = document.getElementById("profile-form");
const profileNameInput = document.getElementById("profile-name");
const profileEmailInput = document.getElementById("profile-email");
const profileMsg = document.getElementById("profile-msg");

const passwordForm = document.getElementById("password-form");
const currentPasswordInput = document.getElementById("current-password");
const newPasswordInput = document.getElementById("new-password-account");
const confirmPasswordInput = document.getElementById("confirm-password-account");
const passwordMsg = document.getElementById("password-msg");

function showToast(text) {
  toast.textContent = text;
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), 2500);
}

function errorTextFromResponse(data, resp) {
  const detail = data && data.detail;
  if (typeof detail === "string") return detail;
  return `Request failed (${resp.status}).`;
}

webhookForm.addEventListener("submit", async (evt) => {
  evt.preventDefault();
  webhookMsg.innerHTML = "";

  const url = webhookInput.value.trim();
  if (!url) {
    webhookMsg.innerHTML = `<div class="msg msg-error">Enter a webhook URL first.</div>`;
    return;
  }

  const submitBtn = webhookForm.querySelector("button[type=submit]");
  submitBtn.disabled = true;

  try {
    const resp = await api.setWebhook(url);

    if (resp.ok) {
      showToast("Webhook saved.");
      webhookInput.value = ""; // never leave the secret sitting in the field
      await loadSlackSettings(); // refresh the masked preview to reflect the new value
    } else {
      const data = await resp.json().catch(() => null);
      webhookMsg.innerHTML = `<div class="msg msg-error">${escapeHtml(errorTextFromResponse(data, resp))}</div>`;
    }
  } catch (e) {
    webhookMsg.innerHTML = `<div class="msg msg-error">Could not reach gridscan backend.</div>`;
  } finally {
    submitBtn.disabled = false;
  }
});

slackTestBtn.addEventListener("click", async () => {
  webhookMsg.innerHTML = "";
  slackTestBtn.disabled = true;
  try {
    const resp = await api.testSlackWebhook();
    if (resp.ok) {
      webhookMsg.innerHTML = `<div class="msg msg-success">Test Slack message sent.</div>`;
    } else {
      const data = await resp.json().catch(() => null);
      webhookMsg.innerHTML = `<div class="msg msg-error">${escapeHtml(errorTextFromResponse(data, resp))}</div>`;
    }
  } catch (e) {
    webhookMsg.innerHTML = `<div class="msg msg-error">Could not reach gridscan backend.</div>`;
  } finally {
    slackTestBtn.disabled = false;
  }
});

async function loadSlackSettings() {
  slackRevealed = false;
  slackRealValue = null;
  try {
    const data = await api.getSlackSettings();
    if (data.configured) {
      slackMaskedText = data.masked;
      slackMaskedValueEl.textContent = data.masked;
      slackRevealBtn.disabled = false;
    } else {
      slackMaskedText = null;
      slackMaskedValueEl.textContent = "Not configured";
      slackRevealBtn.disabled = true;
    }
    slackRevealBtn.textContent = "Show";
  } catch (e) {
    slackMaskedValueEl.textContent = "Failed to load.";
    slackRevealBtn.disabled = true;
  }
}

slackRevealBtn.addEventListener("click", async () => {
  webhookMsg.innerHTML = "";

  if (slackRevealed) {
    // Hide: a pure client-side toggle back to the masked text already
    // fetched by loadSlackSettings() - no network call, since the real
    // value is only ever fetched (and audit-logged) on an explicit reveal.
    slackMaskedValueEl.textContent = slackMaskedText;
    slackRevealBtn.textContent = "Show";
    slackRevealed = false;
    return;
  }

  slackRevealBtn.disabled = true;
  try {
    const resp = await api.revealSlackWebhook();
    if (resp.ok) {
      const data = await resp.json();
      slackRealValue = data.webhook_url;
      slackMaskedValueEl.textContent = slackRealValue;
      slackRevealBtn.textContent = "Hide";
      slackRevealed = true;
    } else {
      const data = await resp.json().catch(() => null);
      webhookMsg.innerHTML = `<div class="msg msg-error">${escapeHtml(errorTextFromResponse(data, resp))}</div>`;
    }
  } catch (e) {
    webhookMsg.innerHTML = `<div class="msg msg-error">Could not reach gridscan backend.</div>`;
  } finally {
    slackRevealBtn.disabled = false;
  }
});

function setSmtpPasswordStatus(configured) {
  smtpPasswordStatus.textContent = configured ? "configured" : "not set";
}

async function loadSmtpSettings() {
  try {
    const data = await api.getSmtpSettings();
    smtpHostInput.value = data.host || "";
    smtpPortInput.value = data.port || "";
    smtpUsernameInput.value = data.username || "";
    smtpFromInput.value = data.from_addr || "";
    smtpToInput.value = data.to_addr || "";
    // password field is intentionally never populated - write-only, same
    // convention as the webhook field above.
    smtpPasswordInput.value = "";
    setSmtpPasswordStatus(data.password_configured);
  } catch (e) {
    smtpMsg.innerHTML = `<div class="msg msg-error">Failed to load SMTP settings.</div>`;
  }
}

smtpForm.addEventListener("submit", async (evt) => {
  evt.preventDefault();
  smtpMsg.innerHTML = "";

  const saveBtn = smtpForm.querySelector("button[type=submit]");
  saveBtn.disabled = true;

  try {
    const fields = {
      host: smtpHostInput.value.trim(),
      port: parseInt(smtpPortInput.value, 10),
      username: smtpUsernameInput.value.trim(),
      from_addr: smtpFromInput.value.trim(),
      to_addr: smtpToInput.value.trim(),
    };
    const password = smtpPasswordInput.value;
    if (password) {
      fields.password = password;
    }

    const resp = await api.putSmtpSettings(fields);

    if (resp.ok) {
      showToast("SMTP settings saved.");
      smtpPasswordInput.value = ""; // never leave the secret sitting in the field
      await loadSmtpSettings();
    } else {
      const data = await resp.json().catch(() => null);
      smtpMsg.innerHTML = `<div class="msg msg-error">${escapeHtml(errorTextFromResponse(data, resp))}</div>`;
    }
  } catch (e) {
    smtpMsg.innerHTML = `<div class="msg msg-error">Could not reach gridscan backend.</div>`;
  } finally {
    saveBtn.disabled = false;
  }
});

smtpTestBtn.addEventListener("click", async () => {
  smtpMsg.innerHTML = "";
  smtpTestBtn.disabled = true;
  try {
    const resp = await api.testSmtpSettings();
    if (resp.ok) {
      smtpMsg.innerHTML = `<div class="msg msg-success">Test email sent.</div>`;
    } else {
      const data = await resp.json().catch(() => null);
      smtpMsg.innerHTML = `<div class="msg msg-error">${escapeHtml(errorTextFromResponse(data, resp))}</div>`;
    }
  } catch (e) {
    smtpMsg.innerHTML = `<div class="msg msg-error">Could not reach gridscan backend.</div>`;
  } finally {
    smtpTestBtn.disabled = false;
  }
});

profileForm.addEventListener("submit", async (evt) => {
  evt.preventDefault();
  profileMsg.innerHTML = "";

  const saveBtn = profileForm.querySelector("button[type=submit]");
  saveBtn.disabled = true;

  try {
    const resp = await api.updateAccount({
      name: profileNameInput.value.trim() || null,
      email: profileEmailInput.value.trim() || null,
    });

    if (resp.ok) {
      showToast("Profile saved.");
    } else {
      const data = await resp.json().catch(() => null);
      profileMsg.innerHTML = `<div class="msg msg-error">${errorTextFromResponse(data, resp)}</div>`;
    }
  } catch (e) {
    profileMsg.innerHTML = `<div class="msg msg-error">Could not reach gridscan backend.</div>`;
  } finally {
    saveBtn.disabled = false;
  }
});

passwordForm.addEventListener("submit", async (evt) => {
  evt.preventDefault();
  passwordMsg.innerHTML = "";

  const currentPassword = currentPasswordInput.value;
  const newPassword = newPasswordInput.value;
  const confirmPassword = confirmPasswordInput.value;

  if (!currentPassword || !newPassword) {
    passwordMsg.innerHTML = `<div class="msg msg-error">Current and new password are both required.</div>`;
    return;
  }
  if (newPassword !== confirmPassword) {
    passwordMsg.innerHTML = `<div class="msg msg-error">New password and confirmation do not match.</div>`;
    return;
  }

  const saveBtn = passwordForm.querySelector("button[type=submit]");
  saveBtn.disabled = true;

  try {
    const resp = await api.updateAccount({
      current_password: currentPassword,
      new_password: newPassword,
    });

    if (resp.ok) {
      showToast("Password changed.");
      passwordForm.reset();
    } else {
      const data = await resp.json().catch(() => null);
      passwordMsg.innerHTML = `<div class="msg msg-error">${errorTextFromResponse(data, resp)}</div>`;
    }
  } catch (e) {
    passwordMsg.innerHTML = `<div class="msg msg-error">Could not reach gridscan backend.</div>`;
  } finally {
    saveBtn.disabled = false;
  }
});

(async () => {
  const session = await requireAuth();
  if (!session) return;
  // Intentionally no pre-fill of the "set new webhook" input above - that
  // field is write-only, same as before. The masked preview is loaded
  // separately below (admin only - GET /api/settings/slack is require_admin).

  accountRoleEl.textContent = session.role || "-";
  profileNameInput.value = session.name || "";
  profileEmailInput.value = session.email || "";

  if (session.role === "admin") {
    await loadSmtpSettings();
    await loadSlackSettings();
  }
})();
