// gridscan-ui / api.js
// Thin wrapper around fetch() for talking to the gridscan FastAPI backend.
// All calls use same-origin credentials (cookies) so the backend's
// session + csrf cookies are sent automatically.

const API_BASE = ""; // same origin as the page

/**
 * Read a cookie value by name from document.cookie.
 */
function getCookie(name) {
  const parts = document.cookie ? document.cookie.split("; ") : [];
  for (const part of parts) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const key = decodeURIComponent(part.slice(0, idx));
    if (key === name) {
      return decodeURIComponent(part.slice(idx + 1));
    }
  }
  return null;
}

/**
 * Returns the current CSRF token cookie set by the backend on login.
 */
function getCsrfToken() {
  return getCookie("csrf_token");
}

/**
 * Core request helper. Always sends cookies. Adds X-CSRF-Token for
 * mutating methods (PUT/POST) except /api/login itself.
 */
async function apiRequest(path, { method = "GET", body = null, headers = {} } = {}) {
  const finalHeaders = Object.assign({}, headers);
  const needsCsrf = method !== "GET" && path !== "/api/login";

  if (needsCsrf) {
    const token = getCsrfToken();
    if (token) {
      finalHeaders["X-CSRF-Token"] = token;
    }
  }

  if (body !== null) {
    finalHeaders["Content-Type"] = "application/json";
  }

  const resp = await fetch(API_BASE + path, {
    method,
    headers: finalHeaders,
    credentials: "same-origin",
    body: body !== null ? JSON.stringify(body) : undefined,
  });

  return resp;
}

/**
 * Parses a response as JSON, tolerating empty bodies.
 */
async function parseJsonSafe(resp) {
  const text = await resp.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch (e) {
    return null;
  }
}

const api = {
  async login(username, password) {
    const resp = await apiRequest("/api/login", {
      method: "POST",
      body: { username, password },
    });
    return resp;
  },

  async logout() {
    return apiRequest("/api/logout", { method: "POST" });
  },

  async session() {
    const resp = await apiRequest("/api/session");
    if (!resp.ok) return { authenticated: false, username: null };
    return parseJsonSafe(resp);
  },

  async runs({ scope = "prod", limit = 20, offset = 0 } = {}) {
    const qs = new URLSearchParams({ scope, limit: String(limit), offset: String(offset) });
    const resp = await apiRequest(`/api/runs?${qs.toString()}`);
    if (!resp.ok) throw new Error(`GET /api/runs failed (${resp.status})`);
    return parseJsonSafe(resp);
  },

  async runReport(runId) {
    const resp = await apiRequest(`/api/runs/${encodeURIComponent(runId)}/report`);
    if (resp.status === 404) {
      return { run_id: runId, available: false, not_found: true };
    }
    if (!resp.ok) throw new Error(`GET /api/runs/${runId}/report failed (${resp.status})`);
    return parseJsonSafe(resp);
  },

  async runFindingsDelta(runId) {
    const resp = await apiRequest(`/api/runs/${encodeURIComponent(runId)}/findings-delta`);
    if (resp.status === 404) {
      return { run_id: runId, available: false, not_found: true };
    }
    if (!resp.ok) throw new Error(`GET /api/runs/${runId}/findings-delta failed (${resp.status})`);
    return parseJsonSafe(resp);
  },

  async findings({ scope = "prod", severity = [], status = [], triageStatus = [], host = "", runId = "" } = {}) {
    const params = { scope };
    // severity/status/triageStatus are arrays of checked values (see
    // findings.js/review.js) - the backend accepts either repeated params or
    // one comma-separated value; comma-separated is simplest to build from a
    // plain URLSearchParams here.
    const severityList = Array.isArray(severity) ? severity : severity ? [severity] : [];
    const statusList = Array.isArray(status) ? status : status ? [status] : [];
    const triageList = Array.isArray(triageStatus) ? triageStatus : triageStatus ? [triageStatus] : [];
    if (severityList.length) params.severity = severityList.join(",");
    if (statusList.length) params.status = statusList.join(",");
    if (triageList.length) params.triage_status = triageList.join(",");
    if (host) params.host = host;
    if (runId !== "" && runId != null) params.run_id = String(runId);
    const qs = new URLSearchParams(params);
    const resp = await apiRequest(`/api/findings?${qs.toString()}`);
    if (!resp.ok) throw new Error(`GET /api/findings failed (${resp.status})`);
    return parseJsonSafe(resp);
  },

  async assets({ scope = "prod", tech = "", statusCode = "", host = "" } = {}) {
    const params = { scope };
    if (tech) params.tech = tech;
    if (statusCode) params.status_code = statusCode;
    if (host) params.host = host;
    const qs = new URLSearchParams(params);
    const resp = await apiRequest(`/api/assets?${qs.toString()}`);
    if (!resp.ok) throw new Error(`GET /api/assets failed (${resp.status})`);
    return parseJsonSafe(resp);
  },

  async setFindingTriage(findingKey, triageStatus) {
    return apiRequest("/api/findings/triage", {
      method: "PUT",
      body: { finding_key: findingKey, triage_status: triageStatus },
    });
  },

  async getScope() {
    const resp = await apiRequest("/api/scope");
    if (!resp.ok) throw new Error(`GET /api/scope failed (${resp.status})`);
    return parseJsonSafe(resp);
  },

  async putScope(content) {
    const resp = await apiRequest("/api/scope", {
      method: "PUT",
      body: { content },
    });
    return resp;
  },

  async setWebhook(webhookUrl) {
    const resp = await apiRequest("/api/webhook", {
      method: "POST",
      body: { webhook_url: webhookUrl },
    });
    return resp;
  },

  async testSlackWebhook() {
    return apiRequest("/api/settings/slack/test", { method: "POST" });
  },

  async getSlackSettings() {
    const resp = await apiRequest("/api/settings/slack");
    if (!resp.ok) throw new Error(`GET /api/settings/slack failed (${resp.status})`);
    return parseJsonSafe(resp);
  },

  async revealSlackWebhook() {
    return apiRequest("/api/settings/slack/reveal", { method: "POST" });
  },

  async getSmtpSettings() {
    const resp = await apiRequest("/api/settings/smtp");
    if (!resp.ok) throw new Error(`GET /api/settings/smtp failed (${resp.status})`);
    return parseJsonSafe(resp);
  },

  async putSmtpSettings(fields) {
    return apiRequest("/api/settings/smtp", { method: "PUT", body: fields });
  },

  async testSmtpSettings() {
    return apiRequest("/api/settings/smtp/test", { method: "POST" });
  },

  async triggerScan() {
    const resp = await apiRequest("/api/scan/trigger", { method: "POST" });
    return resp;
  },

  async scanStatus() {
    const resp = await apiRequest("/api/scan/status");
    if (!resp.ok) throw new Error(`GET /api/scan/status failed (${resp.status})`);
    return parseJsonSafe(resp);
  },

  async stopScan() {
    const resp = await apiRequest("/api/scan/stop", { method: "POST" });
    return resp;
  },

  async scanLogs() {
    const resp = await apiRequest("/api/scan/logs");
    if (!resp.ok) throw new Error(`GET /api/scan/logs failed (${resp.status})`);
    return parseJsonSafe(resp);
  },

  async triggerDiscover() {
    const resp = await apiRequest("/api/scan/discover", { method: "POST" });
    return resp;
  },

  async discoverStatus() {
    const resp = await apiRequest("/api/scan/discover/status");
    if (!resp.ok) throw new Error(`GET /api/scan/discover/status failed (${resp.status})`);
    return parseJsonSafe(resp);
  },

  async getDiscovery() {
    const resp = await apiRequest("/api/scan/discovery");
    if (!resp.ok) throw new Error(`GET /api/scan/discovery failed (${resp.status})`);
    return parseJsonSafe(resp);
  },

  async runSelected(urls) {
    return apiRequest("/api/scan/run-selected", { method: "POST", body: { urls } });
  },

  async runSelectedStatus() {
    const resp = await apiRequest("/api/scan/run-selected/status");
    if (!resp.ok) throw new Error(`GET /api/scan/run-selected/status failed (${resp.status})`);
    return parseJsonSafe(resp);
  },

  async account() {
    const resp = await apiRequest("/api/account");
    if (!resp.ok) throw new Error(`GET /api/account failed (${resp.status})`);
    return parseJsonSafe(resp);
  },

  async updateAccount(fields) {
    return apiRequest("/api/account", { method: "PUT", body: fields });
  },

  async listUsers() {
    const resp = await apiRequest("/api/users");
    if (!resp.ok) throw new Error(`GET /api/users failed (${resp.status})`);
    return parseJsonSafe(resp);
  },

  async createUser(fields) {
    return apiRequest("/api/users", { method: "POST", body: fields });
  },

  async updateUser(username, fields) {
    return apiRequest(`/api/users/${encodeURIComponent(username)}`, {
      method: "PUT",
      body: fields,
    });
  },

  async deleteUser(username) {
    return apiRequest(`/api/users/${encodeURIComponent(username)}`, { method: "DELETE" });
  },
};
