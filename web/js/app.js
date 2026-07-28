/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

"use strict";

const elements = {
  serviceState: document.querySelector("#service-state"),
  serviceContainer: document.querySelector(".service-state"),
  accountState: document.querySelector("#account-state"),
  currentUser: document.querySelector("#current-user"),
  authView: document.querySelector("#auth-view"),
  appView: document.querySelector("#app-view"),
  loginForm: document.querySelector("#login-form"),
  bootstrapForm: document.querySelector("#bootstrap-form"),
  secondFactor: document.querySelector("#second-factor"),
  loginError: document.querySelector("#login-error"),
  bootstrapError: document.querySelector("#bootstrap-error"),
  dashboardError: document.querySelector("#dashboard-error"),
  refresh: document.querySelector("#refresh"),
  logout: document.querySelector("#logout"),
};

let csrfToken = sessionStorage.getItem("janusgate.csrf") || "";

/**
 * Represent a structured API failure without exposing response internals.
 */
class ApiError extends Error {
  /**
   * Initialize one failure from its HTTP status and public error object.
   */
  constructor(status, code, message) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

/**
 * Return a short safe message from a failed API response.
 */
function errorMessage(error) {
  return error instanceof ApiError
    ? error.message
    : "The management request could not be completed.";
}

/**
 * Display one accessible form or page error.
 */
function showError(container, message) {
  container.textContent = message;
  container.hidden = message.length === 0;
}

/**
 * Exchange one same-origin JSON API request.
 */
async function api(path, options = {}) {
  const method = options.method || "GET";
  const headers = { Accept: "application/json" };
  const request = {
    method,
    credentials: "same-origin",
    cache: "no-store",
    headers,
  };

  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    request.body = JSON.stringify(options.body);
  }
  if (method !== "GET" && csrfToken.length > 0) {
    headers["X-CSRF-Token"] = csrfToken;
  }
  const response = await fetch(path, request);
  let payload;

  try {
    payload = await response.json();
  } catch {
    throw new ApiError(response.status, "invalid_response",
      "The appliance returned an invalid response.");
  }
  if (!response.ok) {
    const detail = payload && payload.error ? payload.error : {};
    throw new ApiError(
      response.status,
      typeof detail.code === "string" ? detail.code : "request_failed",
      typeof detail.message === "string"
        ? detail.message
        : "The management request failed.",
    );
  }
  return payload;
}

/**
 * Persist the CSRF value for the lifetime of this browser tab.
 */
function rememberCsrf(value) {
  csrfToken = typeof value === "string" ? value : "";
  if (csrfToken.length > 0) {
    sessionStorage.setItem("janusgate.csrf", csrfToken);
  } else {
    sessionStorage.removeItem("janusgate.csrf");
  }
}

/**
 * Switch the shell to an authenticated identity.
 */
function showApplication(user) {
  elements.authView.hidden = true;
  elements.appView.hidden = false;
  elements.accountState.hidden = false;
  elements.currentUser.textContent = user.username;
}

/**
 * Return the shell to its unauthenticated state.
 */
function showAuthentication() {
  elements.appView.hidden = true;
  elements.accountState.hidden = true;
  elements.authView.hidden = false;
  elements.loginForm.hidden = false;
  elements.bootstrapForm.hidden = true;
  elements.secondFactor.hidden = true;
  rememberCsrf("");
}

/**
 * Format an integer counter for the active locale.
 */
function formatCounter(value) {
  return Number.isSafeInteger(value) ? value.toLocaleString() : "—";
}

/**
 * Fetch and render the authenticated packet-runtime snapshot.
 */
async function refreshStatus() {
  elements.refresh.disabled = true;
  showError(elements.dashboardError, "");

  try {
    const status = await api("/api/v1/status");
    document.querySelector("#enforcement-status").textContent =
      status.ready ? "Ready" : "Not ready";
    document.querySelector("#policy-generation").textContent =
      formatCounter(status.policy_generation);
    document.querySelector("#allowed-count").textContent =
      formatCounter(status.dataplane.accepted);
    document.querySelector("#blocked-count").textContent =
      formatCounter(status.dataplane.blocked);
    document.querySelector("#malformed-count").textContent =
      formatCounter(status.dataplane.malformed);
    document.querySelector("#queue-drop-count").textContent =
      formatCounter(status.queues.dropped + status.queues.overflows);
    document.querySelector("#tcp-reset-count").textContent =
      formatCounter(status.dataplane.tcp_resets);
    document.querySelector("#sni-count").textContent =
      formatCounter(status.dataplane.sni_inspected);
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      showAuthentication();
    } else {
      showError(elements.dashboardError, errorMessage(error));
    }
  } finally {
    elements.refresh.disabled = false;
  }
}

/**
 * Authenticate one local user, including an optional second factor.
 */
async function submitLogin(event) {
  event.preventDefault();
  showError(elements.loginError, "");
  const data = new FormData(elements.loginForm);
  const body = {
    username: data.get("username"),
    password: data.get("password"),
  };
  const totp = String(data.get("totp") || "");
  const recovery = String(data.get("recovery") || "");

  if (totp.length > 0) {
    body.totp = Number.parseInt(totp, 10);
  } else if (recovery.length > 0) {
    body.recovery_code = recovery;
  }
  const submit = elements.loginForm.querySelector("[type=submit]");
  submit.disabled = true;
  try {
    const session = await api("/api/v1/auth/login", {
      method: "POST",
      body,
    });
    rememberCsrf(session.csrf);
    elements.loginForm.reset();
    showApplication(session.user);
    await refreshStatus();
  } catch (error) {
    if (error instanceof ApiError && error.code === "mfa_required") {
      elements.secondFactor.hidden = false;
      document.querySelector("#login-totp").focus();
    }
    showError(elements.loginError, errorMessage(error));
  } finally {
    submit.disabled = false;
  }
}

/**
 * Consume the console bootstrap token and create the first administrator.
 */
async function submitBootstrap(event) {
  event.preventDefault();
  showError(elements.bootstrapError, "");
  const data = new FormData(elements.bootstrapForm);
  const password = String(data.get("password"));
  const confirm = String(data.get("confirm"));

  if (password !== confirm) {
    showError(elements.bootstrapError, "The password confirmation does not match.");
    document.querySelector("#bootstrap-confirm").focus();
    return;
  }
  const submit = elements.bootstrapForm.querySelector("[type=submit]");
  submit.disabled = true;
  try {
    const session = await api("/api/v1/auth/bootstrap", {
      method: "POST",
      body: {
        token: data.get("token"),
        username: data.get("username"),
        password,
      },
    });
    rememberCsrf(session.csrf);
    elements.bootstrapForm.reset();
    showApplication(session.user);
    await refreshStatus();
  } catch (error) {
    showError(elements.bootstrapError, errorMessage(error));
  } finally {
    submit.disabled = false;
  }
}

/**
 * Revoke the current session and clear all browser-local state.
 */
async function logout() {
  elements.logout.disabled = true;
  try {
    await api("/api/v1/auth/logout", { method: "POST", body: {} });
  } catch {
    // Local state is cleared even if an expired session is already invalid.
  } finally {
    elements.logout.disabled = false;
    showAuthentication();
  }
}

/**
 * Verify HTTPS health and restore an existing browser session.
 */
async function initialize() {
  try {
    const response = await fetch("/api/v1/health", {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    const health = await response.json();
    if (!response.ok || health.status !== "ok") {
      throw new Error("health state is unavailable");
    }
    elements.serviceState.textContent = "Management service ready";
    elements.serviceContainer.classList.add("ready");
  } catch {
    elements.serviceState.textContent = "Management service unavailable";
    return;
  }
  try {
    const session = await api("/api/v1/auth/session");
    showApplication(session.user);
    await refreshStatus();
  } catch {
    showAuthentication();
  }
}

/**
 * Display the first-boot administrator form.
 */
function showBootstrapForm() {
  elements.loginForm.hidden = true;
  elements.bootstrapForm.hidden = false;
  document.querySelector("#bootstrap-token").focus();
}

/**
 * Return from first-boot setup to the login form.
 */
function showLoginForm() {
  elements.bootstrapForm.hidden = true;
  elements.loginForm.hidden = false;
  document.querySelector("#login-username").focus();
}

elements.loginForm.addEventListener("submit", submitLogin);
elements.bootstrapForm.addEventListener("submit", submitBootstrap);
elements.refresh.addEventListener("click", refreshStatus);
elements.logout.addEventListener("click", logout);
document.querySelector("#show-bootstrap").addEventListener(
  "click",
  showBootstrapForm,
);
document.querySelector("#show-login").addEventListener("click", showLoginForm);
void initialize();
