/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

"use strict";

import {
  ApiError,
  api,
  errorMessage,
  initializeCsrf,
  onUnauthorized,
  rememberCsrf,
} from "./api.js";
import * as access from "./access.js";
import * as blocklists from "./blocklists.js";
import * as dashboard from "./dashboard.js";
import * as events from "./events.js";
import * as network from "./network.js";
import * as policies from "./policies.js";
import {
  announce,
  byId,
  showError,
  withBusyButton,
} from "./ui.js";

const pages = new Map([
  ["dashboard", dashboard],
  ["network", network],
  ["policies", policies],
  ["blocklists", blocklists],
  ["events", events],
  ["access", access],
]);

const elements = {
  serviceState: byId("service-state"),
  serviceContainer: document.querySelector(".service-state"),
  accountState: byId("account-state"),
  currentUser: byId("current-user"),
  authView: byId("auth-view"),
  appView: byId("app-view"),
  loginForm: byId("login-form"),
  bootstrapForm: byId("bootstrap-form"),
  passwordForm: byId("password-form"),
  secondFactor: byId("second-factor"),
  loginError: byId("login-error"),
  bootstrapError: byId("bootstrap-error"),
  passwordError: byId("password-error"),
  logout: byId("logout"),
};

let currentUser = null;
let activePage = null;

/**
 * Return the requested page identifier or the dashboard fallback.
 */
function requestedPage() {
  const identifier = window.location.hash.replace(/^#/, "");

  return pages.has(identifier) ? identifier : "dashboard";
}

/**
 * Display and refresh exactly one application page.
 */
async function navigate() {
  const identifier = requestedPage();
  const page = pages.get(identifier);

  announce("");
  if (activePage !== null && activePage !== page &&
      typeof activePage.deactivate === "function") {
    activePage.deactivate();
  }
  activePage = page;
  for (const section of document.querySelectorAll("[data-page]")) {
    section.hidden = section.id !== `page-${identifier}`;
  }
  for (const link of document.querySelectorAll("[data-page-link]")) {
    const active = link.dataset.pageLink === identifier;

    link.classList.toggle("active", active);
    if (active) {
      link.setAttribute("aria-current", "page");
    } else {
      link.removeAttribute("aria-current");
    }
  }
  page.initialize();
  await page.load(currentUser);
  byId(`page-${identifier}`).focus();
}

/**
 * Switch the shell to an authenticated identity.
 */
function showApplication(user) {
  currentUser = user;
  elements.authView.hidden = true;
  elements.appView.hidden = false;
  elements.passwordForm.hidden = true;
  elements.accountState.hidden = false;
  elements.currentUser.textContent = `${user.username} · ${user.role}`;
}

/**
 * Restrict an authenticated identity to the required password form.
 */
function showPasswordChange(user) {
  currentUser = user;
  elements.appView.hidden = true;
  elements.authView.hidden = false;
  elements.loginForm.hidden = true;
  elements.bootstrapForm.hidden = true;
  elements.passwordForm.hidden = false;
  elements.accountState.hidden = false;
  elements.currentUser.textContent = user.username;
  byId("current-password").focus();
}

/**
 * Display the only view permitted by the authenticated account state.
 */
async function showIdentity(user) {
  if (user.force_password_change) {
    showPasswordChange(user);
    return;
  }
  showApplication(user);
  await navigate();
}

/**
 * Return the shell to its unauthenticated state.
 */
function showAuthentication() {
  if (activePage !== null && typeof activePage.deactivate === "function") {
    activePage.deactivate();
  }
  activePage = null;
  currentUser = null;
  elements.appView.hidden = true;
  elements.accountState.hidden = true;
  elements.authView.hidden = false;
  elements.loginForm.hidden = false;
  elements.bootstrapForm.hidden = true;
  elements.passwordForm.hidden = true;
  elements.secondFactor.hidden = true;
  elements.passwordForm.reset();
  showError(elements.passwordError, "");
  rememberCsrf("");
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

  await withBusyButton(submit, async () => {
    try {
      const session = await api("/api/v1/auth/login", {
        method: "POST",
        body,
      });
      rememberCsrf(session.csrf);
      elements.loginForm.reset();
      await showIdentity(session.user);
    } catch (error) {
      if (error instanceof ApiError && error.code === "mfa_required") {
        elements.secondFactor.hidden = false;
        byId("login-totp").focus();
      }
      showError(elements.loginError, errorMessage(error));
    }
  });
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
    showError(
      elements.bootstrapError,
      "The password confirmation does not match.",
    );
    byId("bootstrap-confirm").focus();
    return;
  }
  const submit = elements.bootstrapForm.querySelector("[type=submit]");

  await withBusyButton(submit, async () => {
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
      await showIdentity(session.user);
    } catch (error) {
      showError(elements.bootstrapError, errorMessage(error));
    }
  });
}

/**
 * Revoke the current session and clear all browser-local state.
 */
async function logout() {
  await withBusyButton(elements.logout, async () => {
    try {
      await api("/api/v1/auth/logout", { method: "POST", body: {} });
    } catch {
      // Local state is cleared even if the server session already expired.
    } finally {
      showAuthentication();
    }
  });
}

/**
 * Change the current password and accept the rotated authenticated session.
 */
async function submitPasswordChange(event) {
  event.preventDefault();
  showError(elements.passwordError, "");
  const data = new FormData(elements.passwordForm);
  const currentPassword = String(data.get("current"));
  const password = String(data.get("password"));
  const confirm = String(data.get("confirm"));

  if (password !== confirm) {
    showError(elements.passwordError,
      "The password confirmation does not match.");
    byId("confirm-password").focus();
    return;
  }
  if (password === currentPassword) {
    showError(elements.passwordError,
      "Choose a password different from the current password.");
    byId("new-password").focus();
    return;
  }
  const submit = elements.passwordForm.querySelector("[type=submit]");

  await withBusyButton(submit, async () => {
    try {
      const session = await api("/api/v1/auth/password", {
        method: "POST",
        body: {
          current_password: currentPassword,
          new_password: password,
        },
      });
      rememberCsrf(session.csrf);
      elements.passwordForm.reset();
      await showIdentity(session.user);
    } catch (error) {
      if (!(error instanceof ApiError &&
            error.code === "authentication_required")) {
        showError(elements.passwordError, errorMessage(error));
      }
    }
  });
}

/**
 * Verify HTTPS health and restore an existing browser session.
 */
async function initialize() {
  initializeCsrf();
  onUnauthorized(showAuthentication);
  try {
    const response = await fetch("/healthz", {
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

    await showIdentity(session.user);
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
  byId("bootstrap-token").focus();
}

/**
 * Return from first-boot setup to the login form.
 */
function showLoginForm() {
  elements.bootstrapForm.hidden = true;
  elements.loginForm.hidden = false;
  byId("login-username").focus();
}

elements.loginForm.addEventListener("submit", submitLogin);
elements.bootstrapForm.addEventListener("submit", submitBootstrap);
elements.passwordForm.addEventListener("submit", submitPasswordChange);
elements.logout.addEventListener("click", () => {
  void logout();
});
byId("show-bootstrap").addEventListener("click", showBootstrapForm);
byId("show-login").addEventListener("click", showLoginForm);
window.addEventListener("hashchange", () => {
  if (currentUser !== null) {
    void navigate();
  }
});
window.addEventListener("janusgate:session-ended", showAuthentication);
void initialize();
