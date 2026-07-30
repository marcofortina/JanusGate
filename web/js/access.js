/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

"use strict";

import { api, errorMessage } from "./api.js";
import {
  announce,
  byId,
  confirmAction,
  formatNumber,
  formatTimestamp,
  showEmptyTable,
  showError,
  showSecret,
  tableCell,
  withBusyButton,
} from "./ui.js";

let initialized = false;
let users = [];
let tokens = [];
let editingUser = null;
let passwordUser = null;

/**
 * Create one compact row-action button.
 */
function actionButton(label, action, danger = false) {
  const button = document.createElement("button");

  button.type = "button";
  button.className = danger ? "table-action danger-button" : "table-action";
  button.textContent = label;
  button.addEventListener("click", action);
  return button;
}

/**
 * Reset the user editor to account-creation mode.
 */
function resetUserForm() {
  const form = byId("user-form");

  editingUser = null;
  form.reset();
  form.elements.user_username.disabled = false;
  form.elements.user_password.disabled = false;
  form.elements.user_password.required = true;
  form.elements.user_enabled.checked = true;
  form.elements.user_enabled.disabled = true;
  form.elements.user_force_password_change.checked = true;
  byId("user-form-title").textContent = "Add local user";
  byId("user-submit").textContent = "Add user";
  byId("user-cancel").hidden = true;
}

/**
 * Populate the user editor for a revision-checked update.
 */
function editUser(user) {
  const form = byId("user-form");

  editingUser = user;
  form.elements.user_username.value = user.username;
  form.elements.user_username.disabled = true;
  form.elements.user_password.value = "";
  form.elements.user_password.disabled = true;
  form.elements.user_password.required = false;
  form.elements.user_role.value = user.role;
  form.elements.user_enabled.checked = user.enabled;
  form.elements.user_enabled.disabled = false;
  form.elements.user_force_password_change.checked =
    user.force_password_change;
  byId("user-form-title").textContent = `Edit user ${user.id}`;
  byId("user-submit").textContent = "Save user";
  byId("user-cancel").hidden = false;
  form.scrollIntoView({ behavior: "smooth", block: "start" });
}

/**
 * Render the local account inventory and failed-login state.
 */
function renderUsers() {
  const body = byId("user-list");
  const owner = byId("token-user-id");

  owner.replaceChildren(...users.map((user) => {
    const option = document.createElement("option");

    option.value = String(user.id);
    option.textContent = `${user.username} · ${user.role}`;
    return option;
  }));
  if (users.length === 0) {
    showEmptyTable(body, 8, "User administration is restricted to administrators.");
    return;
  }
  body.replaceChildren(...users.map((user) => {
    const row = document.createElement("tr");
    const actions = document.createElement("td");

    actions.className = "table-actions";
    actions.append(
      actionButton("Edit", () => editUser(user)),
      actionButton("Reset password", () => showPasswordReset(user)),
    );
    if (user.totp_enabled) {
      actions.append(actionButton("Reset TOTP", () => {
        void resetUserTotp(user);
      }, true));
    }
    row.append(
      tableCell(user.id),
      tableCell(user.username),
      tableCell(user.role),
      tableCell(user.enabled ? "Enabled" : "Disabled"),
      tableCell(user.totp_enabled ? "Enabled" : "Disabled"),
      tableCell(formatNumber(user.failed_logins), "numeric"),
      tableCell(formatTimestamp(user.last_login_at)),
      actions,
    );
    return row;
  }));
}

/**
 * Render API-token metadata without exposing secrets.
 */
function renderTokens() {
  const body = byId("token-list");

  if (tokens.length === 0) {
    showEmptyTable(body, 8, "No API tokens are visible to this role.");
    return;
  }
  body.replaceChildren(...tokens.map((token) => {
    const row = document.createElement("tr");
    const actions = document.createElement("td");

    actions.className = "table-actions";
    if (!token.revoked) {
      actions.append(actionButton("Revoke", () => {
        void revokeToken(token);
      }, true));
    } else {
      actions.textContent = "Revoked";
    }
    row.append(
      tableCell(token.id),
      tableCell(token.name),
      tableCell(token.username),
      tableCell(token.scopes),
      tableCell(token.source_network),
      tableCell(formatTimestamp(token.expires_at)),
      tableCell(formatTimestamp(token.last_used_at)),
      actions,
    );
    return row;
  }));
}

/**
 * Fetch administrator-owned account and token pages.
 */
async function fetchAccessState() {
  const [userResult, tokenResult] = await Promise.all([
    api("/api/v1/users?limit=100"),
    api("/api/v1/tokens?limit=100"),
  ]);

  users = userResult.users;
  tokens = tokenResult.tokens;
  renderUsers();
  renderTokens();
}

/**
 * Create or update one local user.
 */
async function submitUser(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const updating = editingUser !== null;
  const body = updating
    ? {
      revision: editingUser.revision,
      role: String(form.elements.user_role.value),
      enabled: form.elements.user_enabled.checked,
      force_password_change:
        form.elements.user_force_password_change.checked,
    }
    : {
      username: String(form.elements.user_username.value),
      password: String(form.elements.user_password.value),
      role: String(form.elements.user_role.value),
      force_password_change:
        form.elements.user_force_password_change.checked,
    };

  await withBusyButton(byId("user-submit"), async () => {
    try {
      await api(updating ? `/api/v1/users/${editingUser.id}` : "/api/v1/users", {
        method: updating ? "PATCH" : "POST",
        body,
      });
      announce(updating ? "The user was updated." : "The user was created.");
      resetUserForm();
      await fetchAccessState();
    } catch (error) {
      showError(byId("access-error"), errorMessage(error));
    }
  });
}

/**
 * Display the password-reset editor for one selected user.
 */
function showPasswordReset(user) {
  passwordUser = user;
  byId("user-password-title").textContent =
    `Reset password for ${user.username}`;
  byId("user-password-form").hidden = false;
  byId("user-new-password").focus();
}

/**
 * Reset one user's password at its current revision.
 */
async function submitPasswordReset(event) {
  event.preventDefault();
  if (passwordUser === null) {
    return;
  }
  const form = event.currentTarget;

  await withBusyButton(byId("user-password-submit"), async () => {
    try {
      await api(`/api/v1/users/${passwordUser.id}/password`, {
        method: "POST",
        body: {
          revision: passwordUser.revision,
          password: String(form.elements.user_new_password.value),
          force_password_change:
            form.elements.password_force_change.checked,
        },
      });
      announce("The user password was reset.");
      form.reset();
      form.hidden = true;
      passwordUser = null;
      await fetchAccessState();
    } catch (error) {
      showError(byId("access-error"), errorMessage(error));
    }
  });
}

/**
 * Disable another user's TOTP credential.
 */
async function resetUserTotp(user) {
  if (!await confirmAction(
    "Reset TOTP",
    `Disable multifactor authentication for ${user.username}?`,
    "Reset TOTP",
  )) {
    return;
  }
  try {
    await api(`/api/v1/users/${user.id}/totp`, {
      method: "DELETE",
      body: { revision: user.revision },
    });
    announce("The user's TOTP credential was removed.");
    await fetchAccessState();
  } catch (error) {
    showError(byId("access-error"), errorMessage(error));
  }
}

/**
 * Begin TOTP enrollment for the current browser identity.
 */
async function provisionTotp() {
  await withBusyButton(byId("totp-provision"), async () => {
    try {
      const result = await api("/api/v1/auth/totp/provision", {
        method: "POST",
        body: {},
      });

      byId("totp-confirm-form").hidden = false;
      await showSecret(
        "TOTP enrollment secret",
        "Store this Base32 secret in the authenticator before entering its first code.",
        result.secret,
      );
      byId("totp-code").focus();
    } catch (error) {
      showError(byId("access-error"), errorMessage(error));
    }
  });
}

/**
 * Confirm TOTP and present one-time recovery codes.
 */
async function confirmTotp(event) {
  event.preventDefault();
  const code = Number(byId("totp-code").value);

  await withBusyButton(byId("totp-confirm"), async () => {
    try {
      const result = await api("/api/v1/auth/totp/confirm", {
        method: "POST",
        body: { code },
      });

      await showSecret(
        "TOTP recovery codes",
        "These codes are shown once. Store them offline before continuing.",
        result.recovery_codes.join("\n"),
      );
      window.dispatchEvent(new Event("janusgate:session-ended"));
    } catch (error) {
      showError(byId("access-error"), errorMessage(error));
    }
  });
}

/**
 * Verify a current TOTP code and disable multifactor authentication.
 */
async function disableTotp(event) {
  event.preventDefault();
  if (!await confirmAction(
    "Disable TOTP",
    "Disabling multifactor authentication revokes this browser session.",
    "Disable TOTP",
  )) {
    return;
  }
  try {
    await api("/api/v1/auth/totp/disable", {
      method: "POST",
      body: { code: Number(byId("totp-disable-code").value) },
    });
    window.dispatchEvent(new Event("janusgate:session-ended"));
  } catch (error) {
    showError(byId("access-error"), errorMessage(error));
  }
}

/**
 * Create one scoped API token and present its secret exactly once.
 */
async function createToken(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const scopes = [...form.querySelectorAll(
    'input[name="token_scope[]"]:checked',
  )].map((control) => control.value);
  const expiry = form.elements.token_expiry.value;

  if (scopes.length === 0) {
    showError(byId("access-error"), "Select at least one API-token scope.");
    return;
  }
  const expiresAt = expiry.length === 0
    ? null
    : Math.floor(new Date(expiry).getTime() / 1000);
  const sourceNetwork = String(form.elements.token_source_network.value).trim();

  await withBusyButton(byId("token-submit"), async () => {
    try {
      const result = await api("/api/v1/tokens", {
        method: "POST",
        body: {
          user_id: Number(form.elements.token_user_id.value),
          name: String(form.elements.token_name.value),
          scopes: scopes.join(","),
          expires_at: expiresAt,
          source_network: sourceNetwork.length === 0 ? null : sourceNetwork,
          requests_per_minute:
            Number(form.elements.requests_per_minute.value),
        },
      });

      form.reset();
      form.elements.requests_per_minute.value = "120";
      await showSecret(
        "API token secret",
        "This bearer token is shown once. Store it in a private caller-owned file.",
        result.token.secret,
      );
      await fetchAccessState();
    } catch (error) {
      showError(byId("access-error"), errorMessage(error));
    }
  });
}

/**
 * Revoke one API token.
 */
async function revokeToken(token) {
  if (!await confirmAction(
    "Revoke API token",
    `Permanently revoke ${token.name}?`,
    "Revoke token",
  )) {
    return;
  }
  try {
    await api(`/api/v1/tokens/${token.id}`, {
      method: "DELETE",
      body: {},
    });
    announce("The API token was revoked.");
    await fetchAccessState();
  } catch (error) {
    showError(byId("access-error"), errorMessage(error));
  }
}

/**
 * Load current-account security and administrator-owned inventories.
 */
export async function load(user) {
  const administrator = user.role === "administrator";

  byId("current-access-user").textContent = user.username;
  byId("current-access-role").textContent = user.role;
  byId("current-access-totp").textContent =
    user.totp_enabled ? "Enabled" : "Disabled";
  byId("totp-disabled-actions").hidden = user.totp_enabled;
  byId("totp-enabled-actions").hidden = !user.totp_enabled;
  byId("access-administrator").hidden = !administrator;
  byId("access-restricted").hidden = administrator;
  showError(byId("access-error"), "");
  if (!administrator) {
    users = [];
    tokens = [];
    renderUsers();
    renderTokens();
    return;
  }
  try {
    await fetchAccessState();
  } catch (error) {
    showError(byId("access-error"), errorMessage(error));
  }
}

/**
 * Bind identity and token management controls exactly once.
 */
export function initialize() {
  if (initialized) {
    return;
  }
  initialized = true;
  byId("user-form").addEventListener("submit", submitUser);
  byId("user-cancel").addEventListener("click", resetUserForm);
  byId("user-password-form").addEventListener(
    "submit",
    submitPasswordReset,
  );
  byId("user-password-cancel").addEventListener("click", () => {
    byId("user-password-form").reset();
    byId("user-password-form").hidden = true;
    passwordUser = null;
  });
  byId("totp-provision").addEventListener("click", () => {
    void provisionTotp();
  });
  byId("totp-confirm-form").addEventListener("submit", confirmTotp);
  byId("totp-enabled-actions").addEventListener("submit", disableTotp);
  byId("token-form").addEventListener("submit", createToken);
  resetUserForm();
}
