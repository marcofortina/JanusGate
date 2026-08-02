/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

"use strict";

import { ApiError, api, errorMessage, waitForJob } from "./api.js";
import {
  announce,
  byId,
  confirmAction,
  displayValue,
  downloadText,
  formatTimestamp,
  showEmptyTable,
  showError,
  tableCell,
  withBusyButton,
} from "./ui.js";

let initialized = false;
let certificate = null;
let authorities = [];
let mappings = [];
let users = [];
let writable = false;

/**
 * Return the number of whole days until one Unix timestamp.
 */
function daysUntil(timestamp) {
  return Math.floor((timestamp * 1000 - Date.now()) / 86400000);
}

/**
 * Render the active TLS identity and its expiration state.
 */
function renderCertificate() {
  const warning = byId("certificate-warning");

  if (certificate === null) {
    byId("certificate-subject").textContent = "Not installed";
    byId("certificate-issuer").textContent = "—";
    byId("certificate-validity").textContent = "—";
    byId("certificate-fingerprint").textContent = "—";
    byId("certificate-key-state").textContent = "Unavailable";
    warning.textContent =
      "No server certificate is installed. HTTPS cannot be reloaded safely.";
    warning.dataset.state = "degraded";
    return;
  }
  const remaining = daysUntil(certificate.not_after);

  byId("certificate-subject").textContent = certificate.subject;
  byId("certificate-issuer").textContent = certificate.issuer;
  byId("certificate-validity").textContent =
    `${formatTimestamp(certificate.not_before)} — ` +
    `${formatTimestamp(certificate.not_after)}`;
  byId("certificate-fingerprint").textContent =
    certificate.fingerprint_sha256;
  byId("certificate-key-state").textContent =
    certificate.private_key_available ? "Available and matched" : "Unavailable";
  if (remaining < 0) {
    warning.textContent = "The active server certificate has expired.";
    warning.dataset.state = "degraded";
  } else if (remaining < 30) {
    warning.textContent =
      `The active server certificate expires in ${remaining} days.`;
    warning.dataset.state = "warning";
  } else {
    warning.textContent =
      `The active ${certificate.self_signed ? "self-signed" : "CA-issued"} ` +
      `certificate is valid for ${remaining} more days.`;
    warning.dataset.state = "healthy";
  }
}

/**
 * Create one compact destructive table action.
 */
function revokeButton(mapping) {
  const button = document.createElement("button");

  button.type = "button";
  button.className = "table-action danger-button";
  button.textContent = "Revoke";
  button.addEventListener("click", () => {
    void revokeMapping(mapping);
  });
  return button;
}

/**
 * Render the trusted authority bundle and remote-listener state.
 */
function renderAuthorities() {
  const body = byId("mtls-authority-list");
  const state = byId("mtls-state");

  if (authorities.length === 0) {
    showEmptyTable(body, 4, "No client-certificate authorities are trusted.");
    state.textContent =
      "Remote API disabled. Install a client CA bundle to enable TCP 9443.";
    state.dataset.state = "warning";
    byId("mtls-ca-remove").disabled = true;
    return;
  }
  body.replaceChildren(...authorities.map((authority) => {
    const row = document.createElement("tr");

    row.append(
      tableCell(authority.subject),
      tableCell(authority.issuer),
      tableCell(formatTimestamp(authority.not_after)),
      tableCell(authority.fingerprint_sha256, "monospace-value"),
    );
    return row;
  }));
  state.textContent =
    `${authorities.length} client ` +
    `${authorities.length === 1 ? "authority is" : "authorities are"} ` +
    "trusted by the dedicated remote API listener on TCP 9443.";
  state.dataset.state = "healthy";
  byId("mtls-ca-remove").disabled = false;
}

/**
 * Render persistent client-certificate mappings and their revocation state.
 */
function renderMappings() {
  const body = byId("mtls-mapping-list");

  if (mappings.length === 0) {
    showEmptyTable(body, 6, "No client certificates are mapped.");
    return;
  }
  body.replaceChildren(...mappings.map((mapping) => {
    const row = document.createElement("tr");
    const actions = document.createElement("td");
    const expired = mapping.not_after * 1000 < Date.now();
    const revoked = mapping.revoked_at !== null;
    const target = mapping.user_id === null
      ? `Role: ${mapping.role}`
      : `User: ${mapping.username} (#${mapping.user_id})`;

    actions.className = "table-actions";
    if (revoked) {
      actions.textContent = "Revoked";
    } else {
      actions.append(revokeButton(mapping));
    }
    row.append(
      tableCell(mapping.id),
      tableCell(
        `${mapping.subject} · ${mapping.fingerprint_sha256}`,
        "monospace-value",
      ),
      tableCell(target),
      tableCell(formatTimestamp(mapping.not_after)),
      tableCell(revoked ? "Revoked" : expired ? "Expired" : "Active"),
      actions,
    );
    return row;
  }));
}

/**
 * Populate the user mapping selector from the current local accounts.
 */
function renderMappingUsers() {
  const selector = byId("mtls-user");

  selector.replaceChildren(...users.map((user) => {
    const option = document.createElement("option");

    option.value = String(user.id);
    option.textContent = `${user.username} · ${user.role}`;
    return option;
  }));
  byId("mtls-mapping-submit").disabled = users.length === 0;
}

/**
 * Read one optional uploaded PEM file as bounded text.
 */
async function uploadedText(input) {
  const file = input.files[0];

  if (file === undefined) {
    return "";
  }
  if (file.size > 65536) {
    throw new Error("A certificate or private-key file exceeds 64 KiB.");
  }
  return file.text();
}

/**
 * Copy selected PEM files into their explicit review fields.
 */
async function importPemFiles() {
  try {
    const form = byId("certificate-install-form");
    const [certificateText, privateKeyText] = await Promise.all([
      uploadedText(byId("certificate-file")),
      uploadedText(byId("private-key-file")),
    ]);

    if (certificateText.length > 0) {
      form.elements.certificate.value = certificateText;
    }
    if (privateKeyText.length > 0) {
      form.elements.private_key.value = privateKeyText;
    }
  } catch (error) {
    showError(byId("certificates-error"), error.message);
  }
}

/**
 * Copy one selected public PEM file into its review field.
 */
async function importPublicPem(input, form, field) {
  try {
    const text = await uploadedText(input);

    if (text.length > 0) {
      form.elements[field].value = text;
    }
  } catch (error) {
    showError(byId("certificates-error"), error.message);
  }
}

/**
 * Create a CSR while retaining its private key on the appliance.
 */
async function createCsr(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const alternativeNames = String(form.elements.alternative_names.value)
    .split(/[\n,]+/)
    .map((name) => name.trim())
    .filter((name, index, names) =>
      name.length > 0 && names.indexOf(name) === index);

  showError(byId("certificates-error"), "");
  if (alternativeNames.length > 32) {
    showError(
      byId("certificates-error"),
      "A certificate request accepts at most 32 alternative names.",
    );
    return;
  }
  await withBusyButton(byId("csr-submit"), async () => {
    try {
      const accepted = await api("/api/v1/certificates/csr", {
        method: "POST",
        body: {
          common_name: String(form.elements.common_name.value).trim(),
          alternative_names: alternativeNames,
        },
      });
      const result = await waitForJob(accepted);

      byId("csr-result").textContent = result.request;
      byId("csr-result-panel").hidden = false;
      downloadText(
        "janusgate-request.csr",
        result.request,
        "application/pkcs10",
      );
      announce(
        "The CSR was created and its private key is stored on the appliance.",
      );
    } catch (error) {
      showError(byId("certificates-error"), errorMessage(error));
    }
  });
}

/**
 * Validate and atomically install one server certificate.
 */
async function installCertificate(event) {
  event.preventDefault();
  const form = event.currentTarget;

  showError(byId("certificates-error"), "");
  if (!await confirmAction(
    "Install server certificate",
    "Validate and replace the HTTPS identity? A service reload is required " +
      "before browsers receive the new certificate.",
    "Install certificate",
  )) {
    return;
  }
  await withBusyButton(byId("certificate-install-submit"), async () => {
    try {
      const privateKey = String(form.elements.private_key.value);
      const result = await api("/api/v1/certificates/install", {
        method: "POST",
        body: {
          certificate: String(form.elements.certificate.value),
          private_key: privateKey.length === 0 ? null : privateKey,
          expected_fingerprint:
            certificate === null ? null : certificate.fingerprint_sha256,
        },
      });

      form.reset();
      certificate = result.certificate;
      renderCertificate();
      announce(
        result.reload_required
          ? "The certificate was installed. HTTPS listeners are reloading " +
            "automatically."
          : "The certificate was installed.",
        result.reload_required ? "warning" : "success",
      );
    } catch (error) {
      showError(byId("certificates-error"), errorMessage(error));
    }
  });
}

/**
 * Validate and atomically install the remote client CA bundle.
 */
async function installAuthorities(event) {
  event.preventDefault();
  const form = event.currentTarget;

  showError(byId("certificates-error"), "");
  if (!await confirmAction(
    "Install client authorities",
    "Replace the complete remote API client trust store? The HTTPS listeners " +
      "will reload automatically.",
    "Install authorities",
  )) {
    return;
  }
  await withBusyButton(byId("mtls-ca-submit"), async () => {
    try {
      const result = await api("/api/v1/mtls/authorities", {
        method: "PUT",
        body: {
          certificate_authorities:
            String(form.elements.certificate_authorities.value),
        },
      });

      authorities = result.authorities;
      form.reset();
      renderAuthorities();
      announce(
        "The client CA bundle was installed. HTTPS listeners are reloading " +
        "to activate the remote API.",
        "warning",
      );
    } catch (error) {
      showError(byId("certificates-error"), errorMessage(error));
    }
  });
}

/**
 * Remove the client trust store and disable the remote listener on restart.
 */
async function removeAuthorities() {
  if (!await confirmAction(
    "Disable remote API",
    "Remove every trusted client authority? Existing mappings remain, but " +
      "TCP 9443 will be disabled when the HTTPS listeners reload.",
    "Remove authorities",
  )) {
    return;
  }
  await withBusyButton(byId("mtls-ca-remove"), async () => {
    try {
      const result = await api("/api/v1/mtls/authorities", {
        method: "DELETE",
        body: {},
      });

      authorities = result.authorities;
      renderAuthorities();
      announce(
        "Client trust was removed. HTTPS listeners are reloading to disable " +
        "the remote API.",
        "warning",
      );
    } catch (error) {
      showError(byId("certificates-error"), errorMessage(error));
    }
  });
  renderAuthorities();
}

/**
 * Create one user- or role-bound client-certificate mapping.
 */
async function createMapping(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const userTarget = form.elements.target_kind.value === "user";

  showError(byId("certificates-error"), "");
  await withBusyButton(byId("mtls-mapping-submit"), async () => {
    try {
      await api("/api/v1/mtls/mappings", {
        method: "POST",
        body: {
          certificate: String(form.elements.certificate.value),
          user_id: userTarget ? Number(form.elements.user_id.value) : null,
          role: userTarget ? null : String(form.elements.role.value),
        },
      });
      const result = await api("/api/v1/mtls/mappings?limit=100");

      mappings = result.mappings;
      form.reset();
      updateMappingTarget();
      renderMappings();
      announce("The client certificate mapping was created.");
    } catch (error) {
      showError(byId("certificates-error"), errorMessage(error));
    }
  });
}

/**
 * Revoke one client-certificate mapping immediately.
 */
async function revokeMapping(mapping) {
  if (!await confirmAction(
    "Revoke client certificate",
    `Revoke mapping ${mapping.id} for ${mapping.subject}?`,
    "Revoke mapping",
  )) {
    return;
  }
  try {
    const result = await api(`/api/v1/mtls/mappings/${mapping.id}`, {
      method: "DELETE",
      body: {},
    });

    mappings = mappings.map((current) =>
      current.id === result.mapping.id ? result.mapping : current);
    renderMappings();
    announce("The client certificate mapping was revoked.");
  } catch (error) {
    showError(byId("certificates-error"), errorMessage(error));
  }
}

/**
 * Show exactly one mapping target selector.
 */
function updateMappingTarget() {
  const userTarget = byId("mtls-target-kind").value === "user";

  byId("mtls-user-field").hidden = !userTarget;
  byId("mtls-role-field").hidden = userTarget;
  byId("mtls-mapping-submit").disabled = userTarget && users.length === 0;
}

/**
 * Load certificate metadata for a security administrator.
 */
export async function load(user) {
  writable = user.role === "administrator";
  byId("certificate-controls").hidden = !writable;
  byId("certificate-refresh").hidden = !writable;
  showError(byId("certificates-error"), "");
  if (!writable) {
    certificate = null;
    authorities = [];
    mappings = [];
    users = [];
    byId("certificate-subject").textContent = "Restricted";
    byId("certificate-issuer").textContent = "Restricted";
    byId("certificate-validity").textContent = "Restricted";
    byId("certificate-fingerprint").textContent = "Restricted";
    byId("certificate-key-state").textContent = "Restricted";
    byId("certificate-warning").textContent =
      "Certificate metadata is restricted to appliance administrators.";
    byId("certificate-warning").dataset.state = "warning";
    showError(
      byId("certificates-error"),
      `Certificate administration is not granted to the ${displayValue(
        user.role,
      )} role.`,
    );
    return;
  }
  try {
    let certificateResult = null;

    try {
      certificateResult = await api("/api/v1/certificates");
    } catch (error) {
      if (!(error instanceof ApiError && error.status === 404)) {
        throw error;
      }
    }
    const [authorityResult, mappingResult, userResult] = await Promise.all([
      api("/api/v1/mtls/authorities"),
      api("/api/v1/mtls/mappings?limit=100"),
      api("/api/v1/users?limit=100"),
    ]);

    certificate = certificateResult === null
      ? null
      : certificateResult.certificate;
    authorities = authorityResult.authorities;
    mappings = mappingResult.mappings;
    users = userResult.users;
    renderCertificate();
    renderAuthorities();
    renderMappings();
    renderMappingUsers();
    updateMappingTarget();
  } catch (error) {
    showError(byId("certificates-error"), errorMessage(error));
  }
}

/**
 * Bind certificate-management controls exactly once.
 */
export function initialize() {
  if (initialized) {
    return;
  }
  initialized = true;
  byId("certificate-refresh").addEventListener("click", () => {
    void load({ role: writable ? "administrator" : "restricted" });
  });
  byId("csr-form").addEventListener("submit", createCsr);
  byId("certificate-install-form")
    .addEventListener("submit", installCertificate);
  byId("certificate-file").addEventListener("change", () => {
    void importPemFiles();
  });
  byId("private-key-file").addEventListener("change", () => {
    void importPemFiles();
  });
  byId("mtls-ca-form").addEventListener("submit", installAuthorities);
  byId("mtls-ca-remove").addEventListener("click", () => {
    void removeAuthorities();
  });
  byId("mtls-ca-file").addEventListener("change", () => {
    void importPublicPem(
      byId("mtls-ca-file"),
      byId("mtls-ca-form"),
      "certificate_authorities",
    );
  });
  byId("mtls-mapping-form").addEventListener("submit", createMapping);
  byId("mtls-client-file").addEventListener("change", () => {
    void importPublicPem(
      byId("mtls-client-file"),
      byId("mtls-mapping-form"),
      "certificate",
    );
  });
  byId("mtls-target-kind").addEventListener("change", updateMappingTarget);
  byId("csr-download").addEventListener("click", () => {
    downloadText(
      "janusgate-request.csr",
      byId("csr-result").textContent,
      "application/pkcs10",
    );
  });
}
