/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

"use strict";

import { ApiError, api, errorMessage } from "./api.js";
import {
  announce,
  byId,
  confirmAction,
  displayValue,
  downloadText,
  formatTimestamp,
  showError,
  withBusyButton,
} from "./ui.js";

let initialized = false;
let certificate = null;
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
      const result = await api("/api/v1/certificates/csr", {
        method: "POST",
        body: {
          common_name: String(form.elements.common_name.value).trim(),
          alternative_names: alternativeNames,
        },
      });

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
          ? "The certificate was installed. Reload the JanusGate service " +
            "from the System page to activate it."
          : "The certificate was installed.",
        result.reload_required ? "warning" : "success",
      );
    } catch (error) {
      showError(byId("certificates-error"), errorMessage(error));
    }
  });
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
    const result = await api("/api/v1/certificates");

    certificate = result.certificate;
    renderCertificate();
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) {
      certificate = null;
      renderCertificate();
      return;
    }
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
  byId("csr-download").addEventListener("click", () => {
    downloadText(
      "janusgate-request.csr",
      byId("csr-result").textContent,
      "application/pkcs10",
    );
  });
}
