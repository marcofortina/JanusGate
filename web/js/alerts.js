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
  renderJson,
  showEmptyTable,
  showError,
  showSecret,
  tableCell,
  withBusyButton,
} from "./ui.js";

let initialized = false;
let configuration = null;
let incidents = [];
let nextCursor = null;
let writable = false;

/**
 * Create one compact incident-details control.
 */
function detailsButton(incident) {
  const button = document.createElement("button");

  button.type = "button";
  button.className = "table-action";
  button.textContent = "Details";
  button.addEventListener("click", () => {
    renderJson(byId("alert-details"), incident);
  });
  return button;
}

/**
 * Render the currently loaded persistent incidents.
 */
function renderIncidents() {
  const body = byId("alert-incident-list");

  byId("alerts-loaded-count").textContent = formatNumber(incidents.length);
  if (incidents.length === 0) {
    showEmptyTable(body, 7, "No incidents match the current filters.");
    return;
  }
  body.replaceChildren(...incidents.map((incident) => {
    const row = document.createElement("tr");
    const severity = document.createElement("td");
    const state = document.createElement("td");
    const details = document.createElement("td");

    severity.className = `severity-${incident.severity}`;
    severity.textContent = incident.severity;
    state.className = incident.state === "open"
      ? "status-failure"
      : "status-success";
    state.textContent = incident.state;
    details.append(detailsButton(incident));
    row.append(
      tableCell(formatTimestamp(incident.opened_at)),
      severity,
      tableCell(incident.type),
      tableCell(incident.resource),
      tableCell(incident.summary),
      state,
      details,
    );
    return row;
  }));
}

/**
 * Build exact stable filters for an incident page.
 */
function incidentQuery(append) {
  const form = byId("alert-filter-form");
  const parameters = new URLSearchParams({ limit: "50" });
  const state = form.elements.alert_state.value;
  const type = form.elements.alert_type.value;

  if (append && nextCursor !== null) {
    parameters.set("before_id", String(nextCursor));
  }
  if (state.length > 0) {
    parameters.set("state", state);
  }
  if (type.length > 0) {
    parameters.set("type", type);
  }
  return parameters.toString();
}

/**
 * Fetch one newest-first incident page.
 */
async function fetchIncidents(append = false) {
  const payload = await api(`/api/v1/alerts?${incidentQuery(append)}`);

  incidents = append ? [...incidents, ...payload.alerts] : payload.alerts;
  nextCursor = payload.has_more && payload.alerts.length > 0
    ? payload.alerts[payload.alerts.length - 1].id
    : null;
  byId("alert-load-more").hidden = nextCursor === null;
  renderIncidents();
}

/**
 * Populate every configuration field from one safe server response.
 */
function renderConfiguration(value) {
  const form = byId("alert-configuration-form");

  configuration = value;
  form.elements.alert_enabled.checked = value.enabled;
  form.elements.evaluation_interval_seconds.value =
    value.evaluation_interval_seconds;
  form.elements.certificate_warning_days.value =
    value.certificate_warning_days;
  form.elements.source_failure_threshold.value =
    value.source_failure_threshold;
  form.elements.source_stale_seconds.value = value.source_stale_seconds;
  form.elements.filesystem_minimum_percent.value =
    value.filesystem_minimum_percent;
  form.elements.filesystem_minimum_bytes.value =
    value.filesystem_minimum_bytes;
  form.elements.queue_window_seconds.value = value.queue_window_seconds;
  form.elements.queue_drop_threshold.value = value.queue_drop_threshold;
  form.elements.authentication_window_seconds.value =
    value.authentication_window_seconds;
  form.elements.authentication_failure_threshold.value =
    value.authentication_failure_threshold;
  form.elements.webhook_enabled.checked = value.webhook_enabled;
  form.elements.webhook_url.value = value.webhook_url || "";
  form.elements.webhook_ca_pem.value = value.webhook_ca_pem || "";
  form.elements.webhook_timeout_seconds.value =
    value.webhook_timeout_seconds;
  byId("alerts-evaluation-state").textContent = value.enabled
    ? "Enabled"
    : "Disabled";
  byId("alerts-evaluation-interval").textContent =
    `${formatNumber(value.evaluation_interval_seconds)} s`;
  byId("alerts-webhook-state").textContent = value.webhook_enabled
    ? "Enabled"
    : "Disabled";
  byId("alert-secret-state").textContent = value.webhook_secret_configured
    ? "An encrypted webhook secret is configured."
    : "No webhook secret is configured. Rotate it before enabling delivery.";
}

/**
 * Convert the editor into one complete revision-bound replacement.
 */
function configurationBody() {
  const form = byId("alert-configuration-form");
  const data = new FormData(form);
  const optional = (name) => {
    const value = String(data.get(name) || "").trim();

    return value.length === 0 ? null : value;
  };

  return {
    revision: configuration.revision,
    enabled: data.has("alert_enabled"),
    evaluation_interval_seconds:
      Number(data.get("evaluation_interval_seconds")),
    certificate_warning_days: Number(data.get("certificate_warning_days")),
    source_failure_threshold: Number(data.get("source_failure_threshold")),
    source_stale_seconds: Number(data.get("source_stale_seconds")),
    filesystem_minimum_percent:
      Number(data.get("filesystem_minimum_percent")),
    filesystem_minimum_bytes: Number(data.get("filesystem_minimum_bytes")),
    queue_window_seconds: Number(data.get("queue_window_seconds")),
    queue_drop_threshold: Number(data.get("queue_drop_threshold")),
    authentication_window_seconds:
      Number(data.get("authentication_window_seconds")),
    authentication_failure_threshold:
      Number(data.get("authentication_failure_threshold")),
    webhook_enabled: data.has("webhook_enabled"),
    webhook_url: optional("webhook_url"),
    webhook_ca_pem: optional("webhook_ca_pem"),
    webhook_timeout_seconds: Number(data.get("webhook_timeout_seconds")),
  };
}

/**
 * Persist and immediately reevaluate one complete configuration.
 */
async function saveConfiguration(event) {
  event.preventDefault();
  if (configuration === null || !writable) {
    return;
  }
  const body = configurationBody();

  if (body.webhook_enabled && !configuration.webhook_secret_configured) {
    showError(
      byId("alerts-error"),
      "Rotate and store the webhook HMAC secret before enabling delivery.",
    );
    return;
  }
  if (body.webhook_enabled && body.webhook_url === null) {
    showError(byId("alerts-error"), "An HTTPS webhook URL is required.");
    return;
  }
  showError(byId("alerts-error"), "");
  await withBusyButton(byId("alert-configuration-save"), async () => {
    try {
      renderConfiguration(await api("/api/v1/alerts/configuration", {
        method: "PUT",
        body,
      }));
      announce("Native alert configuration was updated.");
      await fetchIncidents();
    } catch (error) {
      showError(byId("alerts-error"), errorMessage(error));
    }
  });
}

/**
 * Rotate and display the webhook HMAC secret exactly once.
 */
async function rotateSecret() {
  if (configuration === null || !writable ||
      !await confirmAction(
        "Rotate webhook secret",
        "The current receiver secret will stop validating new notifications.",
        "Rotate secret",
      )) {
    return;
  }
  showError(byId("alerts-error"), "");
  await withBusyButton(byId("alert-webhook-secret"), async () => {
    try {
      const result = await api("/api/v1/alerts/webhook/secret", {
        method: "POST",
        body: { revision: configuration.revision },
      });
      const secret = result.webhook_secret;

      renderConfiguration(result);
      await showSecret(
        "Webhook HMAC secret",
        "Store this value in the receiver now. JanusGate will not display it again.",
        secret,
      );
      announce("The webhook HMAC secret was rotated.");
    } catch (error) {
      showError(byId("alerts-error"), errorMessage(error));
    }
  });
}

/**
 * Enqueue one signed test notification for the configured receiver.
 */
async function testWebhook() {
  if (!writable) {
    return;
  }
  showError(byId("alerts-error"), "");
  await withBusyButton(byId("alert-webhook-test"), async () => {
    try {
      const result = await api("/api/v1/alerts/webhook/test", {
        method: "POST",
        body: {},
      });

      announce(`Webhook test ${result.event_id} was queued.`);
    } catch (error) {
      showError(byId("alerts-error"), errorMessage(error));
    }
  });
}

/**
 * Load alert configuration and the selected incident page.
 */
export async function load(user) {
  writable = user.role === "administrator";
  byId("alert-configuration-fieldset").disabled = !writable;
  byId("alerts-read-only").hidden = writable;
  showError(byId("alerts-error"), "");
  try {
    const [settings] = await Promise.all([
      api("/api/v1/alerts/configuration"),
      fetchIncidents(),
    ]);

    renderConfiguration(settings);
  } catch (error) {
    showError(byId("alerts-error"), errorMessage(error));
  }
}

/**
 * Bind native alert controls exactly once.
 */
export function initialize() {
  if (initialized) {
    return;
  }
  initialized = true;
  byId("alerts-refresh").addEventListener("click", () => {
    void withBusyButton(byId("alerts-refresh"), async () => {
      try {
        const [settings] = await Promise.all([
          api("/api/v1/alerts/configuration"),
          fetchIncidents(),
        ]);

        renderConfiguration(settings);
      } catch (error) {
        showError(byId("alerts-error"), errorMessage(error));
      }
    });
  });
  byId("alert-filter-form").addEventListener("submit", (event) => {
    event.preventDefault();
    void withBusyButton(byId("alert-filter-submit"), async () => {
      try {
        await fetchIncidents();
      } catch (error) {
        showError(byId("alerts-error"), errorMessage(error));
      }
    });
  });
  byId("alert-load-more").addEventListener("click", () => {
    void fetchIncidents(true);
  });
  byId("alert-configuration-form").addEventListener(
    "submit",
    saveConfiguration,
  );
  byId("alert-webhook-secret").addEventListener("click", () => {
    void rotateSecret();
  });
  byId("alert-webhook-test").addEventListener("click", () => {
    void testWebhook();
  });
}
