/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

"use strict";

import { api, apiText, errorMessage, waitForJob } from "./api.js";
import {
  announce,
  byId,
  confirmAction,
  downloadBase64,
  formatNumber,
  renderJson,
  showEmptyTable,
  showError,
  tableCell,
  withBusyButton,
} from "./ui.js";

const loggingComponents = ["management", "dataplane", "runtime"];
let initialized = false;
let canOperate = false;
let loggingConfiguration = null;
let additionalLoggingOverrides = [];

/**
 * Report whether one level enables diagnostic verbosity.
 */
function diagnosticLevel(level) {
  return level === "debug" || level === "trace";
}

/**
 * Format one short diagnostic interval without false precision.
 */
function formatDuration(seconds) {
  return seconds < 120
    ? `${formatNumber(seconds)} s`
    : `${formatNumber(Math.ceil(seconds / 60))} min`;
}

/**
 * Keep diagnostic-duration requirements aligned with selected levels.
 */
function updateDiagnosticDuration() {
  const form = byId("logging-form");
  const selected = [
    form.elements.logging_global_level.value,
    ...loggingComponents.map(
      (component) => form.elements[`logging_${component}`].value,
    ),
    ...additionalLoggingOverrides.map((override) => override.level),
  ];
  const diagnostic = selected.some(diagnosticLevel);
  const duration = form.elements.logging_duration;
  const identifiers = form.elements.logging_identifiers;

  duration.disabled = !diagnostic;
  duration.required = diagnostic;
  identifiers.disabled = !diagnostic;
  if (!diagnostic) {
    identifiers.checked = false;
  }
}

/**
 * Render persistent logging configuration and bounded runtime counters.
 */
function renderLogging(configuration) {
  const form = byId("logging-form");
  const overrideMap = new Map(
    configuration.overrides.map(
      (override) => [override.component, override.level],
    ),
  );
  const remaining = configuration.diagnostic_remaining_seconds;
  const diagnostic = configuration.diagnostic_active === true;
  const state = byId("logging-diagnostic-state");

  loggingConfiguration = configuration;
  additionalLoggingOverrides = configuration.overrides.filter(
    (override) => !loggingComponents.includes(override.component),
  );
  byId("logging-level").textContent = configuration.global_level;
  byId("logging-buffered").textContent =
    formatNumber(configuration.buffered);
  byId("logging-suppressed").textContent =
    formatNumber(configuration.suppressed);
  state.textContent = diagnostic
    ? `Diagnostic · ${formatDuration(remaining)}`
    : "Production";
  state.classList.toggle("health-diagnostic", diagnostic);
  state.classList.toggle("health-healthy", !diagnostic);

  form.elements.logging_global_level.value = configuration.global_level;
  form.elements.logging_rate.value = configuration.rate_limit_per_second;
  form.elements.logging_capacity.value = configuration.trace_capacity;
  form.elements.logging_duration.value = diagnostic
    ? Math.max(60, Math.min(3600, remaining))
    : 900;
  form.elements.logging_identifiers.checked =
    configuration.include_identifiers;
  for (const checkbox of form.querySelectorAll(
    'input[name="logging_destination[]"]',
  )) {
    checkbox.checked = configuration.destinations.includes(checkbox.value);
  }
  for (const component of loggingComponents) {
    form.elements[`logging_${component}`].value =
      overrideMap.get(component) || "";
  }
  const additional = byId("logging-additional-overrides");

  additional.hidden = additionalLoggingOverrides.length === 0;
  additional.textContent = additional.hidden
    ? ""
    : `Additional CLI/API overrides are preserved: ${
      additionalLoggingOverrides.map(
        (override) => `${override.component}=${override.level}`,
      ).join(", ")
    }.`;
  updateDiagnosticDuration();
}

/**
 * Load active logging configuration without affecting other system data.
 */
async function refreshLogging() {
  try {
    renderLogging(await api("/api/v1/logging"));
  } catch (error) {
    showError(byId("system-error"), errorMessage(error));
  }
}

/**
 * Create one details button without copying trace data into markup.
 */
function traceDetailsButton(record) {
  const button = document.createElement("button");

  button.type = "button";
  button.className = "table-action";
  button.textContent = "Details";
  button.addEventListener("click", () => {
    renderJson(byId("logging-trace-details"), record);
  });
  return button;
}

/**
 * Render the bounded chronological trace snapshot.
 */
function renderTraces(payload) {
  const body = byId("logging-trace-list");

  byId("logging-buffered").textContent = formatNumber(payload.count);
  byId("logging-suppressed").textContent =
    formatNumber(payload.suppressed);
  if (payload.records.length === 0) {
    showEmptyTable(body, 7, "No diagnostic trace records are retained.");
    return;
  }
  body.replaceChildren(...payload.records.map((record) => {
    const row = document.createElement("tr");
    const severity = document.createElement("td");
    const actions = document.createElement("td");

    severity.className = `severity-${record.severity}`;
    severity.textContent = record.severity;
    actions.append(traceDetailsButton(record));
    row.append(
      tableCell(record.timestamp),
      severity,
      tableCell(record.component),
      tableCell(record.event),
      tableCell(record.correlation_id),
      tableCell(record.message),
      actions,
    );
    return row;
  }));
}

/**
 * Refresh the trace window when the current role may operate the appliance.
 */
async function refreshTraces() {
  if (!canOperate) {
    return;
  }
  try {
    renderTraces(await api("/api/v1/logging/traces"));
  } catch (error) {
    showError(byId("system-error"), errorMessage(error));
  }
}

/**
 * Refresh every independently authorized System-page observation.
 */
async function refreshPage() {
  await Promise.all([
    refreshSystem(),
    refreshLogging(),
    refreshTraces(),
  ]);
}

/**
 * Build and activate one exact revision-bound logging configuration.
 */
async function saveLogging(event) {
  event.preventDefault();
  showError(byId("system-error"), "");
  if (loggingConfiguration === null) {
    showError(
      byId("system-error"),
      "Refresh logging configuration before applying changes.",
    );
    return;
  }
  const form = byId("logging-form");
  const data = new FormData(form);
  const destinations = data.getAll("logging_destination[]");
  const overrides = [...additionalLoggingOverrides];

  if (destinations.length === 0) {
    showError(
      byId("system-error"),
      "Select at least one logging destination.",
    );
    return;
  }
  for (const component of loggingComponents) {
    const level = String(data.get(`logging_${component}`) || "");

    if (level.length > 0) {
      overrides.push({ component, level });
    }
  }
  const selectedLevels = [
    String(data.get("logging_global_level")),
    ...overrides.map((override) => override.level),
  ];
  const diagnostic = selectedLevels.some(diagnosticLevel);
  const includeIdentifiers = data.has("logging_identifiers");

  if (includeIdentifiers && !loggingConfiguration.include_identifiers &&
      !await confirmAction(
        "Include diagnostic identifiers",
        "Permit domain and client identifiers in live operational traces " +
          "until diagnostic logging expires?",
        "Include identifiers",
      )) {
    return;
  }
  await withBusyButton(byId("logging-save"), async () => {
    try {
      const result = await api("/api/v1/logging", {
        method: "PUT",
        body: {
          revision: loggingConfiguration.revision,
          global_level: String(data.get("logging_global_level")),
          destinations,
          rate_limit_per_second: Number(data.get("logging_rate")),
          trace_capacity: Number(data.get("logging_capacity")),
          diagnostic_duration_seconds: diagnostic
            ? Number(data.get("logging_duration"))
            : 0,
          include_identifiers: includeIdentifiers,
          overrides,
        },
      });

      renderLogging(result);
      renderJson(byId("system-operation-result"), result);
      announce(
        result.diagnostic_active
          ? "Time-bounded diagnostic logging is active."
          : "Production logging configuration is active.",
        result.diagnostic_active ? "warning" : "success",
      );
      await refreshTraces();
    } catch (error) {
      showError(byId("system-error"), errorMessage(error));
    }
  });
}

/**
 * Render appliance runtime state without inventing unavailable telemetry.
 */
function renderStatus(status, health) {
  const dataplane = status.dataplane || {};
  const queues = status.queues || {};
  const managementDegraded = health.management.degraded;
  const policy = health.management.policy;
  const policyPending = policy.available && !policy.synchronized;

  byId("system-readiness").textContent =
    status.ready && health.healthy ? "Ready" : "Degraded";
  byId("system-policy-generation").textContent =
    formatNumber(status.policy_generation);
  byId("system-packets").textContent =
    formatNumber(dataplane.packets);
  byId("system-blocked").textContent =
    formatNumber(dataplane.blocked);
  byId("system-queue-overflows").textContent =
    formatNumber(queues.overflows);
  byId("system-health").dataset.state =
    health.healthy ? "healthy" : "degraded";
  byId("system-health").textContent = policyPending
    ? "Policy publication is pending. Validate and reload configuration."
    : managementDegraded
      ? "Management mutations are suspended pending consistency recovery."
      : health.healthy
        ? "The policy daemon and transactional network service are healthy."
        : "One or more enforcement services report a degraded state.";
  renderJson(byId("system-status-details"), { status, health });
}

/**
 * Refresh status, health, and Prometheus metrics independently.
 */
async function refreshSystem() {
  showError(byId("system-error"), "");
  const [statusResult, healthResult, metricsResult] = await Promise.allSettled([
    api("/api/v1/status"),
    api("/api/v1/health"),
    apiText("/api/v1/metrics"),
  ]);

  if (statusResult.status === "fulfilled" &&
      healthResult.status === "fulfilled") {
    renderStatus(statusResult.value, healthResult.value);
  } else {
    const failure = statusResult.status === "rejected"
      ? statusResult.reason
      : healthResult.reason;

    showError(byId("system-error"), errorMessage(failure));
  }
  byId("system-metrics").textContent = metricsResult.status === "fulfilled"
    ? metricsResult.value
    : "Metrics are not granted to this identity.";
}

/**
 * Validate or atomically reload persistent daemon configuration.
 */
async function configure(reload, button) {
  showError(byId("system-error"), "");
  await withBusyButton(button, async () => {
    try {
      const result = await api(
        reload ? "/api/v1/config/reload" : "/api/v1/config/validate",
        { method: "POST", body: {} },
      );

      renderJson(byId("system-operation-result"), result);
      announce(
        reload
          ? "Persistent configuration was validated and reloaded."
          : "Persistent configuration passed validation.",
        result.restart_required ? "warning" : "success",
      );
      await refreshSystem();
    } catch (error) {
      showError(byId("system-error"), errorMessage(error));
    }
  });
}

/**
 * Create and download one bounded sanitized diagnostic archive.
 */
async function createDiagnostics() {
  showError(byId("system-error"), "");
  await withBusyButton(byId("diagnostics-create"), async () => {
    try {
      const accepted = await api("/api/v1/diagnostics", {
        method: "POST",
        body: {},
      });
      const result = await waitForJob(accepted);
      const metadata = {
        filename: result.filename,
        media_type: result.media_type,
        size_bytes: result.size_bytes,
        checksum_sha256: result.checksum_sha256,
      };

      downloadBase64(
        result.filename,
        result.data_base64,
        result.media_type,
      );
      renderJson(byId("system-operation-result"), metadata);
      announce(
        `Diagnostic archive created (${formatNumber(result.size_bytes)} bytes).`,
      );
    } catch (error) {
      showError(byId("system-error"), errorMessage(error));
    }
  });
}

/**
 * Request one explicitly confirmed deferred lifecycle action.
 */
async function lifecycle(path, title, message, label, button) {
  if (!await confirmAction(title, message, label)) {
    return;
  }
  showError(byId("system-error"), "");
  await withBusyButton(button, async () => {
    try {
      const result = await api(path, {
        method: "POST",
        body: { confirm: true },
      });

      renderJson(byId("system-operation-result"), result);
      announce(
        `${result.action} was accepted. The management connection may close.`,
        "warning",
      );
    } catch (error) {
      showError(byId("system-error"), errorMessage(error));
    }
  });
}

/**
 * Load the system page and apply role-specific operation boundaries.
 */
export async function load(user) {
  canOperate =
    user.role === "administrator" || user.role === "operator";
  const canManageSystem = user.role === "administrator";

  byId("system-operate-controls").hidden = !canOperate;
  byId("system-lifecycle-controls").hidden = !canManageSystem;
  byId("logging-form").hidden = !canManageSystem;
  byId("logging-read-only").hidden = canManageSystem;
  byId("logging-trace-panel").hidden = !canOperate;
  await refreshPage();
}

/**
 * Bind system-management controls exactly once.
 */
export function initialize() {
  if (initialized) {
    return;
  }
  initialized = true;
  byId("system-refresh").addEventListener("click", () => {
    void withBusyButton(byId("system-refresh"), refreshPage);
  });
  byId("config-validate").addEventListener("click", () => {
    void configure(false, byId("config-validate"));
  });
  byId("config-reload").addEventListener("click", () => {
    void configure(true, byId("config-reload"));
  });
  byId("diagnostics-create").addEventListener("click", () => {
    void createDiagnostics();
  });
  byId("logging-form").addEventListener("submit", (event) => {
    void saveLogging(event);
  });
  for (const name of [
    "logging_global_level",
    ...loggingComponents.map((component) => `logging_${component}`),
  ]) {
    byId("logging-form").elements[name].addEventListener(
      "change",
      updateDiagnosticDuration,
    );
  }
  byId("logging-trace-refresh").addEventListener("click", () => {
    void withBusyButton(byId("logging-trace-refresh"), refreshTraces);
  });
  byId("service-restart").addEventListener("click", () => {
    void lifecycle(
      "/api/v1/service/restart",
      "Restart JanusGate service",
      "Restart policy enforcement and the management service?",
      "Restart service",
      byId("service-restart"),
    );
  });
  byId("system-reboot").addEventListener("click", () => {
    void lifecycle(
      "/api/v1/system/reboot",
      "Reboot appliance",
      "Reboot the complete JanusGate appliance now?",
      "Reboot appliance",
      byId("system-reboot"),
    );
  });
  byId("system-shutdown").addEventListener("click", () => {
    void lifecycle(
      "/api/v1/system/shutdown",
      "Shut down appliance",
      "Power off the complete JanusGate appliance now?",
      "Shut down",
      byId("system-shutdown"),
    );
  });
}
