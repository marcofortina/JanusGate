/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

"use strict";

import { api, apiText, errorMessage } from "./api.js";
import {
  announce,
  byId,
  confirmAction,
  downloadBase64,
  formatNumber,
  renderJson,
  showError,
  withBusyButton,
} from "./ui.js";

let initialized = false;

/**
 * Render appliance runtime state without inventing unavailable telemetry.
 */
function renderStatus(status, health) {
  const dataplane = status.dataplane || {};
  const queues = status.queues || {};

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
  byId("system-health").textContent = health.healthy
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
      const result = await api("/api/v1/diagnostics", {
        method: "POST",
        body: {},
      });
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
  const canOperate =
    user.role === "administrator" || user.role === "operator";
  const canManageSystem = user.role === "administrator";

  byId("system-operate-controls").hidden = !canOperate;
  byId("system-lifecycle-controls").hidden = !canManageSystem;
  await refreshSystem();
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
    void withBusyButton(byId("system-refresh"), refreshSystem);
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
