/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

"use strict";

import { api, errorMessage } from "./api.js";
import {
  byId,
  formatNumber,
  formatTimestamp,
  showEmptyTable,
  showError,
  tableCell,
  withBusyButton,
} from "./ui.js";

let initialized = false;

/**
 * Render the current packet-path counters.
 */
function renderStatus(status) {
  byId("enforcement-status").textContent = status.ready ? "Ready" : "Not ready";
  byId("policy-generation").textContent = formatNumber(status.policy_generation);
  byId("packet-count").textContent = formatNumber(status.dataplane.packets);
  byId("allowed-count").textContent = formatNumber(status.dataplane.accepted);
  byId("blocked-count").textContent = formatNumber(status.dataplane.blocked);
  byId("malformed-count").textContent = formatNumber(status.dataplane.malformed);
  byId("queue-drop-count").textContent = formatNumber(
    status.queues.dropped + status.queues.overflows,
  );
  byId("tcp-reset-count").textContent =
    formatNumber(status.dataplane.tcp_resets);
  byId("sni-count").textContent =
    formatNumber(status.dataplane.sni_inspected);
}

/**
 * Render daemon and helper availability.
 */
function renderHealth(health) {
  const managementDegraded = health.management.degraded;
  const policy = health.management.policy;
  const policyPending = policy.available && !policy.synchronized;

  byId("daemon-health").textContent =
    health.daemon.available ? "Available" : "Unavailable";
  byId("network-health").textContent =
    health.network.available ? "Available" : "Unavailable";
  byId("overall-health").dataset.state =
    health.healthy ? "healthy" : "degraded";
  byId("overall-health").textContent = policyPending
    ? "Policy publication is pending. Use System > Reload configuration."
    : managementDegraded
      ? "Management mutations are suspended pending consistency recovery."
      : health.healthy
        ? "All enforcement services are healthy."
        : "One or more enforcement services are degraded.";
}

/**
 * Render the active failure mode and pending transaction state.
 */
function renderNetwork(network) {
  const pending = network.runtime !== null &&
    network.runtime.pending !== null;

  byId("failure-mode").textContent =
    network.configuration.failure_mode === "fail_open"
      ? "Fail open"
      : "Fail closed";
  byId("bridge-state").textContent =
    network.runtime_available ? "Runtime available" : "Runtime unavailable";
  byId("network-transaction").textContent =
    pending ? "Awaiting confirmation" : "No pending change";
}

/**
 * Render bounded blocklist source health.
 */
function renderSources(payload) {
  const body = byId("dashboard-sources");

  if (payload.sources.length === 0) {
    showEmptyTable(body, 4, "No blocklist sources are configured.");
    return;
  }
  body.replaceChildren(...payload.sources.slice(0, 5).map((source) => {
    const row = document.createElement("tr");

    row.append(
      tableCell(source.name),
      tableCell(source.health),
      tableCell(formatNumber(source.active_entries), "numeric"),
      tableCell(formatTimestamp(source.last_success_at)),
    );
    return row;
  }));
}

/**
 * Render recent operational events.
 */
function renderEvents(payload) {
  const body = byId("dashboard-events");

  if (payload.events.length === 0) {
    showEmptyTable(body, 4, "No operational events have been recorded.");
    return;
  }
  body.replaceChildren(...payload.events.map((event) => {
    const row = document.createElement("tr");

    row.append(
      tableCell(formatTimestamp(event.occurred_at)),
      tableCell(event.severity, `severity-${event.severity}`),
      tableCell(event.component),
      tableCell(event.message),
    );
    return row;
  }));
}

/**
 * Refresh every dashboard source without failing the entire page.
 */
export async function load() {
  const error = byId("dashboard-error");
  const refresh = byId("dashboard-refresh");

  showError(error, "");
  await withBusyButton(refresh, async () => {
    const [status, health, network, sources, events] =
      await Promise.allSettled([
        api("/api/v1/status"),
        api("/api/v1/health"),
        api("/api/v1/network"),
        api("/api/v1/sources?limit=5"),
        api("/api/v1/events?limit=5"),
      ]);

    if (status.status === "fulfilled") {
      renderStatus(status.value);
    }
    if (health.status === "fulfilled") {
      renderHealth(health.value);
    }
    if (network.status === "fulfilled") {
      renderNetwork(network.value);
    } else {
      byId("failure-mode").textContent = "Restricted";
      byId("bridge-state").textContent = "Restricted";
      byId("network-transaction").textContent = "Restricted";
    }
    if (sources.status === "fulfilled") {
      renderSources(sources.value);
    } else {
      showEmptyTable(byId("dashboard-sources"), 4, "Source state is restricted.");
    }
    if (events.status === "fulfilled") {
      renderEvents(events.value);
    } else {
      showEmptyTable(byId("dashboard-events"), 4, "Event access is restricted.");
    }
    const primaryFailure = [status, health].find(
      (result) => result.status === "rejected",
    );
    if (primaryFailure !== undefined) {
      showError(error, errorMessage(primaryFailure.reason));
    }
  });
}

/**
 * Bind the dashboard controls exactly once.
 */
export function initialize() {
  if (initialized) {
    return;
  }
  initialized = true;
  byId("dashboard-refresh").addEventListener("click", () => {
    void load();
  });
}
