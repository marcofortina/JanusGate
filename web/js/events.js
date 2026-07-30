/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

"use strict";

import { api, errorMessage } from "./api.js";
import {
  announce,
  byId,
  downloadJson,
  formatTimestamp,
  renderJson,
  showEmptyTable,
  showError,
  tableCell,
  withBusyButton,
} from "./ui.js";

let initialized = false;
let operationalEvents = [];
let auditEvents = [];
let nextEventCursor = null;
let nextAuditOffset = null;
let refreshTimer = null;

/**
 * Create one compact details button for a structured record.
 */
function detailsButton(record) {
  const button = document.createElement("button");

  button.type = "button";
  button.className = "table-action";
  button.textContent = "Details";
  button.addEventListener("click", () => {
    renderJson(byId("event-details"), record);
  });
  return button;
}

/**
 * Render currently loaded operational events.
 */
function renderOperationalEvents() {
  const body = byId("operational-event-list");

  if (operationalEvents.length === 0) {
    showEmptyTable(body, 6, "No events match the current filters.");
    return;
  }
  body.replaceChildren(...operationalEvents.map((event) => {
    const row = document.createElement("tr");
    const severity = document.createElement("td");
    const actions = document.createElement("td");

    severity.className = `severity-${event.severity}`;
    severity.textContent = event.severity;
    actions.append(detailsButton(event));
    row.append(
      tableCell(event.id),
      tableCell(formatTimestamp(event.occurred_at)),
      severity,
      tableCell(event.component),
      tableCell(event.message),
      actions,
    );
    return row;
  }));
}

/**
 * Render currently loaded immutable audit records.
 */
function renderAuditEvents() {
  const body = byId("audit-event-list");

  if (auditEvents.length === 0) {
    showEmptyTable(body, 7, "No audit records are available to this role.");
    return;
  }
  body.replaceChildren(...auditEvents.map((event) => {
    const row = document.createElement("tr");
    const success = document.createElement("td");
    const actions = document.createElement("td");

    success.className = event.success ? "status-success" : "status-failure";
    success.textContent = event.success ? "Success" : "Failed";
    actions.append(detailsButton(event));
    row.append(
      tableCell(event.id),
      tableCell(formatTimestamp(event.occurred_at)),
      tableCell(`${event.actor_type}${event.actor_id === null
        ? ""
        : ` ${event.actor_id}`}`),
      tableCell(event.action),
      tableCell(`${event.object_type}${event.object_id === null
        ? ""
        : ` ${event.object_id}`}`),
      success,
      actions,
    );
    return row;
  }));
}

/**
 * Build the exact operational event query.
 */
function eventQuery(append) {
  const form = byId("event-filter-form");
  const parameters = new URLSearchParams({ limit: "50" });
  const severity = form.elements.event_severity.value;
  const component = form.elements.event_component.value.trim();

  if (append && nextEventCursor !== null) {
    parameters.set("after_id", String(nextEventCursor));
  }
  if (severity.length > 0) {
    parameters.set("severity", severity);
  }
  if (component.length > 0) {
    parameters.set("component", component);
  }
  return parameters.toString();
}

/**
 * Fetch one page of operational events.
 */
async function fetchOperationalEvents(append = false) {
  const payload = await api(`/api/v1/events?${eventQuery(append)}`);

  operationalEvents = append
    ? [...operationalEvents, ...payload.events]
    : payload.events;
  nextEventCursor = payload.next_after_id;
  byId("event-load-more").hidden = nextEventCursor === null;
  renderOperationalEvents();
}

/**
 * Fetch one page of immutable audit records.
 */
async function fetchAuditEvents(append = false) {
  const parameters = new URLSearchParams({ limit: "50" });

  if (append && nextAuditOffset !== null) {
    parameters.set("offset", String(nextAuditOffset));
  }
  const payload = await api(`/api/v1/audit?${parameters}`);

  auditEvents = append ? [...auditEvents, ...payload.events] : payload.events;
  nextAuditOffset = payload.next_offset;
  byId("audit-load-more").hidden = nextAuditOffset === null;
  renderAuditEvents();
}

/**
 * Refresh both event views while preserving role restrictions.
 */
export async function load() {
  showError(byId("events-error"), "");
  const [events, audit] = await Promise.allSettled([
    fetchOperationalEvents(),
    fetchAuditEvents(),
  ]);

  if (events.status === "rejected") {
    showError(byId("events-error"), errorMessage(events.reason));
  }
  if (audit.status === "rejected") {
    auditEvents = [];
    nextAuditOffset = null;
    byId("audit-load-more").hidden = true;
    showEmptyTable(
      byId("audit-event-list"),
      7,
      "Audit-chain access is not granted to this role.",
    );
  }
}

/**
 * Apply event filters and reset cursor pagination.
 */
async function filterEvents(event) {
  event.preventDefault();
  await withBusyButton(byId("event-filter-submit"), async () => {
    try {
      nextEventCursor = null;
      await fetchOperationalEvents();
    } catch (error) {
      showError(byId("events-error"), errorMessage(error));
    }
  });
}

/**
 * Verify every persistent audit-chain link.
 */
async function verifyAudit() {
  await withBusyButton(byId("audit-verify"), async () => {
    try {
      const result = await api("/api/v1/audit/verify");

      renderJson(byId("event-details"), result);
      announce(
        result.valid
          ? `Audit chain valid: ${result.records_inspected} records inspected.`
          : `Audit chain invalid at record ${result.first_invalid_id}.`,
        result.valid ? "success" : "error",
      );
    } catch (error) {
      showError(byId("events-error"), errorMessage(error));
    }
  });
}

/**
 * Maintain bounded polling while the event page is visible.
 */
function updateLiveRefresh() {
  if (refreshTimer !== null) {
    clearTimeout(refreshTimer);
    refreshTimer = null;
  }
  if (!byId("event-live-refresh").checked) {
    return;
  }
  refreshTimer = setTimeout(async () => {
    if (!byId("page-events").hidden) {
      try {
        await fetchOperationalEvents();
      } catch (error) {
        showError(byId("events-error"), errorMessage(error));
      }
    }
    updateLiveRefresh();
  }, 5000);
}

/**
 * Stop polling when another application page becomes active.
 */
export function deactivate() {
  if (refreshTimer !== null) {
    clearTimeout(refreshTimer);
    refreshTimer = null;
  }
}

/**
 * Bind event and audit controls exactly once.
 */
export function initialize() {
  if (initialized) {
    updateLiveRefresh();
    return;
  }
  initialized = true;
  byId("event-filter-form").addEventListener("submit", filterEvents);
  byId("event-load-more").addEventListener("click", () => {
    void fetchOperationalEvents(true);
  });
  byId("audit-load-more").addEventListener("click", () => {
    void fetchAuditEvents(true);
  });
  byId("audit-verify").addEventListener("click", () => {
    void verifyAudit();
  });
  byId("event-export").addEventListener("click", () => {
    downloadJson("janusgate-events.json", operationalEvents);
  });
  byId("audit-export").addEventListener("click", () => {
    downloadJson("janusgate-audit.json", auditEvents);
  });
  byId("event-live-refresh").addEventListener("change", updateLiveRefresh);
  updateLiveRefresh();
}
