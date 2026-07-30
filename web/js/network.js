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
  formatTimestamp,
  renderJson,
  showError,
  withBusyButton,
} from "./ui.js";

let initialized = false;
let revision = 0;

/**
 * Return one exact network configuration from the editor.
 */
function configurationFromForm() {
  const data = new FormData(byId("network-form"));

  return {
    bridge: String(data.get("bridge")),
    ingress: String(data.get("ingress")),
    egress: String(data.get("egress")),
    management: String(data.get("management")),
    bridge_mtu: Number(data.get("bridge_mtu")),
    queue_first: Number(data.get("queue_first")),
    queue_count: Number(data.get("queue_count")),
    queue_length: Number(data.get("queue_length")),
    failure_mode: String(data.get("failure_mode")),
    stp: data.get("stp") === "on",
    multicast_snooping: data.get("multicast_snooping") === "on",
    queue_cpu_fanout: data.get("queue_cpu_fanout") === "on",
  };
}

/**
 * Populate the network editor from one validated configuration.
 */
function populateForm(configuration) {
  const form = byId("network-form");

  for (const name of [
    "bridge",
    "ingress",
    "egress",
    "management",
    "bridge_mtu",
    "queue_first",
    "queue_count",
    "queue_length",
    "failure_mode",
  ]) {
    form.elements[name].value = configuration[name];
  }
  for (const name of [
    "stp",
    "multicast_snooping",
    "queue_cpu_fanout",
  ]) {
    form.elements[name].checked = configuration[name];
  }
}

/**
 * Render persistent and pending network state.
 */
function renderNetwork(payload) {
  const runtime = payload.runtime || {
    confirmation_seconds_remaining: 0,
    confirmed: null,
    pending: null,
  };

  revision = payload.revision;
  populateForm(payload.configuration);
  byId("network-revision").textContent = String(payload.revision);
  byId("network-updated").textContent = formatTimestamp(payload.updated_at);
  byId("network-runtime-state").textContent =
    payload.runtime_available ? "Available" : "Unavailable";
  const pending = runtime.pending !== null;

  byId("network-pending").hidden = !pending;
  byId("network-confirm").disabled = !pending;
  byId("network-rollback").disabled = !pending;
  byId("network-pending-seconds").textContent =
    String(runtime.confirmation_seconds_remaining);
  renderJson(byId("network-runtime"), runtime);
}

/**
 * Load the active network document and its transaction state.
 */
export async function load() {
  const error = byId("network-error");

  showError(error, "");
  try {
    renderNetwork(await api("/api/v1/network"));
  } catch (requestError) {
    showError(error, errorMessage(requestError));
  }
}

/**
 * Validate the editor without changing packet-path state.
 */
async function validateNetwork() {
  const button = byId("network-validate");

  if (!byId("network-form").reportValidity()) {
    return;
  }
  showError(byId("network-error"), "");
  await withBusyButton(button, async () => {
    try {
      const result = await api("/api/v1/network/validate", {
        method: "POST",
        body: configurationFromForm(),
      });
      renderJson(byId("network-result"), result);
      announce("The network configuration is valid.");
    } catch (error) {
      showError(byId("network-error"), errorMessage(error));
    }
  });
}

/**
 * Stage one revision-checked network transaction.
 */
async function applyNetwork(event) {
  event.preventDefault();
  if (!await confirmAction(
    "Apply network configuration",
    "The appliance will automatically roll back unless this browser confirms the pending change before the deadline.",
    "Apply change",
  )) {
    return;
  }
  const button = byId("network-apply");

  showError(byId("network-error"), "");
  await withBusyButton(button, async () => {
    try {
      const result = await api("/api/v1/network/apply", {
        method: "POST",
        body: {
          revision,
          configuration: configurationFromForm(),
        },
      });
      renderJson(byId("network-result"), result);
      announce("The network change is pending confirmation.", "warning");
      await load();
    } catch (error) {
      showError(byId("network-error"), errorMessage(error));
    }
  });
}

/**
 * Complete a pending network transaction.
 */
async function finishTransaction(action) {
  const verb = action === "confirm" ? "Confirm" : "Roll back";

  if (!await confirmAction(
    `${verb} network configuration`,
    action === "confirm"
      ? "Confirm that management connectivity and data forwarding are working."
      : "Restore the last confirmed network configuration now.",
    verb,
  )) {
    return;
  }
  const button = byId(`network-${action}`);

  await withBusyButton(button, async () => {
    try {
      const result = await api(`/api/v1/network/${action}`, {
        method: "POST",
        body: { revision },
      });
      renderJson(byId("network-result"), result);
      announce(
        action === "confirm"
          ? "The network configuration is confirmed."
          : "The network configuration was rolled back.",
      );
      await load();
    } catch (error) {
      showError(byId("network-error"), errorMessage(error));
    }
  });
}

/**
 * Bind network management controls exactly once.
 */
export function initialize() {
  if (initialized) {
    return;
  }
  initialized = true;
  byId("network-form").addEventListener("submit", applyNetwork);
  byId("network-validate").addEventListener("click", () => {
    void validateNetwork();
  });
  byId("network-confirm").addEventListener("click", () => {
    void finishTransaction("confirm");
  });
  byId("network-rollback").addEventListener("click", () => {
    void finishTransaction("rollback");
  });
  byId("network-refresh").addEventListener("click", () => {
    void load();
  });
}
