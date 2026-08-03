/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

"use strict";

import { api, errorMessage, waitForJob } from "./api.js";
import {
  announce,
  byId,
  confirmAction,
  downloadJson,
  formatNumber,
  formatTimestamp,
  renderJson,
  showEmptyTable,
  showError,
  tableCell,
  withBusyButton,
} from "./ui.js";

const sourceFields = [
  "name",
  "format",
  "mode",
  "enforcement",
  "url",
  "signature_url",
  "enabled",
  "update_interval_seconds",
  "max_download_bytes",
  "max_decompressed_bytes",
  "connect_timeout_ms",
  "transfer_timeout_ms",
  "redirect_limit",
  "retry_base_seconds",
  "retry_max_seconds",
  "sha256_pin",
  "ed25519_public_key",
];

let initialized = false;
let sources = [];
let nextCursor = null;
let editingSource = null;
let writable = true;

/**
 * Return a nullable trimmed string.
 */
function nullableText(value) {
  const text = String(value).trim();

  return text.length === 0 ? null : text;
}

/**
 * Return one exact blocklist source configuration.
 */
function sourceConfiguration(source, includeRevision = false) {
  const configuration = {};

  for (const field of sourceFields) {
    configuration[field] = source[field];
  }
  if (includeRevision) {
    configuration.revision = source.revision;
  }
  return configuration;
}

/**
 * Read one source configuration from the editor.
 */
function sourceFromForm() {
  const form = byId("source-form");
  const configuration = {
    name: String(form.elements.source_name.value),
    format: String(form.elements.source_format.value),
    mode: String(form.elements.source_mode.value),
    enforcement: String(form.elements.source_enforcement.value),
    url: nullableText(form.elements.source_url.value),
    signature_url: nullableText(form.elements.signature_url.value),
    enabled: form.elements.source_enabled.checked,
    update_interval_seconds:
      Number(form.elements.update_interval_seconds.value),
    max_download_bytes: Number(form.elements.max_download_bytes.value),
    max_decompressed_bytes:
      Number(form.elements.max_decompressed_bytes.value),
    connect_timeout_ms: Number(form.elements.connect_timeout_ms.value),
    transfer_timeout_ms: Number(form.elements.transfer_timeout_ms.value),
    redirect_limit: Number(form.elements.redirect_limit.value),
    retry_base_seconds: Number(form.elements.retry_base_seconds.value),
    retry_max_seconds: Number(form.elements.retry_max_seconds.value),
    sha256_pin: nullableText(form.elements.sha256_pin.value),
    ed25519_public_key:
      nullableText(form.elements.ed25519_public_key.value),
  };

  if (editingSource !== null) {
    configuration.revision = editingSource.revision;
  }
  return configuration;
}

/**
 * Reset the source editor to conservative defaults.
 */
function resetSourceForm() {
  const form = byId("source-form");

  editingSource = null;
  form.reset();
  form.elements.source_format.value = "domain";
  form.elements.source_mode.value = "strict";
  form.elements.source_enforcement.value = "enforce";
  form.elements.source_enabled.checked = true;
  form.elements.update_interval_seconds.value = "3600";
  form.elements.max_download_bytes.value = "10485760";
  form.elements.max_decompressed_bytes.value = "67108864";
  form.elements.connect_timeout_ms.value = "5000";
  form.elements.transfer_timeout_ms.value = "30000";
  form.elements.redirect_limit.value = "3";
  form.elements.retry_base_seconds.value = "60";
  form.elements.retry_max_seconds.value = "3600";
  byId("source-form-title").textContent = "Add blocklist source";
  byId("source-submit").textContent = "Add source";
  byId("source-cancel").hidden = true;
}

/**
 * Populate the source editor for a revision-bound replacement.
 */
function editSource(source) {
  const form = byId("source-form");

  editingSource = source;
  for (const field of sourceFields) {
    const control = form.elements[`source_${field}`] || form.elements[field];

    if (field === "enabled") {
      control.checked = source[field];
    } else {
      control.value = source[field] ?? "";
    }
  }
  byId("source-form-title").textContent = `Edit source ${source.id}`;
  byId("source-submit").textContent = "Save source";
  byId("source-cancel").hidden = false;
  form.scrollIntoView({ behavior: "smooth", block: "start" });
}

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
 * Render source state, scheduling, and update health.
 */
function renderSources() {
  const body = byId("source-list");
  const selector = byId("import-source");

  selector.replaceChildren(...sources
    .filter((source) => source.url === null)
    .map((source) => {
      const option = document.createElement("option");

      option.value = String(source.id);
      option.textContent = `${source.name} · revision ${source.revision}`;
      return option;
    }));
  byId("import-submit").disabled = !writable || selector.options.length === 0;
  if (sources.length === 0) {
    showEmptyTable(body, 8, "No blocklist sources are configured.");
    return;
  }
  body.replaceChildren(...sources.map((source) => {
    const row = document.createElement("tr");
    const actions = document.createElement("td");
    const health = document.createElement("span");

    health.className = `health-pill health-${source.health}`;
    health.textContent = source.health;
    actions.className = "table-actions blocklist-actions";
    actions.append(
      actionButton("Details", () => {
        renderJson(byId("blocklist-result"), source);
      }),
      actionButton("Export", () => {
        downloadJson(
          `janusgate-source-${source.id}.json`,
          sourceConfiguration(source),
        );
      }),
    );
    if (writable) {
      actions.append(
        actionButton("Edit", () => editSource(source)),
        actionButton(source.enabled ? "Disable" : "Enable", () => {
          void toggleSource(source);
        }),
      );
      if (source.url !== null) {
        actions.append(actionButton("Refresh", () => {
          void refreshSource(source);
        }));
      }
      actions.append(actionButton("Remove", () => {
        void removeSource(source);
      }, true));
    }
    const healthCell = document.createElement("td");

    healthCell.append(health);
    row.append(
      tableCell(source.id),
      tableCell(source.name),
      tableCell(source.url === null ? "Local" : "Remote"),
      healthCell,
      tableCell(formatNumber(source.active_entries), "numeric"),
      tableCell(formatNumber(source.rejected_entries), "numeric"),
      tableCell(formatTimestamp(source.last_success_at)),
      actions,
    );
    return row;
  }));
}

/**
 * Fetch one source page and update pagination.
 */
async function fetchSources(append = false) {
  const cursor = append && nextCursor !== null
    ? `&after_id=${nextCursor}`
    : "";
  const payload = await api(`/api/v1/sources?limit=100${cursor}`);

  sources = append ? [...sources, ...payload.sources] : payload.sources;
  nextCursor = payload.next_after_id;
  byId("source-load-more").hidden = nextCursor === null;
  renderSources();
}

/**
 * Create or replace one blocklist source.
 */
async function submitSource(event) {
  event.preventDefault();
  const updating = editingSource !== null;
  const configuration = sourceFromForm();

  if (configuration.ed25519_public_key !== null &&
      (configuration.url === null || configuration.signature_url === null)) {
    showError(
      byId("blocklists-error"),
      "A signed source requires both content and signature HTTPS URLs.",
    );
    return;
  }
  if (configuration.ed25519_public_key === null &&
      configuration.signature_url !== null) {
    showError(
      byId("blocklists-error"),
      "A signature URL requires an Ed25519 public key.",
    );
    return;
  }
  await withBusyButton(byId("source-submit"), async () => {
    try {
      const result = await api(
        updating ? `/api/v1/sources/${editingSource.id}` : "/api/v1/sources",
        {
          method: updating ? "PATCH" : "POST",
          body: configuration,
        },
      );
      announce(result.published
        ? "The blocklist source was saved and policy was published."
        : "The source was saved; policy publication is pending.",
      result.published ? "success" : "warning");
      resetSourceForm();
      await fetchSources();
    } catch (error) {
      showError(byId("blocklists-error"), errorMessage(error));
    }
  });
}

/**
 * Replace a source with only its enabled state changed.
 */
async function toggleSource(source) {
  try {
    const body = sourceConfiguration(source, true);

    body.enabled = !source.enabled;
    const result = await api(`/api/v1/sources/${source.id}`, {
      method: "PATCH",
      body,
    });
    announce(result.published
      ? `The source is now ${body.enabled ? "enabled" : "disabled"}.`
      : "The source state changed; policy publication is pending.",
    result.published ? "success" : "warning");
    await fetchSources();
  } catch (error) {
    showError(byId("blocklists-error"), errorMessage(error));
  }
}

/**
 * Run one immediate remote-source update.
 */
async function refreshSource(source) {
  try {
    const accepted = await api(`/api/v1/sources/${source.id}/refresh`, {
      method: "POST",
      body: { revision: source.revision },
    });
    const result = await waitForJob(accepted);
    renderJson(byId("blocklist-result"), result);
    announce(
      result.attempt.outcome === "updated"
        ? "The remote source activated a new list."
        : "The remote source is already current.",
    );
    await fetchSources();
  } catch (error) {
    showError(byId("blocklists-error"), errorMessage(error));
  }
}

/**
 * Delete one source and its active imported rules.
 */
async function removeSource(source) {
  if (!await confirmAction(
    "Remove blocklist source",
    `Remove ${source.name} and all policy entries attributed to it?`,
    "Remove source",
  )) {
    return;
  }
  try {
    const result = await api(`/api/v1/sources/${source.id}`, {
      method: "DELETE",
      body: { revision: source.revision },
    });
    announce(result.published
      ? "The source was removed and policy was published."
      : "The source was removed; policy publication is pending.",
    result.published ? "success" : "warning");
    await fetchSources();
  } catch (error) {
    showError(byId("blocklists-error"), errorMessage(error));
  }
}

/**
 * Import bounded local-list content into one local source.
 */
async function importBlocklist(event) {
  event.preventDefault();
  const selector = byId("import-source");
  const source = sources.find((candidate) =>
    candidate.id === Number(selector.value));
  const content = byId("import-content").value;

  if (source === undefined) {
    showError(byId("blocklists-error"), "Choose an existing local source.");
    return;
  }
  await withBusyButton(byId("import-submit"), async () => {
    try {
      const accepted = await api("/api/v1/blocklists", {
        method: "POST",
        body: {
          source_id: source.id,
          revision: source.revision,
          content,
        },
      });
      const result = await waitForJob(accepted);
      renderJson(byId("blocklist-result"), result);
      announce(result.published
        ? "The local blocklist was imported and published."
        : "The local blocklist was imported; publication is pending.",
      result.published ? "success" : "warning");
      byId("blocklist-import-form").reset();
      await fetchSources();
    } catch (error) {
      showError(byId("blocklists-error"), errorMessage(error));
    }
  });
}

/**
 * Copy a selected local text file into the bounded import editor.
 */
async function loadImportFile(event) {
  const [file] = event.currentTarget.files;

  if (file === undefined) {
    return;
  }
  if (file.size > 60000) {
    showError(
      byId("blocklists-error"),
      "Browser imports are limited to 60,000 bytes; use janusgatectl for larger lists.",
    );
    event.currentTarget.value = "";
    return;
  }
  byId("import-content").value = await file.text();
}

/**
 * Load every blocklist source visible to the current role.
 */
export async function load(user) {
  writable = user.role !== "auditor";
  byId("source-fieldset").disabled = !writable;
  byId("import-fieldset").disabled = !writable;
  byId("blocklists-read-only").hidden = writable;
  showError(byId("blocklists-error"), "");
  try {
    await fetchSources();
  } catch (error) {
    showError(byId("blocklists-error"), errorMessage(error));
  }
}

/**
 * Bind blocklist management controls exactly once.
 */
export function initialize() {
  if (initialized) {
    return;
  }
  initialized = true;
  byId("source-form").addEventListener("submit", submitSource);
  byId("source-cancel").addEventListener("click", resetSourceForm);
  byId("source-load-more").addEventListener("click", () => {
    void fetchSources(true);
  });
  byId("blocklist-import-form").addEventListener(
    "submit",
    importBlocklist,
  );
  byId("import-file").addEventListener("change", (event) => {
    void loadImportFile(event);
  });
  byId("source-export-all").addEventListener("click", () => {
    downloadJson(
      "janusgate-blocklist-sources.json",
      sources.map((source) => sourceConfiguration(source)),
    );
  });
  resetSourceForm();
}
