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
  formatNumber,
  formatTimestamp,
  renderJson,
  showEmptyTable,
  showError,
  tableCell,
  withBusyButton,
} from "./ui.js";

const backupPassphraseMinimum = 16;

let initialized = false;
let backups = [];
let nextCursor = null;
let selectedBackup = null;
let validatedRestore = null;

/**
 * Create one compact backup action button.
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
 * Render the currently loaded backup page.
 */
function renderBackups() {
  const body = byId("backup-list");

  if (backups.length === 0) {
    showEmptyTable(body, 7, "No appliance backups have been created.");
    return;
  }
  body.replaceChildren(...backups.map((backup) => {
    const row = document.createElement("tr");
    const actions = document.createElement("td");

    actions.className = "table-actions";
    actions.append(
      actionButton("Inspect", () => {
        void inspectBackup(backup);
      }),
      actionButton("Restore", () => {
        selectRestore(backup);
      }, true),
    );
    row.append(
      tableCell(backup.id),
      tableCell(formatTimestamp(backup.created_at)),
      tableCell(backup.kind),
      tableCell(backup.encrypted ? "Yes" : "No"),
      tableCell(formatNumber(backup.size_bytes), "numeric"),
      tableCell(backup.schema_version),
      actions,
    );
    return row;
  }));
}

/**
 * Fetch one cursor page of stored backup metadata.
 */
async function fetchBackups(append = false) {
  const cursor = append && nextCursor !== null
    ? `&after_id=${nextCursor}`
    : "";
  const payload = await api(`/api/v1/backups?limit=50${cursor}`);

  backups = append ? [...backups, ...payload.backups] : payload.backups;
  nextCursor = payload.next_after_id;
  byId("backup-load-more").hidden = nextCursor === null;
  renderBackups();
}

/**
 * Show and verify one backup manifest.
 */
async function inspectBackup(backup) {
  showError(byId("backups-error"), "");
  try {
    const result = await api(`/api/v1/backups/${backup.id}`);

    renderJson(byId("backup-details"), result);
    byId("backup-details-panel").hidden = false;
    byId("backup-details-panel").scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
  } catch (error) {
    showError(byId("backups-error"), errorMessage(error));
  }
}

/**
 * Select one backup and reset its required dry-run evidence.
 */
function selectRestore(backup) {
  selectedBackup = backup;
  validatedRestore = null;
  const panel = byId("restore-panel");
  const form = byId("restore-form");

  form.reset();
  form.elements.restore_passphrase.required = backup.encrypted;
  byId("restore-selection").textContent =
    `Backup ${backup.id} · ${backup.kind} · ` +
    `${formatTimestamp(backup.created_at)}`;
  byId("restore-passphrase-row").hidden = !backup.encrypted;
  byId("restore-apply").disabled = true;
  byId("restore-result").textContent = "";
  panel.hidden = false;
  panel.scrollIntoView({ behavior: "smooth", block: "start" });
}

/**
 * Return the passphrase required by the selected backup kind.
 */
function restorePassphrase() {
  if (selectedBackup === null || !selectedBackup.encrypted) {
    return null;
  }
  return String(
    byId("restore-form").elements.restore_passphrase.value,
  );
}

/**
 * Dry-run one restore before permitting its application.
 */
async function validateRestore(event) {
  event.preventDefault();
  if (selectedBackup === null) {
    return;
  }
  const passphrase = restorePassphrase();

  if (selectedBackup.encrypted &&
      passphrase.length < backupPassphraseMinimum) {
    showError(
      byId("backups-error"),
      `The full-backup passphrase must contain at least ${backupPassphraseMinimum} characters.`,
    );
    return;
  }
  await withBusyButton(byId("restore-validate"), async () => {
    try {
      const accepted = await api(
        `/api/v1/backups/${selectedBackup.id}/restore`,
        {
          method: "POST",
          body: { passphrase, dry_run: true, confirm: false },
        },
      );
      const result = await waitForJob(accepted);

      validatedRestore = {
        id: selectedBackup.id,
        passphrase,
      };
      byId("restore-apply").disabled = false;
      renderJson(byId("restore-result"), result);
      announce(
        result.changes
          ? "The dry run succeeded and found restorable changes."
          : "The dry run succeeded; the appliance already matches this backup.",
      );
    } catch (error) {
      validatedRestore = null;
      byId("restore-apply").disabled = true;
      showError(byId("backups-error"), errorMessage(error));
    }
  });
}

/**
 * Apply one restore whose current inputs passed a dry run.
 */
async function applyRestore() {
  if (selectedBackup === null || validatedRestore === null ||
      validatedRestore.id !== selectedBackup.id ||
      validatedRestore.passphrase !== restorePassphrase()) {
    showError(
      byId("backups-error"),
      "Run the restore dry run again after changing its inputs.",
    );
    byId("restore-apply").disabled = true;
    return;
  }
  if (!await confirmAction(
    "Restore appliance backup",
    `Apply backup ${selectedBackup.id}? JanusGate creates an automatic ` +
      "checkpoint before changing persistent state.",
    "Restore backup",
  )) {
    return;
  }
  await withBusyButton(byId("restore-apply"), async () => {
    try {
      const accepted = await api(
        `/api/v1/backups/${selectedBackup.id}/restore`,
        {
          method: "POST",
          body: {
            passphrase: validatedRestore.passphrase,
            dry_run: false,
            confirm: true,
          },
        },
      );
      const result = await waitForJob(accepted);

      renderJson(byId("restore-result"), result);
      validatedRestore = null;
      byId("restore-apply").disabled = true;
      announce(
        result.reload_required
          ? "The backup was restored. Reload the service to activate all " +
            "restored configuration."
          : "The restore completed without persistent changes.",
        result.reload_required ? "warning" : "success",
      );
      await fetchBackups();
    } catch (error) {
      showError(byId("backups-error"), errorMessage(error));
    }
  });
  byId("restore-apply").disabled = validatedRestore === null;
}

/**
 * Create a configuration or encrypted full backup.
 */
async function createBackup(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const kind = String(form.elements.backup_kind.value);
  const full = kind === "full";
  const passphrase = full
    ? String(form.elements.backup_passphrase.value)
    : null;
  const includePrivateKey =
    full && form.elements.include_private_key.checked;

  showError(byId("backups-error"), "");
  if (full && passphrase.length < backupPassphraseMinimum) {
    showError(
      byId("backups-error"),
      `A full-backup passphrase must contain at least ${backupPassphraseMinimum} characters.`,
    );
    return;
  }
  if (includePrivateKey && !await confirmAction(
    "Include TLS private key",
    "The encrypted full backup will contain the active HTTPS private key. " +
      "Keep the archive and passphrase under separate control.",
    "Create encrypted backup",
  )) {
    return;
  }
  await withBusyButton(byId("backup-create-submit"), async () => {
    try {
      const accepted = await api("/api/v1/backups", {
        method: "POST",
        body: {
          kind,
          include_private_key: includePrivateKey,
          passphrase,
        },
      });
      const result = await waitForJob(accepted);

      form.reset();
      updateCreateFields();
      announce(`Backup ${result.backup.id} was created and verified.`);
      await fetchBackups();
    } catch (error) {
      showError(byId("backups-error"), errorMessage(error));
    }
  });
}

/**
 * Show full-backup controls only when their values are accepted.
 */
function updateCreateFields() {
  const form = byId("backup-create-form");
  const full = form.elements.backup_kind.value === "full";

  byId("full-backup-fields").hidden = !full;
  form.elements.backup_passphrase.required = full;
  if (!full) {
    form.elements.backup_passphrase.value = "";
    form.elements.include_private_key.checked = false;
  }
}

/**
 * Invalidate dry-run evidence whenever restore inputs change.
 */
function invalidateRestore() {
  validatedRestore = null;
  byId("restore-apply").disabled = true;
}

/**
 * Load backups for an authorized administrator.
 */
export async function load(user) {
  const writable = user.role === "administrator";

  byId("backup-controls").hidden = !writable;
  byId("backup-refresh").hidden = !writable;
  byId("restore-panel").hidden = true;
  byId("backup-details-panel").hidden = true;
  showError(byId("backups-error"), "");
  if (!writable) {
    backups = [];
    nextCursor = null;
    byId("backup-load-more").hidden = true;
    showEmptyTable(
      byId("backup-list"),
      7,
      `Backup administration is not granted to the ${user.role} role.`,
    );
    return;
  }
  try {
    await fetchBackups();
  } catch (error) {
    showError(byId("backups-error"), errorMessage(error));
  }
}

/**
 * Bind backup and transactional restore controls exactly once.
 */
export function initialize() {
  if (initialized) {
    return;
  }
  initialized = true;
  byId("backup-refresh").addEventListener("click", () => {
    void fetchBackups();
  });
  byId("backup-create-form").addEventListener("submit", createBackup);
  byId("backup-kind").addEventListener("change", updateCreateFields);
  byId("backup-load-more").addEventListener("click", () => {
    void fetchBackups(true);
  });
  byId("restore-form").addEventListener("submit", validateRestore);
  byId("restore-apply").addEventListener("click", () => {
    void applyRestore();
  });
  byId("restore-passphrase").addEventListener("input", invalidateRestore);
  byId("restore-cancel").addEventListener("click", () => {
    selectedBackup = null;
    validatedRestore = null;
    byId("restore-panel").hidden = true;
  });
  updateCreateFields();
}
