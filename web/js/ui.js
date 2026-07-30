/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

"use strict";

/**
 * Return one required element by identifier.
 */
export function byId(identifier) {
  const element = document.getElementById(identifier);

  if (element === null) {
    throw new Error(`Missing interface element: ${identifier}`);
  }
  return element;
}

/**
 * Display or clear one accessible error summary.
 */
export function showError(container, message) {
  container.textContent = message;
  container.hidden = message.length === 0;
}

/**
 * Publish one non-sensitive application message.
 */
export function announce(message, kind = "success") {
  const container = byId("global-message");

  container.textContent = message;
  container.dataset.kind = kind;
  container.hidden = message.length === 0;
}

/**
 * Format one safe integer counter for the active locale.
 */
export function formatNumber(value) {
  return Number.isSafeInteger(value) ? value.toLocaleString() : "—";
}

/**
 * Format one Unix timestamp without guessing when it is absent.
 */
export function formatTimestamp(value) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    return "Never";
  }
  return new Date(value * 1000).toLocaleString();
}

/**
 * Format a nullable value for concise tabular presentation.
 */
export function displayValue(value, fallback = "—") {
  if (value === null || value === undefined || value === "") {
    return fallback;
  }
  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  }
  return String(value);
}

/**
 * Replace a table body with one accessible empty-state row.
 */
export function showEmptyTable(body, columns, message) {
  const row = document.createElement("tr");
  const cell = document.createElement("td");

  cell.colSpan = columns;
  cell.className = "empty-state";
  cell.textContent = message;
  row.append(cell);
  body.replaceChildren(row);
}

/**
 * Create one plain-text table cell.
 */
export function tableCell(value, className = "") {
  const cell = document.createElement("td");

  cell.textContent = displayValue(value);
  cell.className = className;
  return cell;
}

/**
 * Run an asynchronous button action while preventing duplicate submission.
 */
export async function withBusyButton(button, action) {
  const original = button.textContent;

  button.disabled = true;
  button.textContent = button.dataset.busyLabel || "Working…";
  try {
    return await action();
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

/**
 * Ask for explicit confirmation in the shared modal dialog.
 */
export function confirmAction(title, message, confirmLabel = "Confirm") {
  const dialog = byId("confirmation-dialog");

  byId("confirmation-title").textContent = title;
  byId("confirmation-message").textContent = message;
  byId("confirmation-submit").textContent = confirmLabel;
  dialog.returnValue = "cancel";
  dialog.showModal();
  return new Promise((resolve) => {
    dialog.addEventListener("close", () => {
      resolve(dialog.returnValue === "confirm");
    }, { once: true });
  });
}

/**
 * Present one secret exactly once without placing it in page markup.
 */
export function showSecret(title, description, secret) {
  const dialog = byId("secret-dialog");

  byId("secret-title").textContent = title;
  byId("secret-description").textContent = description;
  byId("secret-value").value = secret;
  dialog.showModal();
  return new Promise((resolve) => {
    dialog.addEventListener("close", resolve, { once: true });
  });
}

/**
 * Download a browser-generated JSON document.
 */
export function downloadJson(filename, value) {
  const data = JSON.stringify(value, null, 2);
  const url = URL.createObjectURL(new Blob([`${data}\n`], {
    type: "application/json",
  }));
  const link = document.createElement("a");

  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

/**
 * Render one object as stable, readable JSON.
 */
export function renderJson(element, value) {
  element.textContent = JSON.stringify(value, null, 2);
}
