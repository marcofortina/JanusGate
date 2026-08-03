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
  displayValue,
  renderJson,
  showEmptyTable,
  showError,
  tableCell,
  withBusyButton,
} from "./ui.js";

let initialized = false;
let domainRules = [];
let destinationRules = [];
let domainCursor = null;
let destinationCursor = null;
let editingDomain = null;
let editingDestination = null;
let writable = true;

/**
 * Return one policy scope from a form field prefix.
 */
function scopeFromForm(form, prefix) {
  const type = String(form.elements[`${prefix}_scope_type`].value);
  const value = String(form.elements[`${prefix}_scope_value`].value).trim();
  const prefixLength =
    String(form.elements[`${prefix}_scope_prefix`].value).trim();

  if (type === "global") {
    return { type };
  }
  if (type === "vlan") {
    return { type, vlan: Number(value) };
  }
  if (type === "mac") {
    return { type, address: value };
  }
  return {
    type,
    address: value,
    prefix_length: Number(prefixLength),
  };
}

/**
 * Populate one policy scope editor.
 */
function populateScope(form, prefix, scope) {
  const value = form.elements[`${prefix}_scope_value`];
  const prefixLength = form.elements[`${prefix}_scope_prefix`];

  form.elements[`${prefix}_scope_type`].value = scope.type;
  value.value = scope.vlan ?? scope.address ?? "";
  prefixLength.value = scope.prefix_length ?? "";
  updateScopeFields(form, prefix);
}

/**
 * Require only the fields meaningful to the selected scope.
 */
function updateScopeFields(form, prefix) {
  const type = form.elements[`${prefix}_scope_type`].value;
  const value = form.elements[`${prefix}_scope_value`];
  const prefixLength = form.elements[`${prefix}_scope_prefix`];
  const global = type === "global";
  const network = type === "ipv4" || type === "ipv6";

  value.disabled = global;
  value.required = !global;
  prefixLength.disabled = !network;
  prefixLength.required = network;
  value.placeholder = type === "vlan"
    ? "100"
    : (type === "mac" ? "00:11:22:33:44:55" : "192.0.2.0");
}

/**
 * Render one scope as concise operator-facing text.
 */
function scopeText(scope) {
  if (scope.type === "global") {
    return "Global";
  }
  if (scope.type === "vlan") {
    return `VLAN ${scope.vlan}`;
  }
  if (scope.type === "mac") {
    return scope.address;
  }
  return `${scope.address}/${scope.prefix_length}`;
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
 * Render all currently loaded domain rules.
 */
function renderDomains() {
  const body = byId("domain-rule-list");

  if (domainRules.length === 0) {
    showEmptyTable(body, 8, "No explicit domain rules are configured.");
    return;
  }
  body.replaceChildren(...domainRules.map((rule) => {
    const row = document.createElement("tr");
    const actions = document.createElement("td");

    actions.className = "table-actions";
    if (writable) {
      actions.append(
        actionButton("Edit", () => editDomain(rule)),
        actionButton("Remove", () => {
          void removeDomain(rule);
        }, true),
      );
    } else {
      actions.textContent = "Read only";
    }
    row.append(
      tableCell(rule.id),
      tableCell(rule.domain),
      tableCell(rule.include_subdomains ? "Suffix" : "Exact"),
      tableCell(`${rule.action} · ${rule.target}`),
      tableCell(scopeText(rule.scope)),
      tableCell(rule.attribution),
      tableCell(rule.enabled ? "Enabled" : "Disabled"),
      actions,
    );
    return row;
  }));
}

/**
 * Render all currently loaded destination rules.
 */
function renderDestinations() {
  const body = byId("destination-rule-list");

  if (destinationRules.length === 0) {
    showEmptyTable(body, 8, "No destination rules are configured.");
    return;
  }
  body.replaceChildren(...destinationRules.map((rule) => {
    const row = document.createElement("tr");
    const actions = document.createElement("td");
    const destination = rule.address === null
      ? `Any address:${rule.port}`
      : `${rule.address}/${rule.prefix_length}${rule.port === null
        ? ""
        : `:${rule.port}`}`;

    actions.className = "table-actions";
    if (writable) {
      actions.append(
        actionButton("Edit", () => editDestination(rule)),
        actionButton("Remove", () => {
          void removeDestination(rule);
        }, true),
      );
    } else {
      actions.textContent = "Read only";
    }
    row.append(
      tableCell(rule.id),
      tableCell(destination),
      tableCell(rule.transport),
      tableCell(rule.action),
      tableCell(scopeText(rule.scope)),
      tableCell(rule.attribution),
      tableCell(rule.enabled ? "Enabled" : "Disabled"),
      actions,
    );
    return row;
  }));
}

/**
 * Fetch one cursor page and merge it without duplicate records.
 */
async function fetchRules(kind, append = false) {
  const domain = kind === "domain";
  const cursor = domain ? domainCursor : destinationCursor;
  const collection = domain ? "/api/v1/domains" :
    "/api/v1/policies/destinations";
  const parameter = append && cursor !== null ? `&after_id=${cursor}` : "";
  const payload = await api(`${collection}?limit=100${parameter}`);
  const records = domain ? payload.domains : payload.destination_rules;

  if (domain) {
    domainRules = append ? [...domainRules, ...records] : records;
    domainCursor = payload.next_after_id;
    byId("domain-load-more").hidden = domainCursor === null;
    renderDomains();
  } else {
    destinationRules = append ? [...destinationRules, ...records] : records;
    destinationCursor = payload.next_after_id;
    byId("destination-load-more").hidden = destinationCursor === null;
    renderDestinations();
  }
}

/**
 * Reset the domain editor to create mode.
 */
function resetDomainForm() {
  const form = byId("domain-rule-form");

  editingDomain = null;
  form.reset();
  form.elements.domain_scope_type.value = "global";
  form.elements.domain_enabled.checked = true;
  form.elements.include_subdomains.checked = true;
  byId("domain-form-title").textContent = "Add domain rule";
  byId("domain-submit").textContent = "Add rule";
  byId("domain-cancel").hidden = true;
  updateScopeFields(form, "domain");
}

/**
 * Populate the domain editor for a revision-checked update.
 */
function editDomain(rule) {
  const form = byId("domain-rule-form");

  editingDomain = rule;
  form.elements.domain.value = rule.domain;
  form.elements.action.value = rule.action;
  form.elements.target.value = rule.target;
  form.elements.include_subdomains.checked = rule.include_subdomains;
  form.elements.attribution.value = rule.attribution;
  form.elements.domain_enabled.checked = rule.enabled;
  populateScope(form, "domain", rule.scope);
  byId("domain-form-title").textContent = `Edit domain rule ${rule.id}`;
  byId("domain-submit").textContent = "Save rule";
  byId("domain-cancel").hidden = false;
  form.scrollIntoView({ behavior: "smooth", block: "start" });
}

/**
 * Create or update one domain rule.
 */
async function submitDomain(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = byId("domain-submit");
  const body = {
    domain: String(form.elements.domain.value),
    action: String(form.elements.action.value),
    target: String(form.elements.target.value),
    include_subdomains: form.elements.include_subdomains.checked,
    scope: scopeFromForm(form, "domain"),
    attribution: String(form.elements.attribution.value),
    enabled: form.elements.domain_enabled.checked,
  };
  const updating = editingDomain !== null;

  if (updating) {
    body.revision = editingDomain.revision;
  }
  showError(byId("policies-error"), "");
  await withBusyButton(button, async () => {
    try {
      const result = await api(
        updating ? `/api/v1/domains/${editingDomain.id}` : "/api/v1/domains",
        {
          method: updating ? "PATCH" : "POST",
          body,
        },
      );
      announce(result.published
        ? "The domain policy was published."
        : "The domain policy was stored and awaits publication.",
      result.published ? "success" : "warning");
      resetDomainForm();
      await fetchRules("domain");
    } catch (error) {
      showError(byId("policies-error"), errorMessage(error));
    }
  });
}

/**
 * Remove one exact domain-rule revision.
 */
async function removeDomain(rule) {
  if (!await confirmAction(
    "Remove domain rule",
    `Remove the ${rule.action} rule for ${rule.domain}?`,
    "Remove rule",
  )) {
    return;
  }
  try {
    const result = await api(`/api/v1/domains/${rule.id}`, {
      method: "DELETE",
      body: { revision: rule.revision },
    });
    announce(result.published
      ? "The domain rule was removed and policy was published."
      : "The domain rule was removed; publication is pending.",
    result.published ? "success" : "warning");
    await fetchRules("domain");
  } catch (error) {
    showError(byId("policies-error"), errorMessage(error));
  }
}

/**
 * Reset the destination editor to create mode.
 */
function resetDestinationForm() {
  const form = byId("destination-rule-form");

  editingDestination = null;
  form.reset();
  form.elements.destination_scope_type.value = "global";
  form.elements.destination_enabled.checked = true;
  byId("destination-form-title").textContent = "Add destination rule";
  byId("destination-submit").textContent = "Add rule";
  byId("destination-cancel").hidden = true;
  updateScopeFields(form, "destination");
}

/**
 * Populate the destination editor for a revision-checked update.
 */
function editDestination(rule) {
  const form = byId("destination-rule-form");

  editingDestination = rule;
  form.elements.destination_action.value = rule.action;
  form.elements.transport.value = rule.transport;
  form.elements.address.value = rule.address ?? "";
  form.elements.prefix_length.value = rule.prefix_length ?? "";
  form.elements.port.value = rule.port ?? "";
  form.elements.destination_attribution.value = rule.attribution;
  form.elements.destination_enabled.checked = rule.enabled;
  populateScope(form, "destination", rule.scope);
  byId("destination-form-title").textContent =
    `Edit destination rule ${rule.id}`;
  byId("destination-submit").textContent = "Save rule";
  byId("destination-cancel").hidden = false;
  form.scrollIntoView({ behavior: "smooth", block: "start" });
}

/**
 * Create or update one destination rule.
 */
async function submitDestination(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const address = String(form.elements.address.value).trim();
  const prefixLength = String(form.elements.prefix_length.value).trim();
  const port = String(form.elements.port.value).trim();

  if (address.length === 0 && port.length === 0) {
    showError(
      byId("policies-error"),
      "A destination rule requires an address, a port, or both.",
    );
    form.elements.address.focus();
    return;
  }
  if (address.length > 0 && prefixLength.length === 0) {
    showError(
      byId("policies-error"),
      "A destination address requires a prefix length.",
    );
    form.elements.prefix_length.focus();
    return;
  }
  const body = {
    action: String(form.elements.destination_action.value),
    transport: String(form.elements.transport.value),
    address: address.length === 0 ? null : address,
    prefix_length: address.length === 0
      ? null
      : Number(prefixLength),
    port: port.length === 0 ? null : Number(port),
    scope: scopeFromForm(form, "destination"),
    attribution: String(form.elements.destination_attribution.value),
    enabled: form.elements.destination_enabled.checked,
  };
  const updating = editingDestination !== null;

  if (updating) {
    body.revision = editingDestination.revision;
  }
  const button = byId("destination-submit");

  showError(byId("policies-error"), "");
  await withBusyButton(button, async () => {
    try {
      const result = await api(
        updating
          ? `/api/v1/policies/destinations/${editingDestination.id}`
          : "/api/v1/policies/destinations",
        {
          method: updating ? "PATCH" : "POST",
          body,
        },
      );
      announce(result.published
        ? "The destination policy was published."
        : "The destination policy was stored and awaits publication.",
      result.published ? "success" : "warning");
      resetDestinationForm();
      await fetchRules("destination");
    } catch (error) {
      showError(byId("policies-error"), errorMessage(error));
    }
  });
}

/**
 * Remove one exact destination-rule revision.
 */
async function removeDestination(rule) {
  if (!await confirmAction(
    "Remove destination rule",
    `Remove destination rule ${rule.id}?`,
    "Remove rule",
  )) {
    return;
  }
  try {
    const result = await api(`/api/v1/policies/destinations/${rule.id}`, {
      method: "DELETE",
      body: { revision: rule.revision },
    });
    announce(result.published
      ? "The destination rule was removed and policy was published."
      : "The destination rule was removed; publication is pending.",
    result.published ? "success" : "warning");
    await fetchRules("destination");
  } catch (error) {
    showError(byId("policies-error"), errorMessage(error));
  }
}

/**
 * Simulate one decision using the production policy matcher.
 */
async function simulatePolicy(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const body = {
    domain: String(form.elements.simulation_domain.value),
    target: String(form.elements.simulation_target.value),
  };
  const optional = {
    source_ip: form.elements.source_ip.value,
    source_mac: form.elements.source_mac.value,
    vlan: form.elements.simulation_vlan.value,
    destination_ip: form.elements.destination_ip.value,
    destination_port: form.elements.destination_port.value,
    transport: form.elements.simulation_transport.value,
  };

  for (const [name, value] of Object.entries(optional)) {
    if (String(value).trim().length > 0) {
      body[name] = name === "vlan" || name === "destination_port"
        ? Number(value)
        : String(value);
    }
  }
  const destinationFields = [
    "destination_ip",
    "destination_port",
    "transport",
  ].filter((name) => Object.hasOwn(body, name));

  if (destinationFields.length !== 0 && destinationFields.length !== 3) {
    showError(
      byId("policies-error"),
      "Destination IP, port, and transport must be supplied together.",
    );
    return;
  }
  await withBusyButton(byId("simulation-submit"), async () => {
    try {
      const result = await api("/api/v1/policies/simulate", {
        method: "POST",
        body,
      });
      renderJson(byId("simulation-result"), result);
      const configured = displayValue(result.configured_action, "No action");
      const effective = displayValue(result.action, "No action");
      byId("simulation-summary").textContent = result.would_have_blocked
        ? `Would block · effective ${effective} · generation ` +
          `${displayValue(result.policy_generation)}`
        : `${configured} · effective ${effective} · generation ` +
          `${displayValue(result.policy_generation)}`;
    } catch (error) {
      showError(byId("policies-error"), errorMessage(error));
    }
  });
}

/**
 * Load the current domain and destination policy collections.
 */
export async function load(user) {
  const readOnly = user.role === "auditor";

  writable = !readOnly;
  byId("domain-rule-fieldset").disabled = readOnly;
  byId("destination-rule-fieldset").disabled = readOnly;
  byId("policy-read-only").hidden = !readOnly;
  showError(byId("policies-error"), "");
  try {
    await Promise.all([fetchRules("domain"), fetchRules("destination")]);
  } catch (error) {
    showError(byId("policies-error"), errorMessage(error));
  }
}

/**
 * Bind policy management controls exactly once.
 */
export function initialize() {
  if (initialized) {
    return;
  }
  initialized = true;
  byId("domain-rule-form").addEventListener("submit", submitDomain);
  byId("destination-rule-form").addEventListener(
    "submit",
    submitDestination,
  );
  byId("policy-simulation-form").addEventListener("submit", simulatePolicy);
  byId("domain-cancel").addEventListener("click", resetDomainForm);
  byId("destination-cancel").addEventListener(
    "click",
    resetDestinationForm,
  );
  byId("domain-load-more").addEventListener("click", () => {
    void fetchRules("domain", true);
  });
  byId("destination-load-more").addEventListener("click", () => {
    void fetchRules("destination", true);
  });
  for (const prefix of ["domain", "destination"]) {
    const form = byId(`${prefix}-rule-form`);

    form.elements[`${prefix}_scope_type`].addEventListener("change", () => {
      updateScopeFields(form, prefix);
    });
  }
  resetDomainForm();
  resetDestinationForm();
}
