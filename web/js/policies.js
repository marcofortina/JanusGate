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
  formatNumber,
  formatTimestamp,
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
let globalMode = null;
let policyGroups = [];
let scopeModes = [];
let policyStatistics = null;
let editingGroup = null;
let editingScopeMode = null;
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
 * Keep observe-only available only for blocking rules.
 */
function updateRuleEnforcement(form, actionName, enforcementName) {
  const enforcement = form.elements[enforcementName];
  const blocking = form.elements[actionName].value === "block";

  if (!blocking) {
    enforcement.value = "enforce";
  }
  enforcement.disabled = !blocking;
}

/**
 * Refresh rule-group selectors while preserving their current values.
 */
function renderGroupSelectors() {
  for (const prefix of ["domain", "destination"]) {
    const selector = byId(`${prefix}-rule-form`).elements[`${prefix}_group_id`];
    const selected = selector.value;
    const ungrouped = document.createElement("option");

    ungrouped.value = "";
    ungrouped.textContent = "No group";
    selector.replaceChildren(ungrouped, ...policyGroups.map((group) => {
      const option = document.createElement("option");

      option.value = String(group.id);
      option.textContent = `${group.name} · ${group.enforcement}`;
      return option;
    }));
    selector.value = selected;
  }
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
 * Load and present one rule's retained impact and static findings.
 */
async function analyzeRule(kind, rule) {
  const domain = kind === "domain";
  const path = domain
    ? `/api/v1/domains/${rule.id}/analysis`
    : `/api/v1/policies/destinations/${rule.id}/analysis`;

  showError(byId("policies-error"), "");
  try {
    const result = await api(path);
    const lifetime = result.lifetime;
    const detail = result.retained_detail;
    const findings = result.findings;
    const relatedRules = new Set([
      ...findings.duplicates,
      ...findings.conflicts,
      ...findings.shadowed_by,
      ...findings.allow_exceptions,
    ]).size;
    const traffic = Number.isFinite(result.traffic_percentage)
      ? `${result.traffic_percentage.toLocaleString(undefined, {
        maximumFractionDigits: 2,
      })}% of traffic`
      : "traffic share unavailable";
    const review = [];

    if (result.possible_false_positive) {
      review.push("observed blocks need review");
    }
    if (result.cleanup_candidate) {
      review.push("never used; assisted-cleanup candidate");
    }
    if (findings.unreachable) {
      review.push("currently unreachable");
    }
    byId("policy-impact-title").textContent =
      `${domain ? "Domain" : "Destination"} rule ${rule.id} impact`;
    byId("policy-impact-summary").textContent = [
      `${formatNumber(lifetime.match_count)} matches`,
      `${formatNumber(lifetime.would_block_count)} would block`,
      `${formatNumber(lifetime.enforced_block_count)} enforced`,
      `${formatNumber(detail.distinct_client_count)} clients`,
      traffic,
      `last used ${formatTimestamp(lifetime.last_hit_at)}`,
      `${formatNumber(relatedRules)} related rules`,
      ...review,
    ].join(" · ");
    renderJson(byId("policy-impact-result"), result);
    byId("policy-impact-panel").hidden = false;
    byId("policy-impact-panel").scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
  } catch (error) {
    showError(byId("policies-error"), errorMessage(error));
  }
}

/**
 * Render configured detail storage and lifetime counters.
 */
function renderPolicyStatistics() {
  const form = byId("policy-statistics-form");
  const lifetime = policyStatistics.lifetime;

  form.elements.retention_enabled.checked =
    policyStatistics.retention_enabled;
  form.elements.retention_months.value = policyStatistics.retention_months;
  form.elements.detail_enabled.checked = policyStatistics.detail_enabled;
  form.elements.detail_max_rows.value = policyStatistics.detail_max_rows;
  form.elements.detail_max_rows_per_rule_hour.value =
    policyStatistics.detail_max_rows_per_rule_hour;
  form.elements.detail_max_domains_per_rule_hour.value =
    policyStatistics.detail_max_domains_per_rule_hour;
  form.elements.maximum_database_mib.value =
    policyStatistics.maximum_database_bytes / 1048576;
  form.elements.minimum_free_mib.value =
    policyStatistics.minimum_free_bytes / 1048576;
  byId("policy-statistics-summary").textContent = [
    policyStatistics.detail_enabled
      ? "Detailed collection enabled"
      : "Detailed collection disabled",
    policyStatistics.retention_enabled
      ? "Scheduled cleanup enabled"
      : "Scheduled cleanup disabled",
    `${formatNumber(policyStatistics.retention_months)} months of detail`,
    `${formatNumber(policyStatistics.storage.detail_rows)} retained rows`,
    `${formatNumber(policyStatistics.storage.cardinality_dropped)} cardinality drops`,
    policyStatistics.storage.storage_suspended
      ? "storage suspended"
      : "storage available",
    `${formatNumber(lifetime.request_count)} lifetime requests`,
    `${formatNumber(lifetime.would_block_count)} lifetime would-blocks`,
    `last cleanup ${formatTimestamp(policyStatistics.last_cleanup_at)}`,
  ].join(" · ");
}

/**
 * Fetch policy-statistics storage and lifetime counters.
 */
async function fetchPolicyStatistics() {
  policyStatistics = await api("/api/v1/policies/statistics");
  renderPolicyStatistics();
}

/**
 * Replace detailed-statistics storage policy at its current revision.
 */
async function submitPolicyStatistics(event) {
  event.preventDefault();
  const form = event.currentTarget;

  await withBusyButton(byId("policy-statistics-submit"), async () => {
    try {
      policyStatistics = await api("/api/v1/policies/statistics", {
        method: "PUT",
        body: {
          revision: policyStatistics.revision,
          retention_enabled: form.elements.retention_enabled.checked,
          retention_months: Number(form.elements.retention_months.value),
          detail_enabled: form.elements.detail_enabled.checked,
          detail_max_rows: Number(form.elements.detail_max_rows.value),
          detail_max_rows_per_rule_hour: Number(
            form.elements.detail_max_rows_per_rule_hour.value,
          ),
          detail_max_domains_per_rule_hour: Number(
            form.elements.detail_max_domains_per_rule_hour.value,
          ),
          maximum_database_bytes:
            Number(form.elements.maximum_database_mib.value) * 1048576,
          minimum_free_bytes:
            Number(form.elements.minimum_free_mib.value) * 1048576,
        },
      });
      renderPolicyStatistics();
      announce("Policy-statistics storage policy was updated.", "success");
    } catch (error) {
      showError(byId("policies-error"), errorMessage(error));
    }
  });
}

/**
 * Present one cleanup preview or completed batch.
 */
function renderStatisticsCleanup(result) {
  const eligible = result.eligible_impact_rows +
    result.eligible_traffic_rows;
  const deleted = result.deleted_impact_rows + result.deleted_traffic_rows;

  byId("policy-statistics-cleanup-summary").textContent = result.preview
    ? `${formatNumber(eligible)} expired detail rows are eligible before ` +
      `${formatTimestamp(result.cutoff_at)}. Lifetime counters are preserved.`
    : `${formatNumber(deleted)} detail rows removed · ` +
      `${result.complete ? "cleanup complete" : "more rows remain"} · ` +
      "lifetime counters preserved.";
  renderJson(byId("policy-statistics-result"), result);
}

/**
 * Preview expired policy-statistics detail without changing it.
 */
async function previewStatisticsCleanup() {
  await withBusyButton(byId("policy-statistics-preview"), async () => {
    try {
      const result = await api("/api/v1/policies/statistics/cleanup", {
        method: "POST",
        body: { preview: true },
      });

      renderStatisticsCleanup(result);
    } catch (error) {
      showError(byId("policies-error"), errorMessage(error));
    }
  });
}

/**
 * Remove one bounded batch of expired detail after confirmation.
 */
async function runStatisticsCleanup() {
  if (!await confirmAction(
    "Remove expired statistics detail?",
    "Only expired hourly detail is removed. Lifetime counters and policy " +
      "rules are preserved.",
    "Remove expired detail",
  )) {
    return;
  }
  await withBusyButton(byId("policy-statistics-cleanup"), async () => {
    try {
      const result = await api("/api/v1/policies/statistics/cleanup", {
        method: "POST",
        body: { preview: false, batch_size: 10000 },
      });

      renderStatisticsCleanup(result);
      await fetchPolicyStatistics();
      announce(
        result.complete
          ? "Expired policy-statistics detail was removed."
          : "One cleanup batch was removed; more expired detail remains.",
        "success",
      );
    } catch (error) {
      showError(byId("policies-error"), errorMessage(error));
    }
  });
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
    actions.append(actionButton("Impact", () => {
      void analyzeRule("domain", rule);
    }));
    if (writable) {
      actions.append(
        actionButton("Edit", () => editDomain(rule)),
        actionButton("Remove", () => {
          void removeDomain(rule);
        }, true),
      );
    }
    row.append(
      tableCell(rule.id),
      tableCell(rule.domain),
      tableCell(rule.include_subdomains ? "Suffix" : "Exact"),
      tableCell(`${rule.action} · ${rule.target} · ${rule.enforcement}`),
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
    actions.append(actionButton("Impact", () => {
      void analyzeRule("destination", rule);
    }));
    if (writable) {
      actions.append(
        actionButton("Edit", () => editDestination(rule)),
        actionButton("Remove", () => {
          void removeDestination(rule);
        }, true),
      );
    }
    row.append(
      tableCell(rule.id),
      tableCell(destination),
      tableCell(rule.transport),
      tableCell(`${rule.action} · ${rule.enforcement}`),
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
  form.elements.domain_group_id.value = "";
  form.elements.domain_enabled.checked = true;
  form.elements.include_subdomains.checked = true;
  byId("domain-form-title").textContent = "Add domain rule";
  byId("domain-submit").textContent = "Add rule";
  byId("domain-cancel").hidden = true;
  updateScopeFields(form, "domain");
  updateRuleEnforcement(form, "action", "domain_enforcement");
}

/**
 * Populate the domain editor for a revision-checked update.
 */
function editDomain(rule) {
  const form = byId("domain-rule-form");

  editingDomain = rule;
  form.elements.domain.value = rule.domain;
  form.elements.action.value = rule.action;
  form.elements.domain_enforcement.value = rule.enforcement;
  form.elements.domain_group_id.value = rule.group_id ?? "";
  form.elements.target.value = rule.target;
  form.elements.include_subdomains.checked = rule.include_subdomains;
  form.elements.attribution.value = rule.attribution;
  form.elements.domain_enabled.checked = rule.enabled;
  populateScope(form, "domain", rule.scope);
  updateRuleEnforcement(form, "action", "domain_enforcement");
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
    enforcement: String(form.elements.domain_enforcement.value),
    group_id: form.elements.domain_group_id.value === ""
      ? null
      : Number(form.elements.domain_group_id.value),
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
  form.elements.destination_group_id.value = "";
  form.elements.destination_enabled.checked = true;
  byId("destination-form-title").textContent = "Add destination rule";
  byId("destination-submit").textContent = "Add rule";
  byId("destination-cancel").hidden = true;
  updateScopeFields(form, "destination");
  updateRuleEnforcement(
    form,
    "destination_action",
    "destination_enforcement",
  );
}

/**
 * Populate the destination editor for a revision-checked update.
 */
function editDestination(rule) {
  const form = byId("destination-rule-form");

  editingDestination = rule;
  form.elements.destination_action.value = rule.action;
  form.elements.destination_enforcement.value = rule.enforcement;
  form.elements.destination_group_id.value = rule.group_id ?? "";
  form.elements.transport.value = rule.transport;
  form.elements.address.value = rule.address ?? "";
  form.elements.prefix_length.value = rule.prefix_length ?? "";
  form.elements.port.value = rule.port ?? "";
  form.elements.destination_attribution.value = rule.attribution;
  form.elements.destination_enabled.checked = rule.enabled;
  populateScope(form, "destination", rule.scope);
  updateRuleEnforcement(
    form,
    "destination_action",
    "destination_enforcement",
  );
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
    enforcement: String(form.elements.destination_enforcement.value),
    group_id: form.elements.destination_group_id.value === ""
      ? null
      : Number(form.elements.destination_group_id.value),
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
 * Render policy groups and their current inherited mode.
 */
function renderPolicyGroups() {
  const body = byId("policy-group-list");

  if (policyGroups.length === 0) {
    showEmptyTable(body, 6, "No policy groups are configured.");
    renderGroupSelectors();
    return;
  }
  body.replaceChildren(...policyGroups.map((group) => {
    const row = document.createElement("tr");
    const actions = document.createElement("td");

    actions.className = "table-actions";
    if (writable) {
      actions.append(
        actionButton("Edit", () => editPolicyGroup(group)),
        actionButton("Remove", () => {
          void removePolicyGroup(group);
        }, true),
      );
    } else {
      actions.textContent = "Read only";
    }
    row.append(
      tableCell(group.id),
      tableCell(group.description.length === 0
        ? group.name
        : `${group.name} · ${group.description}`),
      tableCell(group.enforcement),
      tableCell(group.domain_rule_count + group.destination_rule_count),
      tableCell(group.enabled ? "Enabled" : "Disabled"),
      actions,
    );
    return row;
  }));
  renderGroupSelectors();
}

/**
 * Render client, network, and VLAN policy modes.
 */
function renderScopeModes() {
  const body = byId("policy-scope-list");

  if (scopeModes.length === 0) {
    showEmptyTable(body, 6, "No client or VLAN modes are configured.");
    return;
  }
  body.replaceChildren(...scopeModes.map((mode) => {
    const row = document.createElement("tr");
    const actions = document.createElement("td");

    actions.className = "table-actions";
    if (writable) {
      actions.append(
        actionButton("Edit", () => editScopeMode(mode)),
        actionButton("Remove", () => {
          void removeScopeMode(mode);
        }, true),
      );
    } else {
      actions.textContent = "Read only";
    }
    row.append(
      tableCell(mode.id),
      tableCell(mode.name),
      tableCell(scopeText(mode.scope)),
      tableCell(mode.enforcement),
      tableCell(mode.enabled ? "Enabled" : "Disabled"),
      actions,
    );
    return row;
  }));
}

/**
 * Load global, group, and client-scoped enforcement state.
 */
async function fetchPolicyModes() {
  const [mode, groups, scopes] = await Promise.all([
    api("/api/v1/policies/mode"),
    api("/api/v1/policies/groups?limit=100"),
    api("/api/v1/policies/scopes?limit=100"),
  ]);

  globalMode = mode;
  policyGroups = groups.groups;
  scopeModes = scopes.scope_modes;
  byId("policy-mode-form").elements.global_enforcement.value =
    mode.enforcement;
  renderPolicyGroups();
  renderScopeModes();
}

/**
 * Replace snapshot-wide enforcement at the loaded revision.
 */
async function submitGlobalMode(event) {
  event.preventDefault();
  if (globalMode === null) {
    return;
  }
  await withBusyButton(byId("policy-mode-submit"), async () => {
    try {
      const result = await api("/api/v1/policies/mode", {
        method: "PUT",
        body: {
          revision: globalMode.revision,
          enforcement: String(
            event.currentTarget.elements.global_enforcement.value,
          ),
        },
      });

      globalMode = result;
      announce("Global policy mode was updated.", "success");
    } catch (error) {
      showError(byId("policies-error"), errorMessage(error));
    }
  });
}

/**
 * Reset the policy-group editor to create mode.
 */
function resetPolicyGroupForm() {
  const form = byId("policy-group-form");

  editingGroup = null;
  form.reset();
  form.elements.group_enforcement.value = "enforce";
  form.elements.group_enabled.checked = true;
  byId("policy-group-form-title").textContent = "Add rule group";
  byId("policy-group-submit").textContent = "Add group";
  byId("policy-group-cancel").hidden = true;
}

/**
 * Populate the policy-group editor.
 */
function editPolicyGroup(group) {
  const form = byId("policy-group-form");

  editingGroup = group;
  form.elements.group_name.value = group.name;
  form.elements.group_description.value = group.description;
  form.elements.group_enforcement.value = group.enforcement;
  form.elements.group_enabled.checked = group.enabled;
  byId("policy-group-form-title").textContent = `Edit group ${group.id}`;
  byId("policy-group-submit").textContent = "Save group";
  byId("policy-group-cancel").hidden = false;
  form.scrollIntoView({ behavior: "smooth", block: "start" });
}

/**
 * Create or replace one policy group.
 */
async function submitPolicyGroup(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const updating = editingGroup !== null;
  const body = {
    name: String(form.elements.group_name.value),
    description: String(form.elements.group_description.value),
    enforcement: String(form.elements.group_enforcement.value),
    enabled: form.elements.group_enabled.checked,
  };

  if (updating) {
    body.revision = editingGroup.revision;
  }
  await withBusyButton(byId("policy-group-submit"), async () => {
    try {
      await api(
        updating
          ? `/api/v1/policies/groups/${editingGroup.id}`
          : "/api/v1/policies/groups",
        { method: updating ? "PATCH" : "POST", body },
      );
      resetPolicyGroupForm();
      await fetchPolicyModes();
      announce("Policy group was saved.", "success");
    } catch (error) {
      showError(byId("policies-error"), errorMessage(error));
    }
  });
}

/**
 * Remove one group after warning about assigned rules.
 */
async function removePolicyGroup(group) {
  const assigned = group.domain_rule_count + group.destination_rule_count;

  if (!await confirmAction(
    "Remove policy group",
    `Remove ${group.name} and its ${assigned} assigned rules?`,
    "Remove group",
  )) {
    return;
  }
  try {
    await api(`/api/v1/policies/groups/${group.id}`, {
      method: "DELETE",
      body: { revision: group.revision },
    });
    await Promise.all([fetchPolicyModes(), fetchRules("domain"),
      fetchRules("destination")]);
    announce("Policy group and assigned rules were removed.", "success");
  } catch (error) {
    showError(byId("policies-error"), errorMessage(error));
  }
}

/**
 * Reset the client-scope editor to create mode.
 */
function resetScopeModeForm() {
  const form = byId("policy-scope-form");

  editingScopeMode = null;
  form.reset();
  form.elements.mode_enforcement.value = "observe";
  form.elements.mode_scope_type.value = "ipv4";
  form.elements.mode_enabled.checked = true;
  byId("policy-scope-form-title").textContent = "Add client or VLAN mode";
  byId("policy-scope-submit").textContent = "Add selector";
  byId("policy-scope-cancel").hidden = true;
  updateScopeFields(form, "mode");
}

/**
 * Populate the client-scope editor.
 */
function editScopeMode(mode) {
  const form = byId("policy-scope-form");

  editingScopeMode = mode;
  form.elements.mode_name.value = mode.name;
  form.elements.mode_enforcement.value = mode.enforcement;
  form.elements.mode_enabled.checked = mode.enabled;
  populateScope(form, "mode", mode.scope);
  byId("policy-scope-form-title").textContent = `Edit selector ${mode.id}`;
  byId("policy-scope-submit").textContent = "Save selector";
  byId("policy-scope-cancel").hidden = false;
  form.scrollIntoView({ behavior: "smooth", block: "start" });
}

/**
 * Create or replace one client-scoped policy mode.
 */
async function submitScopeMode(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const updating = editingScopeMode !== null;
  const body = {
    name: String(form.elements.mode_name.value),
    enforcement: String(form.elements.mode_enforcement.value),
    scope: scopeFromForm(form, "mode"),
    enabled: form.elements.mode_enabled.checked,
  };

  if (updating) {
    body.revision = editingScopeMode.revision;
  }
  await withBusyButton(byId("policy-scope-submit"), async () => {
    try {
      await api(
        updating
          ? `/api/v1/policies/scopes/${editingScopeMode.id}`
          : "/api/v1/policies/scopes",
        { method: updating ? "PATCH" : "POST", body },
      );
      resetScopeModeForm();
      await fetchPolicyModes();
      announce("Client-scoped policy mode was saved.", "success");
    } catch (error) {
      showError(byId("policies-error"), errorMessage(error));
    }
  });
}

/**
 * Remove one client-scoped policy mode.
 */
async function removeScopeMode(mode) {
  if (!await confirmAction(
    "Remove client policy mode",
    `Remove ${mode.name}?`,
    "Remove selector",
  )) {
    return;
  }
  try {
    await api(`/api/v1/policies/scopes/${mode.id}`, {
      method: "DELETE",
      body: { revision: mode.revision },
    });
    await fetchPolicyModes();
    announce("Client-scoped policy mode was removed.", "success");
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
  byId("policy-mode-fieldset").disabled = readOnly;
  byId("policy-group-fieldset").disabled = readOnly;
  byId("policy-scope-fieldset").disabled = readOnly;
  byId("policy-statistics-fieldset").disabled = readOnly;
  byId("domain-rule-fieldset").disabled = readOnly;
  byId("destination-rule-fieldset").disabled = readOnly;
  byId("policy-read-only").hidden = !readOnly;
  showError(byId("policies-error"), "");
  try {
    await Promise.all([
      fetchPolicyModes(),
      fetchPolicyStatistics(),
      fetchRules("domain"),
      fetchRules("destination"),
    ]);
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
  byId("policy-mode-form").addEventListener("submit", submitGlobalMode);
  byId("policy-group-form").addEventListener("submit", submitPolicyGroup);
  byId("policy-scope-form").addEventListener("submit", submitScopeMode);
  byId("policy-statistics-form").addEventListener(
    "submit",
    submitPolicyStatistics,
  );
  byId("policy-statistics-preview").addEventListener("click", () => {
    void previewStatisticsCleanup();
  });
  byId("policy-statistics-cleanup").addEventListener("click", () => {
    void runStatisticsCleanup();
  });
  byId("domain-rule-form").addEventListener("submit", submitDomain);
  byId("domain-rule-form").elements.action.addEventListener("change", () => {
    updateRuleEnforcement(
      byId("domain-rule-form"),
      "action",
      "domain_enforcement",
    );
  });
  byId("destination-rule-form").addEventListener(
    "submit",
    submitDestination,
  );
  byId("destination-rule-form").elements.destination_action.addEventListener(
    "change",
    () => {
      updateRuleEnforcement(
        byId("destination-rule-form"),
        "destination_action",
        "destination_enforcement",
      );
    },
  );
  byId("policy-simulation-form").addEventListener("submit", simulatePolicy);
  byId("domain-cancel").addEventListener("click", resetDomainForm);
  byId("destination-cancel").addEventListener(
    "click",
    resetDestinationForm,
  );
  byId("policy-group-cancel").addEventListener(
    "click",
    resetPolicyGroupForm,
  );
  byId("policy-scope-cancel").addEventListener(
    "click",
    resetScopeModeForm,
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
  byId("policy-scope-form").elements.mode_scope_type.addEventListener(
    "change",
    () => {
      updateScopeFields(byId("policy-scope-form"), "mode");
    },
  );
  resetDomainForm();
  resetDestinationForm();
  resetPolicyGroupForm();
  resetScopeModeForm();
}
