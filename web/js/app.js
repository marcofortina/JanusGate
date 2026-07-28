/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

"use strict";

const serviceState = document.querySelector("#service-state");
const serviceContainer = serviceState.closest(".service-state");
const httpsStatus = document.querySelector("#https-status");
const refreshButton = document.querySelector("#refresh");

/**
 * Update management-service readiness from the local health endpoint.
 */
async function refreshHealth() {
  refreshButton.disabled = true;
  serviceState.textContent = "Checking management service";
  serviceContainer.classList.remove("ready");

  try {
    const response = await fetch("/api/v1/health", {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    if (!response.ok) {
      throw new Error("health response failed");
    }
    const health = await response.json();
    if (health.status !== "ok") {
      throw new Error("health state is not ready");
    }
    serviceState.textContent = "Management service ready";
    httpsStatus.textContent = "Ready";
    serviceContainer.classList.add("ready");
  } catch {
    serviceState.textContent = "Management service unavailable";
    httpsStatus.textContent = "Unavailable";
  } finally {
    refreshButton.disabled = false;
  }
}

refreshButton.addEventListener("click", refreshHealth);
void refreshHealth();
