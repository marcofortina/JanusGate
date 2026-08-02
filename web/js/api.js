/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

"use strict";

let csrfToken = "";
let unauthorizedHandler = null;

/**
 * Represent one structured management API failure.
 */
export class ApiError extends Error {
  /**
   * Initialize a failure from its HTTP status and public error object.
   */
  constructor(status, code, message, requestId = "") {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

/**
 * Load the tab-shared CSRF value for the current browser session.
 */
export function initializeCsrf() {
  try {
    csrfToken = localStorage.getItem("janusgate.csrf") || "";
  } catch {
    csrfToken = "";
  }
}

/**
 * Persist the CSRF value shared by tabs using the same session cookie.
 */
export function rememberCsrf(value) {
  csrfToken = typeof value === "string" ? value : "";
  try {
    if (csrfToken.length > 0) {
      localStorage.setItem("janusgate.csrf", csrfToken);
    } else {
      localStorage.removeItem("janusgate.csrf");
    }
  } catch {
    // Cookie authentication remains usable for read-only requests.
  }
}

/**
 * Register the application callback used when the session expires.
 */
export function onUnauthorized(handler) {
  unauthorizedHandler = typeof handler === "function" ? handler : null;
}

/**
 * Convert an unsuccessful JSON response to one stable API error.
 */
async function responseError(response) {
  let payload = null;

  try {
    payload = await response.json();
  } catch {
    return new ApiError(
      response.status,
      "invalid_response",
      "The appliance returned an invalid response.",
    );
  }
  const detail = payload && payload.error ? payload.error : {};
  return new ApiError(
    response.status,
    typeof detail.code === "string" ? detail.code : "request_failed",
    typeof detail.message === "string"
      ? detail.message
      : "The management request failed.",
    typeof detail.request_id === "string" ? detail.request_id : "",
  );
}

/**
 * Build one same-origin, no-cache management request.
 */
function requestOptions(options) {
  const method = options.method || "GET";
  const headers = { Accept: options.accept || "application/json" };
  const request = {
    method,
    credentials: "same-origin",
    cache: "no-store",
    headers,
  };

  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    request.body = JSON.stringify(options.body);
  }
  if (method !== "GET" && csrfToken.length > 0) {
    headers["X-CSRF-Token"] = csrfToken;
  }
  return request;
}

/**
 * Notify the application when a request proves the session is invalid.
 */
function handleUnauthorized(error) {
  if (error.status === 401 && error.code === "authentication_required" &&
      unauthorizedHandler !== null) {
    unauthorizedHandler();
  }
}

/**
 * Exchange one same-origin JSON API request.
 */
export async function api(path, options = {}) {
  const response = await fetch(path, requestOptions(options));

  if (!response.ok) {
    const error = await responseError(response);
    handleUnauthorized(error);
    throw error;
  }
  try {
    return await response.json();
  } catch {
    throw new ApiError(
      response.status,
      "invalid_response",
      "The appliance returned an invalid response.",
    );
  }
}

/**
 * Wait for one accepted asynchronous operation and return its result body.
 */
export async function waitForJob(reference) {
  const identifier = reference && reference.job ? reference.job.id : 0;

  if (!Number.isSafeInteger(identifier) || identifier <= 0) {
    throw new ApiError(
      500,
      "invalid_job",
      "The appliance returned an invalid job.",
    );
  }
  for (let attempt = 0; attempt < 3600; attempt += 1) {
    const result = await api(`/api/v1/jobs/${identifier}`);
    const job = result.job;

    if (!job || typeof job.state !== "string") {
      throw new ApiError(
        500,
        "invalid_job",
        "The appliance returned an invalid job.",
      );
    }
    if (job.state === "completed") {
      const response = job.response;
      const status = response && response.status;
      const body = response && response.body;

      if (!Number.isInteger(status) || !body || typeof body !== "object") {
        throw new ApiError(
          500,
          "invalid_job",
          "The appliance returned an invalid job result.",
        );
      }
      if (status < 200 || status >= 300) {
        const detail = body.error || {};

        throw new ApiError(
          status,
          typeof detail.code === "string" ? detail.code : "job_failed",
          typeof detail.message === "string"
            ? detail.message
            : "The asynchronous operation failed.",
          typeof detail.request_id === "string" ? detail.request_id : "",
        );
      }
      return body;
    }
    if (job.state !== "queued" && job.state !== "running") {
      throw new ApiError(
        500,
        "invalid_job",
        "The appliance returned an invalid job state.",
      );
    }
    await new Promise((resolve) => window.setTimeout(resolve, 1000));
  }
  throw new ApiError(
    504,
    "job_timeout",
    "The asynchronous operation did not finish in time.",
  );
}

/**
 * Exchange one same-origin text API request.
 */
export async function apiText(path, options = {}) {
  const response = await fetch(path, requestOptions({
    ...options,
    accept: "text/plain",
  }));

  if (!response.ok) {
    const error = await responseError(response);
    handleUnauthorized(error);
    throw error;
  }
  return response.text();
}

/**
 * Return a concise safe message for an unknown request failure.
 */
export function errorMessage(error) {
  return error instanceof ApiError
    ? error.message
    : "The management request could not be completed.";
}
