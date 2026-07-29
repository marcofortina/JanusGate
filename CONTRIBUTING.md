<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Contributing

Keep changes small, direct, and justified by a requirement, defect, or measured
improvement. Avoid unrelated refactoring in corrective changes.

## Code

- Use portable C17, explicit ownership, bounded arithmetic, and errno-style
  results.
- Keep privileged operations inside the narrow network helper.
- Prefer structured cleanup and early validation; do not use `goto`.
- Put an immediately preceding Doxygen comment on every C function, including
  private functions, tests, and `main`.
- Preserve strict compiler warnings, warnings as errors, and the existing
  clang-format style.
- Do not add placeholders, unfinished markers, silent fallbacks, or
  architecture-dependent persistent formats.

Every authored file must carry
`SPDX-License-Identifier: AGPL-3.0-or-later` and the project copyright in a
syntax valid for that format. `LICENSE` is the sole canonical license text and
must not be copied or replaced by sidecar license files.

## Tests and review

Add the narrowest regression test that fails before a fix. Parser changes need
malformed and boundary cases; policy changes need precedence and scope cases;
concurrency changes need deterministic synchronization coverage; management
changes need authentication, authorization, revision, and audit coverage.

Run the relevant preset and tests, then the formatting, Doxygen, OpenAPI,
source metadata, and static-analysis gates described in
[Build and verification](docs/build.md). Changes affecting images must boot
the affected image under QEMU. Performance-sensitive changes must rerun the
published benchmark and record the source revision.

Review focuses on correctness, failure behavior, resource bounds, privilege
separation, compatibility, tests, and operator impact. A static-analysis
suppression requires a precise local explanation and a regression test.

## Commits

Use a clean linear series of focused commits with imperative subjects such as
`policy: reject oversized source input`. Each commit should build when
practical and should not mix mechanical cleanup with a functional change.
Never commit build directories, downloaded sources, credentials, private keys,
local configuration, or diagnostic data.
