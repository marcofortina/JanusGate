<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Performance

## Method

The reproducible benchmark builds the Release preset with hardening enabled,
creates an immutable policy snapshot containing 1,000,000 unique exact domain
blocks, and measures 200,000 randomized lookups plus 500,000 complete
Ethernet/IPv4/UDP/DNS evaluations. Each DNS sample traverses the production
parser and policy matcher. A paired empty-policy evaluation measures added
policy latency.

The run was pinned to four logical CPUs:

```sh
/usr/bin/time -v taskset -c 0-3 scripts/run-benchmarks.sh
```

Acceptance was measured on commit `7acac7240370b808660c0311eed058b3786fcba2`
with GCC 13.3.0, Linux 7.0.0 x86_64, and an Intel Core i7-13620H host with
32 GiB RAM. Frequency scaling and other host workloads were left enabled, so
these numbers should be treated as a reproducible observed run, not a
best-case claim.

## Results

| Measurement | Result | Required limit |
| --- | ---: | ---: |
| Snapshot construction | 0.645570 s | informational |
| Resident set after construction | 146.340 MiB | ≤512 MiB |
| Peak resident set | 341.742 MiB | ≤1024 MiB |
| Direct lookup throughput | 1,947,340 QPS | informational |
| Direct lookup median | 0.442 µs | <100 µs |
| Direct lookup p99 | 0.649 µs | informational |
| Complete DNS evaluation | 4,821,623 QPS | ≥25,000 QPS |
| Complete DNS median | 0.235 µs | informational |
| Complete DNS p99 | 0.255 µs | informational |
| Added DNS policy p99 | 0.068 µs | <2,000 µs |

The benchmark returned `passed: true`. External `/usr/bin/time` measured a
349,944 KiB maximum resident set for configuration, compilation, and the run
combined.

## Interpretation

The measurements cover policy construction and selected-packet processing in
one process. They do not substitute for a hardware forwarding test: NIC,
driver, bridge, nftables, queue scheduling, and interrupt behavior depend on
the appliance. Before deployment, compare unselected bridge throughput against
the same host bridge without JanusGate policy hooks and require at least 95%
of that baseline at 1 Gbit/s.

The base-process target is less than 128 MiB RSS without large lists. The
one-million-rule snapshot intentionally uses a separate, documented 512 MiB
steady-state budget. Run the benchmark after compiler, allocator, policy
representation, or dependency changes; never carry these results to a
different source revision.
