<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Performance

## Policy benchmark

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

### Results

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

## Virtual appliance forwarding

The x86_64 firmware built from commit
`f5e64596db5a9b66762b5304da2d61832f9fab14` was measured in a three-VM
VirtualBox 7.2.14 laboratory. The appliance used two virtual CPUs, 2 GiB RAM,
and VirtIO adapters between a one-CPU router and a one-CPU client. Both peers
used 1 GiB RAM. The Linux 7.0.0 host ran on an Intel Core i7-13620H.

The router served the same 512 MiB object and certificate over HTTPS on two
ports. Port 8443 provided the unselected bridge control; port 443 traversed the
production nftables queue and TLS/SNI parser without a matching block rule.
Eight HTTP/1.1 transfers per port were alternated to limit ordering bias.

| HTTPS path | Median | Observed range | Control retained |
| --- | ---: | ---: | ---: |
| Unselected port 8443 | 3.535 Gbit/s | 3.269–3.675 Gbit/s | 100.0% |
| Selected port 443 | 3.593 Gbit/s | 3.230–3.792 Gbit/s | 101.6% |

All 16 transfers returned HTTP 200. JanusGate inspected 69,387 selected
packets and reported no blocked or malformed packets, queue drops, or queue
overflows. The small apparent gain on port 443 is within virtual-host run
variation; the result demonstrates no measurable regression in this sample,
not acceleration by inspection.

## Interpretation

The policy benchmark isolates construction and selected-packet evaluation in
one process. The virtual forwarding measurement adds the firmware bridge,
nftables queue, scheduling, and network drivers, but it does not substitute
for target-hardware validation: physical NICs, interrupts, and workload mixes
remain deployment-specific. Native rules select ingress TCP and UDP ports 53,
443, and 853, so common HTTPS and HTTP/3 traffic incurs queue-copy and
scheduling overhead even when no rule blocks it. Before deployment, compare
unselected and selected paths on the target appliance under the expected load
and require at least 95% of the unselected baseline at 1 Gbit/s.

The base-process target is less than 128 MiB RSS without large lists. The
one-million-rule snapshot intentionally uses a separate, documented 512 MiB
steady-state budget. Run the benchmark after compiler, allocator, policy
representation, or dependency changes; never carry these results to a
different source revision.
