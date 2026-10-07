# ADR 0002: Rust for Data Plane & Go for Control Plane

## Status
Accepted

## Context
A common failure mode in infrastructure companies is using a garbage-collected language (like Go or Java) for line-rate L4/L7 ingress, resulting in unpredictable p99 latency spikes due to GC pauses, or conversely using C/C++ everywhere, introducing memory corruption risks and slow developer iteration cycles.

## Decision
- All packet-processing, L4/L7 proxying, caching, WAF, and WebAssembly execution must be written in **Rust** (with kernel eBPF/XDP hooks in C).
- All cluster management, API gateways, Kubernetes operators, IAM, schedulers, and billing must be written in **Go**.

## Consequences
- Zero-cost memory safety on critical user-traffic paths.
- Rapid developer velocity for distributed microservices in the control plane.
