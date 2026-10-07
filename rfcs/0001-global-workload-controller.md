# RFC 0001: The Global Workload Controller & Universal Placement Engine

- **Author:** Mahmud Hasan
- **Status:** Draft / Active Review
- **Date:** 2026-10-07

## 1. Summary
This RFC proposes the architecture for the **Global Workload Controller**, which unifies heterogeneous compute nodes (bare-metal, K8s pods, Firecracker microVMs, and multi-cloud GPU instances) under a single declarative API.

## 2. Motivation
Instead of forcing developers to pick cloud regions and instance types, the controller evaluates real-time latency, GPU memory availability, grid power carbon metrics, and legal sovereignty (NDMA 2026) to place and dispatch workloads dynamically.

## 3. Proposal
The controller exposes `POST /api/v1/workload/dispatch` and receives a `WorkloadSpec` protobuf message. It executes a mathematical multi-objective scoring pass across candidate nodes and dispatches traffic via Envoy and the Rust fast-path in under 1ms.
