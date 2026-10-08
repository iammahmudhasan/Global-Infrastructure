# AI Engineering Rules

## Global Infrastructure Platform

**Status:** Mandatory
**Scope:** Entire repository
**Applies to:** All AI coding agents and AI-assisted code generation
**Priority:** These rules override convenience, speed, and speculative implementation.

---

# 1. Mission

This repository is building a long-term global infrastructure platform spanning:

* Global networking
* DNS
* Edge infrastructure
* Security
* DDoS mitigation
* CDN and caching
* Compute
* GPU infrastructure
* Storage
* AI inference
* Global workload scheduling
* Developer infrastructure

Every AI-generated change must preserve the ability of this system to scale from an early-stage prototype to a globally distributed production infrastructure platform.

The AI must optimize for:

**Correctness > Security > Reliability > Maintainability > Performance > Development Speed**

Never reverse this order merely to ship faster.

---

# 2. First Rule: Understand Before Editing

Before changing code, the AI MUST:

1. Inspect the relevant repository structure.
2. Read the nearest `README.md`.
3. Read relevant architecture documentation.
4. Read applicable RFCs and ADRs.
5. Identify the owning domain/service.
6. Identify API/protobuf/event contracts involved.
7. Inspect existing tests.
8. Determine whether the requested change crosses an architectural boundary.

The AI MUST NOT immediately create new files or rewrite existing code based only on the user's one-line request.

If existing architecture already solves the problem, extend it instead of creating a parallel implementation.

---

# 3. Never Invent Architecture

The AI MUST NOT introduce a new:

* Framework
* Database
* Message broker
* Programming language
* Infrastructure orchestrator
* Networking technology
* Authentication system
* Serialization format

unless there is a clear technical reason and the change is consistent with existing architecture.

For major architectural changes:

```text
Problem
→ Analysis
→ RFC
→ Review
→ ADR
→ Implementation
```

Do not silently introduce architecture through code.

---

# 4. Repository Architecture Is Mandatory

The repository follows these primary boundaries:

```text
apps/
services/
dataplane/
intelligence/
libs/
proto/
schemas/
infra/
deploy/
tests/
benchmarks/
security/
docs/
rfcs/
adr/
tools/
```

The AI MUST preserve these boundaries.

## Data Plane

Primary technologies:

* Rust
* C
* eBPF
* XDP

Responsibilities:

* Packet processing
* High-performance networking
* L4/L7 fast paths
* Edge processing
* Security fast paths
* Low-latency execution

## Control Plane

Primary technology:

* Go

Responsibilities:

* APIs
* Resource management
* Controllers
* Scheduling
* Provisioning
* Configuration
* Billing
* Fleet management
* Desired-state reconciliation

## Intelligence Plane

Primary technology:

* Python
* PyTorch

Responsibilities:

* ML
* Optimization
* Forecasting
* Anomaly detection
* Capacity planning
* AI scheduling
* Model evaluation

## Product Layer

Primary technologies:

* TypeScript
* React
* Next.js

Responsibilities:

* Dashboard
* Developer tools
* Customer experience
* Documentation portals

---

# 5. Do Not Mix Data Plane and Control Plane

The AI MUST NOT move high-performance packet processing into ordinary Go control-plane services simply because it is easier to implement.

The AI MUST NOT put infrastructure orchestration logic inside a packet-processing daemon.

Correct:

```text
Control Plane
      ↓
Desired State / Policy
      ↓
Data Plane Configuration
      ↓
Packet Processing
```

Incorrect:

```text
Packet
 ↓
Database
 ↓
API
 ↓
Control Plane
 ↓
Packet Forwarding
```

Packets must never depend on a slow control-plane round trip for ordinary forwarding.

---

# 6. Dependency Direction

Allowed dependency direction:

```text
Product
  ↓
Control Plane
  ↓
Infrastructure Controllers
  ↓
Data Plane / Infrastructure
```

Intelligence:

```text
Intelligence
  ↓
Recommendations / Optimization
  ↓
Control Plane
```

The AI MUST NOT create circular dependencies.

Examples prohibited:

```text
network → compute → network
service A → service B internals
control plane → dashboard
dataplane → PostgreSQL
```

---

# 7. Internal Service Boundaries

A service MUST NOT import another service's private implementation.

Forbidden:

```text
services/a/internal/...
        ↓
services/b/internal/...
```

Required:

```text
Service A
   ↓
API / gRPC / Proto / Event
   ↓
Service B
```

Each service owns its own internal implementation.

---

# 8. Database Ownership

Each domain owns its data.

For example:

```text
billing → billing data
network → network data
compute → compute data
identity → identity data
```

A service MUST NOT directly query another domain's private database tables.

Forbidden:

```text
Compute Service
   ↓
SELECT * FROM billing_private_table
```

Required:

```text
Compute Service
   ↓
Billing API / Event
```

---

# 9. API Contracts Are Sacred

Public and internal APIs must be treated as compatibility contracts.

Source of truth:

```text
proto/
schemas/
```

The AI MUST NOT casually change:

* field names
* field types
* enum semantics
* required/optional behavior
* event payload meaning
* API response structure

Breaking API changes require explicit versioning.

Use:

```text
v1
v2
```

rather than silently changing `v1`.

---

# 10. Protobuf Rules

For protobuf:

* Use clear package names.
* Use semantic versioning of API packages.
* Never reuse deleted field numbers.
* Never reuse deleted field names when compatibility matters.
* Prefer additive changes.
* Run Buf linting and breaking-change checks.
* Keep generated code deterministic.

Example:

```text
proto/network/v1/router.proto
```

Not:

```text
proto/misc.proto
```

---

# 11. Event Rules

Events must be:

* Explicit
* Versioned
* Idempotency-aware
* Observable
* Documented

Example:

```text
instance.created.v1
route.changed.v1
billing.usage_recorded.v1
```

Events MUST NOT contain secrets.

Events should contain stable identifiers rather than unnecessary private data.

---

# 12. Desired State Architecture

Infrastructure must follow a reconciliation model whenever applicable:

```text
Desired State
      ↓
Controller
      ↓
Infrastructure
      ↓
Observed State
      ↓
Reconciliation
```

The AI MUST prefer controllers and reconciliation over one-off imperative scripts for long-lived infrastructure state.

Example:

Desired:

```text
10 edge nodes
```

Observed:

```text
8 edge nodes
```

Controller:

```text
Provision 2
```

---

# 13. Global vs Regional Architecture

Global infrastructure must distinguish:

```text
Global Control Plane
Regional Controller
PoP / Site Agent
Node Agent
```

Global responsibilities:

* Global policy
* Global scheduling
* Global routing intent
* Resource placement

Regional responsibilities:

* Local execution
* Local health
* Local reconciliation
* Local infrastructure state

The AI MUST NOT create an architecture where every packet or local infrastructure operation requires constant global control-plane availability.

---

# 14. Failure Is Normal

The AI MUST assume:

* Servers fail.
* Networks partition.
* Routers fail.
* Switches fail.
* DNS nodes fail.
* Databases become unavailable.
* Regions become isolated.
* GPU nodes disappear.
* Dependencies become slow.
* APIs return partial failures.
* Messages arrive more than once.
* Requests are retried.

Every distributed component must explicitly consider failure behavior.

---

# 15. No Single Point of Failure

When implementing production infrastructure, the AI MUST identify:

```text
Single process failure
Single host failure
Single rack failure
Single switch failure
Single router failure
Single transit failure
Single PoP failure
Single region failure
Control-plane degradation
Database replica failure
```

The implementation should document the intended behavior for each relevant failure mode.

---

# 16. Idempotency

All provisioning and mutating infrastructure operations should be safe to retry whenever technically applicable.

Examples:

```text
create server
attach volume
change DNS
deploy workload
provision IP
configure route
```

The AI should design:

```text
Request ID
Idempotency Key
Desired State
Reconciliation
```

rather than assuming requests will execute exactly once.

---

# 17. Security Is a Default Requirement

Security MUST NOT be treated as a later feature.

Every feature must consider:

* Authentication
* Authorization
* Input validation
* Secrets
* Encryption
* Isolation
* Rate limiting
* Auditability
* Abuse prevention
* Logging
* Privilege boundaries

---

# 18. Never Hardcode Secrets

The AI MUST NEVER commit:

* API keys
* Tokens
* Passwords
* Private keys
* Cloud credentials
* Database credentials
* JWT secrets
* Signing keys
* Production certificates

into source code.

Forbidden:

```go
const apiKey = "..."
```

Also forbidden:

```text
.env
credentials.json
private-key.pem
```

unless explicitly documented as an intentionally non-secret test fixture.

Use proper secret management.

---

# 19. Logs Must Never Leak Secrets

Do not log:

* Passwords
* API tokens
* Authorization headers
* Private keys
* Session cookies
* Sensitive customer information

Bad:

```text
Authorization: Bearer eyJ...
```

Good:

```text
authentication_failed request_id=...
```

Sensitive values must be redacted.

---

# 20. Least Privilege

Every component should receive the minimum permissions required.

Prefer:

```text
read-only
specific resource scope
specific operation scope
short-lived credentials
workload identity
```

Avoid:

```text
root
cluster-admin
global admin
full cloud credentials
```

unless genuinely required.

---

# 21. Authentication and Authorization

Do not build a custom authentication system when an existing standard mechanism is appropriate.

Prefer:

```text
OIDC
OAuth 2.0
WebAuthn
Passkeys
SPIFFE/SPIRE
```

Authorization should be explicit.

Every privileged API must answer:

```text
Who?
What resource?
What action?
Under what policy?
```

---

# 22. Network Security

For network-facing code, the AI must consider:

* DDoS
* spoofing
* malformed packets
* connection exhaustion
* protocol abuse
* amplification attacks
* rate limits
* ACLs
* route leaks
* BGP mistakes
* RPKI
* tenant isolation

Never assume that Internet traffic is well-formed.

---

# 23. Untrusted Input

All external input is untrusted.

Validate:

* Length
* Type
* Encoding
* Ranges
* IDs
* URLs
* IP addresses
* Ports
* Headers
* JSON
* Protobuf payloads
* Configuration files

Avoid:

```text
panic on malformed user input
buffer overflow
unsafe parsing
unbounded allocations
unbounded recursion
```

---

# 24. Unsafe Code

Rust `unsafe` is allowed only when technically necessary.

Every `unsafe` block must have:

1. A clear reason.
2. A safety invariant.
3. Minimal scope.
4. Tests validating assumptions.

Bad:

```rust
unsafe {
    // performance
}
```

Good:

```rust
// SAFETY:
// The buffer is guaranteed to remain alive for the duration...
unsafe {
    ...
}
```

Do not use `unsafe` merely because safe Rust is inconvenient.

---

# 25. Performance-Critical Code

Do not optimize based on intuition.

Required process:

```text
Implement
 ↓
Benchmark
 ↓
Profile
 ↓
Identify bottleneck
 ↓
Optimize
 ↓
Benchmark again
```

The AI MUST NOT claim:

> "This is faster"

without benchmark evidence when performance is a central requirement.

Relevant metrics:

```text
throughput
p50
p95
p99
p99.9
CPU utilization
memory usage
allocations
GC pressure
packets/sec
Gbps
requests/sec
```

---

# 26. Data Plane Performance

Data-plane code should minimize:

* unnecessary allocations
* locks
* context switches
* copies
* heap churn
* serialization
* syscalls
* database access
* control-plane calls

The AI should prefer:

```text
zero-copy
batching
lock-free structures where justified
CPU locality
cache locality
preallocation
async I/O where appropriate
```

But optimization must be justified by profiling.

---

# 27. Control Plane Correctness

For control-plane systems, correctness is more important than raw speed.

Prioritize:

```text
consistency
validation
idempotency
retry safety
auditability
observability
clear state transitions
```

Do not sacrifice correctness for micro-optimizations.

---

# 28. AI / Intelligence Layer Rules

AI may recommend:

```text
route
placement
capacity
scaling
model
region
GPU
```

But AI MUST NOT silently bypass deterministic safety policies.

Correct:

```text
AI Recommendation
      ↓
Policy Validation
      ↓
Safety Constraints
      ↓
Final Decision
```

Not:

```text
LLM
 ↓
Production infrastructure mutation
```

without validation.

---

# 29. AI Must Never Be the Sole Source of Truth

Machine-learning predictions must not become authoritative infrastructure state.

For important decisions:

```text
Observed facts
+
Deterministic constraints
+
ML prediction
=
Decision
```

The system must remain operational when the ML component is:

* unavailable
* wrong
* stale
* degraded
* hallucinating
* out of distribution

---

# 30. Deterministic Fallbacks

Every AI-assisted infrastructure feature should define a fallback.

Example:

```text
AI scheduler available
→ intelligent placement

AI scheduler unavailable
→ deterministic least-loaded placement
```

Never:

```text
AI unavailable
→ production outage
```

---

# 31. Model Changes

AI models used in production must be versioned.

Track:

```text
model version
dataset version
training configuration
evaluation metrics
deployment date
rollback version
```

Never silently replace a production model.

---

# 32. No Blind Dependency Addition

Before adding a dependency, the AI MUST evaluate:

* Is it already in the repository?
* Is the functionality already available?
* Is the dependency maintained?
* Is the license compatible?
* Is it security-sensitive?
* Does it significantly increase binary size?
* Does it increase supply-chain risk?
* Is there a strong reason to add it?

Do not add a dependency for a trivial utility function.

---

# 33. Prefer Existing Battle-Tested Infrastructure

Do not rewrite mature infrastructure without a measurable reason.

Prefer established components where appropriate:

```text
Linux
Kubernetes
Envoy
FRR
PowerDNS
Cilium
Ceph
PostgreSQL
NATS
OpenTelemetry
KVM
Firecracker
```

Build custom technology only when it creates meaningful technical advantage.

---

# 34. Custom Code Must Create Moat

Custom engineering should focus on:

```text
Global routing
Workload scheduling
Capacity intelligence
Traffic intelligence
AI placement
Network automation
Infrastructure policy
Global control plane
```

Do not spend core engineering time rebuilding mature generic components unless necessary.

---

# 35. Error Handling

Errors must be explicit.

Do not:

```text
ignore errors
panic without reason
swallow exceptions
return empty success
```

Bad:

```go
result, _ := database.Query(...)
```

Good:

```go
result, err := database.Query(...)
if err != nil {
    return fmt.Errorf("query instances: %w", err)
}
```

---

# 36. Error Messages

Errors should contain enough context for debugging without leaking secrets.

Good:

```text
failed to provision instance project_id=... region=... request_id=...
```

Bad:

```text
something went wrong
```

Never include credentials or sensitive payloads.

---

# 37. Timeouts

Every external network/API operation should have an explicit timeout where appropriate.

Never create an unbounded request path such as:

```text
request → external dependency → wait forever
```

Distributed systems must have:

```text
timeout
retry policy
backoff
circuit breaking where applicable
```

---

# 38. Retries

Retries must be deliberate.

Use:

```text
exponential backoff
jitter
bounded retry count
idempotency
```

Do not blindly retry:

```text
every HTTP error
every database error
every mutation
```

A retry can make an outage worse.

---

# 39. Concurrency

The AI must reason about:

* races
* deadlocks
* starvation
* duplicate work
* ordering
* cancellation
* resource leaks

For asynchronous code, every task must have a lifecycle.

Do not create background tasks that have no cancellation or shutdown behavior.

---

# 40. Resource Lifecycle

Every acquired resource must have a clear release path.

Examples:

```text
socket
file
connection
goroutine
thread
memory
GPU allocation
Kubernetes resource
database transaction
lease
lock
```

The AI must consider:

```text
success
error
timeout
cancellation
shutdown
panic
```

---

# 41. Graceful Shutdown

Production services should support:

```text
SIGTERM
drain
stop accepting new work
finish safe in-flight work
close connections
flush telemetry
exit
```

Never assume processes will always terminate cleanly.

---

# 42. Observability Is Mandatory

New production services must expose appropriate:

```text
metrics
logs
traces
health
readiness
```

Use:

```text
OpenTelemetry
Prometheus-compatible metrics
structured logging
distributed tracing
```

Important infrastructure metrics should be explicitly named and documented.

---

# 43. Request IDs and Correlation

Requests crossing services must be traceable.

Preferred:

```text
request_id
trace_id
span_id
```

A production incident should allow engineers to follow:

```text
Customer request
 ↓
API Gateway
 ↓
Control Plane
 ↓
Scheduler
 ↓
Regional Controller
 ↓
Node
 ↓
Workload
```

---

# 44. Health Checks

Services should distinguish:

```text
liveness
readiness
startup
```

A service being alive does not mean it is ready to serve production traffic.

Do not make readiness depend on every non-critical external dependency.

---

# 45. Testing Is Required

Every meaningful code change must include appropriate tests.

At minimum, choose from:

```text
unit
integration
contract
e2e
network
security
performance
fuzz
chaos
```

based on the type of change.

---

# 46. Test Pyramid

Prefer:

```text
          E2E
        /──────\
      Integration
    /────────────\
       Unit Tests
```

Do not attempt to solve everything with slow end-to-end tests.

---

# 47. Network Code Requires Special Testing

Network-facing code should consider:

```text
malformed packets
fragmentation
IPv4
IPv6
TCP
UDP
HTTP
TLS
connection exhaustion
packet loss
reordering
latency
MTU differences
route changes
```

Where appropriate, use:

```text
fuzzing
packet generators
network emulation
hardware-in-the-loop
```

---

# 48. Security Testing

Security-sensitive changes should consider:

```text
fuzzing
dependency scanning
static analysis
secret scanning
SBOM
container scanning
permission tests
authz tests
abuse scenarios
```

---

# 49. Performance Regression Protection

Performance-sensitive code must have regression benchmarks.

Do not merge a change that significantly degrades:

```text
latency
throughput
memory
CPU
packet rate
GPU utilization
```

without documenting why the regression is acceptable.

---

# 50. Infrastructure Changes Need Rollback

Any production infrastructure change should answer:

```text
How is this deployed?
How is it canaried?
How is it monitored?
How is it rolled back?
```

Preferred:

```text
test
→ staging
→ canary
→ small percentage
→ regional expansion
→ global rollout
```

Avoid immediate global rollout for risky changes.

---

# 51. Configuration Changes

Configuration must be:

* Versioned
* Validated
* Reviewable
* Tested
* Observable

Never introduce configuration that can silently put the network into an unsafe state.

---

# 52. BGP / Routing Changes

Routing changes are high-risk.

AI-generated routing changes must receive extra validation.

Before applying:

```text
syntax validation
policy validation
topology validation
simulation where possible
RPKI checks
route sanity checks
blast-radius analysis
```

Production route changes should support:

```text
rollback
canary
automatic safety limits
```

---

# 53. DNS Changes

AI must treat DNS as production-critical.

Consider:

```text
TTL
propagation
DNSSEC
negative caching
authoritative availability
zone validation
rollback
```

Never blindly overwrite an entire zone when an additive record change is sufficient.

---

# 54. Customer Isolation

Any multi-tenant feature must explicitly consider:

```text
tenant IDs
resource ownership
authorization
network isolation
data isolation
storage isolation
compute isolation
logging isolation
billing isolation
```

A customer must never be able to access another customer's resources through an ID guessing attack or missing authorization check.

---

# 55. Never Trust IDs

This is forbidden:

```text
GET /instances/{id}
→ query DB
→ return instance
```

without verifying ownership/authorization.

Required conceptual flow:

```text
identity
 ↓
organization
 ↓
project
 ↓
resource
 ↓
authorization
 ↓
access
```

---

# 56. API Design

APIs must be:

* Predictable
* Consistent
* Versioned
* Idempotent where needed
* Observable
* Secure

Use consistent:

```text
pagination
error formats
request IDs
timestamps
resource IDs
status semantics
```

Do not create every endpoint with a different response format.

---

# 57. Naming

Names must describe domain concepts.

Prefer:

```text
global-router
traffic-manager
gpu-controller
edge-runtime
billing-meter
```

Avoid:

```text
core-service
main-service
backend
misc
utils
helper
common-service
```

Avoid ambiguous abbreviations.

---

# 58. Code Organization

Keep files focused.

A file should not become a dumping ground for unrelated logic.

Avoid:

```text
5000-line service.go
8000-line utils.ts
```

Prefer domain-specific modules.

---

# 59. `utils`, `common`, `helpers`

Use these extremely carefully.

Do not create:

```text
libs/utils/everything.go
```

Shared code must represent a clear capability:

```text
libs/go/telemetry
libs/go/auth
libs/rust/crypto
libs/rust/http
```

---

# 60. Comments

Comments should explain:

```text
why
```

not merely:

```text
what
```

Bad:

```go
// increment counter
counter++
```

Good:

```go
// Increment after successful admission so rejected requests do not
// affect capacity calculations.
counter++
```

---

# 61. Public APIs Need Documentation

Every externally exposed API must have:

* Purpose
* Inputs
* Outputs
* Errors
* Authentication requirements
* Authorization behavior
* Rate limits where relevant
* Idempotency semantics
* Example request
* Example response

---

# 62. No Dead Code

Do not leave abandoned experiments inside production code.

Use:

```text
git branches
feature flags
experiments/
prototypes/
```

for experimental work.

Remove obsolete implementations after migration.

---

# 63. Feature Flags

Use feature flags for risky rollouts where appropriate.

Preferred:

```text
disabled
→ internal
→ canary
→ 5%
→ 25%
→ 50%
→ 100%
```

Avoid hard-coded emergency switches scattered throughout code.

---

# 64. Backward Compatibility

The AI must prefer backward-compatible migrations.

Example:

```text
old field
+
new field
↓
dual read
↓
migration
↓
new field only
↓
remove old field
```

Do not destroy compatibility merely because the new design is cleaner.

---

# 65. Database Migrations

Every schema change must:

1. Have a migration.
2. Be reversible where practical.
3. Consider existing production data.
4. Consider long-running queries.
5. Avoid unnecessary table locks.
6. Be tested against realistic data sizes.

Do not casually run destructive migrations in application startup.

---

# 66. Storage

For distributed storage, always consider:

```text
durability
replication
consistency
repair
scrubbing
corruption
backup
restore
regional failure
```

Never assume replication automatically means backup.

---

# 67. Backup

Every persistent critical system should answer:

```text
What is backed up?
How often?
Where?
How long retained?
How encrypted?
How restored?
How tested?
```

A backup that has never been restored is not a proven backup strategy.

---

# 68. Disaster Recovery

Critical systems should document:

```text
RPO
RTO
failover
restore
regional recovery
data consistency
dependency recovery
```

The AI must not claim disaster recovery readiness without actually validating the recovery path.

---

# 69. Third-Party Systems

External dependencies must be treated as unreliable.

Always consider:

```text
dependency unavailable
dependency slow
dependency returns malformed response
dependency changes behavior
dependency rate-limits
dependency credentials expire
```

Design appropriate fallback behavior.

---

# 70. Supply Chain Security

Every production dependency should be traceable.

Prefer:

```text
SBOM
dependency pinning
signature verification
security scanning
reproducible builds where practical
```

Do not casually execute downloaded code during builds.

---

# 71. Reproducible Builds

Builds should be deterministic wherever practical.

Pin:

```text
compiler versions
dependency versions
base images
tool versions
code generation versions
```

Avoid:

```text
latest
```

for critical production dependencies.

---

# 72. Docker / Container Rules

Production images should:

* Be minimal.
* Run as non-root when possible.
* Have pinned base images.
* Expose only necessary ports.
* Avoid unnecessary packages.
* Include health behavior where appropriate.
* Be scanned.
* Have SBOM metadata.

---

# 73. Kubernetes Rules

Kubernetes resources must have:

```text
resource requests
resource limits where appropriate
probes
security context
network policies where required
pod disruption considerations
```

Avoid creating workloads that silently consume unlimited cluster resources.

---

# 74. Infrastructure as Code

Infrastructure must be represented declaratively whenever practical.

Prefer:

```text
OpenTofu
Helm
Kubernetes manifests
GitOps
```

Avoid undocumented manual production changes.

If a manual emergency change occurs, reconcile it back into source control.

---

# 75. Local Development

A developer must be able to reproduce important development paths locally.

Provide:

```text
local dependencies
test data
development configuration
startup scripts
health checks
```

Do not make engineers depend on undocumented personal infrastructure.

---

# 76. AI Must Preserve Existing Functionality

Before changing code:

```text
Understand current behavior.
```

After changing code:

```text
Run relevant tests.
```

The AI MUST NOT “clean up” unrelated code during a feature implementation.

---

# 77. Minimal Change Principle

Make the smallest coherent change that solves the problem.

Avoid:

```text
feature request
→ rewrite subsystem
→ rename 70 files
→ introduce 8 dependencies
```

unless the rewrite is explicitly required.

---

# 78. No Opportunistic Refactoring

Do not mix:

```text
feature
+
large refactor
+
dependency migration
+
formatting entire repository
```

in one change.

Keep changes reviewable.

---

# 79. Formatting

Use repository-defined formatters.

Do not manually invent formatting conventions.

Expected tooling may include:

```text
rustfmt
gofmt
Ruff
Prettier
ESLint
Buf
```

---

# 80. Static Analysis

Run relevant static analysis before considering work complete.

Examples:

```text
Rust:
clippy

Go:
go vet
staticcheck where configured

Python:
Ruff
mypy where configured

TypeScript:
tsc
ESLint

Protobuf:
buf lint
buf breaking
```

---

# 81. Test Before Claiming Completion

AI MUST NOT say:

> "Done"

until it has actually determined what validation is possible.

Correct wording:

```text
Implemented.
Unit tests pass.
Integration tests not run because dependency X is unavailable.
```

Never fabricate successful tests, deployments, benchmarks, or security scans.

---

# 82. Environment Limitations

If a required tool is unavailable, the AI must explicitly state:

```text
what was not run
why it was not run
what was validated instead
```

It must never pretend that a test passed because it “should pass”.

---

# 83. No Fabricated Metrics

The AI must never invent:

```text
latency
throughput
cost
availability
CPU utilization
GPU utilization
benchmark improvements
security coverage
```

Measurements must come from actual execution or explicitly labeled estimates.

---

# 84. Benchmark Claims

Never write:

> 30% faster

unless an actual benchmark demonstrates it.

Prefer:

```text
Benchmark:
baseline: X
new: Y
workload: Z
hardware: A
iterations: B
result: C
```

---

# 85. Incident Safety

When modifying critical infrastructure, assume an unexpected failure may happen.

The implementation should support:

```text
safe failure
rollback
observability
audit logs
rate limits
blast-radius control
```

Do not optimize solely for the happy path.

---

# 86. Production Safety

The AI MUST NOT automatically make destructive production changes merely because a user says:

> "fix production"

unless the execution environment and authorization explicitly permit it.

Dangerous actions include:

```text
delete database
delete production resources
change BGP routes
rotate production keys
disable security
destroy storage
remove customer resources
```

These require explicit authorization and validation.

---

# 87. Never Disable Security to Make Tests Pass

Forbidden shortcuts:

```text
disable TLS
disable auth
disable authorization
allow all traffic
disable certificate validation
run everything as root
disable tenant isolation
```

Test-specific bypasses must be isolated to test environments.

---

# 88. No Silent Fallback to Unsafe Defaults

If secure configuration is missing:

Prefer:

```text
fail closed
```

rather than:

```text
disable security
```

Example:

```text
missing auth policy
→ reject request
```

not:

```text
missing auth policy
→ allow request
```

---

# 89. Rate Limiting

Internet-facing systems should consider resource exhaustion.

Rate limiting should be:

```text
tenant-aware
identity-aware
endpoint-aware
resource-aware
distributed where necessary
```

Do not rely on a single local process counter for a global distributed rate limit unless that's the intended behavior.

---

# 90. Caching

Caching logic must explicitly define:

```text
cache key
TTL
invalidation
staleness
ownership
privacy
tenant isolation
failure behavior
```

Never cache sensitive tenant data under a shared key.

---

# 91. Networking Documentation

Any new networking subsystem must document:

```text
traffic flow
protocols
ports
state
failure modes
routing
security
dependencies
```

A future engineer must be able to understand how packets move through the system.

---

# 92. Architecture Diagrams

Major systems should have an architecture diagram.

At minimum document:

```text
request path
control path
data path
failure path
deployment path
```

---

# 93. RFC Requirements

Create an RFC when a change affects:

* Public API
* Data model
* Global routing
* Network architecture
* Storage architecture
* Security model
* Multi-region topology
* Scheduler
* Edge runtime
* Major technology choice

RFCs should answer:

```text
Problem
Goals
Non-goals
Existing system
Proposed design
Alternatives
Trade-offs
Failure modes
Migration
Rollout
Rollback
Security
Observability
```

---

# 94. ADR Requirements

After a significant architecture decision is made, create an ADR describing:

```text
Decision
Context
Alternatives
Reason
Consequences
```

Never rely solely on people's memory.

---

# 95. Ownership

Every production subsystem should have a clear owner.

Recommended metadata:

```text
OWNER
PRIMARY_TEAM
SECURITY_OWNER
ON_CALL
```

Use `CODEOWNERS` for review ownership.

---

# 96. Commits

Commits should be:

* Small
* Coherent
* Descriptive
* Reviewable

Prefer:

```text
feat:
fix:
refactor:
perf:
test:
docs:
build:
chore:
security:
```

Avoid:

```text
update
changes
stuff
final
final2
fixagain
```

---

# 97. Pull Requests

A PR should explain:

```text
What changed?
Why?
Architecture impact?
Security impact?
Testing?
Performance impact?
Migration?
Rollback?
```

A reviewer should not have to reverse-engineer the reason for the change.

---

# 98. AI-Generated Code Must Look Human-Maintainable

Do not generate:

* absurd abstraction layers
* over-generic code
* unnecessary design patterns
* massive helper frameworks
* unreadable one-liners
* meaningless comments
* repetitive wrappers

Readable, boring code is often preferable to clever code.

---

# 99. Prefer Explicitness in Infrastructure

Infrastructure code should make important behavior obvious.

Prefer:

```text
explicit configuration
explicit errors
explicit state transitions
explicit policies
explicit timeouts
explicit ownership
```

Avoid hidden magic.

---

# 100. Backpressure

Every high-throughput system should consider:

```text
queue growth
memory pressure
consumer lag
downstream saturation
retry storms
```

Never allow an unbounded queue unless explicitly justified.

---

# 101. Queue Semantics

When using asynchronous messaging, explicitly define:

```text
at-most-once
at-least-once
exactly-once illusion
ordering
deduplication
retention
replay
dead-letter behavior
```

Assume messages may be delivered more than once unless the architecture explicitly guarantees otherwise.

---

# 102. Distributed Locks

Locks must have:

```text
timeout
ownership
renewal
release
failure behavior
```

Do not create permanent locks.

Prefer leases when appropriate.

---

# 103. Time and Clocks

Distributed systems must not assume perfect clocks.

Consider:

```text
clock skew
UTC
monotonic clocks
expiration
lease renewal
timestamp ordering
```

Use monotonic time for duration measurement where appropriate.

---

# 104. IDs

IDs should be:

* Stable
* Unique within intended scope
* Non-secret
* Suitable for logging
* Hard to accidentally collide

Do not expose database auto-increment IDs as a security boundary.

---

# 105. Data Privacy

Only collect data that is necessary.

The AI must consider:

```text
PII
customer logs
IP addresses
request metadata
location
billing data
credentials
```

Do not copy sensitive data into:

```text
debug logs
test fixtures
analytics
developer notebooks
```

without justification and protection.

---

# 106. Data Residency

Any feature that moves customer data across regions must consider:

```text
data residency
customer policy
regulatory constraints
encryption
replication
storage locality
```

Do not automatically replicate everything globally.

---

# 107. Observability Data Is Also Data

Logs and telemetry can contain sensitive customer information.

Apply:

```text
retention
access control
redaction
encryption
tenant isolation
```

to observability data too.

---

# 108. Cost Awareness

Infrastructure code must consider cost.

Where relevant measure:

```text
CPU
RAM
storage
bandwidth
GPU
API requests
egress
power
```

The AI should not introduce expensive polling or unnecessary cross-region traffic.

---

# 109. Cross-Region Traffic

Do not casually make:

```text
Region A
 ↓
Region B
 ↓
Region C
```

requests for ordinary control operations.

Cross-region communication should be deliberate because it impacts:

```text
latency
cost
availability
data sovereignty
failure propagation
```

---

# 110. Global Routing Rules

Routing decisions should be based on explicit signals.

Potential inputs:

```text
latency
health
capacity
network congestion
cost
policy
data residency
GPU availability
model availability
```

Do not make routing behavior depend on arbitrary hard-coded location lists unless documented.

---

# 111. Scheduler Safety

Schedulers must never knowingly:

```text
overcommit unavailable capacity
violate tenant limits
cross residency constraints
bypass security policy
create resource loops
```

A scheduler should return explainable decisions.

Example:

```text
Selected:
Singapore GPU cluster

Reason:
latency 22 ms
capacity available
policy allowed
estimated cost lower
model available
```

---

# 112. AI Decisions Should Be Explainable

For important automated infrastructure decisions, retain decision metadata.

Example:

```json
{
  "decision": "region-singapore",
  "reason_codes": [
    "LOW_LATENCY",
    "GPU_AVAILABLE",
    "POLICY_ALLOWED"
  ]
}
```

This is important for debugging and customer trust.

---

# 113. AI Rollback

Any production AI component should support:

```text
model rollback
policy rollback
configuration rollback
scheduler fallback
```

Never make the newest model irreversible.

---

# 114. No Hidden Model Calls

Production code must not unexpectedly call external AI APIs.

AI dependencies must be explicit and documented.

Do not embed:

```text
OpenAI
Anthropic
Google
other third-party model calls
```

into infrastructure code without architectural approval.

---

# 115. External AI Must Never Receive Secrets

Never send the following to an external model:

```text
private keys
customer credentials
production tokens
raw confidential logs
unfiltered customer data
```

unless an explicitly approved security architecture requires it.

---

# 116. Prompt Injection Defense

If customer-controlled text reaches AI systems, treat it as untrusted input.

Never allow customer text to override:

```text
system policies
authorization
security controls
tool permissions
infrastructure constraints
```

---

# 117. Tools Used by AI Agents

AI agents operating infrastructure must follow:

```text
least privilege
read-only by default
explicit mutation tools
audit logging
resource scope
approval requirements
```

A tool capable of:

```text
delete resource
change route
rotate key
```

must be separately protected from ordinary read operations.

---

# 118. Never Hide Failures

Do not turn infrastructure failures into fake success responses.

Bad:

```text
provision failed
→ return 200 "success"
```

Good:

```text
provision failed
→ explicit failure
→ structured error
→ telemetry
→ retry/fallback if safe
```

---

# 119. Keep State Machines Explicit

Complex resources should have explicit lifecycle states.

Example:

```text
PENDING
→ PROVISIONING
→ READY
→ DEGRADED
→ DRAINING
→ DELETING
→ DELETED
```

Do not encode complicated lifecycle logic as scattered booleans.

---

# 120. When in Doubt

When requirements are ambiguous, the AI should choose the safest interpretation that preserves architecture and existing behavior.

The AI must not invent business rules.

For unresolved product requirements:

```text
preserve existing behavior
+
document assumption
+
keep implementation reversible
```

---

# 121. Final Completion Checklist

Before considering a task complete, the AI must mentally verify:

```text
[ ] Correct domain?
[ ] Correct architectural boundary?
[ ] Existing code inspected?
[ ] Existing behavior preserved?
[ ] API contracts preserved?
[ ] Database ownership preserved?
[ ] Security reviewed?
[ ] Tenant isolation reviewed?
[ ] Failure modes considered?
[ ] Timeouts considered?
[ ] Retries safe?
[ ] Idempotency considered?
[ ] Observability added?
[ ] Tests added/updated?
[ ] Performance measured when relevant?
[ ] No secrets added?
[ ] No unnecessary dependencies?
[ ] No unrelated refactor?
[ ] Documentation updated?
[ ] Migration considered?
[ ] Rollback considered?
[ ] Actual validation performed?
[ ] No fabricated test/benchmark claims?
```

---

# 122. Absolute Rules

The following are non-negotiable:

### NEVER

* Commit secrets.
* Invent test results.
* Invent benchmark results.
* Disable security to make code work.
* Bypass authorization.
* Cross service private boundaries.
* Directly access another domain's database.
* Introduce dependencies without justification.
* Make destructive production changes without authorization.
* Put packet-path logic behind unnecessary control-plane calls.
* Make AI the sole authority for critical infrastructure decisions.
* Hide errors.
* Claim completion without validation.
* Rewrite mature infrastructure without a strong reason.

### ALWAYS

* Preserve architecture.
* Validate external input.
* Use least privilege.
* Add observability.
* Test meaningful changes.
* Consider failure.
* Consider rollback.
* Prefer idempotent operations.
* Keep APIs versioned and compatible.
* Document major architecture decisions.
* Measure performance rather than guessing.
* Make AI decisions bounded by deterministic policy.
* Optimize for correctness and long-term maintainability.

---

# 123. Engineering Philosophy

The goal is not to produce the most code.

The goal is to produce the smallest amount of correct, secure, observable, maintainable code that can become part of a globally distributed infrastructure system.

Every implementation should ask:

> **Will this still make sense when this system operates across hundreds of PoPs, thousands of nodes, millions of workloads, multiple continents, and thousands of engineers?**

If the answer is no, redesign it before merging.

---

# 124. Architectural Graph Anchor Mandate

Before generating, modifying, or deleting code for any milestone or subsystem, the agent MUST construct and output a complete architectural relationship graph (Mermaid diagram). The graph must explicitly illustrate:
* Component boundaries
* Data-plane vs. control-plane vs. intelligence-plane paths
* Data stores and state synchronization loops
* External dependencies and physical boundaries (clearly separating SIMULATED vs. LIVE infrastructure)
* Failure transitions and fallbacks

This visually anchors the system topology and prevents architectural drift, false assumptions, or blind patching.

---

# 125. The 4-Question Code Justification Mandate

Before writing OR deleting any code in the codebase, the agent MUST explicitly define and document:
1. **WHERE:** The exact file path, package, and layer (Data Plane / Control Plane / Intelligence).
2. **WHY:** The concrete technical and business requirement driving this addition/deletion.
3. **IMPACT:** What happens when this code is written (operational behavior, state transitions, outputs).
4. **RISK OF OMISSION:** What breaks, what fails, or what security/reliability hole opens up if this code is NOT written.

---

# 126. Cleanliness & Industrial Discipline Mandate

Every file, module, and commit must adhere to strict industrial discipline:
* **Zero Unused Code:** No dead functions, unused struct fields, orphaned files, or dangling imports.
* **Zero Zombie Comments:** No commented-out dead code blocks.
* **No Gratuitous Emojis:** Keep production code, type definitions, log messages, and comments strictly industrial, professional, and free of emoji clutter.
* **Honest Subsystem Status:** Never label simulated or prototype capabilities as production-ready. Clearly distinguish `SIMULATED` vs `PRODUCTION`.

---

# 127. Pre-Push CI Parity Mandate (Zero CI Failure Protocol)

No commit or push shall ever be made to `origin/main` without first executing and passing the complete local CI parity verification suite matching `.github/workflows/ci.yml`.

Functional compilation alone is strictly insufficient. All formatting, linting, and compiler gates MUST be verified clean locally before pushing:

1. **Go Format Gate:** `gofmt -l .` must return zero unformatted files across all Go services (`services/edge/config-controller`, `services/network/global-router`, etc.).
2. **Go Vet Gate:** `go vet ./...` must exit 0 across all services.
3. **Go Test Gate:** `go test -v ./...` must exit 0 across all services.
4. **Rust Format Gate:** `cargo fmt --manifest-path dataplane/edge/gateway/Cargo.toml --all -- --check` must exit 0.
5. **Rust Clippy Gate:** `cargo clippy --manifest-path dataplane/edge/gateway/Cargo.toml --all-targets --all-features -- -D warnings` must exit 0 with zero warnings.
6. **Rust Check & Test Gate:** `cargo check` and `cargo test` must exit 0.
7. **Python Intelligence Gate:** `python intelligence/scheduling/workload-scheduler/optimizer.py` must exit 0.

Verification can be executed in one step via:
* Windows: `powershell -ExecutionPolicy Bypass -File tools/ci/verify-ci.ps1`
* Linux / macOS: `bash tools/ci/verify-ci.sh`
* Makefile: `make verify-ci`

Pushing code that subsequently fails remote GitHub Actions CI due to skipped local formatting, linting, or test checks is a direct constitutional breach.

