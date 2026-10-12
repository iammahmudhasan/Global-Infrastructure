# Threat Model: Hosting Blast Radius & Multi-Tenant Containment

> **Document Status:** Active Industrial Standard  
> **Classification:** Security Governance & Architectural Enforcement  
> **Applies to:** Data Plane, Control Plane, Physical Compute Substrates, and MicroVM Sandboxes  
> **Constitutional Priority Hierarchy:** $\mathbf{Correctness} > \mathbf{Security} > \mathbf{Reliability} > \mathbf{Maintainability} > \mathbf{Performance} > \mathbf{Speed}$

---

## 1. Executive Problem Statement

In an infrastructure and cloud hosting business, **a customer workload will eventually be compromised**. Attackers exploit vulnerable customer code (e.g., WordPress RCE, insecure deserialization, leaked credentials). 

Under legacy hosting architectures, a compromised guest container or VM frequently enables:
1. **Lateral Movement:** Probing adjacent tenant workloads over flat networks.
2. **Infrastructure Pivot:** Exploiting internal Control Plane ports (`:9091`, etcd, Raft, or link-local cloud metadata `169.254.169.254`).
3. **Outbound Weaponization:** Launching high-bandwidth DDoS attacks or sending bulk spam, causing the hosting provider's ASNs and IP ranges to be blacklisted globally.
4. **Hypervisor Breakout:** Kernel privilege escalation compromising the bare-metal host.

**NexusEdge Constitutional Mandate:** *A compromise of a customer's guest server MUST NEVER compromise other tenants, our internal control plane, or our network reputation.*

---

## 2. Threat Vector Taxonomy & Containment Matrix

```
┌────────────────────────────────────────────────────────────────────────┐
│                   ATTACKER COMPROMISES GUEST WORKLOAD                  │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         ▼                         ▼                         ▼
   [LATERAL MOVEMENT]     [INFRASTRUCTURE PIVOT]     [OUTBOUND ABUSE]
   • Cross-tenant probe   • SSRF to Metadata        • DDoS amplification
   • Packet sniffing      • Internal gRPC probe     • Port 25 Spam
   • Shared bridge access • DB credential theft     • Crypto-mining
         │                         │                         │
         ▼                         ▼                         ▼
 ┌───────────────┐        ┌──────────────────┐      ┌─────────────────┐
 │ eBPF / VPC    │        │ WAF SSRF Shield  │      │ Strict Egress   │
 │ MicroVM Jail  │        │ mTLS Auth Token  │      │ Filtering & BPF │
 └───────────────┘        └──────────────────┘      └─────────────────┘
         │                         │                         │
         └─────────────────────────┼─────────────────────────┘
                                   ▼
              CONTAINED BLAST RADIUS: GUEST ISOLATED ONLY
```

### Threat Breakdown:

| Threat ID | Threat Vector | Attack Mechanism | NexusEdge Containment Countermeasure |
|---|---|---|---|
| **THREAT-01** | **SSRF to Cloud Metadata** | Customer app tricked into querying `169.254.169.254` or internal IPs. | Line-rate WAF inspection blocks link-local/metadata patterns; eBPF drops all guest packets addressed to link-local metadata. |
| **THREAT-02** | **Tenant Lateral Movement** | Guest attempts ARP poisoning, MAC spoofing, or promiscuous sniffing. | MicroVM (Firecracker/gVisor) with dedicated tap devices; zero shared bridges. eBPF/XDP drops any inter-tenant traffic. |
| **THREAT-03** | **Internal Port Probing** | Compromised instance scans localhost or internal subnet for Control Plane (`:9091`). | Strict namespace isolation; host loopback is inaccessible to guests; Control Plane binds only to private mTLS management mesh. |
| **THREAT-04** | **Outbound DDoS Weaponization** | Attacker installs botnet daemon to send SYN/UDP floods outward. | Egress token-bucket rate limiting per instance; rate anomalies trigger automated quarantine. |
| **THREAT-05** | **Outbound Spam Abuse** | Attacker starts postfix/sendmail to blast spam emails. | TCP port 25 egress is blocked globally by default at the firewall/gateway layer. |
| **THREAT-06** | **Crypto-Mining Abuse** | Unauthorized Monero/cryptocurrency miner launched on GPU/CPU. | Heuristic CPU/GPU saturation monitoring; Stratum mining protocol signatures (ports 3333, 4444) blocked. |
| **THREAT-07** | **Host Hypervisor Escape** | Attacker exploits Linux kernel vulnerability to escape container. | Hardware-assisted virtualization (KVM + Firecracker MicroVMs) with seccomp-bpf system call filters, dropping dangerous syscalls. |

---

## 3. The 5 Defense-in-Depth Containment Boundaries

### Boundary 1: Compute Sandboxing & MicroVM Isolation
- Workloads run inside **Firecracker MicroVMs** or **gVisor** user-space kernels with distinct memory boundaries.
- Linux `cgroups v2` strictly cap CPU, RAM, IOPS, and process count (PIDs) to prevent noisy neighbor starvation and fork bombs.
- Root filesystems are ephemeral and read-only by default, with copy-on-write scratch spaces.

### Boundary 2: Network Virtualization & Zero-Trust Mesh
- Guests communicate exclusively over isolated point-to-point WireGuard or Geneve overlay tunnels.
- Default policy: **DENY ALL**. No customer instance can communicate with another customer instance unless an explicit inter-service policy is created by the same tenant.
- Link-local `169.254.0.0/16` and internal management subnets are dropped at the interface level.

### Boundary 3: Edge WAF & Application Gateway Ingress Shield
- All incoming web traffic is scrubbed by the Rust Edge Gateway WAF before hitting backends.
- Real-time rejection of OWASP Top 10 patterns (SQLi, XSS, Path Traversal, Command Injection).
- SSRF metadata signature blocking (`OWASP_CRS_SSRF_METADATA_ATTEMPT`).

### Boundary 4: Cryptographic Secret Envelopes (AES-256-GCM)
- Customer API credentials and database keys are never stored in plaintext on disk.
- All secrets are sealed in `enc:v1:...` envelopes with SHA-256 derived keys and 96-bit nonces.
- Internal service-to-service communication requires mutual TLS (mTLS) with short-lived rotated certificates.

### Boundary 5: Immutable Audit Logging & Automated Quarantining
- Every administrative action and anomaly trigger emits a cryptographically hash-chained audit record.
- If outbound egress or packet rates exceed 10x baseline thresholds, the Control Plane automatically isolates the tenant's instance into a quarantined network slice and notifies the operations team.
