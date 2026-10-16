# NexusEdge Comprehensive Threat Model & Trust Boundaries Specification

> **Standards Alignment:** OWASP ASVS v4.0.3 (Level 2/3), NIST SSDF (SP 800-218), CISA Secure by Design  
> **Constitutional Rulebook:** [docs/AI_ENGINEERING_RULES.md](../../docs/AI_ENGINEERING_RULES.md) (Rules 1, 18, 23, 54, 55, 124–127)  
> **Platform Mission:** Zero-Trust, Sovereign, Line-Rate Global Edge Network

---

## 1. System Topology & Trust Boundaries (OWASP ASVS V1)

```
 [ UNTRUSTED WORLD (Public Internet) ]
                  │
                  ▼ TLS 1.3 Termination (Port 443 / 80)
   ┌────────────────────────────────────────────────────────┐
   │ TRUST BOUNDARY 1: Edge Envoy Ingress                   │
   │ - Dynamic Cert Discovery (sds.json)                    │
   │ - Header Sanitization & Strict Request-Smuggling Guard │
   │ - Rate Limiting & TLS Fingerprint Extraction           │
   └───────────────────┬────────────────────────────────────┘
                       │
         ┌─────────────┴─────────────┐
         ▼                           ▼
 ┌──────────────────────┐    ┌──────────────────────────────────┐
 │ TRUST BOUNDARY 2:    │    │ TRUST BOUNDARY 3:                │
 │ Rust Data Plane      │    │ Dashboard BFF (:3000)            │
 │ Gateway (:8080)      │    │ - Cookie HMAC & CSRF Protection  │
 │ - Zero-Alloc RingBuf │    │ - Rate Limiting per IP           │
 │ - Bounded Reads      │    │ - Upstream Token Isolation       │
 └──────────┬───────────┘    └──────────────────┬───────────────┘
            │                                   │
            │  HMAC-SHA256 Service Token        │
            └─────────────┬─────────────────────┘
                          ▼
   ┌────────────────────────────────────────────────────────┐
   │ TRUST BOUNDARY 4: Go Control Plane (:9091)             │
   │ - Strict Server-Side RBAC Guard (Token + Project + Role)│
   │ - S3 Sovereign Storage Engine (internal/storage)       │
   │ - Subsea Cable BGP Director (internal/cable)           │
   │ - Automated Edge PoP Health Prober & Watchdog          │
   └───────────────────┬────────────────────────────────────┘
                       │
                       ▼ PostgreSQL verify-full TLS (:5432)
   ┌────────────────────────────────────────────────────────┐
   │ TRUST BOUNDARY 5: Sovereign Persistence Vault          │
   │ - Isolated schemas per tenant                          │
   │ - Encrypted at rest (AES-256)                          │
   │ - Zero cross-tenant queries                            │
   └────────────────────────────────────────────────────────┘
```

---

## 2. STRIDE Threat Analysis Matrix

| Threat Category (STRIDE) | Attack Vector & Scenario | Impact | NexusEdge Concrete Defense (Mitigation) | ASVS / NIST Ref |
|---|---|---|---|---|
| **Spoofing** | Attacker crafts illegitimate requests claiming to be an Edge PoP or Tenant Operator. | Unauthorized control plane reconfiguration. | Constant-time HMAC-SHA256 signature verification (`crypto/subtle.ConstantTimeCompare`), API key format enforcement (`nke_live_...`). | ASVS V2.1<br>NIST PW.1.1 |
| **Tampering** | Man-in-the-Middle alters configuration snapshots or subsea BGP routing metrics in transit. | Malicious traffic redirection, DNS hijack. | Mutual TLS and `verify-full` certificate verification on all internal hops; SHA-256 checksums on all S3 objects and snapshot blobs. | ASVS V9.1<br>NIST PW.2.1 |
| **Repudiation** | Tenant or admin executes an illicit DNS change or cable cut and denies the action. | Lack of accountability, compliance audit failure. | Append-only cryptographically hashed audit logger (`AUDIT_HMAC_KEY`) recording Actor, Timestamp, Action, IP, and Resource ID. | ASVS V7.1<br>NIST PW.3.1 |
| **Information Disclosure** | Memory dump or error stack trace reveals database credentials or private keys. | Tenant data compromise, host takeover. | Zero secrets in code/logs (Rule 18, 19); automatic log redaction of `Authorization`, `Cookie`, and `X-API-Key`; generic RFC-7807 error responses to clients. | ASVS V2.8<br>CISA Default Secure |
| **Denial of Service** | Attacker sends infinite byte streams (Slowloris) or giant payloads to consume memory. | OOM crash, service degradation across all tenants. | Explicit bounded stream readers (`http.MaxBytesReader`, `io.LimitReader(10MB)`), strict read/write timeouts on all HTTP servers. | ASVS V5.2<br>NIST PW.1.2 |
| **Elevation of Privilege** | Attacker accesses `/api/proxy/storage/buckets` of another tenant by guessing bucket ID. | Cross-tenant data leakage. | Mandatory tenant isolation checks in every handler: `bucket.TenantID != session.TenantID -> ErrUnauthorizedTenant`. | ASVS V4.1<br>Rule 54, 55 |

---

## 3. The 7 Non-Negotiable Operational Principles (Evidence)

1. **Never trust untrusted input:** Every header, query parameter, JSON payload, and URL path is validated against bounded regex and byte limits before processing.
2. **Never bypass authorization:** Server-side authentication alone does not grant access. Multi-tenant entity ownership is verified on every state-mutating operation.
3. **Never expose secrets:** Private keys (`.key`, `.pem`) are forbidden from git tracking. Secrets are passed strictly via encrypted environment variables or HashiCorp Vault / OCI Vault.
4. **Never ship unverified code:** Passing compilation is insufficient. 100% Pre-Push CI Parity (Rule 127) must pass locally and in GitHub Actions.
5. **Never ignore failures:** Swallowed errors (`_ = err`) are forbidden. External calls have bounded timeouts and jittered exponential backoffs.
6. **Never deploy without recovery planning:** All state updates are atomic; migrations support rollback; container failure triggers autonomous heal loops.
7. **Never claim 100% security:** Continual threat modeling, fuzzing, static analysis (SAST), and dependency vulnerability scans (`govulncheck`, `npm audit`, `scan-secrets.py`) are mandatory on every commit.
