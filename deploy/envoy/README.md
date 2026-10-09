# NexusEdge Envoy Edge Ingress Proxy

## Architecture Overview

Envoy operates as the outer L7 ingress proxy for the NexusEdge Single-PoP Edge Security Gateway:
- **Port 10000 (HTTP Ingress / Public 80):**
  - Routes `/.well-known/acme-challenge/` to `config-controller:9091` for automated ACME HTTP-01 challenge fulfillment.
  - Routes customer traffic (`prefix: "/"`) directly to the Rust Data Plane (`nexusedge-gateway:8080`).
- **Port 10443 (HTTPS Ingress / Public 443 with TLS Termination):**
  - Terminates TLS downstream with certificates mounted at `/etc/envoy/certs/server.crt` and `/etc/envoy/certs/server.key`.
  - Routes decrypted customer traffic (`prefix: "/"`) directly to the Rust Data Plane (`nexusedge-gateway:8080`).

---

## TLS Certificate Strategy: Development vs. Production

### 1. Development & Local Testing (Static Fixture Flow)
- Staging and development environments use self-signed certificates mounted from `deploy/envoy/certs/`.
- Certificates are generated using the standard Go certificate generator:
  ```bash
  go run tools/release/generate_certs.go deploy/envoy/certs
  ```
- Checked-in development certificates allow `docker compose up -d` to boot immediately on fresh repository clones without configuration failure.

### 2. TLS Architecture & Production Readiness Status
- **Local Fixture Rotation Prototype:** Tested locally. Rotates single-fixture certificates (`server.crt` / `server.key`) with atomic rename and verifies served serial change.
- **Production ACME (RFC 8555):** `INCOMPLETE`. Real ACME client and WebPKI CA validation are not yet implemented. In production environments (`ENVIRONMENT=production` or `APP_ENV=production`), the Control Plane returns `501 Not Implemented` (`ErrProductionACMENotConfigured`).
- **Per-Domain TLS:** `INCOMPLETE`. Multi-domain certificate isolation and individual per-tenant Envoy filter chains are scheduled for V1.
- **gRPC SDS (Secret Discovery Service):** `INCOMPLETE`. Live dynamic gRPC SDS daemon streaming is planned for V1; current single-PoP deployment uses file-based secret rotation.
- **External Secret Management (Target Production Design):** In Kubernetes or VPS production clusters, secrets are provisioned externally via Cert-Manager or KMS mounts read-only into `/etc/envoy/certs/`.
