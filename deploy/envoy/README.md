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

### 2. Production Deployments (External Secret Management)
- In production Kubernetes or VPS environments, TLS certificates are provisioned externally:
  - **Kubernetes / Cert-Manager:** Secrets are mounted read-only into `/etc/envoy/certs/` containing valid Let's Encrypt or CA-signed certificates (`tls.crt` as `server.crt`, `tls.key` as `server.key`).
  - **ACME HTTP-01:** ACME challenges received on HTTP port 80 are routed to the NexusEdge Control Plane (`config-controller:9091`), which handles ACME validation and stores issued certificates in the cluster secret store.
- **SDS (Secret Discovery Service) Road-map:** As multi-tenant custom domain certificates expand beyond static mounting, Envoy will integrate with a dynamic SDS endpoint served by the Control Plane.
