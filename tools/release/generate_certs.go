package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func generateCertPair(outDir, certName, keyName, commonName string, org []string, dnsNames []string, ips []net.IP) (string, string, error) {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", "", fmt.Errorf("failed to create directory %s: %w", outDir, err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: org,
			CommonName:   commonName,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", fmt.Errorf("failed to create certificate: %w", err)
	}

	certPath := filepath.Join(outDir, certName)
	certOut, err := os.Create(certPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to open %s: %w", certPath, err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return "", "", fmt.Errorf("failed to write cert PEM: %w", err)
	}

	keyPath := filepath.Join(outDir, keyName)
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return "", "", fmt.Errorf("failed to open %s: %w", keyPath, err)
	}

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		keyOut.Close()
		return "", "", fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
		keyOut.Close()
		return "", "", fmt.Errorf("failed to write key PEM: %w", err)
	}
	keyOut.Close()

	if err := os.Chmod(keyPath, 0600); err != nil {
		return "", "", fmt.Errorf("failed to restrict key permissions: %w", err)
	}

	return certPath, keyPath, nil
}

func main() {
	envoyDir := filepath.Join("deploy", "envoy", "certs")
	if len(os.Args) > 1 && os.Args[1] != "" {
		envoyDir = os.Args[1]
	}

	postgresDir := filepath.Join("deploy", "postgres", "certs")
	if len(os.Args) > 2 && os.Args[2] != "" {
		postgresDir = os.Args[2]
	}

	// 1. Generate Envoy Ingress TLS certificates
	envoyCert, envoyKey, err := generateCertPair(
		envoyDir,
		"server.crt",
		"server.key",
		"*.nexusedge.internal",
		[]string{"NexusEdge Staging Ingress"},
		[]string{"localhost", "*.nexusedge.internal", "api.nexusedge.io", "app.nexusedge.io", "customer-a.example.com", "aeitron.com", "dashboard.aeitron.com", "api.aeitron.com"},
		[]net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate envoy certs: %v\n", err)
		os.Exit(1)
	}

	sdsPath := filepath.Join(envoyDir, "sds.json")
	sdsContent := `{
  "resources": [
    {
      "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
      "name": "dynamic_server_cert",
      "tls_certificate": {
        "certificate_chain": {
          "filename": "/etc/envoy/certs/server.crt"
        },
        "private_key": {
          "filename": "/etc/envoy/certs/server.key"
        }
      }
    }
  ]
}
`
	if err := os.WriteFile(sdsPath, []byte(sdsContent), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write sds.json: %v\n", err)
		os.Exit(1)
	}

	// 2. Generate Dedicated PostgreSQL Database TLS certificates
	pgCert, pgKey, err := generateCertPair(
		postgresDir,
		"postgres.crt",
		"postgres.key",
		"postgres",
		[]string{"NexusEdge Sovereign Database"},
		[]string{"postgres", "nexusedge-postgres-prod", "nexusedge-postgres", "localhost"},
		[]net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1"), net.ParseIP("172.30.0.5"), net.ParseIP("172.28.0.5")},
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate postgres certs: %v\n", err)
		os.Exit(1)
	}

	// Root CA copy for client-side sslmode=verify-full verification
	rootCaPath := filepath.Join(postgresDir, "root.crt")
	certData, err := os.ReadFile(pgCert)
	if err == nil {
		_ = os.WriteFile(rootCaPath, certData, 0644)
	}

	fmt.Printf("Generated NexusEdge TLS certificates:\n")
	fmt.Printf("  [Envoy Ingress]\n    - Cert: %s\n    - Key:  %s\n    - SDS:  %s\n", envoyCert, envoyKey, sdsPath)
	fmt.Printf("  [PostgreSQL Sovereign DB]\n    - Cert: %s\n    - Key:  %s\n    - Root: %s\n", pgCert, pgKey, rootCaPath)
}
