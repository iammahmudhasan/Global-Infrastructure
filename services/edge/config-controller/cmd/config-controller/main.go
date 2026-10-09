package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/api"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/compiler"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/onboarding"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/store"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9091"
	}

	log.Printf("[INFO] Initializing NexusEdge Control Plane (Config Controller)...")

	// 1. Initialize In-Memory Data Store (backed by Postgres in full cluster)
	dataStore := store.NewStore()

	// In explicit local development mode, seed active fixture domain for PoPs
	if os.Getenv("NEXUSEDGE_DEV_MODE") == "true" {
		env := strings.ToLower(strings.TrimSpace(os.Getenv("NEXUSEDGE_ENV")))
		if env == "development" || env == "test" {
			devDomain := &model.Domain{
				ID:             "dom-dev-api",
				ProjectID:      "proj-core",
				Hostname:       "api.nexusedge.io",
				Status:         model.DomainStatusActive,
				OnboardingType: "CNAME",
				CNAMETarget:    "edge.nexusedge.net",
				AllowedPoPs:    []string{"singapore", "dhaka"},
				CreatedAt:      time.Now().UTC(),
				UpdatedAt:      time.Now().UTC(),
			}
			_ = dataStore.SaveDomain(devDomain)

			devPoolDefault := &model.OriginPool{
				ID:          "pool-dev-default",
				ProjectID:   "proj-core",
				Name:        "mock-origin-default-pool",
				LBAlgorithm: model.LBAlgorithmRoundRobin,
				Origins: []model.Origin{
					{
						ID:          "orig-dev-default",
						PoolID:      "pool-dev-default",
						Address:     "172.28.0.10",
						Port:        8081,
						Protocol:    model.ProtocolHTTP,
						Weight:      100,
						Healthy:     true,
						AllowedPoPs: []string{"singapore", "dhaka"},
					},
				},
			}
			_ = dataStore.SaveOriginPool(devPoolDefault)

			devPoolStatus := &model.OriginPool{
				ID:          "pool-dev-status",
				ProjectID:   "proj-core",
				Name:        "mock-origin-status-pool",
				LBAlgorithm: model.LBAlgorithmRoundRobin,
				Origins: []model.Origin{
					{
						ID:          "orig-dev-status",
						PoolID:      "pool-dev-status",
						Address:     "172.28.0.10",
						Port:        8082,
						Protocol:    model.ProtocolHTTP,
						Weight:      100,
						Healthy:     true,
						AllowedPoPs: []string{"singapore", "dhaka"},
					},
				},
			}
			_ = dataStore.SaveOriginPool(devPoolStatus)

			devRouteRoot := &model.Route{
				ID:         "route-dev-root",
				DomainID:   devDomain.ID,
				PoolID:     devPoolDefault.ID,
				PathPrefix: "/",
				Priority:   0,
				TimeoutMs:  5000,
			}
			dataStore.SaveRoute(devRouteRoot)

			devRouteStatus := &model.Route{
				ID:         "route-dev-status",
				DomainID:   devDomain.ID,
				PoolID:     devPoolStatus.ID,
				PathPrefix: "/status/",
				Priority:   10,
				TimeoutMs:  5000,
			}
			dataStore.SaveRoute(devRouteStatus)

			devSec := &model.SecurityPolicy{
				ID:               "sec-dev-01",
				DomainID:         devDomain.ID,
				WAFEnabled:       true,
				WAFMode:          "BLOCK",
				OWASPProtection:  true,
				RateLimitEnabled: true,
				RateLimitRPM:     6000,
			}
			dataStore.SaveSecurityPolicy(devSec)

			devChallenge := &model.ACMEChallenge{
				ID:               "chal-dev-01",
				DomainID:         devDomain.ID,
				Hostname:         devDomain.Hostname,
				Type:             "HTTP-01",
				Token:            "test-token",
				KeyAuthorization: "test-token.mock_key_auth_marker",
				Status:           model.ChallengeStatusPending,
				CreatedAt:        time.Now().UTC(),
				ExpiresAt:        time.Now().UTC().Add(24 * time.Hour),
			}
			dataStore.SaveACMEChallenge(devChallenge)

			log.Printf("[INFO] Seeded development fixture domain: %s (status=%s, default_origin=172.28.0.10:8081, status_origin=172.28.0.10:8082)", devDomain.Hostname, devDomain.Status)
		}
	}

	// 2. Initialize Onboarding Domain Service
	domainSvc := onboarding.NewDomainService(dataStore)

	// 3. Initialize Envoy v3 Configuration Compiler (LDS/RDS/CDS/EDS)
	envoyCompiler := compiler.NewCompiler(9901, 80, 443)

	// 4. Initialize HTTP API Server
	handler := api.NewAPIHandler(dataStore, domainSvc, envoyCompiler)

	certsDir := os.Getenv("NEXUSEDGE_CERTS_DIR")
	if certsDir != "" {
		handler.CertManager().SetCertsDir(certsDir)
		log.Printf("[INFO] Configured Dynamic Envoy SDS Certificate directory: %s", certsDir)

		// If server.crt and server.key exist, sync active certificate for dev fixture domain
		certBytes, errCert := os.ReadFile(filepath.Join(certsDir, "server.crt"))
		keyBytes, errKey := os.ReadFile(filepath.Join(certsDir, "server.key"))
		if errCert == nil && errKey == nil && len(certBytes) > 0 && len(keyBytes) > 0 {
			devCert := &model.Certificate{
				ID:            "cert-dev-api-01",
				DomainID:      "dom-dev-api",
				Domains:       []string{"api.nexusedge.io"},
				Status:        model.CertStatusActive,
				KeyType:       model.KeyTypeECDSA,
				CertPEM:       string(certBytes),
				PrivateKeyPEM: string(keyBytes),
				Issuer:        "NexusEdge Staging Ingress",
				SerialNumber:  "100001",
				IssuedAt:      time.Now().UTC(),
				ExpiresAt:     time.Now().UTC().Add(90 * 24 * time.Hour),
				AutoRenew:     true,
			}
			dataStore.SaveCertificate(devCert)
			_ = handler.CertManager().SyncSDSCertificate(devCert)
			log.Printf("[INFO] Seeded and synchronized active TLS certificate for dom-dev-api via Envoy SDS")
		}
	}

	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", port),
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// 5. Background Sweeper Task (Garbage-collect unverified pending domains older than 24h - Finding 4)
	sweeperCtx, stopSweeper := context.WithCancel(context.Background())
	defer stopSweeper()

	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				swept := domainSvc.SweepExpiredPendingDomains(24 * time.Hour)
				if swept > 0 {
					log.Printf("[INFO] Swept %d expired pending domains", swept)
				}
			case <-sweeperCtx.Done():
				return
			}
		}
	}()

	// 6. Run Server in Background
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("[INFO] NexusEdge Config Controller listening on http://0.0.0.0:%s", port)
		log.Printf("[INFO] Control Plane endpoints ready: POST /v1/projects/{id}/domains, GET /v1/edge/envoy-config")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] Server failure: %v", err)
		}
	}()

	// 7. Graceful Shutdown
	<-stopChan
	log.Printf("[INFO] Shutting down NexusEdge Config Controller gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("[ERROR] Server forced to shutdown: %v", err)
	}

	log.Printf("[INFO] NexusEdge Config Controller stopped cleanly.")
}
