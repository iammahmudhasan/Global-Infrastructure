package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/api"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/compiler"
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

	// 2. Initialize Onboarding Domain Service
	domainSvc := onboarding.NewDomainService(dataStore)

	// 3. Initialize Envoy v3 Configuration Compiler (LDS/RDS/CDS/EDS)
	envoyCompiler := compiler.NewCompiler(9901, 80, 443)

	// 4. Initialize HTTP API Server
	handler := api.NewAPIHandler(dataStore, domainSvc, envoyCompiler)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", port),
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// 5. Run Server in Background
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("[INFO] NexusEdge Config Controller listening on http://0.0.0.0:%s", port)
		log.Printf("[INFO] Control Plane endpoints ready: POST /v1/projects/{id}/domains, GET /v1/edge/envoy-config")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] Server failure: %v", err)
		}
	}()

	// 6. Graceful Shutdown
	<-stopChan
	log.Printf("[INFO] Shutting down NexusEdge Config Controller gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("[ERROR] Server forced to shutdown: %v", err)
	}

	log.Printf("[INFO] NexusEdge Config Controller stopped cleanly.")
}
