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
)

func newOriginHandler(originID string) http.Handler {
	mux := http.NewServeMux()

	// Readiness and Health probes
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK\n"))
	})

	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK\n"))
	})

	// Universal handler returning the explicit origin marker
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin-Id", originID)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		proto := r.Header.Get("X-Forwarded-Proto")
		if proto == "" {
			proto = "http"
		}
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}

		responseBody := fmt.Sprintf("%s: downstream_proto=%s host=%s path=%s\n", originID, proto, host, r.URL.Path)
		_, _ = w.Write([]byte(responseBody))
	})

	return mux
}

func main() {
	portA := os.Getenv("PORT_A")
	if portA == "" {
		portA = "8081"
	}

	portB := os.Getenv("PORT_B")
	if portB == "" {
		portB = "8082"
	}

	serverA := &http.Server{
		Addr:         ":" + portA,
		Handler:      newOriginHandler("ORIGIN_DEFAULT_A"),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	serverB := &http.Server{
		Addr:         ":" + portB,
		Handler:      newOriginHandler("ORIGIN_STATUS_B"),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	go func() {
		log.Printf("[INFO] Mock Origin A listening on :%s (ID: ORIGIN_DEFAULT_A)", portA)
		if err := serverA.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] Server A failed: %v", err)
		}
	}()

	go func() {
		log.Printf("[INFO] Mock Origin B listening on :%s (ID: ORIGIN_STATUS_B)", portB)
		if err := serverB.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] Server B failed: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("[INFO] Shutting down mock origin servers gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = serverA.Shutdown(ctx)
	_ = serverB.Shutdown(ctx)
	log.Println("[INFO] Mock origin servers stopped.")
}
