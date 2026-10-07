package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/iammahmudhasan/nexusedge-control-plane/controller"
)

// Node represents an active global edge Point of Presence (PoP)
type Node struct {
	ID        string    `json:"id"`
	Region    string    `json:"region"`
	City      string    `json:"city"`
	IP        string    `json:"ip"`
	Status    string    `json:"status"`
	LastSeen  time.Time `json:"last_seen"`
	LatencyMs int       `json:"latency_ms"`
}

// GlobalConfig represents the declarative cluster rules synchronized to all Rust Data Planes
type GlobalConfig struct {
	Version    int      `json:"version"`
	UpdatedAt  string   `json:"updated_at"`
	BlockedIPs []string `json:"blocked_ips"`
	WAFRules   []string `json:"waf_rules"`
}

type ControlPlaneState struct {
	mu         sync.RWMutex
	nodes      map[string]Node
	config     GlobalConfig
	controller *controller.WorkloadController
}

func NewControlPlaneState() *ControlPlaneState {
	return &ControlPlaneState{
		controller: controller.NewWorkloadController(),
		nodes: map[string]Node{
			"pop-sin-01": {
				ID:        "pop-sin-01",
				Region:    "ap-southeast-1",
				City:      "Singapore",
				IP:        "185.190.140.10",
				Status:    "ONLINE",
				LastSeen:  time.Now(),
				LatencyMs: 8,
			},
			"pop-fra-01": {
				ID:        "pop-fra-01",
				Region:    "eu-central-1",
				City:      "Frankfurt",
				IP:        "185.190.141.20",
				Status:    "ONLINE",
				LastSeen:  time.Now(),
				LatencyMs: 14,
			},
			"pop-dha-01": {
				ID:        "pop-dha-01",
				Region:    "ap-south-2",
				City:      "Dhaka",
				IP:        "185.190.142.30",
				Status:    "ONLINE",
				LastSeen:  time.Now(),
				LatencyMs: 4,
			},
			"pop-iad-01": {
				ID:        "pop-iad-01",
				Region:    "us-east-1",
				City:      "Virginia",
				IP:        "185.190.143.40",
				Status:    "ONLINE",
				LastSeen:  time.Now(),
				LatencyMs: 22,
			},
		},
		config: GlobalConfig{
			Version:   1,
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
			BlockedIPs: []string{
				"198.51.100.42",
				"203.0.113.195",
			},
			WAFRules: []string{
				"SQLI_STRICT_MODE",
				"XSS_BLOCK_INLINE_SCRIPTS",
				"PATH_TRAVERSAL_PROTECT",
			},
		},
	}
}

func main() {
	state := NewControlPlaneState()

	mux := http.NewServeMux()

	// 1. Health check
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"HEALTHY","service":"nexusedge-control-plane"}`))
	})

	// 2. Nodes discovery API
	mux.HandleFunc("/api/v1/nodes", func(w http.ResponseWriter, r *http.Request) {
		state.mu.RLock()
		defer state.mu.RUnlock()

		nodeList := make([]Node, 0, len(state.nodes))
		for _, n := range state.nodes {
			nodeList = append(nodeList, n)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count": len(nodeList),
			"nodes": nodeList,
		})
	})

	// 3. Declarative Global Config API (read by Rust Data Planes)
	mux.HandleFunc("/api/v1/config", func(w http.ResponseWriter, r *http.Request) {
		state.mu.RLock()
		defer state.mu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(state.config)
	})

	// 4. Multi-Cloud & AI Compute Backends Registry
	mux.HandleFunc("/api/v1/backends", func(w http.ResponseWriter, r *http.Request) {
		backends := state.controller.ListBackends()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count":    len(backends),
			"backends": backends,
		})
	})

	// 5. Phase 0 Core Engine: Real-Time Workload Dispatcher API
	// Answers: "Where should every application & compute workload run right now?"
	mux.HandleFunc("/api/v1/workload/dispatch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed. Use POST.", http.StatusMethodNotAllowed)
			return
		}

		var policy controller.Policy
		if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
			http.Error(w, fmt.Sprintf("Invalid policy JSON payload: %v", err), http.StatusBadRequest)
			return
		}

		decision, err := state.controller.EvaluateWorkload(policy)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnprocessableEntity)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   err.Error(),
				"policy":  policy.Name,
				"status":  "NO_SUITABLE_BACKEND",
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(decision)
	})

	port := 9090
	serverAddr := fmt.Sprintf(":%d", port)
	log.Printf("=================================================================")
	log.Printf(" NexusEdge Global AI & Compute Traffic Controller (Go)")
	log.Printf(" Listening on %s", serverAddr)
	log.Printf(" Phase 0 Engine: Multi-Cloud Workload Placement Active")
	log.Printf(" Sovereign Jurisdictions: Bangladesh (BDIX/SMW6), EU, US, SG")
	log.Printf("=================================================================")

	if err := http.ListenAndServe(serverAddr, mux); err != nil {
		log.Fatalf("Control plane fatal error: %v", err)
	}
}
