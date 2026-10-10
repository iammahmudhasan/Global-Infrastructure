package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_ListProviders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/ai/providers" {
			t.Errorf("expected path /v1/ai/providers, got %s", r.URL.Path)
		}
		if r.URL.Query().Get("project_id") != "test-proj" {
			t.Errorf("expected query param project_id=test-proj, got %s", r.URL.Query().Get("project_id"))
		}
		providers := []AIProvider{
			{
				ID:             "vllm-spot",
				ProjectID:      "test-proj",
				Name:           "CoreWeave Spot",
				Endpoint:       "https://vllm.example.com",
				ProviderType:   "vllm",
				CostPerMTokens: 0.50,
				Priority:       1,
				Enabled:        true,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(providers)
	}))
	defer server.Close()

	client := &Client{
		ControlPlaneURL: server.URL,
		HTTPClient:      server.Client(),
	}

	providers, err := client.ListProviders(context.Background(), "test-proj")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(providers) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(providers))
	}
	if providers[0].ID != "vllm-spot" {
		t.Errorf("expected provider ID vllm-spot, got %s", providers[0].ID)
	}
}

func TestClient_AddProvider(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		var req CreateAIProviderRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		resp := AIProvider{
			ID:             req.ID,
			ProjectID:      req.ProjectID,
			Name:           req.Name,
			Endpoint:       req.Endpoint,
			ProviderType:   req.ProviderType,
			CostPerMTokens: req.CostPerMTokens,
			Priority:       req.Priority,
			Enabled:        true,
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := &Client{
		ControlPlaneURL: server.URL,
		HTTPClient:      server.Client(),
	}

	created, err := client.AddProvider(context.Background(), CreateAIProviderRequest{
		ID:             "azure-openai",
		Name:           "Azure East US",
		Endpoint:       "https://azure.openai.com",
		ProviderType:   "azure",
		CostPerMTokens: 2.50,
		Priority:       2,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if created.ID != "azure-openai" {
		t.Errorf("expected ID azure-openai, got %s", created.ID)
	}
	if created.CostPerMTokens != 2.50 {
		t.Errorf("expected cost 2.50, got %f", created.CostPerMTokens)
	}
}

func TestClient_GetAnalytics(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/nexusedge/ai/analytics" {
			t.Errorf("expected /v1/nexusedge/ai/analytics, got %s", r.URL.Path)
		}
		resp := AnalyticsResponse{
			Status: "healthy",
			Engine: "NexusEdge Universal AI Traffic Director v0.1.0",
			Economics: EconomicsSummary{
				TotalTokensRouted: 50000,
				PromptTokens:      25000,
				CompletionTokens:  25000,
				CostSpentUSD:      0.025,
				CostSavedUSD:      0.100,
				SavingsPercentage: 80.0,
			},
			ProvidersCount: 1,
			Providers: []ProviderTelemetry{
				{
					ID:             "spot-coreweave",
					Type:           "vllm",
					TotalRequests:  50,
					CostPerMTokens: 0.50,
					IsAvailable:    true,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := &Client{
		GatewayURL: server.URL,
		HTTPClient: server.Client(),
	}

	analytics, err := client.GetAnalytics(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if analytics.Economics.TotalTokensRouted != 50000 {
		t.Errorf("expected 50000 tokens, got %d", analytics.Economics.TotalTokensRouted)
	}
	if analytics.Economics.SavingsPercentage != 80.0 {
		t.Errorf("expected 80.0%% savings, got %f", analytics.Economics.SavingsPercentage)
	}
}

func TestClient_TestInference(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("expected /v1/chat/completions, got %s", r.URL.Path)
		}
		if r.Header.Get("X-NexusEdge-Routing-Strategy") != "cost" {
			t.Errorf("expected strategy header cost, got %s", r.Header.Get("X-NexusEdge-Routing-Strategy"))
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-NexusEdge-Provider", "spot-coreweave")
		w.Header().Set("X-NexusEdge-TTFT-Ms", "22")
		w.Header().Set("X-NexusEdge-Failover-Count", "0")
		w.Header().Set("X-NexusEdge-Total-Duration-Ms", "35")
		w.Header().Set("X-NexusEdge-Routing-Strategy", "cost")
		w.Header().Set("X-NexusEdge-Cost-Per-MTokens", "0.50")
		w.Header().Set("X-NexusEdge-Tokens-Total", "1000")
		w.Header().Set("X-NexusEdge-Estimated-Savings-USD", "0.002000")

		body := map[string]interface{}{
			"id": "chatcmpl-test",
			"choices": []map[string]interface{}{
				{
					"message": map[string]string{
						"role":    "assistant",
						"content": "This workload should run on CoreWeave Spot in Virginia.",
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer server.Close()

	client := &Client{
		GatewayURL: server.URL,
		HTTPClient: server.Client(),
	}

	result, err := client.TestInference(context.Background(), "llama-3.3-70b", "Where to run?", "cost", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ProviderID != "spot-coreweave" {
		t.Errorf("expected provider spot-coreweave, got %s", result.ProviderID)
	}
	if result.TokensTotal != "1000" {
		t.Errorf("expected tokens 1000, got %s", result.TokensTotal)
	}
	if result.EstimatedSavingsUSD != "0.002000" {
		t.Errorf("expected savings 0.002000, got %s", result.EstimatedSavingsUSD)
	}
	if result.ResponseContent != "This workload should run on CoreWeave Spot in Virginia." {
		t.Errorf("unexpected content: %s", result.ResponseContent)
	}
}

func TestHandleAICommand_Help(t *testing.T) {
	client := &Client{}
	if err := HandleAICommand(client, []string{}); err != nil {
		t.Errorf("expected nil error for empty args, got %v", err)
	}
	if err := HandleAICommand(client, []string{"help"}); err != nil {
		t.Errorf("expected nil error for help, got %v", err)
	}
}
