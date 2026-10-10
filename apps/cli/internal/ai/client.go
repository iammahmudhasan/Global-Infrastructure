package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// AIProvider represents an AI compute provider registered in the Control Plane.
type AIProvider struct {
	ID                      string    `json:"id"`
	ProjectID               string    `json:"project_id"`
	Name                    string    `json:"name"`
	Endpoint                string    `json:"endpoint"`
	ProviderType            string    `json:"provider_type"`
	APIKey                  string    `json:"api_key,omitempty"`
	CostPerMTokens          float64   `json:"cost_per_m_tokens"`
	Priority                int       `json:"priority"`
	SovereigntyJurisdiction string    `json:"sovereignty_jurisdiction,omitempty"`
	FailoverCooldownSecs    int       `json:"failover_cooldown_secs"`
	Enabled                 bool      `json:"enabled"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

// CreateAIProviderRequest defines payload to register a new AI upstream provider.
type CreateAIProviderRequest struct {
	ID                      string  `json:"id"`
	ProjectID               string  `json:"project_id"`
	Name                    string  `json:"name"`
	Endpoint                string  `json:"endpoint"`
	ProviderType            string  `json:"provider_type"`
	APIKey                  string  `json:"api_key,omitempty"`
	CostPerMTokens          float64 `json:"cost_per_m_tokens"`
	Priority                int     `json:"priority"`
	SovereigntyJurisdiction string  `json:"sovereignty_jurisdiction,omitempty"`
	FailoverCooldownSecs    int     `json:"failover_cooldown_secs"`
	Enabled                 bool    `json:"enabled"`
}

// EconomicsSummary tracks aggregate token usage, costs, and arbitrage savings.
type EconomicsSummary struct {
	TotalTokensRouted uint64  `json:"total_tokens_routed"`
	PromptTokens      uint64  `json:"prompt_tokens"`
	CompletionTokens  uint64  `json:"completion_tokens"`
	CostSpentUSD      float64 `json:"cost_spent_usd"`
	CostSavedUSD      float64 `json:"cost_saved_usd"`
	SavingsPercentage float64 `json:"savings_percentage"`
}

// ProviderTelemetry encapsulates real-time operational health and metrics per provider.
type ProviderTelemetry struct {
	ID                 string  `json:"id"`
	Name               string  `json:"name"`
	Endpoint           string  `json:"endpoint"`
	Type               string  `json:"type"`
	Jurisdiction       string  `json:"jurisdiction"`
	IsAvailable        bool    `json:"is_available"`
	TotalRequests      uint64  `json:"total_requests"`
	SuccessfulRequests uint64  `json:"successful_requests"`
	RateLimited429     uint64  `json:"rate_limited_429"`
	FailoversTriggered uint64  `json:"failovers_triggered"`
	AvgTTFTMs          float64 `json:"avg_ttft_ms"`
	CostPerMTokens     float64 `json:"cost_per_m_tokens"`
}

// AnalyticsResponse is returned by GET /v1/nexusedge/ai/analytics.
type AnalyticsResponse struct {
	Status         string              `json:"status"`
	Engine         string              `json:"engine"`
	Timestamp      string              `json:"timestamp"`
	Economics      EconomicsSummary    `json:"economics"`
	ProvidersCount int                 `json:"providers_count"`
	Providers      []ProviderTelemetry `json:"providers"`
}

// TestInferenceResult represents the outcome of an end-to-end inference request.
type TestInferenceResult struct {
	StatusCode          int
	ProviderID          string
	Model               string
	TTFTMs              string
	FailoverCount       string
	TotalDurationMs     string
	RoutingStrategy     string
	CostPerMTokens      string
	TokensTotal         string
	EstimatedSavingsUSD string
	ResponseContent     string
}

// Client interacts with NexusEdge Control Plane and Edge Gateway APIs.
type Client struct {
	ControlPlaneURL string
	GatewayURL      string
	AuthToken       string
	HTTPClient      *http.Client
}

// NewClient initializes a client with environment variable defaults.
func NewClient() *Client {
	cpURL := os.Getenv("NEXUSEDGE_CP_ENDPOINT")
	if cpURL == "" {
		cpURL = "http://127.0.0.1:9091"
	}
	gwURL := os.Getenv("NEXUSEDGE_GATEWAY_ENDPOINT")
	if gwURL == "" {
		gwURL = "http://127.0.0.1:8080"
	}
	token := os.Getenv("NEXUSEDGE_CP_AUTH_TOKEN")
	if token == "" {
		token = "dev-fixture-key-01"
	}

	return &Client{
		ControlPlaneURL: strings.TrimRight(cpURL, "/"),
		GatewayURL:      strings.TrimRight(gwURL, "/"),
		AuthToken:       token,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// ListProviders retrieves the registered AI providers for a project.
func (c *Client) ListProviders(ctx context.Context, projectID string) ([]AIProvider, error) {
	if projectID == "" {
		projectID = "proj-default"
	}
	url := fmt.Sprintf("%s/v1/ai/providers?project_id=%s", c.ControlPlaneURL, projectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to construct request: %w", err)
	}
	if c.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("control plane connection error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var providers []AIProvider
	if err := json.NewDecoder(resp.Body).Decode(&providers); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return providers, nil
}

// AddProvider registers a new upstream AI provider in the Control Plane Key Vault.
func (c *Client) AddProvider(ctx context.Context, providerReq CreateAIProviderRequest) (*AIProvider, error) {
	if providerReq.ProjectID == "" {
		providerReq.ProjectID = "proj-default"
	}
	data, err := json.Marshal(providerReq)
	if err != nil {
		return nil, fmt.Errorf("failed to encode provider request: %w", err)
	}

	url := fmt.Sprintf("%s/v1/ai/providers", c.ControlPlaneURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to construct request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("control plane connection error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var created AIProvider
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return nil, fmt.Errorf("failed to decode created provider: %w", err)
	}
	return &created, nil
}

// DeleteProvider deletes an AI provider from the Control Plane Key Vault.
func (c *Client) DeleteProvider(ctx context.Context, id string) error {
	url := fmt.Sprintf("%s/v1/ai/providers/%s", c.ControlPlaneURL, id)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("failed to construct request: %w", err)
	}
	if c.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("control plane connection error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned HTTP %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// GetAnalytics fetches live token volumes, costs, and savings from the Gateway.
func (c *Client) GetAnalytics(ctx context.Context) (*AnalyticsResponse, error) {
	url := fmt.Sprintf("%s/v1/nexusedge/ai/analytics", c.GatewayURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to construct request: %w", err)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gateway connection error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("gateway returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var analytics AnalyticsResponse
	if err := json.NewDecoder(resp.Body).Decode(&analytics); err != nil {
		return nil, fmt.Errorf("failed to decode analytics response: %w", err)
	}
	return &analytics, nil
}

// TestInference dispatches an AI inference request across the NexusEdge Universal AI Director.
func (c *Client) TestInference(ctx context.Context, model, prompt, strategy, jurisdiction string) (*TestInferenceResult, error) {
	if model == "" {
		model = "llama-3.3-70b"
	}
	if prompt == "" {
		prompt = "Where should this AI workload run right now?"
	}
	if strategy == "" {
		strategy = "cost"
	}

	payload := map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"temperature": 0.7,
		"max_tokens":  256,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request payload: %w", err)
	}

	url := fmt.Sprintf("%s/v1/chat/completions", c.GatewayURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to construct request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-NexusEdge-Routing-Strategy", strategy)
	if jurisdiction != "" {
		req.Header.Set("X-NexusEdge-Jurisdiction", jurisdiction)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gateway dispatch failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	result := &TestInferenceResult{
		StatusCode:          resp.StatusCode,
		ProviderID:          resp.Header.Get("X-NexusEdge-Provider"),
		Model:               model,
		TTFTMs:              resp.Header.Get("X-NexusEdge-TTFT-Ms"),
		FailoverCount:       resp.Header.Get("X-NexusEdge-Failover-Count"),
		TotalDurationMs:     resp.Header.Get("X-NexusEdge-Total-Duration-Ms"),
		RoutingStrategy:     resp.Header.Get("X-NexusEdge-Routing-Strategy"),
		CostPerMTokens:      resp.Header.Get("X-NexusEdge-Cost-Per-MTokens"),
		TokensTotal:         resp.Header.Get("X-NexusEdge-Tokens-Total"),
		EstimatedSavingsUSD: resp.Header.Get("X-NexusEdge-Estimated-Savings-USD"),
	}

	// Try extracting text content from chat completions response format
	var chatResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(bodyBytes, &chatResp); err == nil {
		if chatResp.Error != nil && chatResp.Error.Message != "" {
			result.ResponseContent = fmt.Sprintf("Error: %s", chatResp.Error.Message)
		} else if len(chatResp.Choices) > 0 {
			result.ResponseContent = chatResp.Choices[0].Message.Content
		} else {
			result.ResponseContent = string(bodyBytes)
		}
	} else {
		result.ResponseContent = string(bodyBytes)
	}

	return result, nil
}
