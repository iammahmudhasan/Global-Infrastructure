package network

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ValidatePrefixRequest defines payload for RFC 7454 prefix sanitization.
type ValidatePrefixRequest struct {
	Prefix     string `json:"prefix"`
	Simulation bool   `json:"simulation"`
}

// ValidatePrefixResponse encapsulates prefix sanitization result.
type ValidatePrefixResponse struct {
	Status string `json:"status"`
	Prefix string `json:"prefix"`
	Error  string `json:"error,omitempty"`
}

// ValidateRPKIRequest defines payload for RFC 6811 Route Origin Validation.
type ValidateRPKIRequest struct {
	Prefix string `json:"prefix"`
	ASN    uint32 `json:"asn"`
}

// ValidateRPKIResponse encapsulates RPKI ROV result.
type ValidateRPKIResponse struct {
	Status string `json:"status"`
	Prefix string `json:"prefix"`
	ASN    uint32 `json:"asn"`
	Error  string `json:"error,omitempty"`
}

// FlapRecordRequest defines payload to record a route flap event.
type FlapRecordRequest struct {
	Prefix string `json:"prefix"`
}

// FlapRecordResponse encapsulates route flap damping penalty status.
type FlapRecordResponse struct {
	Prefix  string  `json:"prefix"`
	State   string  `json:"state"`
	Penalty float64 `json:"penalty"`
}

// DampingStatusResponse encapsulates current decayed route damping status.
type DampingStatusResponse struct {
	Prefix  string  `json:"prefix"`
	State   string  `json:"state"`
	Penalty float64 `json:"penalty"`
}

// DrainPlanRequest defines parameters for RFC 8326 graceful shutdown.
type DrainPlanRequest struct {
	PeerID            string `json:"peer_id"`
	TargetAlternative string `json:"target_alternative"`
	DwellSeconds      int    `json:"dwell_seconds"`
}

// DrainPlanResponse encapsulates RFC 8326 Graceful Shutdown instructions.
type DrainPlanResponse struct {
	PeerID            string        `json:"peer_id"`
	CommunityTag      string        `json:"community_tag"`
	LocalPreference   int           `json:"local_preference"`
	MED               int           `json:"med"`
	DwellDuration     time.Duration `json:"dwell_duration"`
	TargetAlternative string        `json:"target_alternative"`
}

// FlowDispatchRequest defines 5-tuple L4 flow routing parameters.
type FlowDispatchRequest struct {
	SrcIP    string `json:"src_ip"`
	SrcPort  uint16 `json:"src_port"`
	DstIP    string `json:"dst_ip"`
	DstPort  uint16 `json:"dst_port"`
	Protocol uint8  `json:"protocol"`
}

// FlowDispatchResponse encapsulates Maglev consistent hash routing decision.
type FlowDispatchResponse struct {
	BackendID   string `json:"backend_id"`
	BackendIP   string `json:"backend_ip"`
	BackendPort uint16 `json:"backend_port"`
	Weight      int    `json:"weight"`
}

// MaglevStatsResponse encapsulates Maglev lookup table and conntrack metrics.
type MaglevStatsResponse struct {
	TableSize        int `json:"table_size"`
	BackendCount     int `json:"backend_count"`
	ConntrackEntries int `json:"conntrack_entries"`
}

// Client interacts with NexusEdge Global Router and Edge Config Controller network plane APIs.
type Client struct {
	RouterURL           string
	ConfigControllerURL string
	AuthToken           string
	HTTPClient          *http.Client
}

// NewClient initializes a Client using environment variable defaults.
func NewClient() *Client {
	endpoint := os.Getenv("NEXUSEDGE_GLOBAL_ROUTER_ENDPOINT")
	if endpoint == "" {
		endpoint = os.Getenv("NEXUSEDGE_CP_ENDPOINT")
	}
	if endpoint == "" {
		endpoint = "http://127.0.0.1:9091"
	}

	ccEndpoint := os.Getenv("NEXUSEDGE_CONFIG_CONTROLLER_ENDPOINT")
	if ccEndpoint == "" {
		ccEndpoint = os.Getenv("NEXUSEDGE_EDGE_ENDPOINT")
	}
	if ccEndpoint == "" {
		ccEndpoint = "http://127.0.0.1:8080"
	}

	token := os.Getenv("NEXUSEDGE_CP_AUTH_TOKEN")
	if token == "" {
		token = "dev-fixture-key-01"
	}

	return &Client{
		RouterURL:           strings.TrimRight(endpoint, "/"),
		ConfigControllerURL: strings.TrimRight(ccEndpoint, "/"),
		AuthToken:           token,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *Client) sendRequest(ctx context.Context, method, path string, body interface{}, out interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to encode request payload: %w", err)
		}
		bodyReader = bytes.NewReader(buf)
	}

	fullURL := fmt.Sprintf("%s%s", c.RouterURL, path)
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to construct HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.AuthToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.AuthToken))
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("request to %s failed: %w", fullURL, err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusUnprocessableEntity {
		var errObj struct {
			Error string `json:"error"`
		}
		if jsonErr := json.Unmarshal(respBytes, &errObj); jsonErr == nil && errObj.Error != "" {
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, errObj.Error)
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBytes))
	}

	if out != nil {
		if err := json.Unmarshal(respBytes, out); err != nil {
			return fmt.Errorf("failed to parse response JSON: %w (raw: %s)", err, string(respBytes))
		}
	}

	return nil
}

// ValidatePrefix calls RFC 7454 prefix validation endpoint.
func (c *Client) ValidatePrefix(ctx context.Context, prefix string, simulation bool) (*ValidatePrefixResponse, error) {
	req := ValidatePrefixRequest{
		Prefix:     prefix,
		Simulation: simulation,
	}
	var resp ValidatePrefixResponse
	if err := c.sendRequest(ctx, http.MethodPost, "/api/v1/network/bgp/validate-prefix", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ValidateRPKI calls RFC 6811 Route Origin Validation endpoint.
func (c *Client) ValidateRPKI(ctx context.Context, prefix string, asn uint32) (*ValidateRPKIResponse, error) {
	req := ValidateRPKIRequest{
		Prefix: prefix,
		ASN:    asn,
	}
	var resp ValidateRPKIResponse
	if err := c.sendRequest(ctx, http.MethodPost, "/api/v1/network/bgp/validate-rpki", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RecordFlap records a route flap event (Operator required).
func (c *Client) RecordFlap(ctx context.Context, prefix string) (*FlapRecordResponse, error) {
	req := FlapRecordRequest{Prefix: prefix}
	var resp FlapRecordResponse
	if err := c.sendRequest(ctx, http.MethodPost, "/api/v1/network/bgp/record-flap", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetDampingStatus queries RFC 2439 route flap damping penalty.
func (c *Client) GetDampingStatus(ctx context.Context, prefix string) (*DampingStatusResponse, error) {
	path := fmt.Sprintf("/api/v1/network/bgp/damping-status?prefix=%s", url.QueryEscape(prefix))
	var resp DampingStatusResponse
	if err := c.sendRequest(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GenerateDrainPlan generates RFC 8326 Graceful Shutdown instructions.
func (c *Client) GenerateDrainPlan(ctx context.Context, peerID, altPoP string, dwellSeconds int) (*DrainPlanResponse, error) {
	req := DrainPlanRequest{
		PeerID:            peerID,
		TargetAlternative: altPoP,
		DwellSeconds:      dwellSeconds,
	}
	var resp DrainPlanResponse
	if err := c.sendRequest(ctx, http.MethodPost, "/api/v1/network/bgp/drain-plan", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DispatchFlow routes 5-tuple flow using Maglev consistent hashing with conntrack.
func (c *Client) DispatchFlow(ctx context.Context, srcIP string, srcPort uint16, dstIP string, dstPort uint16, protocol uint8) (*FlowDispatchResponse, error) {
	req := FlowDispatchRequest{
		SrcIP:    srcIP,
		SrcPort:  srcPort,
		DstIP:    dstIP,
		DstPort:  dstPort,
		Protocol: protocol,
	}
	var resp FlowDispatchResponse
	if err := c.sendRequest(ctx, http.MethodPost, "/api/v1/network/maglev/dispatch", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetMaglevStats retrieves lookup table size and conntrack metrics.
func (c *Client) GetMaglevStats(ctx context.Context) (*MaglevStatsResponse, error) {
	var resp MaglevStatsResponse
	if err := c.sendRequest(ctx, http.MethodGet, "/api/v1/network/maglev/stats", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// FailoverHop models an alternative PoP destination reached via subsea or terrestrial fiber transit.
type FailoverHop struct {
	TargetPoP             string  `json:"target_pop"`
	SubseaCable           string  `json:"subsea_cable"`
	SLARTTMs              float64 `json:"sla_rtt_ms"`
	SovereigntyRestricted bool    `json:"sovereignty_restricted"`
	Status                string  `json:"status"`
}

// MultiPoPRouteRule models edge ingress, primary transit, and ordered failover hops for a PoP.
type MultiPoPRouteRule struct {
	PoPID           string        `json:"pop_id"`
	Region          string        `json:"region"`
	PrimaryTarget   string        `json:"primary_target"`
	PrimaryRTTMs    float64       `json:"primary_rtt_ms"`
	FailoverTargets []FailoverHop `json:"failover_targets"`
	ActiveTarget    string        `json:"active_target"`
	Status          string        `json:"status"`
	UpdatedAt       time.Time     `json:"updated_at"`
}

// PoPHealthState tracks real-time health, probe latencies, and failover state for a PoP.
type PoPHealthState struct {
	PoPID               string    `json:"pop_id"`
	Name                string    `json:"name"`
	Region              string    `json:"region"`
	TargetEndpoint      string    `json:"target_endpoint"`
	Status              string    `json:"status"`
	Healthy             bool      `json:"healthy"`
	ConsecutivePasses   int       `json:"consecutive_passes"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	LastRTTMs           float64   `json:"last_rtt_ms"`
	EWMALatencyMs       float64   `json:"ewma_latency_ms"`
	PacketLossPercent   float64   `json:"packet_loss_percent"`
	LastProbedAt        time.Time `json:"last_probed_at"`
	LastError           string    `json:"last_error,omitempty"`
	FailoverPoPID       string    `json:"failover_pop_id,omitempty"`
}

// PoPProbeResult models the outcome of a single synthetic health probe cycle on a PoP.
type PoPProbeResult struct {
	PoPID      string    `json:"pop_id"`
	Target     string    `json:"target"`
	Success    bool      `json:"success"`
	LatencyMs  float64   `json:"latency_ms"`
	StatusCode int       `json:"status_code"`
	Error      string    `json:"error,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

func (c *Client) sendConfigControllerRequest(ctx context.Context, method, path string, body interface{}, out interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to encode request payload: %w", err)
		}
		bodyReader = bytes.NewReader(buf)
	}

	fullURL := fmt.Sprintf("%s%s", c.ConfigControllerURL, path)
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to construct HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.AuthToken != "" {
		req.Header.Set("X-API-Key", c.AuthToken)
		req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("request to %s failed: %w", fullURL, err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBytes))
	}

	if out != nil {
		if err := json.Unmarshal(respBytes, out); err != nil {
			return fmt.Errorf("failed to decode response payload: %w", err)
		}
	}
	return nil
}

// ListPoPHealth retrieves live health metrics for all 4 PoPs from Edge Config Controller.
func (c *Client) ListPoPHealth(ctx context.Context) ([]PoPHealthState, error) {
	var resp struct {
		TotalPoPs int              `json:"total_pops"`
		PoPs      []PoPHealthState `json:"pops"`
	}
	if err := c.sendConfigControllerRequest(ctx, http.MethodGet, "/v1/edge/pops/health", nil, &resp); err != nil {
		return nil, err
	}
	return resp.PoPs, nil
}

// GetPoPRoutes retrieves the global multi-region routing table from Edge Config Controller.
func (c *Client) GetPoPRoutes(ctx context.Context) ([]MultiPoPRouteRule, error) {
	var resp struct {
		TotalRoutes int                 `json:"total_routes"`
		Routes      []MultiPoPRouteRule `json:"routes"`
	}
	if err := c.sendConfigControllerRequest(ctx, http.MethodGet, "/v1/edge/pops/routes", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Routes, nil
}

// TriggerPoPProbe initiates an immediate synthetic health probe cycle across all PoPs.
func (c *Client) TriggerPoPProbe(ctx context.Context) (map[string]PoPProbeResult, error) {
	var resp struct {
		TotalProbed int                       `json:"total_probed"`
		Results     map[string]PoPProbeResult `json:"results"`
	}
	if err := c.sendConfigControllerRequest(ctx, http.MethodPost, "/v1/edge/pops/health/probe", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Results, nil
}
