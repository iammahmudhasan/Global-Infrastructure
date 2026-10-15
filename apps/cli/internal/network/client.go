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

// Client interacts with NexusEdge Global Router network plane APIs.
type Client struct {
	RouterURL  string
	AuthToken  string
	HTTPClient *http.Client
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

	token := os.Getenv("NEXUSEDGE_CP_AUTH_TOKEN")
	if token == "" {
		token = "dev-fixture-key-01"
	}

	return &Client{
		RouterURL: strings.TrimRight(endpoint, "/"),
		AuthToken: token,
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
