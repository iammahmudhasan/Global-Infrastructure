package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Severity defines the urgency level of an operational alert.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityWarning  Severity = "WARNING"
	SeverityCritical Severity = "CRITICAL"
)

// Standard Event Types
const (
	EventTypeOriginDown                  = "ORIGIN_DOWN"
	EventTypeOriginRecovered             = "ORIGIN_RECOVERED"
	EventTypeHighLatency                 = "HIGH_LATENCY"
	EventTypeTest                        = "TEST"
	EventTypePoPDegraded                 = "POP_DEGRADED"
	EventTypePoPDown                     = "POP_DOWN"
	EventTypePoPRecovered                = "POP_RECOVERED"
	EventTypePoPFailover                 = "POP_FAILOVER"
	EventTypeReconcilerThresholdExceeded = "RECONCILER_THRESHOLD_EXCEEDED"
	EventTypeReconcilerRecovered         = "RECONCILER_RECOVERED"
)

// Event represents a structured infrastructure health or performance alert.
type Event struct {
	Type        string            `json:"type"`                   // e.g. "ORIGIN_DOWN", "ORIGIN_RECOVERED", "HIGH_LATENCY", "TEST"
	Severity    Severity          `json:"severity"`               // INFO, WARNING, CRITICAL
	Title       string            `json:"title"`                  // Short human-readable headline
	Message     string            `json:"message"`                // Detailed explanation
	Origin      string            `json:"origin,omitempty"`       // Target origin address or hostname
	LatencyMs   float64           `json:"latency_ms,omitempty"`   // Measured latency in milliseconds
	ThresholdMs float64           `json:"threshold_ms,omitempty"` // Configured threshold
	Timestamp   time.Time         `json:"timestamp"`              // UTC event timestamp
	Details     map[string]string `json:"details,omitempty"`      // Additional diagnostic key-values
}

// Alerter defines the interface for dispatching infrastructure notifications.
type Alerter interface {
	SendAlert(ctx context.Context, event Event) error
	IsConfigured() bool
}

// TelegramAlerter delivers real-time notifications to a Telegram chat or channel.
type TelegramAlerter struct {
	botToken   string
	chatID     string
	httpClient *http.Client
	baseURL    string // default "https://api.telegram.org"
}

// NewTelegramAlerter constructs a Telegram alerter with configurable token and chat ID.
func NewTelegramAlerter(botToken, chatID string) *TelegramAlerter {
	return &TelegramAlerter{
		botToken: strings.TrimSpace(botToken),
		chatID:   strings.TrimSpace(chatID),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		baseURL: "https://api.telegram.org",
	}
}

func (t *TelegramAlerter) IsConfigured() bool {
	return t.botToken != "" && t.chatID != ""
}

// SetBaseURL overrides the API endpoint for mock testing.
func (t *TelegramAlerter) SetBaseURL(url string) {
	t.baseURL = strings.TrimRight(url, "/")
}

// FormatTelegramMessage formats the event into industrial MarkdownV2 or HTML.
func (t *TelegramAlerter) FormatTelegramMessage(event Event) string {
	icon := "[INFO]"
	switch event.Severity {
	case SeverityCritical:
		icon = "[CRITICAL ALERT]"
	case SeverityWarning:
		icon = "[WARNING]"
	case SeverityInfo:
		icon = "[SYSTEM NOTICE]"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("<b>%s: %s</b>\n", icon, htmlEscape(event.Title)))
	sb.WriteString(fmt.Sprintf("<b>Type:</b> <code>%s</code>\n", htmlEscape(event.Type)))
	sb.WriteString(fmt.Sprintf("<b>Severity:</b> %s\n", htmlEscape(string(event.Severity))))
	if event.Origin != "" {
		sb.WriteString(fmt.Sprintf("<b>Origin:</b> <code>%s</code>\n", htmlEscape(event.Origin)))
	}
	if event.LatencyMs > 0 {
		if event.ThresholdMs > 0 {
			sb.WriteString(fmt.Sprintf("<b>Latency:</b> %.1f ms (Threshold: %.1f ms)\n", event.LatencyMs, event.ThresholdMs))
		} else {
			sb.WriteString(fmt.Sprintf("<b>Latency:</b> %.1f ms\n", event.LatencyMs))
		}
	}
	sb.WriteString(fmt.Sprintf("<b>Message:</b> %s\n", htmlEscape(event.Message)))
	sb.WriteString(fmt.Sprintf("<b>Timestamp:</b> %s UTC\n", event.Timestamp.UTC().Format("2006-01-02 15:04:05")))

	if len(event.Details) > 0 {
		sb.WriteString("<b>Diagnostics:</b>\n")
		for k, v := range event.Details {
			sb.WriteString(fmt.Sprintf("  • <i>%s</i>: <code>%s</code>\n", htmlEscape(k), htmlEscape(v)))
		}
	}

	sb.WriteString("\n<i>NexusEdge Autonomous Edge Operations</i>")
	return sb.String()
}

func htmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
	)
	return r.Replace(s)
}

func (t *TelegramAlerter) SendAlert(ctx context.Context, event Event) error {
	if !t.IsConfigured() {
		return nil
	}

	msgText := t.FormatTelegramMessage(event)
	payload := map[string]interface{}{
		"chat_id":                  t.chatID,
		"text":                     msgText,
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal telegram payload: %w", err)
	}

	apiURL := fmt.Sprintf("%s/bot%s/sendMessage", t.baseURL, t.botToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("create telegram request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("execute telegram request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errResp map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		return fmt.Errorf("telegram api error (status %d): %v", resp.StatusCode, errResp)
	}

	return nil
}

// ThrottledDispatcher wraps an Alerter with de-duplication and cooldown logic
// to prevent alert fatigue and notification storms during continuous network degradation.
type ThrottledDispatcher struct {
	mu           sync.Mutex
	inner        Alerter
	lastSent     map[string]time.Time
	cooldownMins time.Duration
}

// NewThrottledDispatcher creates a throttling wrapper with a specified cooldown window.
func NewThrottledDispatcher(inner Alerter, cooldown time.Duration) *ThrottledDispatcher {
	if cooldown <= 0 {
		cooldown = 5 * time.Minute
	}
	return &ThrottledDispatcher{
		inner:        inner,
		lastSent:     make(map[string]time.Time),
		cooldownMins: cooldown,
	}
}

func (d *ThrottledDispatcher) IsConfigured() bool {
	if d.inner == nil {
		return false
	}
	return d.inner.IsConfigured()
}

// SendAlert evaluates throttling rules:
// - CRITICAL state transitions (e.g. DOWN or RECOVERED) bypass cooldown and are delivered immediately.
// - WARNING alerts (e.g. HIGH_LATENCY) are deduplicated per origin within the cooldown window.
// - Timestamp is committed ONLY after successful delivery so failed attempts are eligible for retry.
func (d *ThrottledDispatcher) SendAlert(ctx context.Context, event Event) error {
	if d.inner == nil || !d.inner.IsConfigured() {
		return nil
	}

	key := fmt.Sprintf("%s:%s", event.Origin, event.Type)

	// Check suppression under lock
	d.mu.Lock()
	if event.Type != "ORIGIN_DOWN" && event.Type != "ORIGIN_RECOVERED" && event.Type != "TEST" {
		last, exists := d.lastSent[key]
		if exists && time.Since(last) < d.cooldownMins {
			d.mu.Unlock()
			// Suppressed by cooldown window
			return nil
		}
	}
	d.mu.Unlock()

	// Attempt delivery first
	err := d.inner.SendAlert(ctx, event)
	if err != nil {
		// Delivery failed: do NOT commit lastSent timestamp so subsequent attempts are not suppressed
		return err
	}

	// Commit timestamp only upon verified delivery
	d.mu.Lock()
	d.lastSent[key] = time.Now()
	d.mu.Unlock()

	return nil
}

// MultiAlerter dispatches events to all configured alerters concurrently.
type MultiAlerter struct {
	alerters []Alerter
}

func NewMultiAlerter(alerters ...Alerter) *MultiAlerter {
	var active []Alerter
	for _, a := range alerters {
		if a != nil {
			active = append(active, a)
		}
	}
	return &MultiAlerter{alerters: active}
}

func (m *MultiAlerter) IsConfigured() bool {
	for _, a := range m.alerters {
		if a.IsConfigured() {
			return true
		}
	}
	return false
}

func (m *MultiAlerter) SendAlert(ctx context.Context, event Event) error {
	var errs []string
	var errMu sync.Mutex
	var wg sync.WaitGroup

	for _, a := range m.alerters {
		if !a.IsConfigured() {
			continue
		}
		wg.Add(1)
		go func(target Alerter) {
			defer wg.Done()
			if err := target.SendAlert(ctx, event); err != nil {
				errMu.Lock()
				errs = append(errs, err.Error())
				errMu.Unlock()
			}
		}(a)
	}

	wg.Wait()
	if len(errs) > 0 {
		return fmt.Errorf("alert delivery failed on %d channels: %s", len(errs), strings.Join(errs, "; "))
	}
	return nil
}

// NewFromEnv initializes a complete alerter hierarchy from standard environment variables.
func NewFromEnv() Alerter {
	tgToken := os.Getenv("NEXUSEDGE_ALERT_TELEGRAM_BOT_TOKEN")
	tgChatID := os.Getenv("NEXUSEDGE_ALERT_TELEGRAM_CHAT_ID")
	tgAlerter := NewTelegramAlerter(tgToken, tgChatID)

	cooldownSec := 300
	if raw := os.Getenv("NEXUSEDGE_ALERT_COOLDOWN_SECONDS"); raw != "" {
		if val, err := strconv.Atoi(raw); err == nil && val > 0 {
			cooldownSec = val
		}
	}

	multi := NewMultiAlerter(tgAlerter)
	return NewThrottledDispatcher(multi, time.Duration(cooldownSec)*time.Second)
}
