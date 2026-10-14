package alert

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTelegramAlerter_SendAlert(t *testing.T) {
	var capturedPayload map[string]interface{}
	var capturedPath string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&capturedPayload)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer server.Close()

	alerter := NewTelegramAlerter("fake-bot-token-123", "123456789")
	alerter.SetBaseURL(server.URL)

	if !alerter.IsConfigured() {
		t.Fatalf("expected alerter to be configured with token and chat id")
	}

	event := Event{
		Type:        "HIGH_LATENCY",
		Severity:    SeverityWarning,
		Title:       "High Origin Latency Detected",
		Message:     "Origin aeitron.com response latency exceeded threshold",
		Origin:      "185.232.14.188:443",
		LatencyMs:   1450.5,
		ThresholdMs: 1000.0,
		Timestamp:   time.Now().UTC(),
		Details: map[string]string{
			"status_code": "200",
			"pop_id":      "singapore",
		},
	}

	err := alerter.SendAlert(context.Background(), event)
	if err != nil {
		t.Fatalf("unexpected error sending telegram alert: %v", err)
	}

	expectedPath := "/botfake-bot-token-123/sendMessage"
	if capturedPath != expectedPath {
		t.Fatalf("expected path %s, got %s", expectedPath, capturedPath)
	}

	if capturedPayload["chat_id"] != "123456789" {
		t.Fatalf("expected chat_id 123456789, got %v", capturedPayload["chat_id"])
	}

	text, ok := capturedPayload["text"].(string)
	if !ok || text == "" {
		t.Fatalf("expected non-empty message text")
	}

	if !capturedPayload["disable_web_page_preview"].(bool) {
		t.Fatalf("expected disable_web_page_preview to be true")
	}
}

func TestTelegramAlerter_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"ok": false, "description": "Unauthorized"}`))
	}))
	defer server.Close()

	alerter := NewTelegramAlerter("invalid-token", "123456789")
	alerter.SetBaseURL(server.URL)

	event := Event{
		Type:      "TEST",
		Severity:  SeverityInfo,
		Title:     "Test Ping",
		Message:   "Testing connection",
		Timestamp: time.Now().UTC(),
	}

	err := alerter.SendAlert(context.Background(), event)
	if err == nil {
		t.Fatalf("expected error on 401 unauthorized response from Telegram")
	}
}

type mockAlerter struct {
	sentCount int
	lastEvent Event
}

func (m *mockAlerter) SendAlert(ctx context.Context, event Event) error {
	m.sentCount++
	m.lastEvent = event
	return nil
}

func (m *mockAlerter) IsConfigured() bool {
	return true
}

func TestThrottledDispatcher(t *testing.T) {
	mock := &mockAlerter{}
	dispatcher := NewThrottledDispatcher(mock, 100*time.Millisecond)

	eventWarn := Event{
		Type:      "HIGH_LATENCY",
		Severity:  SeverityWarning,
		Origin:    "185.232.14.188:443",
		Timestamp: time.Now().UTC(),
	}

	// First warning must be sent
	_ = dispatcher.SendAlert(context.Background(), eventWarn)
	if mock.sentCount != 1 {
		t.Fatalf("expected 1 alert sent, got %d", mock.sentCount)
	}

	// Second warning within cooldown window must be throttled
	_ = dispatcher.SendAlert(context.Background(), eventWarn)
	if mock.sentCount != 1 {
		t.Fatalf("expected duplicate warning within cooldown to be throttled, got %d", mock.sentCount)
	}

	// State flip (CRITICAL: ORIGIN_DOWN) must bypass cooldown immediately
	eventDown := Event{
		Type:      "ORIGIN_DOWN",
		Severity:  SeverityCritical,
		Origin:    "185.232.14.188:443",
		Timestamp: time.Now().UTC(),
	}
	_ = dispatcher.SendAlert(context.Background(), eventDown)
	if mock.sentCount != 2 {
		t.Fatalf("expected state transition ORIGIN_DOWN to bypass cooldown, got %d", mock.sentCount)
	}

	// After cooldown window expires, next warning should be sent
	time.Sleep(150 * time.Millisecond)
	_ = dispatcher.SendAlert(context.Background(), eventWarn)
	if mock.sentCount != 3 {
		t.Fatalf("expected warning after cooldown expiry to be sent, got %d", mock.sentCount)
	}
}
