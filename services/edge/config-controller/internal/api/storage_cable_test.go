package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIHandler_StorageAndCables(t *testing.T) {
	h := setupTestServer()

	// 1. GET /v1/storage/buckets
	req := httptest.NewRequest(http.MethodGet, "/v1/storage/buckets", nil)
	req.Header.Set("Authorization", "Bearer dev-fixture-key-01")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	var bucketList struct {
		Buckets []map[string]interface{} `json:"buckets"`
		Count   int                      `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &bucketList); err != nil {
		t.Fatalf("failed decoding buckets: %v", err)
	}
	if bucketList.Count < 2 {
		t.Errorf("expected at least 2 seeded buckets, got %d", bucketList.Count)
	}

	// 2. POST /v1/storage/buckets (Create new BD sovereign bucket)
	createReq := map[string]interface{}{
		"name":                 "api-test-bd-vault",
		"project_id":           "proj-core",
		"sovereignty_policy":   "BD_ONLY",
		"replication_topology": "SINGLE_REGION_NVME",
		"primary_region":       "ap-south-2",
		"max_size_bytes":       1048576,
	}
	bodyBytes, _ := json.Marshal(createReq)
	req = httptest.NewRequest(http.MethodPost, "/v1/storage/buckets", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer dev-fixture-key-01")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", w.Code, w.Body.String())
	}

	// 3. PUT /v1/storage/buckets/{name}/objects/{key}
	objectPayload := []byte("confidential edge sovereign payload")
	req = httptest.NewRequest(http.MethodPut, "/v1/storage/buckets/api-test-bd-vault/objects/test.bin", bytes.NewReader(objectPayload))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", "Bearer dev-fixture-key-01")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("X-NexusEdge-Sovereignty") != "BD" {
		t.Errorf("expected X-NexusEdge-Sovereignty=BD, got %s", w.Header().Get("X-NexusEdge-Sovereignty"))
	}

	// 4. GET /v1/storage/buckets/{name}/objects/{key} (Attempt export to US -> must be 451 Legal Reasons)
	req = httptest.NewRequest(http.MethodGet, "/v1/storage/buckets/api-test-bd-vault/objects/test.bin?destination_jurisdiction=US", nil)
	req.Header.Set("Authorization", "Bearer dev-fixture-key-01")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnavailableForLegalReasons {
		t.Errorf("expected 451 Legal Reasons for cross-border breach, got %d", w.Code)
	}

	// 5. GET /v1/storage/buckets/{name}/objects/{key} (Local BD access -> 200 OK)
	req = httptest.NewRequest(http.MethodGet, "/v1/storage/buckets/api-test-bd-vault/objects/test.bin?destination_jurisdiction=BD", nil)
	req.Header.Set("Authorization", "Bearer dev-fixture-key-01")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), objectPayload) {
		t.Errorf("expected payload %q, got %q", objectPayload, w.Body.Bytes())
	}

	// 6. GET /v1/edge/network/cables
	req = httptest.NewRequest(http.MethodGet, "/v1/edge/network/cables", nil)
	req.Header.Set("Authorization", "Bearer dev-fixture-key-01")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for cables, got %d: %s", w.Code, w.Body.String())
	}

	// 7. POST /v1/edge/network/cables/smw6/cut
	req = httptest.NewRequest(http.MethodPost, "/v1/edge/network/cables/smw6/cut", nil)
	req.Header.Set("Authorization", "Bearer dev-fixture-key-01")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for cable cut simulation, got %d: %s", w.Code, w.Body.String())
	}

	// 8. POST /v1/edge/network/cables/smw6/restore
	req = httptest.NewRequest(http.MethodPost, "/v1/edge/network/cables/smw6/restore", nil)
	req.Header.Set("Authorization", "Bearer dev-fixture-key-01")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for cable restore, got %d: %s", w.Code, w.Body.String())
	}
}
