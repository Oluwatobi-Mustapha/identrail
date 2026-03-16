package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Oluwatobi-Mustapha/aurelius/internal/telemetry"
	"go.uber.org/zap"
)

func TestRouterHealthz(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("unexpected status body: %+v", body)
	}
}

func TestRouterSchedulesScan(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics)

	req := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected status 202, got %d", w.Code)
	}
}
