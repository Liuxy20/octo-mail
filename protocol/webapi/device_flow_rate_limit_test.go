package webapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/mox/ratelimit"
)

func TestDeviceFlowEndpointsHaveIndependentPerIPLimit(t *testing.T) {
	for _, path := range []string{
		"/webapi/v0/agent-auth/device",
		"/webapi/v0/agent-auth/token",
	} {
		t.Run(path, func(t *testing.T) {
			limiter := &ratelimit.Limiter{WindowLimits: []ratelimit.WindowLimit{{
				Window: time.Minute,
				Limits: [3]int64{1, 10, 100},
			}}}
			handler := (&Server{DeviceFlowLimiter: limiter}).Handler()

			first := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
			first.RemoteAddr = "192.0.2.10:1234"
			first.Header.Set("Content-Type", "application/json")
			firstResponse := httptest.NewRecorder()
			handler.ServeHTTP(firstResponse, first)
			if firstResponse.Code == http.StatusTooManyRequests {
				t.Fatalf("first request unexpectedly limited: %s", firstResponse.Body.String())
			}

			second := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
			second.RemoteAddr = "192.0.2.10:1234"
			second.Header.Set("Content-Type", "application/json")
			secondResponse := httptest.NewRecorder()
			handler.ServeHTTP(secondResponse, second)
			if secondResponse.Code != http.StatusTooManyRequests || !strings.Contains(secondResponse.Body.String(), `"code":"slow_down"`) {
				t.Fatalf("second request = %d %s, want 429 slow_down", secondResponse.Code, secondResponse.Body.String())
			}
		})
	}
}

func TestDeviceFlowCreationAndPollingUseSeparateKeys(t *testing.T) {
	newLimiter := func() *ratelimit.Limiter {
		return &ratelimit.Limiter{WindowLimits: []ratelimit.WindowLimit{{
			Window: time.Minute,
			Limits: [3]int64{1, 100, 1000},
		}}}
	}
	handler := (&Server{
		DeviceCreateLimiter: newLimiter(),
		DeviceTokenLimiter:  newLimiter(),
	}).Handler()

	request := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.RemoteAddr = "192.0.2.10:1234"
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		return recorder
	}

	// Polling does not consume the creation budget, and two independent device
	// codes behind the same reverse proxy do not consume each other's poll budget.
	if got := request("/webapi/v0/agent-auth/token", `{"deviceCode":"omd_one","codeVerifier":"v"}`); got.Code == http.StatusTooManyRequests {
		t.Fatalf("first token poll unexpectedly limited: %s", got.Body.String())
	}
	if got := request("/webapi/v0/agent-auth/token", `{"deviceCode":"omd_two","codeVerifier":"v"}`); got.Code == http.StatusTooManyRequests {
		t.Fatalf("independent device code unexpectedly limited: %s", got.Body.String())
	}
	if got := request("/webapi/v0/agent-auth/token", `{"deviceCode":"omd_one","codeVerifier":"v"}`); got.Code != http.StatusTooManyRequests {
		t.Fatalf("repeated device-code poll = %d %s, want 429", got.Code, got.Body.String())
	}
	if got := request("/webapi/v0/agent-auth/device", `{}`); got.Code == http.StatusTooManyRequests {
		t.Fatalf("first device creation unexpectedly limited after polling: %s", got.Body.String())
	}
	if got := request("/webapi/v0/agent-auth/device", `{}`); got.Code != http.StatusTooManyRequests {
		t.Fatalf("second device creation = %d %s, want 429", got.Code, got.Body.String())
	}
}

func TestDeviceFlowEndpointsRejectOversizedBodies(t *testing.T) {
	handler := (&Server{}).Handler()
	for _, path := range []string{
		"/webapi/v0/agent-auth/device",
		"/webapi/v0/agent-auth/token",
	} {
		t.Run(path, func(t *testing.T) {
			body := `{"value":"` + strings.Repeat("x", maxDeviceAuthorizationBodySize) + `"}`
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != http.StatusRequestEntityTooLarge || !strings.Contains(response.Body.String(), `"code":"request_too_large"`) {
				t.Fatalf("oversized device request = %d %s, want 413 request_too_large", response.Code, response.Body.String())
			}
		})
	}
}
