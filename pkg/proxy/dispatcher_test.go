package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPDispatcherUsesConfiguredTargetAndDoesNotForwardAuthorization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization header was forwarded: %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read request body: %v", err)
		}
		if string(body) != `{"jsonrpc":"2.0"}` {
			t.Errorf("unexpected body: %s", body)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	dispatcher := NewHTTPDispatcher(server.URL, 0)
	response, err := dispatcher.Dispatch(
		context.Background(),
		"",
		[]byte(`{"jsonrpc":"2.0"}`),
		http.Header{
			"Authorization": []string{"Bearer secret"},
			"Content-Type":  []string{"application/json"},
		},
	)
	if err != nil {
		t.Fatalf("Dispatch returned an error: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, response.StatusCode)
	}
}

func TestHTTPDispatcherRejectsEmptyTarget(t *testing.T) {
	dispatcher := NewHTTPDispatcher("", 0)
	_, err := dispatcher.Dispatch(context.Background(), "", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "target URL is empty") {
		t.Fatalf("expected empty target error, got %v", err)
	}
}
