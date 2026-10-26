package proxy

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"time"
)

type Dispatcher interface {
	Dispatch(ctx context.Context, targetURL string, rawBody []byte, originalHeaders http.Header) (*http.Response, error)
}

type HTTPDispatcher struct {
	client    *http.Client
	targetURL string
}

func NewHTTPDispatcher(targetURL string, timeout time.Duration) *HTTPDispatcher {
	return &HTTPDispatcher{
		client: &http.Client{
			Timeout: timeout,
		},
		targetURL: targetURL,
	}
}

func isHopByHop(headerKey string) bool {
	switch strings.ToLower(headerKey) {
	case "connection", "keep-alive", "proxy-authenticate",
		"proxy-authorization", "te", "trailers",
		"transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func (d *HTTPDispatcher) Dispatch(ctx context.Context, targetURL string, rawBody []byte, originalHeaders http.Header) (*http.Response, error) {
	urlToUse := targetURL
	if urlToUse == "" {
		urlToUse = d.targetURL
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlToUse, bytes.NewReader(rawBody))

	if err != nil {
		return nil, err
	}

	for key, values := range originalHeaders {
		if isHopByHop(key) {
			continue
		}
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
