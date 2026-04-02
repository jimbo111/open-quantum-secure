package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// apiErrorEnvelope is the JSON wrapper around the error object.
type apiErrorEnvelope struct {
	Error APIError `json:"error"`
}

// parseError reads the response body and attempts to construct a meaningful error.
// It always includes the X-Request-ID from the response header when present.
// The caller is responsible for closing resp.Body (typically via defer).
func parseError(resp *http.Response) error {
	requestID := resp.Header.Get("X-Request-ID")

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16)) // 64 KiB cap
	if err != nil {
		return &APIError{
			Code:      fmt.Sprintf("HTTP_%d", resp.StatusCode),
			Message:   "failed to read error response body",
			RequestID: requestID,
		}
	}

	trimmed := strings.TrimSpace(string(body))

	// Try to unmarshal as {"error": {...}}.
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var envelope apiErrorEnvelope
		if jsonErr := json.Unmarshal(body, &envelope); jsonErr == nil && envelope.Error.Code != "" {
			envelope.Error.RequestID = requestID
			return &envelope.Error
		}
	}

	// Fallback: wrap status + raw body.
	msg := strings.TrimSpace(string(body))
	if msg == "" {
		msg = http.StatusText(resp.StatusCode)
		if msg == "" {
			msg = "unknown error"
		}
	}
	return &APIError{
		Code:      fmt.Sprintf("HTTP_%d", resp.StatusCode),
		Message:   msg,
		RequestID: requestID,
	}
}
