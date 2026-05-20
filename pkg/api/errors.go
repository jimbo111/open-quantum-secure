package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// maxAPIResponseBytes is the hard cap applied to every JSON success-body
// read by the API client (16 MiB). Without this bound a hostile or
// runaway server could stream unbounded JSON into json.NewDecoder.Decode
// and OOM the scanner.
//
// 16 MiB is generous for every documented response (Identity is < 1 KiB,
// scan/apikey/history list responses are bounded by server-side paging).
// Larger payloads should use a dedicated endpoint with explicit streaming
// (cf. DownloadCache which has its own 50 MiB+1 cap).
const maxAPIResponseBytes int64 = 16 << 20

// decodeJSONResponse wraps resp.Body in an io.LimitReader before decoding
// JSON into dst. Callers MUST still defer resp.Body.Close().
func decodeJSONResponse(resp *http.Response, dst interface{}) error {
	return json.NewDecoder(io.LimitReader(resp.Body, maxAPIResponseBytes)).Decode(dst)
}

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
