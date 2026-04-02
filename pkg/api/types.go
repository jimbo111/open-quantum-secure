package api

import "fmt"

// apiResponse is the standard response envelope from the OQS platform.
type apiResponse[T any] struct {
	Data T       `json:"data"`
	Meta apiMeta `json:"meta"`
}

// apiMeta carries request-level metadata returned in every response.
type apiMeta struct {
	RequestID string `json:"requestId"`
	Timestamp string `json:"timestamp"`
}

// APIError is a structured error returned by the OQS platform.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	// RequestID is populated from the X-Request-ID response header.
	RequestID string `json:"-"`
}

func (e *APIError) Error() string {
	if e.RequestID != "" {
		return fmt.Sprintf("%s: %s (request-id: %s)", e.Code, e.Message, e.RequestID)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// UploadRequest is the payload sent when uploading a CBOM.
type UploadRequest struct {
	Project   string      `json:"project"`
	Branch    string      `json:"branch"`
	CommitSHA string      `json:"commitSha"`
	ScanMode  string      `json:"scanMode"`
	CBOM      interface{} `json:"cbom"`
}

// UploadResponse is the result returned after a successful CBOM upload.
type UploadResponse struct {
	ScanID                string         `json:"scanId"`
	DashboardURL          string         `json:"dashboardUrl"`
	QuantumReadinessScore int            `json:"quantumReadinessScore"`
	QuantumReadinessGrade string         `json:"quantumReadinessGrade"`
	FindingSummary        FindingSummary `json:"findingSummary"`
}

// FindingSummary holds per-severity finding counts.
type FindingSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// ScanEntry represents a single scan in the history list.
type ScanEntry struct {
	ScanID                string         `json:"scanId"`
	Branch                string         `json:"branch"`
	CommitSHA             string         `json:"commitSha"`
	ScanMode              string         `json:"scanMode"`
	QuantumReadinessScore int            `json:"quantumReadinessScore"`
	QuantumReadinessGrade string         `json:"quantumReadinessGrade"`
	FindingSummary        FindingSummary `json:"findingSummary"`
	StartedAt             string         `json:"startedAt"`
	CompletedAt           string         `json:"completedAt"`
}

// ScanListResponse holds paginated scan history results.
type ScanListResponse struct {
	Scans      []ScanEntry `json:"scans"`
	Pagination struct {
		Cursor  string `json:"cursor"`
		HasMore bool   `json:"hasMore"`
	} `json:"pagination"`
}

// Identity holds the authenticated user's profile information.
type Identity struct {
	Email    string `json:"email"`
	Org      string `json:"org"`
	Plan     string `json:"plan"`
	Endpoint string `json:"endpoint"`
}

// APIKeyCreateResponse is returned when creating a new API key.
// The RawKey is shown exactly once and cannot be recovered after this response.
type APIKeyCreateResponse struct {
	KeyPrefix string `json:"keyPrefix"` // e.g. "oqs_k_Ab"
	RawKey    string `json:"rawKey"`    // full key (shown once)
	Name      string `json:"name"`
	CreatedAt string `json:"createdAt"`
}

// APIKeyEntry represents a single API key in the list response (key is masked).
type APIKeyEntry struct {
	KeyPrefix string `json:"keyPrefix"`
	Name      string `json:"name"`
	LastUsed  string `json:"lastUsed,omitempty"`
	CreatedAt string `json:"createdAt"`
	Revoked   bool   `json:"revoked"`
}

// APIKeyListResponse holds the list of API keys for the authenticated user.
type APIKeyListResponse struct {
	Keys []APIKeyEntry `json:"keys"`
}

// CacheUploadRequest is the payload for uploading a gzipped scan cache blob.
type CacheUploadRequest struct {
	// Project is the project name (may contain slashes; will be URL-encoded).
	Project string
	// Branch is the branch the cache belongs to (e.g. "main").
	Branch string
	// EngineVersionsHash is the SHA-256 hex of the engine versions map,
	// used as a cache key to detect engine upgrades.
	EngineVersionsHash string
	// Data is the raw gzip-compressed cache JSON.
	Data []byte
}

// CacheUploadResponse is returned after a successful cache upload.
type CacheUploadResponse struct {
	SizeBytes          int64  `json:"sizeBytes"`
	EngineVersionsHash string `json:"engineVersionsHash"`
	Branch             string `json:"branch"`
}

// CacheDownloadRequest identifies a remote cache entry to retrieve.
type CacheDownloadRequest struct {
	// Project is the project name.
	Project string
	// Branch is the branch to retrieve the cache for.
	Branch string
	// EngineVersionsHash is the SHA-256 hex of the engine versions map.
	EngineVersionsHash string
}
