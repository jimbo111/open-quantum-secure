package store

import (
	"context"
	"fmt"

	"github.com/jimbo111/open-quantum-secure/pkg/api"
)

// RemoteStore implements ScanStore by delegating to the OQS platform API.
// SaveScan is a no-op because the platform records scans automatically on
// CBOM upload. ListScans calls api.Client.ListScans and maps the response.
type RemoteStore struct {
	client *api.Client
}

// NewRemoteStore returns a RemoteStore backed by client.
func NewRemoteStore(client *api.Client) *RemoteStore {
	return &RemoteStore{client: client}
}

// SaveScan is a no-op for the remote store. The platform persists scan records
// automatically when a CBOM is uploaded via api.Client.Upload.
func (r *RemoteStore) SaveScan(_ context.Context, _ string, _ ScanRecord) error {
	return nil
}

// ListScans retrieves scan history from the OQS platform and maps each
// api.ScanEntry to a ScanRecord. Returns an empty non-nil slice when the
// project has no scans. The opts.Limit is forwarded to the API.
func (r *RemoteStore) ListScans(ctx context.Context, project string, opts ListOptions) ([]ScanRecord, error) {
	resp, err := r.client.ListScans(ctx, project, opts.Limit)
	if err != nil {
		return nil, fmt.Errorf("store: list scans from API: %w", err)
	}

	records := make([]ScanRecord, 0, len(resp.Scans))
	for _, entry := range resp.Scans {
		records = append(records, mapScanEntry(entry))
	}
	return records, nil
}

// mapScanEntry converts an api.ScanEntry to a store.ScanRecord.
func mapScanEntry(entry api.ScanEntry) ScanRecord {
	return ScanRecord{
		ScanID:                entry.ScanID,
		Timestamp:             entry.CompletedAt,
		Branch:                entry.Branch,
		CommitSHA:             entry.CommitSHA,
		ScanMode:              entry.ScanMode,
		QuantumReadinessScore: entry.QuantumReadinessScore,
		QuantumReadinessGrade: entry.QuantumReadinessGrade,
		FindingSummary: FindingSummary{
			Total:    entry.FindingSummary.Total,
			Critical: entry.FindingSummary.Critical,
			High:     entry.FindingSummary.High,
			Medium:   entry.FindingSummary.Medium,
			Low:      entry.FindingSummary.Low,
			Info:     entry.FindingSummary.Info,
		},
	}
}
