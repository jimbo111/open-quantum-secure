// Package dashboard provides a lightweight local HTTP server that visualises
// scan history stored by LocalStore. It exposes a JSON API and serves a
// self-contained HTML dashboard page — no external dependencies required.
package dashboard

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/store"
	"github.com/jimbo111/open-quantum-secure/pkg/trends"
)

//go:embed templates/dashboard.html
var staticFS embed.FS

// Serve starts a local HTTP server on addr (e.g. ":8899") that reads scan
// history from historyDir. It blocks until the server returns an error.
//
// All API endpoints are read-only. No mutations are performed.
func Serve(addr string, historyDir string) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/projects", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleProjects(w, r, historyDir)
	})

	mux.HandleFunc("/api/projects/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Route /api/projects/{slug}/history or /api/projects/{slug}/trends.
		rest := strings.TrimPrefix(r.URL.Path, "/api/projects/")
		lastSlash := strings.LastIndex(rest, "/")
		if lastSlash < 0 {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		slug := rest[:lastSlash]
		action := rest[lastSlash+1:]
		if slug == "" || action == "" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		switch action {
		case "history":
			handleHistory(w, r, historyDir, slug)
		case "trends":
			handleTrends(w, r, historyDir, slug)
		case "findings":
			handleFindings(w, r, historyDir, slug)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		serveHTML(w, r)
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return srv.ListenAndServe()
}

// ── Static asset ──────────────────────────────────────────────────────────────

func serveHTML(w http.ResponseWriter, _ *http.Request) {
	data, err := staticFS.ReadFile("templates/dashboard.html")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// ── API: list projects ────────────────────────────────────────────────────────

// projectSummary is the JSON payload for each entry in GET /api/projects.
type projectSummary struct {
	Slug      string `json:"slug"`
	Name      string `json:"name"`
	LatestQRS *int   `json:"latestQRS"`
	ScanCount int    `json:"scanCount"`
	LastScan  string `json:"lastScan,omitempty"` // RFC3339 timestamp
}

func handleProjects(w http.ResponseWriter, r *http.Request, historyDir string) {
	slugs, err := listSlugs(historyDir)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "could not list history: "+err.Error())
		return
	}

	summaries := make([]projectSummary, 0, len(slugs))
	ctx := r.Context()

	// LocalStore baseDir is the parent of "history/" per store.LocalStore contract.
	st := store.NewLocalStore(filepath.Dir(historyDir))

	for _, slug := range slugs {
		project := slugToProject(slug)
		records, listErr := st.ListScans(ctx, project, store.ListOptions{})
		if listErr != nil || len(records) == 0 {
			summaries = append(summaries, projectSummary{
				Slug: slug,
				Name: project,
			})
			continue
		}
		latest := records[len(records)-1]
		qrs := latest.QuantumReadinessScore
		summaries = append(summaries, projectSummary{
			Slug:      slug,
			Name:      project,
			LatestQRS: &qrs,
			ScanCount: len(records),
			LastScan:  latest.Timestamp,
		})
	}

	// Sort by latest scan timestamp descending (most recently scanned first).
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].LastScan > summaries[j].LastScan
	})

	writeJSON(w, http.StatusOK, summaries)
}

// ── API: project history ──────────────────────────────────────────────────────

func handleHistory(w http.ResponseWriter, r *http.Request, historyDir string, slug string) {
	project := slugToProject(slug)
	// baseDir is the parent of "history/" per store.LocalStore contract.
	st := store.NewLocalStore(filepath.Dir(historyDir))
	records, err := st.ListScans(r.Context(), project, store.ListOptions{})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// records is always non-nil per store contract.
	writeJSON(w, http.StatusOK, records)
}

// ── API: project findings (from latest scan) ─────────────────────────────

func handleFindings(w http.ResponseWriter, r *http.Request, historyDir string, slug string) {
	project := slugToProject(slug)
	st := store.NewLocalStore(filepath.Dir(historyDir))
	records, err := st.ListScans(r.Context(), project, store.ListOptions{})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(records) == 0 {
		writeJSON(w, http.StatusOK, []store.FindingDetail{})
		return
	}
	latest := records[len(records)-1]
	findings := latest.TopFindings
	if findings == nil {
		findings = []store.FindingDetail{}
	}
	writeJSON(w, http.StatusOK, findings)
}

// ── API: project trends ───────────────────────────────────────────────────────

// trendPoint is the per-scan entry sent to the dashboard JS.
// It adds a "date" field (YYYY-MM-DD) that the chart uses for X-axis labels,
// wrapping the existing trends.DataPoint which stores full RFC3339 timestamps.
type trendPoint struct {
	Date       string `json:"date"`
	Timestamp  string `json:"timestamp"`
	QRS        int    `json:"qrs"`
	Grade      string `json:"grade"`
	Findings   int    `json:"findings"`
	Vulnerable int    `json:"vulnerable"`
	Deprecated int    `json:"deprecated"`
}

// trendsResponse is the JSON payload for GET /api/projects/{slug}/trends.
type trendsResponse struct {
	Project    string       `json:"project"`
	DataPoints []trendPoint `json:"dataPoints"`
	Delta      *deltaView   `json:"delta,omitempty"`
	Summary    string       `json:"summary,omitempty"`
}

// deltaView mirrors trends.Delta but uses pointer semantics for JSON omitempty.
type deltaView struct {
	QRS        int  `json:"qrs"`
	Findings   int  `json:"findings"`
	Vulnerable int  `json:"vulnerable"`
	Deprecated int  `json:"deprecated"`
	Improving  bool `json:"improving"`
}

func handleTrends(w http.ResponseWriter, r *http.Request, historyDir string, slug string) {
	project := slugToProject(slug)
	// baseDir is the parent of "history/" per store.LocalStore contract.
	st := store.NewLocalStore(filepath.Dir(historyDir))
	records, err := st.ListScans(r.Context(), project, store.ListOptions{})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	td := trends.Compute(project, records)

	resp := trendsResponse{
		Project:    td.Project,
		DataPoints: make([]trendPoint, 0, len(td.DataPoints)),
		Summary:    td.Summary,
	}

	for _, dp := range td.DataPoints {
		resp.DataPoints = append(resp.DataPoints, trendPoint{
			Date:       dateFromTimestamp(dp.Timestamp),
			Timestamp:  dp.Timestamp,
			QRS:        dp.QRS,
			Grade:      dp.Grade,
			Findings:   dp.Findings,
			Vulnerable: dp.Vulnerable,
			Deprecated: dp.Deprecated,
		})
	}

	if len(td.DataPoints) >= 2 {
		d := td.Delta
		resp.Delta = &deltaView{
			QRS:        d.QRS,
			Findings:   d.Findings,
			Vulnerable: d.Vulnerable,
			Deprecated: d.Deprecated,
			Improving:  d.Improving,
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// listSlugs returns project slugs (filenames without .json) from historyDir.
// Returns nil, nil when the directory does not exist (no history yet).
func listSlugs(historyDir string) ([]string, error) {
	entries, err := os.ReadDir(historyDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var slugs []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), ".json") {
			slugs = append(slugs, strings.TrimSuffix(e.Name(), ".json"))
		}
	}
	sort.Strings(slugs)
	return slugs, nil
}

// slugToProject reverses the store.ProjectSlug transformation ("--" → "/").
// This is a best-effort reversal for display purposes.
func slugToProject(slug string) string {
	return strings.ReplaceAll(slug, "--", "/")
}

// dateFromTimestamp extracts the YYYY-MM-DD prefix from an RFC3339 string.
func dateFromTimestamp(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	if ts == "" {
		return time.Now().Format("2006-01-02")
	}
	return ts
}

// writeJSON encodes v as indented JSON and writes it with the given status.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		// Header already sent; write a best-effort error body fragment.
		fmt.Fprintf(w, `{"error":{"message":"encode error"}}`)
	}
}

// writeJSONError writes a JSON error envelope with the given HTTP status.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	type apiError struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	var payload apiError
	payload.Error.Message = msg
	writeJSON(w, status, payload)
}
