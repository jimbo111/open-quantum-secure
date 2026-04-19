package compliance

import (
	"regexp"
	"strings"
	"testing"
)

// isoDateRe matches ISO 8601 dates (YYYY-MM-DD).
var isoDateRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// TestAllFrameworks_Metadata verifies that every registered framework's metadata
// methods return meaningful, non-empty data. These methods flow directly into the
// compliance-report markdown output, so a typo or accidental empty return would
// ship undetected without this test.
func TestAllFrameworks_Metadata(t *testing.T) {
	frameworks := All()
	if len(frameworks) == 0 {
		t.Fatal("All() returned no frameworks — registry is empty")
	}

	for _, fw := range frameworks {
		fw := fw // capture
		t.Run(fw.ID(), func(t *testing.T) {
			// --- Description ---
			desc := fw.Description()
			if desc == "" {
				t.Errorf("Description() is empty")
			}
			// Require that at least one significant token from Name() appears in Description().
			// Full Name() equality is not required because Description() uses longer formal titles.
			nameTokens := strings.Fields(fw.Name())
			foundToken := false
			for _, tok := range nameTokens {
				if len(tok) > 2 && strings.Contains(strings.ToLower(desc), strings.ToLower(tok)) {
					foundToken = true
					break
				}
			}
			if !foundToken {
				t.Errorf("Description() %q shares no significant token with Name() %q", desc, fw.Name())
			}

			// --- ApprovedAlgos ---
			algos := fw.ApprovedAlgos()
			if len(algos) == 0 {
				t.Errorf("ApprovedAlgos() returned no rows")
			}
			for i, a := range algos {
				if a.UseCase == "" {
					t.Errorf("ApprovedAlgos()[%d].UseCase is empty", i)
				}
				if a.Algorithm == "" {
					t.Errorf("ApprovedAlgos()[%d].Algorithm is empty", i)
				}
				if a.Standard == "" {
					t.Errorf("ApprovedAlgos()[%d].Standard is empty", i)
				}
			}

			// --- Deadlines ---
			deadlines := fw.Deadlines()
			if len(deadlines) == 0 {
				t.Errorf("Deadlines() returned no rows")
			}
			for i, d := range deadlines {
				if !isoDateRe.MatchString(d.Date) {
					t.Errorf("Deadlines()[%d].Date %q is not ISO 8601 (YYYY-MM-DD)", i, d.Date)
				}
				if d.Description == "" {
					t.Errorf("Deadlines()[%d].Description is empty", i)
				}
			}
		})
	}
}
