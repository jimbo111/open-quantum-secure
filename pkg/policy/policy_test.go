package policy

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

// helpers

func algFinding(name string, sev findings.Severity, qr findings.QuantumRisk) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Algorithm:  &findings.Algorithm{Name: name},
		Severity:   sev,
		QuantumRisk: qr,
	}
}

func depFinding(lib string, sev findings.Severity, qr findings.QuantumRisk) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Dependency:  &findings.Dependency{Library: lib},
		Severity:    sev,
		QuantumRisk: qr,
	}
}

func qrs(score int) *quantum.QRS {
	return &quantum.QRS{Score: score, Grade: "test"}
}

func intPtr(n int) *int { return &n }

func summaryFrom(ff []findings.UnifiedFinding) ScanSummary {
	var s ScanSummary
	for _, f := range ff {
		switch f.QuantumRisk {
		case findings.QRVulnerable:
			s.QuantumVulnerable++
		case findings.QRSafe:
			s.QuantumSafe++
		case findings.QRResistant:
			s.QuantumResistant++
		}
	}
	return s
}

// --- Tests ---

func TestEvaluate_EmptyPolicy(t *testing.T) {
	ff := []findings.UnifiedFinding{
		algFinding("RSA-2048", findings.SevHigh, findings.QRVulnerable),
		algFinding("AES-256", findings.SevInfo, findings.QRSafe),
	}
	result := Evaluate(Policy{}, ff, qrs(40), summaryFrom(ff))
	if !result.Pass {
		t.Errorf("empty policy should pass; got violations: %v", result.Violations)
	}
	if len(result.Violations) != 0 {
		t.Errorf("expected 0 violations, got %d", len(result.Violations))
	}
}

func TestEvaluate_EmptyFindings(t *testing.T) {
	p := Policy{
		FailOn:               "high",
		RequirePQC:           false,
		MaxQuantumVulnerable: intPtr(5),
		MinQRS:               50,
	}
	result := Evaluate(p, nil, qrs(100), ScanSummary{})
	if !result.Pass {
		t.Errorf("empty findings with permissive policy should pass; violations: %v", result.Violations)
	}
}

func TestEvaluate_FailOn(t *testing.T) {
	tests := []struct {
		name           string
		failOn         string
		findingSev     findings.Severity
		wantViolations int
		wantRule       string
	}{
		{
			name:           "critical finding triggers critical threshold",
			failOn:         "critical",
			findingSev:     findings.SevCritical,
			wantViolations: 1,
			wantRule:       "fail-on",
		},
		{
			name:           "high finding does not trigger critical threshold",
			failOn:         "critical",
			findingSev:     findings.SevHigh,
			wantViolations: 0,
		},
		{
			name:           "high finding triggers high threshold",
			failOn:         "high",
			findingSev:     findings.SevHigh,
			wantViolations: 1,
			wantRule:       "fail-on",
		},
		{
			name:           "medium finding triggers medium threshold",
			failOn:         "medium",
			findingSev:     findings.SevMedium,
			wantViolations: 1,
			wantRule:       "fail-on",
		},
		{
			name:           "low finding triggers low threshold",
			failOn:         "low",
			findingSev:     findings.SevLow,
			wantViolations: 1,
			wantRule:       "fail-on",
		},
		{
			name:           "info finding does not trigger low threshold",
			failOn:         "low",
			findingSev:     findings.SevInfo,
			wantViolations: 0,
		},
		{
			name:           "critical finding triggers low threshold",
			failOn:         "low",
			findingSev:     findings.SevCritical,
			wantViolations: 1,
			wantRule:       "fail-on",
		},
		{
			name:           "empty failOn does not trigger",
			failOn:         "",
			findingSev:     findings.SevCritical,
			wantViolations: 0,
		},
		{
			name:           "unknown failOn value is ignored",
			failOn:         "disaster",
			findingSev:     findings.SevCritical,
			wantViolations: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ff := []findings.UnifiedFinding{
				algFinding("RSA-2048", tc.findingSev, findings.QRVulnerable),
			}
			p := Policy{FailOn: tc.failOn}
			result := Evaluate(p, ff, nil, summaryFrom(ff))

			if len(result.Violations) != tc.wantViolations {
				t.Errorf("got %d violations, want %d; violations=%v",
					len(result.Violations), tc.wantViolations, result.Violations)
			}
			if tc.wantRule != "" && len(result.Violations) > 0 {
				if result.Violations[0].Rule != tc.wantRule {
					t.Errorf("got rule %q, want %q", result.Violations[0].Rule, tc.wantRule)
				}
			}
			wantPass := tc.wantViolations == 0
			if result.Pass != wantPass {
				t.Errorf("Pass = %v, want %v", result.Pass, wantPass)
			}
		})
	}
}

func TestEvaluate_BlockedAlgorithms(t *testing.T) {
	tests := []struct {
		name             string
		blocked          []string
		algName          string
		wantViolations   int
	}{
		{
			name:           "exact match blocked",
			blocked:        []string{"RSA-2048"},
			algName:        "RSA-2048",
			wantViolations: 1,
		},
		{
			name:           "case-insensitive match",
			blocked:        []string{"rsa-2048"},
			algName:        "RSA-2048",
			wantViolations: 1,
		},
		{
			name:           "no match",
			blocked:        []string{"DES"},
			algName:        "RSA-2048",
			wantViolations: 0,
		},
		{
			name:           "empty blocked list",
			blocked:        nil,
			algName:        "RSA-2048",
			wantViolations: 0,
		},
		{
			name:           "multiple blocked, one matches",
			blocked:        []string{"DES", "RSA-2048", "MD5"},
			algName:        "RSA-2048",
			wantViolations: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ff := []findings.UnifiedFinding{
				algFinding(tc.algName, findings.SevHigh, findings.QRVulnerable),
			}
			p := Policy{BlockedAlgorithms: tc.blocked}
			result := Evaluate(p, ff, nil, summaryFrom(ff))

			if len(result.Violations) != tc.wantViolations {
				t.Errorf("got %d violations, want %d; violations=%v",
					len(result.Violations), tc.wantViolations, result.Violations)
			}
			if tc.wantViolations > 0 && len(result.Violations) > 0 {
				if result.Violations[0].Rule != "blocked-algorithm" {
					t.Errorf("rule = %q, want blocked-algorithm", result.Violations[0].Rule)
				}
				if result.Violations[0].Finding == nil {
					t.Error("violation.Finding should not be nil for per-finding rule")
				}
			}
		})
	}
}

func TestEvaluate_AllowedAlgorithms(t *testing.T) {
	tests := []struct {
		name           string
		allowed        []string
		algName        string
		wantViolations int
	}{
		{
			name:           "algorithm in allowed list passes",
			allowed:        []string{"AES-256", "RSA-2048"},
			algName:        "AES-256",
			wantViolations: 0,
		},
		{
			name:           "algorithm not in allowed list fails",
			allowed:        []string{"AES-256"},
			algName:        "RSA-2048",
			wantViolations: 1,
		},
		{
			name:           "case-insensitive match in allowed list",
			allowed:        []string{"aes-256"},
			algName:        "AES-256",
			wantViolations: 0,
		},
		{
			name:           "empty allowed list allows everything",
			allowed:        nil,
			algName:        "RSA-2048",
			wantViolations: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ff := []findings.UnifiedFinding{
				algFinding(tc.algName, findings.SevMedium, findings.QRWeakened),
			}
			p := Policy{AllowedAlgorithms: tc.allowed}
			result := Evaluate(p, ff, nil, summaryFrom(ff))

			if len(result.Violations) != tc.wantViolations {
				t.Errorf("got %d violations, want %d; violations=%v",
					len(result.Violations), tc.wantViolations, result.Violations)
			}
			if tc.wantViolations > 0 && len(result.Violations) > 0 {
				if result.Violations[0].Rule != "allowed-algorithms" {
					t.Errorf("rule = %q, want allowed-algorithms", result.Violations[0].Rule)
				}
			}
		})
	}
}

func TestEvaluate_DependencyFindings_SkipAlgorithmRules(t *testing.T) {
	// Dependency findings should not trigger allowed/blocked algorithm rules
	ff := []findings.UnifiedFinding{
		depFinding("openssl", findings.SevHigh, findings.QRVulnerable),
	}
	p := Policy{
		AllowedAlgorithms: []string{"AES-256"},  // openssl is not in list
		BlockedAlgorithms: []string{"openssl"},   // but it shouldn't be checked here
	}
	result := Evaluate(p, ff, nil, summaryFrom(ff))
	if !result.Pass {
		t.Errorf("dependency findings should not trigger algorithm rules; violations: %v", result.Violations)
	}
}

func TestEvaluate_RequirePQC(t *testing.T) {
	tests := []struct {
		name           string
		requirePQC     bool
		findings       []findings.UnifiedFinding
		wantViolations int
	}{
		{
			name:       "requirePQC false, no safe findings — passes",
			requirePQC: false,
			findings: []findings.UnifiedFinding{
				algFinding("RSA-2048", findings.SevHigh, findings.QRVulnerable),
			},
			wantViolations: 0,
		},
		{
			name:       "requirePQC true, has quantum-safe finding — passes",
			requirePQC: true,
			findings: []findings.UnifiedFinding{
				algFinding("RSA-2048", findings.SevHigh, findings.QRVulnerable),
				algFinding("ML-KEM-768", findings.SevInfo, findings.QRSafe),
			},
			wantViolations: 0,
		},
		{
			name:       "requirePQC true, has quantum-resistant finding — passes",
			requirePQC: true,
			findings: []findings.UnifiedFinding{
				algFinding("RSA-2048", findings.SevHigh, findings.QRVulnerable),
				algFinding("ML-DSA-65", findings.SevInfo, findings.QRResistant),
			},
			wantViolations: 0,
		},
		{
			name:       "requirePQC true, only vulnerable findings — fails",
			requirePQC: true,
			findings: []findings.UnifiedFinding{
				algFinding("RSA-2048", findings.SevHigh, findings.QRVulnerable),
				algFinding("ECDH-P256", findings.SevHigh, findings.QRVulnerable),
			},
			wantViolations: 1,
		},
		{
			name:           "requirePQC true, empty findings — fails",
			requirePQC:     true,
			findings:       nil,
			wantViolations: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := Policy{RequirePQC: tc.requirePQC}
			result := Evaluate(p, tc.findings, nil, summaryFrom(tc.findings))

			if len(result.Violations) != tc.wantViolations {
				t.Errorf("got %d violations, want %d; violations=%v",
					len(result.Violations), tc.wantViolations, result.Violations)
			}
			if tc.wantViolations > 0 && len(result.Violations) > 0 {
				if result.Violations[0].Rule != "require-pqc" {
					t.Errorf("rule = %q, want require-pqc", result.Violations[0].Rule)
				}
				if result.Violations[0].Finding != nil {
					t.Error("aggregate violation should have nil Finding")
				}
			}
		})
	}
}

func TestEvaluate_MaxQuantumVulnerable(t *testing.T) {
	vulnFinding := func() findings.UnifiedFinding {
		return algFinding("RSA-2048", findings.SevHigh, findings.QRVulnerable)
	}

	tests := []struct {
		name                 string
		maxVulnerable        *int
		numVulnerable        int
		wantViolations       int
	}{
		{
			name:           "nil (disabled) — no violation even with many vulnerable",
			maxVulnerable:  nil,
			numVulnerable:  100,
			wantViolations: 0,
		},
		{
			name:           "max=0, count=0 — passes (zero allowed, zero found)",
			maxVulnerable:  intPtr(0),
			numVulnerable:  0,
			wantViolations: 0,
		},
		{
			name:           "max=0, count=1 — fails (zero allowed, one found)",
			maxVulnerable:  intPtr(0),
			numVulnerable:  1,
			wantViolations: 1,
		},
		{
			name:           "max=5, count=3 — passes",
			maxVulnerable:  intPtr(5),
			numVulnerable:  3,
			wantViolations: 0,
		},
		{
			name:           "max=5, count=5 — passes (equal is ok)",
			maxVulnerable:  intPtr(5),
			numVulnerable:  5,
			wantViolations: 0,
		},
		{
			name:           "max=5, count=6 — fails",
			maxVulnerable:  intPtr(5),
			numVulnerable:  6,
			wantViolations: 1,
		},
		{
			name:           "max=1, count=2 — fails",
			maxVulnerable:  intPtr(1),
			numVulnerable:  2,
			wantViolations: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ff := make([]findings.UnifiedFinding, tc.numVulnerable)
			for i := range ff {
				ff[i] = vulnFinding()
			}
			p := Policy{MaxQuantumVulnerable: tc.maxVulnerable}
			result := Evaluate(p, ff, nil, summaryFrom(ff))

			if len(result.Violations) != tc.wantViolations {
				t.Errorf("got %d violations, want %d; violations=%v",
					len(result.Violations), tc.wantViolations, result.Violations)
			}
			if tc.wantViolations > 0 && len(result.Violations) > 0 {
				if result.Violations[0].Rule != "max-quantum-vulnerable" {
					t.Errorf("rule = %q, want max-quantum-vulnerable", result.Violations[0].Rule)
				}
				if result.Violations[0].Finding != nil {
					t.Error("aggregate violation should have nil Finding")
				}
			}
		})
	}
}

func TestEvaluate_MinQRS(t *testing.T) {
	tests := []struct {
		name           string
		minQRS         int
		qrsScore       *quantum.QRS
		wantViolations int
	}{
		{
			name:           "minQRS=0 disabled — no violation",
			minQRS:         0,
			qrsScore:       qrs(0),
			wantViolations: 0,
		},
		{
			name:           "score meets minimum — passes",
			minQRS:         70,
			qrsScore:       qrs(70),
			wantViolations: 0,
		},
		{
			name:           "score above minimum — passes",
			minQRS:         70,
			qrsScore:       qrs(85),
			wantViolations: 0,
		},
		{
			name:           "score below minimum — fails",
			minQRS:         70,
			qrsScore:       qrs(65),
			wantViolations: 1,
		},
		{
			name:           "nil QRS with minQRS set — violation (score not available)",
			minQRS:         70,
			qrsScore:       nil,
			wantViolations: 1,
		},
		{
			name:           "minQRS=100, score=99 — fails",
			minQRS:         100,
			qrsScore:       qrs(99),
			wantViolations: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := Policy{MinQRS: tc.minQRS}
			result := Evaluate(p, nil, tc.qrsScore, ScanSummary{})

			if len(result.Violations) != tc.wantViolations {
				t.Errorf("got %d violations, want %d; violations=%v",
					len(result.Violations), tc.wantViolations, result.Violations)
			}
			if tc.wantViolations > 0 && len(result.Violations) > 0 {
				if result.Violations[0].Rule != "min-qrs" {
					t.Errorf("rule = %q, want min-qrs", result.Violations[0].Rule)
				}
				if result.Violations[0].Finding != nil {
					t.Error("aggregate violation should have nil Finding")
				}
			}
		})
	}
}

func TestEvaluate_CombinedRules(t *testing.T) {
	// Multiple rules, multiple violations
	ff := []findings.UnifiedFinding{
		algFinding("RSA-2048", findings.SevCritical, findings.QRVulnerable),
		algFinding("DES", findings.SevHigh, findings.QRVulnerable),
		algFinding("MD5", findings.SevMedium, findings.QRDeprecated),
	}

	p := Policy{
		FailOn:               "high",
		BlockedAlgorithms:    []string{"DES", "MD5"},
		AllowedAlgorithms:    []string{"AES-256", "ML-KEM-768"},
		RequirePQC:           true,
		MaxQuantumVulnerable: intPtr(1),
		MinQRS:               80,
	}

	result := Evaluate(p, ff, qrs(40), summaryFrom(ff))

	if result.Pass {
		t.Error("expected policy to fail with multiple violations")
	}
	if len(result.Violations) == 0 {
		t.Error("expected violations but got none")
	}

	// Verify we have at least one of each type of violation
	rulesSeen := make(map[string]bool)
	for _, v := range result.Violations {
		rulesSeen[v.Rule] = true
	}

	expectedRules := []string{"fail-on", "blocked-algorithm", "allowed-algorithms", "require-pqc", "max-quantum-vulnerable", "min-qrs"}
	for _, rule := range expectedRules {
		if !rulesSeen[rule] {
			t.Errorf("expected violation with rule %q but not found; violations=%v", rule, result.Violations)
		}
	}
}

func TestEvaluate_ViolationFindingReference(t *testing.T) {
	// Per-finding violations should reference the specific finding.
	ff := []findings.UnifiedFinding{
		algFinding("RSA-2048", findings.SevHigh, findings.QRVulnerable),
	}
	p := Policy{
		FailOn:            "high",
		BlockedAlgorithms: []string{"RSA-2048"},
	}
	result := Evaluate(p, ff, nil, summaryFrom(ff))

	for _, v := range result.Violations {
		if v.Finding == nil {
			t.Errorf("per-finding rule %q should have non-nil Finding", v.Rule)
		}
		if v.Finding != nil && v.Finding.Algorithm.Name != "RSA-2048" {
			t.Errorf("Finding.Algorithm.Name = %q, want RSA-2048", v.Finding.Algorithm.Name)
		}
	}
}

// TestBuildLookupSet_WhitespaceOnlyEntriesSkipped verifies that whitespace-only
// entries (e.g. "  ") are skipped and do not appear in the lookup set.
// When all entries are whitespace-only, buildLookupSet should return nil.
func TestBuildLookupSet_WhitespaceOnlyEntriesSkipped(t *testing.T) {
	// Whitespace-only entries should be excluded.
	set := buildLookupSet([]string{"  ", "\t", "   "})
	if set != nil {
		t.Errorf("buildLookupSet(whitespace-only) = %v, want nil (all entries skipped)", set)
	}

	// Mixed: one real entry among whitespace entries.
	set2 := buildLookupSet([]string{"  ", "AES-256", "\t"})
	if set2 == nil {
		t.Fatal("buildLookupSet with one valid entry should return non-nil set")
	}
	if _, ok := set2["aes-256"]; !ok {
		t.Error("buildLookupSet: valid entry 'AES-256' not found in set")
	}
	// Whitespace-only entries must not appear as keys.
	for k := range set2 {
		if len(k) == 0 {
			t.Errorf("buildLookupSet: empty string key found in set")
		}
	}
}

func TestBuildLookupSet(t *testing.T) {
	tests := []struct {
		name   string
		input  []string
		lookup string
		exists bool
	}{
		{"empty slice returns nil", nil, "anything", false},
		{"match exact lowercase", []string{"aes-256"}, "aes-256", true},
		{"match uppercase input normalized", []string{"AES-256"}, "aes-256", true},
		{"no match", []string{"DES"}, "aes-256", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			set := buildLookupSet(tc.input)
			_, got := set[tc.lookup]
			if got != tc.exists {
				t.Errorf("lookup %q in set %v: got %v, want %v", tc.lookup, set, got, tc.exists)
			}
		})
	}
}
