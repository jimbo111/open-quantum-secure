package constresolver

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// realFinding builds a finding shaped like what real engines actually emit:
// RawIdentifier is an algorithm name (cipherscope) or a rule ID (astgrep) --
// never source text -- and Location.File is populated. This is the shape
// EnrichFindings (RawIdentifier-keyed) can never match; EnrichFindingsByFile
// (Location-keyed) is the path meant to handle it.
func realFinding(file string, algoName string, rawID string) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location:      findings.Location{File: file, Line: 12},
		Algorithm:     &findings.Algorithm{Name: algoName},
		Confidence:    findings.ConfidenceMedium,
		RawIdentifier: rawID,
	}
}

// TestEnrichFindingsByFile_SingleCandidate_GoCryptoShape reproduces the
// go-crypto ground-truth sample: one file, one integer const, one AES
// finding whose RawIdentifier is cipherscope's algorithm name ("AES"), not
// the const name. EnrichFindings (old, RawIdentifier-keyed) cannot fill
// this; EnrichFindingsByFile (Location-keyed) must.
func TestEnrichFindingsByFile_SingleCandidate_GoCryptoShape(t *testing.T) {
	fc := FileConstants{
		"/repo/main.go": ConstMap{"main.KeySize": 256},
	}
	ff := []findings.UnifiedFinding{
		realFinding("/repo/main.go", "AES", "AES"),
	}

	EnrichFindingsByFile(ff, fc)

	if ff[0].Algorithm.KeySize != 256 {
		t.Errorf("KeySize = %d, want 256 (sole candidate in file)", ff[0].Algorithm.KeySize)
	}
}

// TestEnrichFindingsByFile_AstgrepRuleIDShape uses a rule-ID RawIdentifier
// (astgrep's shape) to confirm the match is truly Location-driven, not an
// accidental RawIdentifier substring hit.
func TestEnrichFindingsByFile_AstgrepRuleIDShape(t *testing.T) {
	fc := FileConstants{
		"/repo/main.go": ConstMap{"main.KeySize": 256},
	}
	ff := []findings.UnifiedFinding{
		realFinding("/repo/main.go", "CIPHER", "crypto-go-aes-new-cipher"),
	}

	EnrichFindingsByFile(ff, fc)

	if ff[0].Algorithm.KeySize != 256 {
		t.Errorf("KeySize = %d, want 256", ff[0].Algorithm.KeySize)
	}
}

// TestEnrichFindingsByFile_NoCrossContamination is the guard case called
// out explicitly: a file with TWO differently-purposed integer constants
// (RSA modulus bits + AES key size) must not let one finding's KeySize leak
// into the other.
func TestEnrichFindingsByFile_NoCrossContamination(t *testing.T) {
	fc := FileConstants{
		"/repo/CryptoService.java": ConstMap{
			"CryptoService.RSA_KEY_LENGTH": 2048,
			"CryptoService.AES_KEY_SIZE":   256,
		},
	}
	ff := []findings.UnifiedFinding{
		realFinding("/repo/CryptoService.java", "AES", "AES"),
		realFinding("/repo/CryptoService.java", "RSA", "RSA"),
	}

	EnrichFindingsByFile(ff, fc)

	if ff[0].Algorithm.KeySize != 256 {
		t.Errorf("AES finding: KeySize = %d, want 256 (must not pick up RSA's 2048)", ff[0].Algorithm.KeySize)
	}
	if ff[1].Algorithm.KeySize != 2048 {
		t.Errorf("RSA finding: KeySize = %d, want 2048 (must not pick up AES's 256)", ff[1].Algorithm.KeySize)
	}
}

// TestEnrichFindingsByFile_AmbiguousMultiCandidate_LeavesUnset covers the
// case where multiple candidates exist AND none can be disambiguated by
// algorithm name -- the safe behavior is to leave KeySize at 0 rather than
// guess, since a wrong guess actively misclassifies quantum risk.
func TestEnrichFindingsByFile_AmbiguousMultiCandidate_LeavesUnset(t *testing.T) {
	fc := FileConstants{
		"/repo/config.go": ConstMap{
			"config.SIZE_ONE": 2048,
			"config.SIZE_TWO": 256,
		},
	}
	ff := []findings.UnifiedFinding{
		realFinding("/repo/config.go", "AES", "AES"),
	}

	EnrichFindingsByFile(ff, fc)

	if ff[0].Algorithm.KeySize != 0 {
		t.Errorf("KeySize = %d, want 0 (ambiguous candidates, neither name-matches AES)", ff[0].Algorithm.KeySize)
	}
}

// TestEnrichFindingsByFile_ImplausiblySmallConstIgnored guards against an
// unrelated small integer const (e.g. a retry count) in a file with no other
// candidates being misread as a key size.
func TestEnrichFindingsByFile_ImplausiblySmallConstIgnored(t *testing.T) {
	fc := FileConstants{
		"/repo/main.go": ConstMap{"main.MaxRetries": 3},
	}
	ff := []findings.UnifiedFinding{
		realFinding("/repo/main.go", "AES", "AES"),
	}

	EnrichFindingsByFile(ff, fc)

	if ff[0].Algorithm.KeySize != 0 {
		t.Errorf("KeySize = %d, want 0 (MaxRetries=3 is not a plausible key size)", ff[0].Algorithm.KeySize)
	}
}

// TestEnrichFindingsByFile_NoFileMatch_NoOp covers a finding whose file
// isn't in FileConstants at all (no consts found in that file, or file
// wasn't walked).
func TestEnrichFindingsByFile_NoFileMatch_NoOp(t *testing.T) {
	fc := FileConstants{
		"/repo/other.go": ConstMap{"other.KeySize": 256},
	}
	ff := []findings.UnifiedFinding{
		realFinding("/repo/main.go", "AES", "AES"),
	}

	EnrichFindingsByFile(ff, fc)

	if ff[0].Algorithm.KeySize != 0 {
		t.Errorf("KeySize = %d, want 0 (no consts recorded for this finding's file)", ff[0].Algorithm.KeySize)
	}
}

// TestEnrichFindingsByFile_AlreadyHasKeySize_NotOverwritten mirrors the
// existing EnrichFindings contract: never clobber a KeySize an engine
// already determined.
func TestEnrichFindingsByFile_AlreadyHasKeySize_NotOverwritten(t *testing.T) {
	fc := FileConstants{
		"/repo/main.go": ConstMap{"main.KeySize": 256},
	}
	ff := []findings.UnifiedFinding{
		{
			Location:   findings.Location{File: "/repo/main.go"},
			Algorithm:  &findings.Algorithm{Name: "AES", KeySize: 128},
			Confidence: findings.ConfidenceMedium,
		},
	}

	EnrichFindingsByFile(ff, fc)

	if ff[0].Algorithm.KeySize != 128 {
		t.Errorf("KeySize = %d, want 128 (unchanged)", ff[0].Algorithm.KeySize)
	}
}

// TestEnrichFindingsByFile_NilAndEmptyInputs covers defensive edge cases:
// nil Algorithm, empty Location.File, empty FileConstants.
func TestEnrichFindingsByFile_NilAndEmptyInputs(t *testing.T) {
	fc := FileConstants{"/repo/main.go": ConstMap{"main.KeySize": 256}}

	ff := []findings.UnifiedFinding{
		{Location: findings.Location{File: "/repo/main.go"}, Algorithm: nil},
		{Location: findings.Location{File: ""}, Algorithm: &findings.Algorithm{Name: "AES"}},
	}
	EnrichFindingsByFile(ff, fc) // must not panic
	if ff[0].Algorithm != nil {
		t.Error("expected Algorithm to remain nil")
	}
	if ff[1].Algorithm.KeySize != 0 {
		t.Error("expected no enrichment for empty Location.File")
	}

	// Empty/nil FileConstants must no-op without panicking.
	ff2 := []findings.UnifiedFinding{realFinding("/repo/main.go", "AES", "AES")}
	EnrichFindingsByFile(ff2, nil)
	if ff2[0].Algorithm.KeySize != 0 {
		t.Error("expected no-op on nil FileConstants")
	}
	EnrichFindingsByFile(ff2, FileConstants{})
	if ff2[0].Algorithm.KeySize != 0 {
		t.Error("expected no-op on empty FileConstants")
	}
}

// TestEnrichFindingsByFile_PathCleaning confirms that a finding's file path
// is matched against FileConstants after filepath.Clean, so trivial path
// spelling differences (redundant "./" segments) don't defeat the match.
func TestEnrichFindingsByFile_PathCleaning(t *testing.T) {
	fc := FileConstants{
		"/repo/main.go": ConstMap{"main.KeySize": 256},
	}
	ff := []findings.UnifiedFinding{
		realFinding("/repo/./main.go", "AES", "AES"),
	}

	EnrichFindingsByFile(ff, fc)

	if ff[0].Algorithm.KeySize != 256 {
		t.Errorf("KeySize = %d, want 256 (path should be cleaned before lookup)", ff[0].Algorithm.KeySize)
	}
}
