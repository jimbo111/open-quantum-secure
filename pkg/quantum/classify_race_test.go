package quantum

// classify_race_test.go — concurrency stress tests for ClassifyAlgorithm.
//
// Runs 1000 goroutines simultaneously calling ClassifyAlgorithm with diverse
// (sector, timeToCRQC, algorithm) inputs. Goals:
//
//  1. No data races — verified by -race flag.
//  2. No panics — any goroutine panic propagates to the test runner.
//  3. Determinism — same input always produces the same output; results are
//     verified against a single-threaded reference run.
//
// Run with:
//   go test -race -count=50 ./pkg/quantum/ -run TestClassifyAlgorithm_ConcurrentStress
//
// -count=50 re-runs 50 times to flush out races that manifest rarely.

import (
	"fmt"
	"sync"
	"testing"
)

// classifyInput describes a single ClassifyAlgorithm call.
type classifyInput struct {
	algorithm string
	primitive string
	keySize   int
}

// classifyResult is the subset of Classification fields we compare for determinism.
type classifyResult struct {
	risk        Risk
	hndlRisk    string
	severity    Severity
}

func toResult(c Classification) classifyResult {
	return classifyResult{
		risk:     c.Risk,
		hndlRisk: c.HNDLRisk,
		severity: c.Severity,
	}
}

// buildStressInputs generates 1000 diverse inputs by cycling through sectors,
// timeToCRQC values, and algorithm names. This ensures goroutines do not all
// hit the same code path, maximising coverage of internal state.
func buildStressInputs() []classifyInput {
	algorithms := []struct{ name, prim string }{
		{"RSA-2048", "signature"},
		{"ECDH", "key-exchange"},
		{"ECDHE", "key-agree"},
		{"X25519", "key-exchange"},
		{"X25519MLKEM768", "kem"},
		{"X25519-MLKEM-768", "kem"},
		{"SecP256r1MLKEM768", "kem"},
		{"ML-KEM-768", "kem"},
		{"ML-KEM-512", "kem"},
		{"ML-DSA-65", "signature"},
		{"SLH-DSA-128s", "signature"},
		{"AES-256-GCM", "symmetric"},
		{"AES-128-CBC", "symmetric"},
		{"ChaCha20-Poly1305", "ae"},
		{"SHA-256", "hash"},
		{"SHA-512", "hash"},
		{"MD5", "hash"},
		{"DES", "symmetric"},
		{"ECDSA", "signature"},
		{"Kyber768", "kem"},
		{"X25519Kyber768Draft00", "kem"},
		{"unknown-algo-fallback", "kem"},
		{"SMAUG-T-128", "kem"},
		{"HAETAE-3", "signature"},
		{"GCKSign", "signature"},
	}
	keySizes := []int{0, 128, 256}

	inputs := make([]classifyInput, 0, 1000)
	for i := 0; i < 1000; i++ {
		alg := algorithms[i%len(algorithms)]
		ks := keySizes[i%len(keySizes)]
		inputs = append(inputs, classifyInput{
			algorithm: alg.name,
			primitive: alg.prim,
			keySize:   ks,
		})
	}
	return inputs
}

// TestClassifyAlgorithm_ConcurrentStress launches 1000 goroutines, each calling
// ClassifyAlgorithm once. Verifies no races (-race flag) and that results match
// a single-threaded reference run (determinism).
func TestClassifyAlgorithm_ConcurrentStress(t *testing.T) {
	inputs := buildStressInputs()

	// Build single-threaded reference results first.
	reference := make([]classifyResult, len(inputs))
	for i, inp := range inputs {
		reference[i] = toResult(ClassifyAlgorithm(inp.algorithm, inp.primitive, inp.keySize))
	}

	// Run all 1000 goroutines in parallel.
	results := make([]classifyResult, len(inputs))
	var wg sync.WaitGroup
	wg.Add(len(inputs))
	for i, inp := range inputs {
		go func(idx int, in classifyInput) {
			defer wg.Done()
			results[idx] = toResult(ClassifyAlgorithm(in.algorithm, in.primitive, in.keySize))
		}(i, inp)
	}
	wg.Wait()

	// Verify determinism: each concurrent result must match the reference.
	failures := 0
	for i, got := range results {
		want := reference[i]
		if got != want {
			t.Errorf("input[%d] %q(%s,ks=%d): concurrent=%+v reference=%+v",
				i, inputs[i].algorithm, inputs[i].primitive, inputs[i].keySize, got, want)
			failures++
			if failures > 10 {
				t.Fatal("too many failures, stopping")
			}
		}
	}
}

// TestClassifyAlgorithm_ConcurrentMoscaStress runs 200 goroutines each computing
// a full Mosca surplus + level for a random (sector, crqc) combination, verifying
// no shared-state corruption between the three pure functions.
func TestClassifyAlgorithm_ConcurrentMoscaStress(t *testing.T) {
	type moscaInput struct {
		sector string
		crqc   int
	}
	sectors := []string{"medical", "finance", "state", "infra", "code", "generic"}
	crqcVals := []int{1, 3, 5, 10, 30, 50}

	// Build 200 inputs cycling over combinations.
	inputs := make([]moscaInput, 200)
	for i := range inputs {
		inputs[i] = moscaInput{
			sector: sectors[i%len(sectors)],
			crqc:   crqcVals[i%len(crqcVals)],
		}
	}

	// Reference: single-threaded.
	type moscaResult struct {
		shelfLife int
		surplus   int
		level     HNDLLevel
	}
	ref := make([]moscaResult, len(inputs))
	for i, inp := range inputs {
		sl := ShelfLifeForSector(inp.sector)
		s := ComputeHNDLSurplus(sl, DefaultMigrationLagYears, inp.crqc)
		ref[i] = moscaResult{shelfLife: sl, surplus: s, level: HNDLLevelFromSurplus(s)}
	}

	// Parallel.
	results := make([]moscaResult, len(inputs))
	var wg sync.WaitGroup
	wg.Add(len(inputs))
	for i, inp := range inputs {
		go func(idx int, in moscaInput) {
			defer wg.Done()
			sl := ShelfLifeForSector(in.sector)
			s := ComputeHNDLSurplus(sl, DefaultMigrationLagYears, in.crqc)
			results[idx] = moscaResult{shelfLife: sl, surplus: s, level: HNDLLevelFromSurplus(s)}
		}(i, inp)
	}
	wg.Wait()

	for i, got := range results {
		want := ref[i]
		if got != want {
			t.Errorf("input[%d] sector=%s crqc=%d: concurrent=%+v reference=%+v",
				i, inputs[i].sector, inputs[i].crqc, got, want)
		}
	}
}

// TestClassifyAlgorithm_ConcurrentExtractBaseName stresses extractBaseName
// with the S0.F4 hyphenated hybrid KEM names — these triggered the bug that
// F4 fixed, and are the most likely to expose races in string processing.
func TestClassifyAlgorithm_ConcurrentExtractBaseName(t *testing.T) {
	hybridNames := []struct{ name, prim string }{
		{"X25519-MLKEM-768", "kem"},
		{"X25519MLKEM768", "kem"},
		{"SecP256r1-MLKEM-768", "kem"},
		{"SecP256r1MLKEM768", "kem"},
		{"X25519", "key-exchange"}, // classical — must NOT be mis-classified as PQ-safe
	}

	var wg sync.WaitGroup
	errCh := make(chan string, len(hybridNames)*100)

	for rep := 0; rep < 100; rep++ {
		for _, h := range hybridNames {
			wg.Add(1)
			go func(name, prim string) {
				defer wg.Done()
				c := ClassifyAlgorithm(name, prim, 0)
				if name == "X25519" {
					// Bare X25519 is classical — must remain HNDLImmediate.
					if c.HNDLRisk != HNDLImmediate {
						errCh <- fmt.Sprintf("X25519 HNDLRisk = %q, want %q (concurrent mis-classification)", c.HNDLRisk, HNDLImmediate)
					}
				} else {
					// Hybrid and pure PQ — must be RiskSafe with empty HNDLRisk.
					if c.Risk != RiskSafe || c.HNDLRisk != "" {
						errCh <- fmt.Sprintf("%q: Risk=%s HNDLRisk=%q, want RiskSafe+\"\" (concurrent mis-classification)", name, c.Risk, c.HNDLRisk)
					}
				}
			}(h.name, h.prim)
		}
	}
	wg.Wait()
	close(errCh)

	for msg := range errCh {
		t.Error(msg)
	}
}
