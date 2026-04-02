package constraints

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/impact"
)

func TestCheck(t *testing.T) {
	// ML-DSA-65: SignatureBytes=3309, base64 encoded = ceil(3309/3)*4 = 1103*4 = 4412
	mldsa65 := AlgorithmSizeProfile{
		PublicKeyBytes:  1952,
		PrivateKeyBytes: 4032,
		SignatureBytes:  3309,
	}

	// ECDSA-P256: SignatureBytes=72
	ecdsaP256 := AlgorithmSizeProfile{
		PublicKeyBytes: 65,
		SignatureBytes: 72,
	}

	// ML-KEM-768: CiphertextBytes=1088 (no SignatureBytes)
	mlkem768 := AlgorithmSizeProfile{
		PublicKeyBytes:    1184,
		CiphertextBytes:   1088,
		SharedSecretBytes: 32,
	}

	tests := []struct {
		name           string
		profile        AlgorithmSizeProfile
		constraint     impact.ConstraintHit
		wantViolation  bool
		wantProjected  int
		wantOverflow   int
	}{
		{
			name:    "ML-DSA-65 base64 signature vs 4096B limit — violation",
			profile: mldsa65,
			constraint: impact.ConstraintHit{
				Type:     "http-header",
				MaxBytes: 4096,
				Encoding: "base64",
			},
			wantViolation: true,
			wantProjected: 4412, // ceil(3309/3)*4 = 1103*4 = 4412
			wantOverflow:  316,  // 4412 - 4096
		},
		{
			name:    "ECDSA-P256 raw signature vs 4096B limit — no violation",
			profile: ecdsaP256,
			constraint: impact.ConstraintHit{
				Type:     "http-header",
				MaxBytes: 4096,
				Encoding: "raw",
			},
			wantViolation: false,
			wantProjected: 72,
		},
		{
			name:    "ML-KEM-768 raw ciphertext vs 2048B limit — no violation",
			profile: mlkem768,
			constraint: impact.ConstraintHit{
				Type:     "buffer",
				MaxBytes: 2048,
				Encoding: "",
			},
			wantViolation: false,
			wantProjected: 1088,
		},
		{
			name:    "ML-DSA-65 raw signature vs 3309B exact limit — no violation",
			profile: mldsa65,
			constraint: impact.ConstraintHit{
				Type:     "buffer",
				MaxBytes: 3309,
				Encoding: "raw",
			},
			wantViolation: false,
			wantProjected: 3309,
		},
		{
			name:    "ML-DSA-65 raw signature vs 3308B limit — violation by 1",
			profile: mldsa65,
			constraint: impact.ConstraintHit{
				Type:     "buffer",
				MaxBytes: 3308,
				Encoding: "raw",
			},
			wantViolation: true,
			wantProjected: 3309,
			wantOverflow:  1,
		},
		{
			name:    "EffectiveMax overrides MaxBytes",
			profile: mldsa65,
			constraint: impact.ConstraintHit{
				Type:         "cookie",
				MaxBytes:     8192, // raw limit — would not violate
				EffectiveMax: 3000, // after overhead — violates
				Encoding:     "raw",
			},
			wantViolation: true,
			wantProjected: 3309,
			wantOverflow:  309,
		},
		{
			name: "fallback to PublicKeyBytes when no sig or ciphertext",
			profile: AlgorithmSizeProfile{
				PublicKeyBytes: 2000,
			},
			constraint: impact.ConstraintHit{
				Type:     "buffer",
				MaxBytes: 1024,
				Encoding: "raw",
			},
			wantViolation: true,
			wantProjected: 2000,
			wantOverflow:  976,
		},
		{
			name:    "ML-KEM-768 base64 ciphertext vs 2048B limit — violation",
			profile: mlkem768,
			constraint: impact.ConstraintHit{
				Type:     "cookie",
				MaxBytes: 2048,
				Encoding: "base64",
			},
			// base64(1088) = ceil(1088/3)*4 = 363*4 = 1452 — no violation
			wantViolation: false,
			wantProjected: 1452,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Check(tt.profile, tt.constraint)
			if tt.wantViolation {
				if got == nil {
					t.Fatalf("expected violation, got nil")
				}
				if got.ProjectedBytes != tt.wantProjected {
					t.Errorf("ProjectedBytes = %d, want %d", got.ProjectedBytes, tt.wantProjected)
				}
				if got.Overflow != tt.wantOverflow {
					t.Errorf("Overflow = %d, want %d", got.Overflow, tt.wantOverflow)
				}
			} else {
				if got != nil {
					t.Errorf("expected no violation, got %+v (projected=%d)", got, got.ProjectedBytes)
				}
			}
		})
	}
}
