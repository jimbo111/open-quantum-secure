package protocols

import "testing"

func TestAll_ReturnsEight(t *testing.T) {
	all := All()
	if len(all) != 8 {
		t.Errorf("All() returned %d protocols, want 8", len(all))
	}
}

func TestAll_IsACopy(t *testing.T) {
	a := All()
	b := All()
	a[0].Name = "MODIFIED"
	if b[0].Name == "MODIFIED" {
		t.Error("All() returned a shared slice (not a copy)")
	}
}

func TestLookup(t *testing.T) {
	tests := []struct {
		input     string
		wantName  string
		wantMax   int
		wantHard  bool
		wantFound bool
	}{
		{"JWT", "JWT", 4096, true, true},
		{"TLS", "TLS", 16384, true, true},
		{"gRPC", "gRPC", 8192, false, true},
		{"X.509", "X.509", 16384, false, true},
		{"DTLS", "DTLS", 1500, true, true},
		{"SSH", "SSH", 35000, true, true},
		{"OCSP", "OCSP", 2048, false, true},
		{"S/MIME", "S/MIME", 51200, false, true},
		// case-insensitive
		{"jwt", "JWT", 4096, true, true},
		{"tls", "TLS", 16384, true, true},
		{"grpc", "gRPC", 8192, false, true},
		// unknown
		{"MQTT", "", 0, false, false},
		{"", "", 0, false, false},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, ok := Lookup(tc.input)
			if ok != tc.wantFound {
				t.Fatalf("Lookup(%q) ok=%v want %v", tc.input, ok, tc.wantFound)
			}
			if !ok {
				return
			}
			if got.Name != tc.wantName {
				t.Errorf("Name=%q want %q", got.Name, tc.wantName)
			}
			if got.MaxBytes != tc.wantMax {
				t.Errorf("MaxBytes=%d want %d", got.MaxBytes, tc.wantMax)
			}
			if got.HardLimit != tc.wantHard {
				t.Errorf("HardLimit=%v want %v", got.HardLimit, tc.wantHard)
			}
		})
	}
}
