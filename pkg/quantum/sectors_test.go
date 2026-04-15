package quantum

import (
	"testing"
)

func TestShelfLifeForSector_AllPresets(t *testing.T) {
	tests := []struct {
		sector    string
		wantYears int
	}{
		{"medical", 30},
		{"finance", 7},
		{"state", 50},
		{"infra", 20},
		{"code", 5},
		{"generic", 10},
	}

	for _, tt := range tests {
		t.Run(tt.sector, func(t *testing.T) {
			got := ShelfLifeForSector(tt.sector)
			if got != tt.wantYears {
				t.Errorf("ShelfLifeForSector(%q) = %d, want %d", tt.sector, got, tt.wantYears)
			}
		})
	}
}

func TestShelfLifeForSector_CaseInsensitive(t *testing.T) {
	variants := []string{"MEDICAL", "Medical", "mEdIcAl", "MEDICAL"}
	for _, v := range variants {
		t.Run(v, func(t *testing.T) {
			got := ShelfLifeForSector(v)
			if got != 30 {
				t.Errorf("ShelfLifeForSector(%q) = %d, want 30 (case-insensitive)", v, got)
			}
		})
	}
}

func TestShelfLifeForSector_UnknownFallsBackToDefault(t *testing.T) {
	unknowns := []string{"aerospace", "retail", "gaming", "xyz123"}
	for _, u := range unknowns {
		t.Run(u, func(t *testing.T) {
			got := ShelfLifeForSector(u)
			if got != DefaultSectorShelfLifeYears {
				t.Errorf("ShelfLifeForSector(%q) = %d, want DefaultSectorShelfLifeYears (%d)",
					u, got, DefaultSectorShelfLifeYears)
			}
		})
	}
}

func TestShelfLifeForSector_EmptyStringFallsBackToDefault(t *testing.T) {
	got := ShelfLifeForSector("")
	if got != DefaultSectorShelfLifeYears {
		t.Errorf("ShelfLifeForSector(\"\") = %d, want %d", got, DefaultSectorShelfLifeYears)
	}
}

func TestSectorShelfLife_AllPresetsConsistentWithMap(t *testing.T) {
	// Verify the SectorShelfLife map contains exactly the documented presets.
	expected := map[string]int{
		"medical": 30,
		"finance": 7,
		"state":   50,
		"infra":   20,
		"code":    5,
		"generic": 10,
	}
	if len(SectorShelfLife) != len(expected) {
		t.Errorf("SectorShelfLife has %d entries, want %d", len(SectorShelfLife), len(expected))
	}
	for sector, years := range expected {
		got, ok := SectorShelfLife[sector]
		if !ok {
			t.Errorf("SectorShelfLife missing %q", sector)
			continue
		}
		if got != years {
			t.Errorf("SectorShelfLife[%q] = %d, want %d", sector, got, years)
		}
	}
}
