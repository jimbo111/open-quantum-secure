package quantum

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// SectorShelfLife maps industry sector names to their typical data shelf-life in years.
// Used as the default for --data-lifetime-years when --sector is specified.
//
// Values are conservative upper bounds sourced from industry retention requirements:
//   - medical: HIPAA requires records for 6 years; state laws can require 30+ years for
//     specific categories (lifetime records, minors, etc.).
//   - finance: SEC Rule 17a-4 requires broker-dealer records for 7 years; bank exam
//     data often retained for the same period.
//   - state: Classified government data may be sensitive for decades; 50 years covers
//     diplomatic cables, defence contracts, and long-term strategic material.
//   - infra: Critical infrastructure operational data (SCADA logs, grid telemetry)
//     retained for 20 years under NERC CIP and similar regimes.
//   - code: Source code and build artefacts are typically rotated within one major
//     release cycle (~5 years for most commercial software).
//   - generic: General enterprise data without a specific classification; 10 years
//     is a common legal hold period across jurisdictions.
var SectorShelfLife = map[string]int{
	"medical": 30,
	"finance": 7,
	"state":   50,
	"infra":   20,
	"code":    5,
	"generic": 10,
}

// DefaultSectorShelfLifeYears is returned when no --sector or --data-lifetime-years
// is provided. 10 years covers the most common legal hold periods.
const DefaultSectorShelfLifeYears = 10

// ShelfLifeForSector returns the data shelf-life for the given sector name.
// Matching is case-insensitive. Returns DefaultSectorShelfLifeYears for an
// empty or unrecognized sector. See WarnOnUnknownSector for a version that
// emits a diagnostic when the sector name is not recognized.
func ShelfLifeForSector(sector string) int {
	if sector == "" {
		return DefaultSectorShelfLifeYears
	}
	if years, ok := SectorShelfLife[strings.ToLower(sector)]; ok {
		return years
	}
	return DefaultSectorShelfLifeYears
}

// WarnOnUnknownSector is like ShelfLifeForSector but writes a warning to w when
// the sector is non-empty and not a recognized preset. The warning lists all valid
// sector names so the user can correct a typo without consulting the docs.
//
// Call this from CLI commands instead of ShelfLifeForSector when user input is
// involved so that silently falling back to the default is visible in the output.
func WarnOnUnknownSector(sector string, w io.Writer) int {
	if sector == "" {
		return DefaultSectorShelfLifeYears
	}
	if years, ok := SectorShelfLife[strings.ToLower(sector)]; ok {
		return years
	}
	// Build a sorted list of valid names for the warning message.
	valid := make([]string, 0, len(SectorShelfLife))
	for s := range SectorShelfLife {
		valid = append(valid, s)
	}
	sort.Strings(valid)
	fmt.Fprintf(w, "WARNING: unknown --sector %q; valid values: %s. Falling back to \"generic\" (%d years).\n",
		sector, strings.Join(valid, ", "), DefaultSectorShelfLifeYears)
	return DefaultSectorShelfLifeYears
}
