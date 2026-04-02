package constraints

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/impact"
)

func TestDetectFromPath(t *testing.T) {
	tests := []struct {
		name  string
		steps []findings.FlowStep
		want  []impact.ConstraintHit
	}{
		{
			name: "empty path",
			steps: nil,
			want:  nil,
		},
		{
			name: "buffer alloc go",
			steps: []findings.FlowStep{
				{File: "main.go", Line: 10, Message: "buf := make([]byte, 256)"},
			},
			want: []impact.ConstraintHit{
				{Type: "buffer-alloc", File: "main.go", Line: 10, MaxBytes: 256, EffectiveMax: 256},
			},
		},
		{
			name: "buffer alloc java",
			steps: []findings.FlowStep{
				{File: "Auth.java", Line: 42, Message: "byte[] key = new byte[512]"},
			},
			want: []impact.ConstraintHit{
				{Type: "buffer-alloc", File: "Auth.java", Line: 42, MaxBytes: 512, EffectiveMax: 512},
			},
		},
		{
			name: "varchar column",
			steps: []findings.FlowStep{
				{File: "schema.sql", Line: 7, Message: "key_data VARCHAR(4096) NOT NULL"},
			},
			want: []impact.ConstraintHit{
				{Type: "db-column", File: "schema.sql", Line: 7, MaxBytes: 4096, EffectiveMax: 4096},
			},
		},
		{
			name: "config max_len",
			steps: []findings.FlowStep{
				{File: "config.py", Line: 3, Message: "max_len = 1024"},
			},
			want: []impact.ConstraintHit{
				{Type: "config", File: "config.py", Line: 3, MaxBytes: 1024, EffectiveMax: 1024},
			},
		},
		{
			name: "constant definition",
			steps: []findings.FlowStep{
				{File: "limits.h", Line: 5, Message: "CERT_MAX_SIZE = 2048"},
			},
			want: []impact.ConstraintHit{
				{Type: "constant", File: "limits.h", Line: 5, MaxBytes: 2048, EffectiveMax: 2048},
			},
		},
		{
			name: "multiple steps multiple patterns",
			steps: []findings.FlowStep{
				{File: "store.go", Line: 20, Message: "buf := make([]byte, 512)"},
				{File: "db.sql", Line: 3, Message: "sig_col VARCHAR(1024)"},
			},
			want: []impact.ConstraintHit{
				{Type: "buffer-alloc", File: "store.go", Line: 20, MaxBytes: 512, EffectiveMax: 512},
				{Type: "db-column", File: "db.sql", Line: 3, MaxBytes: 1024, EffectiveMax: 1024},
			},
		},
		{
			name: "no patterns in message",
			steps: []findings.FlowStep{
				{File: "readme.md", Line: 1, Message: "this is a plain comment"},
			},
			want: nil,
		},
		{
			name: "zero size ignored",
			steps: []findings.FlowStep{
				{File: "bad.go", Line: 1, Message: "buf := make([]byte, 0)"},
			},
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectFromPath(tc.steps)
			if len(got) != len(tc.want) {
				t.Fatalf("DetectFromPath() returned %d hits, want %d\ngot: %+v\nwant: %+v", len(got), len(tc.want), got, tc.want)
			}
			for i, h := range tc.want {
				g := got[i]
				if g.Type != h.Type || g.File != h.File || g.Line != h.Line ||
					g.MaxBytes != h.MaxBytes || g.EffectiveMax != h.EffectiveMax {
					t.Errorf("hit[%d]: got %+v, want %+v", i, g, h)
				}
			}
		})
	}
}
