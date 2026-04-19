package zeeklog

import (
	"bytes"
	"testing"
)

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  logFormat
	}{
		{"tsv header", "#separator \\x09\n#fields\tuid\tts", formatTSV},
		{"tsv fields", "#fields\tuid\tcypher", formatTSV},
		{"json object", `{"uid":"abc"}`, formatJSON},
		{"json with leading whitespace", "\n  {\"uid\":\"abc\"}", formatJSON},
		{"empty", "", formatUnknown},
		{"random text", "some random content", formatUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectFormat([]byte(tt.input))
			if got != tt.want {
				t.Errorf("detectFormat(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestSniffFormat(t *testing.T) {
	t.Run("tsv", func(t *testing.T) {
		r := bytes.NewReader([]byte("#fields\tuid\tts\n"))
		peeked, fmt_, err := sniffFormat(r)
		if err != nil {
			t.Fatalf("sniffFormat: %v", err)
		}
		if fmt_ != formatTSV {
			t.Errorf("format = %v, want formatTSV", fmt_)
		}
		if len(peeked) == 0 {
			t.Error("peeked is empty")
		}
	})
	t.Run("json", func(t *testing.T) {
		r := bytes.NewReader([]byte(`{"uid":"x"}`))
		_, fmt_, err := sniffFormat(r)
		if err != nil {
			t.Fatalf("sniffFormat: %v", err)
		}
		if fmt_ != formatJSON {
			t.Errorf("format = %v, want formatJSON", fmt_)
		}
	})
}
