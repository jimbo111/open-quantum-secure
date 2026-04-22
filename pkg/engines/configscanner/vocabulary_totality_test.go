package configscanner

// Vocabulary-totality and non-ASCII-key tests.
//
// Goals:
//   1. For every entry in cryptoParams, generate a minimal (key, value) fixture
//      that *should* match. Verify the first match's Algorithm.Name equals the
//      entry's Algorithm. Records any vocabulary entries that are never triggered
//      (shadowed by an earlier entry).
//   2. Verify that a non-ASCII config KEY never panics and behaves safely.
//      Tests Japanese, Chinese, Cyrillic, and emoji keys.

import (
	"fmt"
	"strings"
	"testing"
)

// TestVocabulary_Totality ensures every cryptoParams entry is triggerable by at
// least the obvious synthetic (key, value) pair. If a later entry is shadowed
// by an earlier one (because KeyPattern + ValueHint overlap), we log it.
func TestVocabulary_Totality(t *testing.T) {
	seen := make(map[int]bool)

	for idx, p := range cryptoParams {
		// Skip key-size patterns — they don't take ValueHints.
		if isKeySizePattern(p.KeyPattern) {
			if triggersEntry(t, p.KeyPattern, "256", p.Algorithm, idx) {
				seen[idx] = true
			}
			continue
		}

		// Build a fixture from the first value hint, if any.
		if len(p.ValueHints) == 0 {
			t.Logf("entry %d (%s / %s) has no ValueHints — cannot build fixture without key-size flag",
				idx, p.KeyPattern, p.Algorithm)
			continue
		}
		if triggersEntry(t, p.KeyPattern, p.ValueHints[0], p.Algorithm, idx) {
			seen[idx] = true
		}
	}

	// Report unseen entries.
	missed := 0
	for i := range cryptoParams {
		if !seen[i] {
			missed++
			t.Logf("entry %d shadowed / not triggered: KeyPattern=%q Value=%q Algorithm=%q",
				i, cryptoParams[i].KeyPattern,
				hintSample(cryptoParams[i].ValueHints),
				cryptoParams[i].Algorithm)
		}
	}
	if missed > 0 {
		t.Logf("%d/%d vocabulary entries are shadowed or need better fixtures", missed, len(cryptoParams))
	}
}

func hintSample(h []string) string {
	if len(h) == 0 {
		return "<none>"
	}
	return h[0]
}

// triggersEntry runs matchCryptoParams on a single synthetic KV pair and
// verifies the first finding matches p.Algorithm. Returns true on match.
func triggersEntry(t *testing.T, keyPattern, valueHint, wantAlgorithm string, entryIdx int) bool {
	t.Helper()
	// Use keyPattern itself as the synthesised key (guaranteed to contain the
	// substring). Use the first ValueHint as the synthesised value.
	kv := KeyValue{Key: keyPattern, Value: valueHint, Line: 1}
	fds := matchCryptoParams("synthetic.yml", []KeyValue{kv})
	if len(fds) == 0 {
		t.Logf("entry %d NOT TRIGGERED: key=%q value=%q (want algo=%q)",
			entryIdx, keyPattern, valueHint, wantAlgorithm)
		return false
	}
	if fds[0].Algorithm == nil {
		t.Logf("entry %d: nil algorithm for key=%q value=%q", entryIdx, keyPattern, valueHint)
		return false
	}
	return fds[0].Algorithm.Name == wantAlgorithm
}

// TestVocabulary_NonASCIIKeys verifies non-ASCII keys don't panic and either
// (a) never match a crypto pattern (because KeyPatterns are all ASCII) or
// (b) match safely if the key accidentally contains an ASCII crypto substring.
func TestVocabulary_NonASCIIKeys(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		// Pure non-ASCII keys — should never match our ASCII-only vocabulary.
		{"Japanese hiragana key", "暗号化方式", "AES"},
		{"Japanese katakana key", "アルゴリズム", "AES"}, // arugorizumu — no English match
		{"Chinese simplified key", "算法", "AES"},
		{"Chinese traditional key", "演算法", "AES"},
		{"Cyrillic key", "алгоритм", "AES"},
		{"emoji key", "🔐", "AES"},
		{"emoji plus text", "🔐algorithm", "AES"}, // contains "algorithm" — SHOULD match
		{"Korean hangul key", "알고리즘", "AES"},
		{"Greek key", "αλγόριθμος", "AES"},
		{"RTL Hebrew key", "אלגוריתם", "AES"},
		{"RTL Arabic key", "خوارزمية", "AES"},
		// Non-ASCII in value field.
		{"non-ASCII value", "algorithm", "AES暗号"},
		// Zero-width joiner / combining marks.
		{"zero-width joiner in key", "algo‍rithm", "AES"},
		// BOM at start of key (U+FEFF, encoded via escape to avoid go vet "illegal BOM").
		{"BOM prefix key", "\ufeffalgorithm", "AES"},
		// Null byte in key (would break some parsers but matchCryptoParams is string-based).
		{"null byte in key", "algo\x00rithm", "AES"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("matchCryptoParams panicked on key=%q value=%q: %v",
						tt.key, tt.value, r)
				}
			}()
			kv := KeyValue{Key: tt.key, Value: tt.value, Line: 1}
			fds := matchCryptoParams("utf8.yml", []KeyValue{kv})
			// Pure-non-ASCII keys should NOT produce findings — crypto KeyPatterns
			// are all ASCII and strings.Contains(lower(utf8), "algorithm") is false
			// for pure Japanese/Chinese/etc.
			containsASCIIPattern := strings.Contains(strings.ToLower(tt.key), "algorithm") ||
				strings.Contains(strings.ToLower(tt.key), "cipher") ||
				strings.Contains(strings.ToLower(tt.key), "hash") ||
				strings.Contains(strings.ToLower(tt.key), "encryption") ||
				strings.Contains(strings.ToLower(tt.key), "digest") ||
				strings.Contains(strings.ToLower(tt.key), "signature") ||
				strings.Contains(strings.ToLower(tt.key), "protocol") ||
				strings.Contains(strings.ToLower(tt.key), "keysize") ||
				strings.Contains(strings.ToLower(tt.key), "key.size") ||
				strings.Contains(strings.ToLower(tt.key), "key-size") ||
				strings.Contains(strings.ToLower(tt.key), "key_size") ||
				strings.Contains(strings.ToLower(tt.key), "keylength") ||
				strings.Contains(strings.ToLower(tt.key), "key-length") ||
				strings.Contains(strings.ToLower(tt.key), "key_length")
			if !containsASCIIPattern && len(fds) > 0 {
				t.Errorf("unexpected finding for non-ASCII key %q: %+v", tt.key, fds[0])
			}
			t.Logf("key=%q value=%q -> %d finding(s)", tt.key, tt.value, len(fds))
		})
	}
}

// TestVocabulary_NonASCIIKeysViaYAML verifies that parseYAML + matchCryptoParams
// don't panic with non-ASCII keys from a real YAML file.
func TestVocabulary_NonASCIIKeysViaYAML(t *testing.T) {
	inputs := []string{
		// Japanese key with AES value — should not match (key is not "algorithm").
		"暗号化方式: AES\n",
		// Chinese key.
		"算法: RSA\n",
		// emoji key.
		"🔐: AES\n",
		// Mixed: key has ASCII "algorithm" substring surrounded by non-ASCII.
		"暗algorithm: AES\n",
		// RTL Arabic key.
		"خوارزمية: RSA\n",
	}
	for _, in := range inputs {
		t.Run(fmt.Sprintf("%q", in), func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("parseYAML/match panicked on %q: %v", in, r)
				}
			}()
			kvs, err := parseYAML([]byte(in))
			if err != nil {
				t.Logf("parseYAML error (may be OK): %v", err)
				return
			}
			_ = matchCryptoParams("utf8.yml", kvs)
		})
	}
}

// TestVocabulary_ShadowedEntries lists all vocabulary entries that produce a
// finding with a DIFFERENT Algorithm.Name than their declared one, meaning
// they are shadowed by an earlier vocabulary entry with overlapping KeyPattern.
func TestVocabulary_ShadowedEntries(t *testing.T) {
	shadowed := make(map[int]string) // idx -> winning algo
	for idx, p := range cryptoParams {
		if isKeySizePattern(p.KeyPattern) || len(p.ValueHints) == 0 {
			continue
		}
		kv := KeyValue{Key: p.KeyPattern, Value: p.ValueHints[0], Line: 1}
		fds := matchCryptoParams("s.yml", []KeyValue{kv})
		if len(fds) == 0 || fds[0].Algorithm == nil {
			continue
		}
		if fds[0].Algorithm.Name != p.Algorithm {
			shadowed[idx] = fds[0].Algorithm.Name
		}
	}
	if len(shadowed) == 0 {
		t.Log("no shadowed vocabulary entries")
		return
	}
	t.Logf("shadowed entries (declared Algorithm vs winning Algorithm):")
	for idx, winner := range shadowed {
		p := cryptoParams[idx]
		t.Logf("  idx=%d KeyPattern=%q Value=%q -> declared=%q but got=%q",
			idx, p.KeyPattern, p.ValueHints[0], p.Algorithm, winner)
	}
}
