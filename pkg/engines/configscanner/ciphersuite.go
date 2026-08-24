package configscanner

// Cipher-suite / algorithm-list decomposition.
//
// Server configs carry compound crypto values: OpenSSL cipher strings
// ("ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA"), TLS 1.3 suites
// ("TLS_AES_128_GCM_SHA256"), SSH algorithm lists ("curve25519-sha256,
// diffie-hellman-group14-sha1"), krb5 enctypes ("aes256-cts-hmac-sha1-96")
// and IPsec proposals ("aes256-sha256-modp2048"). A single vocabulary hit per
// value would report only one primitive; instead these values are split into
// tokens and each token is decomposed into its crypto atoms, emitting one
// finding per DISTINCT atom.

import (
	"strconv"
	"strings"
)

// cryptoAtom is one crypto primitive extracted from a compound token.
type cryptoAtom struct {
	Name      string
	Primitive string
	KeySize   int
	Mode      string
}

// listValueKeyPatterns are key patterns whose values are algorithm lists and
// therefore go through token decomposition instead of single-hit vocabulary
// matching. These are FULL key strings on purpose: keyMatchesPattern has no
// generic plural tolerance (design decision B7 — "algorithms" must never
// match the "algorithm" pattern), so plural directive names are allowlisted
// here explicitly rather than by loosening the matcher.
var listValueKeyPatterns = []string{
	// nginx
	"ssl_ciphers", "ssl_ecdh_curve", "ssl_protocols",
	// Apache httpd (camelCase keys segment to ssl.cipher.suite etc.;
	// keyMatchesPattern's multi-segment rejoin matches the glued pattern)
	"sslciphersuite", "sslprotocol", "opensslconfcmd",
	// OpenSSH sshd_config / ssh_config
	"ciphers", "macs", "kexalgorithms", "hostkeyalgorithms",
	"pubkeyacceptedalgorithms", "casignaturealgorithms",
	// krb5.conf [libdefaults]
	"permitted_enctypes", "default_tgs_enctypes", "default_tkt_enctypes",
	// ipsec.conf conn proposals
	"ike", "esp",
}

// isListValueKey reports whether key names an algorithm-list directive.
func isListValueKey(key string) bool {
	for _, p := range listValueKeyPatterns {
		if keyMatchesPattern(key, p) {
			return true
		}
	}
	return false
}

// splitListValue splits a compound algorithm-list value into tokens.
// Separators: OpenSSL cipher strings use ':' (and ' ' in Apache directives),
// SSH and krb5 lists use ',' and ' '. Exclusion/annotation tokens
// ("!aNULL", "-SSLv3", "@STRENGTH", "@SECLEVEL=2") are dropped — they remove
// or annotate algorithms rather than enable them. A leading '+' (reorder in
// OpenSSL, "append" in sshd) is stripped; the token itself still counts.
func splitListValue(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ':' || r == ',' || r == ' ' || r == '\t' || r == ';' || r == '"' || r == '\''
	})
	var tokens []string
	for _, f := range fields {
		f = strings.TrimPrefix(f, "^") // sshd "place first" prefix
		f = strings.TrimPrefix(f, "+")
		if f == "" || f[0] == '!' || f[0] == '-' || f[0] == '@' {
			continue
		}
		tokens = append(tokens, f)
	}
	return tokens
}

// protocolTokens maps protocol-version list tokens (ssl_protocols /
// SSLProtocol values) to their canonical Algorithm names. The names match
// pkg/quantum's protocol classification (SSLv3/TLSv1.0/1.1 deprecated,
// TLSv1.2 conditional, TLSv1.3 baseline).
var protocolTokens = map[string]cryptoAtom{
	"sslv2":   {Name: "SSLv2", Primitive: "protocol"},
	"sslv3":   {Name: "SSLv3", Primitive: "protocol"},
	"ssl3":    {Name: "SSLv3", Primitive: "protocol"},
	"tlsv1":   {Name: "TLSv1.0", Primitive: "protocol"},
	"tls1":    {Name: "TLSv1.0", Primitive: "protocol"},
	"tlsv1.0": {Name: "TLSv1.0", Primitive: "protocol"},
	"tls1.0":  {Name: "TLSv1.0", Primitive: "protocol"},
	"tlsv1.1": {Name: "TLSv1.1", Primitive: "protocol"},
	"tls1.1":  {Name: "TLSv1.1", Primitive: "protocol"},
	"tlsv1.2": {Name: "TLSv1.2", Primitive: "protocol"},
	"tls1.2":  {Name: "TLSv1.2", Primitive: "protocol"},
	"tlsv1.3": {Name: "TLSv1.3", Primitive: "protocol"},
	"tls1.3":  {Name: "TLSv1.3", Primitive: "protocol"},
}

// dhGroupBits maps RFC 4253 / RFC 8268 diffie-hellman-groupN numbers to
// modulus bits. Unknown groups (including group-exchange) return 0.
func dhGroupBits(group string) int {
	switch group {
	case "1":
		return 1024
	case "14":
		return 2048
	case "15":
		return 3072
	case "16":
		return 4096
	case "17":
		return 6144
	case "18":
		return 8192
	}
	return 0
}

// leadingInt parses the leading decimal digits of s, returning the value and
// the remaining suffix. Returns (0, s) when s has no leading digits.
func leadingInt(s string) (int, string) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, s
	}
	n, err := strconv.Atoi(s[:i])
	if err != nil {
		return 0, s
	}
	return n, s[i:]
}

// decomposeAlgorithmToken breaks one cipher-suite / SSH-algorithm / enctype /
// IPsec-proposal token into its crypto atoms. Unknown tokens yield nil.
func decomposeAlgorithmToken(token string) []cryptoAtom {
	// Strip vendor suffix ("chacha20-poly1305@openssh.com").
	if i := strings.IndexByte(token, '@'); i >= 0 {
		token = token[:i]
	}
	// Strip IPsec strict-proposal flag ("aes256-sha256-modp2048!").
	t := strings.ToLower(strings.TrimSuffix(token, "!"))
	if t == "" {
		return nil
	}

	// Whole-token forms first: PQC hybrid KEMs and protocol versions.
	glued := strings.NewReplacer("-", "", "_", "").Replace(t)
	switch {
	case strings.Contains(glued, "x25519mlkem768") || strings.Contains(glued, "mlkem768x25519"):
		// OpenSSL group X25519MLKEM768 and OpenSSH kex mlkem768x25519-sha256
		// are the same draft-ietf-tls-hybrid-design hybrid; emit the
		// canonical name that pkg/quantum's pqcSafeFamilies recognizes.
		return []cryptoAtom{{Name: "X25519MLKEM768", Primitive: "kem"}}
	case strings.Contains(glued, "secp256r1mlkem768") || strings.Contains(glued, "p256mlkem768"):
		return []cryptoAtom{{Name: "SecP256r1MLKEM768", Primitive: "kem"}}
	case strings.Contains(glued, "secp384r1mlkem1024") || strings.Contains(glued, "p384mlkem1024"):
		return []cryptoAtom{{Name: "SecP384r1MLKEM1024", Primitive: "kem"}}
	case strings.HasPrefix(t, "sntrup"):
		// OpenSSH NTRU-Prime hybrid (sntrup761x25519-sha512@openssh.com).
		// pkg/quantum has no NTRU-Prime family yet, so the literal hybrid
		// name is emitted rather than mislabeling it as NTRU+ or X25519.
		name := t
		if i := strings.IndexByte(name, '-'); i >= 0 {
			name = name[:i]
		}
		return []cryptoAtom{{Name: name, Primitive: "kem"}}
	}
	if a, ok := protocolTokens[t]; ok {
		return []cryptoAtom{a}
	}

	segs := strings.FieldsFunc(t, func(r rune) bool {
		return r == '-' || r == '_' || r == '+' || r == '/'
	})

	var atoms []cryptoAtom
	lastCipher := -1 // index of last symmetric-cipher atom, for mode attachment
	lastCurve := -1  // index of last ECDH/ECDSA atom, for nistpN size attachment
	addCipher := func(name string, keySize int, mode string) {
		atoms = append(atoms, cryptoAtom{Name: name, Primitive: "symmetric", KeySize: keySize, Mode: mode})
		lastCipher = len(atoms) - 1
	}
	for i := 0; i < len(segs); i++ {
		s := segs[i]
		switch {
		case s == "" || s == "tls" || s == "ssl" || s == "ssh" || s == "with" ||
			s == "openssh" || s == "com" || s == "cert" || s == "v01" || s == "etm":
			// structural noise
		case s == "ecdhe" || s == "eecdh" || s == "kecdhe":
			atoms = append(atoms, cryptoAtom{Name: "ECDHE", Primitive: "key-exchange"})
			lastCurve = len(atoms) - 1
		case s == "ecdh" || s == "kecdh" || s == "aecdh":
			atoms = append(atoms, cryptoAtom{Name: "ECDH", Primitive: "key-exchange"})
			lastCurve = len(atoms) - 1
		case s == "dhe" || s == "edh" || s == "kdhe":
			atoms = append(atoms, cryptoAtom{Name: "DHE", Primitive: "key-exchange"})
		case s == "dh" || s == "kdh" || s == "adh":
			atoms = append(atoms, cryptoAtom{Name: "DH", Primitive: "key-exchange"})
		case s == "diffie":
			// "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha256"
			keySize := 0
			for j := i + 1; j < len(segs); j++ {
				if g := strings.TrimPrefix(segs[j], "group"); g != segs[j] && g != "" {
					keySize = dhGroupBits(g)
					i = j
					break
				}
				if segs[j] == "group" || segs[j] == "hellman" || segs[j] == "exchange" {
					i = j
					continue
				}
				break
			}
			atoms = append(atoms, cryptoAtom{Name: "DH", Primitive: "key-exchange", KeySize: keySize})
		case s == "rsa" || s == "krsa" || s == "arsa":
			atoms = append(atoms, cryptoAtom{Name: "RSA", Primitive: "asymmetric"})
		case s == "rsassa":
			atoms = append(atoms, cryptoAtom{Name: "RSA", Primitive: "signature"})
		case s == "ecdsa" || s == "aecdsa":
			atoms = append(atoms, cryptoAtom{Name: "ECDSA", Primitive: "signature"})
			lastCurve = len(atoms) - 1
		case s == "dss" || s == "dsa":
			atoms = append(atoms, cryptoAtom{Name: "DSA", Primitive: "signature"})
		case s == "ed25519":
			atoms = append(atoms, cryptoAtom{Name: "Ed25519", Primitive: "signature"})
		case s == "ed448":
			atoms = append(atoms, cryptoAtom{Name: "Ed448", Primitive: "signature"})
		case s == "x25519" || s == "curve25519":
			atoms = append(atoms, cryptoAtom{Name: "X25519", Primitive: "key-exchange"})
		case s == "x448" || s == "curve448":
			atoms = append(atoms, cryptoAtom{Name: "X448", Primitive: "key-exchange"})
		case strings.HasPrefix(s, "nistp"):
			n, _ := leadingInt(s[len("nistp"):])
			if lastCurve >= 0 && atoms[lastCurve].KeySize == 0 {
				atoms[lastCurve].KeySize = n
			} else {
				atoms = append(atoms, cryptoAtom{Name: "ECDH", Primitive: "key-exchange", KeySize: n})
			}
		case strings.HasPrefix(s, "secp") || strings.HasPrefix(s, "prime") || strings.HasPrefix(s, "ecp"):
			// secp256r1 / secp256k1 / prime256v1 / ecp256 (IPsec)
			rest := s
			for _, p := range []string{"secp", "prime", "ecp"} {
				if strings.HasPrefix(s, p) {
					rest = s[len(p):]
					break
				}
			}
			n, _ := leadingInt(rest)
			atoms = append(atoms, cryptoAtom{Name: "ECDH", Primitive: "key-exchange", KeySize: n})
		case strings.HasPrefix(s, "modp"):
			n, _ := leadingInt(s[len("modp"):])
			atoms = append(atoms, cryptoAtom{Name: "DH", Primitive: "key-exchange", KeySize: n})
		case strings.HasPrefix(s, "ffdhe"):
			n, _ := leadingInt(s[len("ffdhe"):])
			atoms = append(atoms, cryptoAtom{Name: "DH", Primitive: "key-exchange", KeySize: n})
		case s == "mlkem512":
			atoms = append(atoms, cryptoAtom{Name: "ML-KEM-512", Primitive: "kem"})
		case s == "mlkem768":
			atoms = append(atoms, cryptoAtom{Name: "ML-KEM-768", Primitive: "kem"})
		case s == "mlkem1024":
			atoms = append(atoms, cryptoAtom{Name: "ML-KEM-1024", Primitive: "kem"})
		case s == "chacha20":
			atoms = append(atoms, cryptoAtom{Name: "ChaCha20-Poly1305", Primitive: "ae"})
			if i+1 < len(segs) && segs[i+1] == "poly1305" {
				i++
			}
		case s == "aesgcm":
			addCipher("AES", 0, "GCM")
		case s == "aesccm" || s == "aesccm8":
			addCipher("AES", 0, "CCM")
		case strings.HasPrefix(s, "aes"):
			// aes128 / aes256 / aes (TLS 1.3 "aes_128_gcm") / aes128gcm16 (IPsec)
			keySize, rest := leadingInt(s[len("aes"):])
			mode := ""
			if keySize == 0 && rest == "" && i+1 < len(segs) {
				// TLS_AES_128_GCM_SHA256 — size is the next segment.
				if n, r := leadingInt(segs[i+1]); r == "" && (n == 128 || n == 192 || n == 256) {
					keySize = n
					i++
				}
			}
			switch {
			case strings.HasPrefix(rest, "gcm"):
				mode = "GCM"
			case strings.HasPrefix(rest, "ccm"):
				mode = "CCM"
			case strings.HasPrefix(rest, "cbc"):
				mode = "CBC"
			case strings.HasPrefix(rest, "ctr"):
				mode = "CTR"
			}
			addCipher("AES", keySize, mode)
		case s == "3des" || s == "des3" || s == "desede" || s == "tripledes":
			addCipher("3DES", 0, "")
		case s == "cbc3":
			// DES-CBC3-SHA: upgrade the preceding DES atom to 3DES.
			if lastCipher >= 0 && atoms[lastCipher].Name == "DES" {
				atoms[lastCipher].Name = "3DES"
			} else {
				addCipher("3DES", 0, "")
			}
		case s == "des":
			addCipher("DES", 0, "")
		case strings.HasPrefix(s, "camellia"):
			n, _ := leadingInt(s[len("camellia"):])
			addCipher("Camellia", n, "")
		case strings.HasPrefix(s, "aria"):
			n, _ := leadingInt(s[len("aria"):])
			addCipher("ARIA", n, "")
		case s == "seed":
			addCipher("SEED", 128, "")
		case s == "rc4" || strings.HasPrefix(s, "arcfour"):
			atoms = append(atoms, cryptoAtom{Name: "RC4", Primitive: "stream-cipher"})
		case s == "rc2":
			addCipher("RC2", 0, "")
		case s == "idea":
			addCipher("IDEA", 0, "")
		case s == "gcm" || s == "cbc" || s == "ctr" || s == "ccm" || s == "cts" || s == "ecb":
			if lastCipher >= 0 && atoms[lastCipher].Mode == "" {
				atoms[lastCipher].Mode = strings.ToUpper(s)
			}
		case s == "hmac":
			// hmac-sha2-256 / hmac-sha1[-96] / hmac-md5
			name := ""
			j := i + 1
			if j < len(segs) {
				switch segs[j] {
				case "sha2":
					if j+1 < len(segs) {
						if n, r := leadingInt(segs[j+1]); r == "" && (n == 256 || n == 384 || n == 512) {
							name = "HMAC-SHA" + segs[j+1]
							j++
						}
					}
				case "sha256":
					name = "HMAC-SHA256"
				case "sha384":
					name = "HMAC-SHA384"
				case "sha512":
					name = "HMAC-SHA512"
				case "sha1", "sha":
					name = "HMAC-SHA1"
				case "md5":
					name = "HMAC-MD5"
				}
			}
			if name != "" {
				atoms = append(atoms, cryptoAtom{Name: name, Primitive: "mac"})
				i = j
			}
		case s == "sha" || s == "sha1":
			// In a TLS 1.2 suite the trailing -SHA names the HMAC-SHA1
			// transcript MAC — emitted as SHA-1.
			atoms = append(atoms, cryptoAtom{Name: "SHA-1", Primitive: "hash"})
		case s == "sha224":
			atoms = append(atoms, cryptoAtom{Name: "SHA-224", Primitive: "hash"})
		case s == "sha256":
			atoms = append(atoms, cryptoAtom{Name: "SHA-256", Primitive: "hash"})
		case s == "sha384":
			atoms = append(atoms, cryptoAtom{Name: "SHA-384", Primitive: "hash"})
		case s == "sha512":
			atoms = append(atoms, cryptoAtom{Name: "SHA-512", Primitive: "hash"})
		case s == "sha2":
			// rsa-sha2-512 — digest size is the next segment; ecdh-sha2-nistp256
			// leaves the curve segment for the nistp case above.
			if i+1 < len(segs) {
				if n, r := leadingInt(segs[i+1]); r == "" && (n == 256 || n == 384 || n == 512) {
					atoms = append(atoms, cryptoAtom{Name: "SHA-" + segs[i+1], Primitive: "hash"})
					i++
				}
			}
		case strings.HasPrefix(s, "prfsha"):
			// IPsec PRF (prfsha256, prfsha1, ...).
			if n, r := leadingInt(s[len("prfsha"):]); r == "" {
				if n == 1 {
					atoms = append(atoms, cryptoAtom{Name: "SHA-1", Primitive: "hash"})
				} else if n == 256 || n == 384 || n == 512 {
					atoms = append(atoms, cryptoAtom{Name: "SHA-" + strconv.Itoa(n), Primitive: "hash"})
				}
			}
		case s == "md5":
			atoms = append(atoms, cryptoAtom{Name: "MD5", Primitive: "hash"})
		default:
			// numeric qualifiers ("96", "16"), grades ("high"), unknown names
		}
	}
	return atoms
}

// decomposeListValue decomposes a full algorithm-list value into deduplicated
// crypto atoms (one per distinct Name/Primitive/KeySize/Mode combination,
// in first-seen order).
func decomposeListValue(value string) []cryptoAtom {
	var out []cryptoAtom
	seen := map[cryptoAtom]bool{}
	for _, token := range splitListValue(value) {
		for _, a := range decomposeAlgorithmToken(token) {
			if seen[a] {
				continue
			}
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}
