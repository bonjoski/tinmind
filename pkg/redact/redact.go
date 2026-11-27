package redact

import (
	"math"
	"regexp"
	"strings"
	"unicode"
)

// Placeholder replaces detected secrets before any byte is persisted to disk.
const Placeholder = "[REDACTED_SECRET]"

const (
	// DefaultEntropyThreshold mirrors Halfshard's >4.2 bits/char secret threshold.
	DefaultEntropyThreshold = 4.2
	minEntropyTokenLen      = 24
)

var (
	secretPatterns = []*regexp.Regexp{
		// PEM private keys (multi-line)
		regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`),
		// OpenAI, Anthropic, Stripe keys
		regexp.MustCompile(`\bsk-(?:proj-|ant-|live-|test-|svcacct-)?[A-Za-z0-9_-]{16,}\b`),
		// AWS Access Key IDs
		regexp.MustCompile(`\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b`),
		// AWS Secret Access Key / Session Token assignments
		regexp.MustCompile(`(?i)\b(aws_secret_access_key|aws_session_token)\s*[:=]\s*["']?[A-Za-z0-9/+=_-]{16,}["']?`),
		// GitHub Personal Access Tokens (classic & fine-grained)
		regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b`),
		regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`),
		// Google / Gemini API keys
		regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{30,}\b`),
		// Slack tokens
		regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`),
		// JWTs (3 dot-separated base64url segments starting with eyJ)
		regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
		// Authorization Bearer / Basic credentials
		regexp.MustCompile(`(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{20,}`),
		// Embedded URL credentials (scheme://user:pass@host)
		regexp.MustCompile(`\b([a-zA-Z][a-zA-Z0-9+.-]{1,15}://[^/\s:@]{1,64}:)([^/\s@]{8,})@`),
		// Sensitive environment/config key=value assignments
		regexp.MustCompile(`(?i)\b((?:openai|anthropic|gemini|aws|stripe|github|gitlab|slack|npm|pypi|api|auth|client|secret|private|access|database|db)_(?:api_)?(?:key|token|secret|password|passwd|url))\s*[:=]\s*["']?([A-Za-z0-9._~+/:@=-]{12,})["']?`),
	}

	hexOnlyRe = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

// ScrubText removes all ANSI/control escape sequences, smuggling characters, known credential
// patterns, high-entropy tokens, and caller-supplied extraSecrets. Use for structured fields.
func ScrubText(input string, extraSecrets ...string) string {
	cleaned := StripAllANSI(input)
	return scrubSecrets(cleaned, extraSecrets...)
}

// ScrubPTY preserves benign SGR/cursor escapes via SafeANSI while stripping OSC-52/DCS/C1/bidi
// attacks and scrubbing all secrets before bytes touch disk. If an attacker splits a secret
// across SGR escape codes, detection falls back to scrubbing the ANSI-stripped text fail-closed.
func ScrubPTY(input string, extraSecrets ...string) string {
	safe := SafeANSI(input)
	scrubbed := scrubSecrets(safe, extraSecrets...)

	// Defend against secret smuggling split across ANSI SGR codes (e.g. "sk-proj-\x1b[31m...").
	strippedBefore := StripAllANSI(safe)
	strippedAfter := StripAllANSI(scrubbed)
	reScrubbed := scrubSecrets(strippedBefore, extraSecrets...)
	if reScrubbed != strippedAfter {
		return reScrubbed
	}
	return scrubbed
}

func scrubSecrets(s string, extraSecrets ...string) string {
	res := s
	for _, sec := range extraSecrets {
		trimmed := strings.TrimSpace(sec)
		if len(trimmed) >= 6 {
			res = strings.ReplaceAll(res, trimmed, Placeholder)
		}
	}
	for i, re := range secretPatterns {
		switch i {
		case 10: // URL credentials: keep scheme://user:, redact password
			res = re.ReplaceAllString(res, "${1}"+Placeholder+"@")
		case 11: // Env assignments: keep variable name, redact value
			res = re.ReplaceAllString(res, "${1}="+Placeholder)
		default:
			res = re.ReplaceAllString(res, Placeholder)
		}
	}
	return scrubHighEntropyTokens(res, DefaultEntropyThreshold)
}

func scrubHighEntropyTokens(s string, threshold float64) string {
	if len(s) < minEntropyTokenLen {
		return s
	}
	var out strings.Builder
	out.Grow(len(s))

	i := 0
	for i < len(s) {
		if isTokenDelim(s[i]) {
			out.WriteByte(s[i])
			i++
			continue
		}
		start := i
		for i < len(s) && !isTokenDelim(s[i]) {
			i++
		}
		tok := s[start:i]
		if shouldRedactByEntropy(tok, threshold) {
			out.WriteString(Placeholder)
		} else {
			out.WriteString(tok)
		}
	}
	return out.String()
}

func isTokenDelim(b byte) bool {
	switch b {
	case ' ', '\t', '\r', '\n', '"', '\'', '`', ',', ';', '(', ')', '[', ']', '{', '}', '<', '>', '=', ':':
		return true
	}
	return false
}

func shouldRedactByEntropy(tok string, threshold float64) bool {
	if len(tok) < minEntropyTokenLen || len(tok) > 512 {
		return false
	}
	if strings.Contains(tok, Placeholder) {
		return false
	}
	// Do not falsely redact filesystem paths, URLs, or Go import paths.
	if strings.HasPrefix(tok, "/") || strings.HasPrefix(tok, "./") || strings.HasPrefix(tok, "../") ||
		strings.Contains(tok, "://") || strings.Count(tok, "/") >= 2 {
		return false
	}
	// Do not falsely redact standard git commit SHAs / SHA-256 hex digests.
	if hexOnlyRe.MatchString(tok) && (len(tok) == 40 || len(tok) == 64 || len(tok) == 128) {
		return false
	}
	// Require at least 3 character classes (upper, lower, digit, symbol) to avoid natural-language false positives.
	var hasUpper, hasLower, hasDigit, hasSym bool
	for _, r := range tok {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case r == '_' || r == '-' || r == '+' || r == '/' || r == '=':
			hasSym = true
		default:
			return false
		}
	}
	classes := 0
	if hasUpper {
		classes++
	}
	if hasLower {
		classes++
	}
	if hasDigit {
		classes++
	}
	if hasSym {
		classes++
	}
	if classes < 3 {
		return false
	}
	return ShannonEntropy(tok) > threshold
}

// ShannonEntropy computes Shannon entropy in bits per byte.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var ent float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		ent -= p * math.Log2(p)
	}
	return ent
}

// SafeANSI strips dangerous terminal escape sequences (OSC including OSC-52 clipboard writes,
// DCS, SOS, PM, APC, window manipulation / device-query CSI, 8-bit C1 controls, Unicode Bidi
// overrides, and zero-width / Unicode tag smuggling) while preserving benign SGR colors and
// standard cursor-movement CSI sequences.
func SafeANSI(s string) string {
	return filterANSI(s, true)
}

// StripAllANSI removes every ANSI/VT100/OSC/DCS/C1 escape sequence and unsafe control/smuggling
// rune, preserving only printable runes, '\n', and '\t'.
func StripAllANSI(s string) string {
	return filterANSI(s, false)
}

func filterANSI(s string, keepSafeCSI bool) string {
	runes := []rune(s)
	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(runes); i++ {
		r := runes[i]

		// 7-bit ESC sequences
		if r == 0x1b {
			if i+1 >= len(runes) {
				break
			}
			next := runes[i+1]
			switch next {
			case '[': // CSI: ESC [ params intermediate final
				start := i
				i += 2
				paramStart := i
				for i < len(runes) {
					c := runes[i]
					if c >= 0x40 && c <= 0x7e {
						break
					}
					i++
				}
				if keepSafeCSI && i < len(runes) {
					final := runes[i]
					params := runes[paramStart:i]
					if isSafeCSI(params, final) {
						for k := start; k <= i; k++ {
							b.WriteRune(runes[k])
						}
					}
				}
			case ']', 'P', 'X', '^', '_': // OSC / DCS / SOS / PM / APC (terminated by BEL, ST, or C1 ST)
				i += 2
				for i < len(runes) {
					if runes[i] == 0x07 || runes[i] == 0x9c {
						break
					}
					if runes[i] == 0x1b && i+1 < len(runes) && runes[i+1] == '\\' {
						i++
						break
					}
					i++
				}
			default:
				// 2-byte or intermediate ESC sequence (always strip for safety)
				i++
				for i < len(runes) && runes[i] >= 0x20 && runes[i] <= 0x2f {
					i++
				}
			}
			continue
		}

		// 8-bit C1 CSI (0x9B)
		if r == 0x9b {
			i++
			for i < len(runes) {
				if runes[i] >= 0x40 && runes[i] <= 0x7e {
					break
				}
				i++
			}
			continue
		}

		// 8-bit C1 OSC / DCS / SOS / PM / APC
		if r == 0x9d || r == 0x90 || r == 0x98 || r == 0x9e || r == 0x9f {
			i++
			for i < len(runes) {
				if runes[i] == 0x07 || runes[i] == 0x9c {
					break
				}
				if runes[i] == 0x1b && i+1 < len(runes) && runes[i+1] == '\\' {
					i++
					break
				}
				i++
			}
			continue
		}

		// Preserve newline, tab, and (in PTY mode) carriage return & backspace
		if r == '\n' || r == '\t' {
			b.WriteRune(r)
			continue
		}
		if keepSafeCSI && (r == '\r' || r == '\b') {
			b.WriteRune(r)
			continue
		}

		// Strip remaining C0, DEL, C1 controls
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			continue
		}
		// Strip Unicode Bidi overrides, zero-width smuggling, BOM, and Unicode Tag block
		if isUnsafeUnicode(r) {
			continue
		}

		b.WriteRune(r)
	}

	return b.String()
}

func isSafeCSI(params []rune, final rune) bool {
	if len(params) > 48 {
		return false
	}
	// Only allow SGR color/style ('m') and benign cursor/erase controls.
	// Explicitly excludes 't' (window ops), 'c'/'n' (device queries), 'p' (soft reset), etc.
	switch final {
	case 'm':
		for _, p := range params {
			if (p < '0' || p > '9') && p != ';' && p != ':' {
				return false
			}
		}
		return true
	case 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'f':
		for _, p := range params {
			if (p < '0' || p > '9') && p != ';' {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func isUnsafeUnicode(r rune) bool {
	switch {
	case r >= 0x202a && r <= 0x202e: // Bidi embedding/override
		return true
	case r >= 0x2066 && r <= 0x2069: // Bidi isolates
		return true
	case r >= 0x200b && r <= 0x200f: // Zero-width spaces & marks
		return true
	case r == 0xfeff: // BOM
		return true
	case r >= 0xe0000 && r <= 0xe007f: // Unicode Tag block smuggling
		return true
	default:
		return false
	}
}
