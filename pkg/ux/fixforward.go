package ux

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Exit codes aligned with UB-CLI-v2 / UB-MCP-v1 conventions.
const (
	ExitOK          = 0
	ExitGeneralErr  = 1
	ExitUsageErr    = 2
	ExitPolicyDeny  = 10
	ExitNotFound    = 11
	ExitSecurityErr = 126
)

// FixForwardError enforces the UB-CLI-v2 "Teach, Don't Scold" error contract.
// Every user-facing non-zero failure supplies Summary, RemediationCmd, and WhyOneLiner.
type FixForwardError struct {
	Tool           string   `json:"tool"`
	Code           string   `json:"code"`
	Summary        string   `json:"summary"`
	RemediationCmd string   `json:"remediation_cmd"`
	WhyOneLiner    string   `json:"why"`
	DeepWhy        string   `json:"deep_why,omitempty"`
	References     []string `json:"references,omitempty"`
	ExitCode       int      `json:"exit_code"`
}

func (e *FixForwardError) Error() string {
	if e == nil {
		return ""
	}
	return SanitizeSingleLine(e.Summary)
}

// Render writes either machine-readable single-line JSON (--json), calm <=3-line default output,
// or full progressive-disclosure output (--why). All strings are ANSI/control-char sanitized.
func (e *FixForwardError) Render(w io.Writer, asJSON bool, showWhy bool) error {
	if e == nil {
		return nil
	}
	tool := SanitizeSingleLine(e.Tool)
	if tool == "" {
		tool = "tinmind"
	}
	if asJSON {
		sanitized := FixForwardError{
			Tool:           tool,
			Code:           SanitizeSingleLine(e.Code),
			Summary:        SanitizeSingleLine(e.Summary),
			RemediationCmd: SanitizeSingleLine(e.RemediationCmd),
			WhyOneLiner:    SanitizeSingleLine(e.WhyOneLiner),
			DeepWhy:        SanitizeTerminalText(e.DeepWhy),
			ExitCode:       e.ExitCode,
		}
		if len(e.References) > 0 {
			sanitized.References = make([]string, len(e.References))
			for i, ref := range e.References {
				sanitized.References[i] = SanitizeSingleLine(ref)
			}
		}
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		return enc.Encode(&sanitized)
	}

	summary := SanitizeSingleLine(e.Summary)
	fix := SanitizeSingleLine(e.RemediationCmd)
	why := SanitizeSingleLine(e.WhyOneLiner)
	deepWhy := strings.TrimSpace(SanitizeTerminalText(e.DeepWhy))

	if _, err := fmt.Fprintf(w, "⚠ %s: %s\n", tool, summary); err != nil {
		return err
	}
	if fix != "" {
		if _, err := fmt.Fprintf(w, "  Fix:  %s\n", fix); err != nil {
			return err
		}
	}
	if why != "" || (!showWhy && deepWhy != "") {
		whyLine := why
		if !showWhy && deepWhy != "" {
			hint := "re-run with --why for details"
			if whyLine != "" {
				whyLine = fmt.Sprintf("%s (%s)", whyLine, hint)
			} else {
				whyLine = "Re-run with --why for details."
			}
		}
		if _, err := fmt.Fprintf(w, "  Why:  %s\n", whyLine); err != nil {
			return err
		}
	}
	if showWhy && deepWhy != "" {
		if _, err := fmt.Fprintf(w, "\n  Deep Dive (--why):\n  %s\n", strings.ReplaceAll(deepWhy, "\n", "\n  ")); err != nil {
			return err
		}
		for _, ref := range e.References {
			cleanRef := SanitizeSingleLine(ref)
			if cleanRef != "" {
				if _, err := fmt.Fprintf(w, "  Ref:  %s\n", cleanRef); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

var remediationTokenRe = regexp.MustCompile(`^[a-zA-Z0-9@._/-]+$`)

// ValidateRemediationToken restricts tokens interpolated into RemediationCmd so untrusted input
// can never smuggle shell metacharacters, flags, path traversal, or homoglyphs.
func ValidateRemediationToken(token string) bool {
	if token == "" || len(token) > 214 {
		return false
	}
	if !remediationTokenRe.MatchString(token) {
		return false
	}
	if strings.HasPrefix(token, "-") || strings.HasPrefix(token, "/") || strings.HasSuffix(token, "/") {
		return false
	}
	if strings.Contains(token, "..") || strings.Contains(token, "//") {
		return false
	}
	return true
}

// SanitizeSingleLine strips terminal escape sequences and flattens newlines/tabs into spaces.
func SanitizeSingleLine(s string) string {
	clean := SanitizeTerminalText(s)
	clean = strings.ReplaceAll(clean, "\n", " ")
	clean = strings.ReplaceAll(clean, "\t", " ")
	return strings.TrimSpace(clean)
}

// SanitizeTerminalText strips ESC, CSI, OSC, DCS/SOS/PM/APC, C0/C1 controls, DEL, and Unicode bidi overrides.
func SanitizeTerminalText(s string) string {
	runes := []rune(s)
	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r == 0x1b {
			if i+1 >= len(runes) {
				break
			}
			next := runes[i+1]
			switch next {
			case '[':
				i += 2
				for i < len(runes) {
					if runes[i] >= 0x40 && runes[i] <= 0x7e {
						break
					}
					i++
				}
			case ']', 'P', 'X', '^', '_':
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
				i++
				for i < len(runes) && runes[i] >= 0x20 && runes[i] <= 0x2f {
					i++
				}
			}
			continue
		}
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
		if r == '\n' || r == '\t' {
			b.WriteRune(r)
			continue
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			continue
		}
		if (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
