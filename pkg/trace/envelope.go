package trace

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	// DefaultMaxDecompressedBytes caps zstd/jsonl reads at 64 MiB (anti-decompression-bomb).
	DefaultMaxDecompressedBytes int64 = 64 * 1024 * 1024
	// DefaultMaxLineBytes caps a single JSONL line at 1 MiB.
	DefaultMaxLineBytes = 1024 * 1024
	// CoppermindMaxTraceBytes matches coppermind/pkg/flightdeck.DefaultMaxTraceBytes (16 MiB).
	CoppermindMaxTraceBytes int64 = 16 * 1024 * 1024
	// DefaultQuotaBytes caps local rolling trace storage at 500 MiB.
	DefaultQuotaBytes int64 = 500 * 1024 * 1024
	// DefaultRetention is the rolling 7-day trace TTL.
	DefaultRetention = 7 * 24 * time.Hour

	FormatZstd  = "zstd"
	FormatJSONL = "jsonl"

	// Event types in Canonical Event Envelope v1.
	TypeSessionStart = "session_start"
	TypeStdin        = "stdin"
	TypeStdout       = "stdout"
	TypeStderr       = "stderr"
	TypeCmdExit      = "cmd_exit"
	TypeMCPCall      = "mcp_call"
	TypeProbe        = "probe"
	TypeFinding      = "finding"
	TypeKataStep     = "kata_step"
	TypeSignal       = "signal"
	TypeResize       = "resize"
	TypeSessionEnd   = "session_end"
)

var (
	traceIDRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

	ErrInvalidTraceID  = errors.New("invalid trace ID (must match ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$ without traversal)")
	ErrSymlinkRefused  = errors.New("security violation: symlink refused fail-closed")
	ErrUnsafeTraceDir  = errors.New("security violation: trace directory failed safety checks")
	ErrTraceNotFound   = errors.New("trace not found")
	ErrDecompressLimit = errors.New("security violation: trace exceeded maximum decompressed size limit")
	ErrLineTooLong     = errors.New("security violation: trace line exceeded 1 MiB cap")
)

// Event is the canonical Tinmind Event Envelope v1.
// Backward-compatible with aegisbox/pkg/aisafety.TraceEvent and coppermind/pkg/flightdeck.TraceEvent.
type Event struct {
	TS        time.Time `json:"ts"`
	Seq       uint64    `json:"seq,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
	Type      string    `json:"type"`
	Data      string    `json:"data,omitempty"`

	// Coppermind ingest-flightdeck structured fields (populated on cmd_exit / mcp_call)
	Command  string `json:"command,omitempty"`
	Tool     string `json:"tool,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	Stdout   string `json:"stdout,omitempty"`
	Cwd      string `json:"cwd,omitempty"`
	Repo     string `json:"repo,omitempty"`

	// Aegisbox kata / ai-safety fields (pass-through on replay & inspect)
	ProbeID  string `json:"probe_id,omitempty"`
	Category string `json:"category,omitempty"`

	// Terminal geometry for resize events
	Cols uint16 `json:"cols,omitempty"`
	Rows uint16 `json:"rows,omitempty"`

	// Ring-buffer overflow / recording diagnostics on session_end
	DroppedChunks uint64 `json:"dropped_chunks,omitempty"`
}

// TraceInfo describes a stored trace file discovered in a trace directory.
type TraceInfo struct {
	ID         string    `json:"id"`
	Filename   string    `json:"filename"`
	Path       string    `json:"path"`
	Dir        string    `json:"dir"`
	Compressed bool      `json:"compressed"`
	SizeBytes  int64     `json:"size_bytes"`
	ModTime    time.Time `json:"mod_time"`
	Legacy     bool      `json:"legacy,omitempty"`
}

// Summary aggregates structured metadata extracted from a recorded trace.
type Summary struct {
	TraceID       string        `json:"trace_id"`
	Path          string        `json:"path"`
	EventCount    int           `json:"event_count"`
	FailureCount  int           `json:"failure_count"`
	FindingCount  int           `json:"finding_count"`
	DroppedChunks uint64        `json:"dropped_chunks"`
	StartTime     time.Time     `json:"start_time,omitempty"`
	EndTime       time.Time     `json:"end_time,omitempty"`
	Duration      time.Duration `json:"duration_ns"`
	ExitCode      *int          `json:"exit_code,omitempty"`
	Command       string        `json:"command,omitempty"`
	SHA256        string        `json:"sha256,omitempty"`
	SizeBytes     int64         `json:"size_bytes"`
}

// NewTraceID generates a unique Tinmind trace ID (tm-YYYYMMDD-<8-hex>).
func NewTraceID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("tm-%s-%08x", time.Now().UTC().Format("20060102"), uint32(time.Now().UnixNano()))
	}
	return fmt.Sprintf("tm-%s-%s", time.Now().UTC().Format("20060102"), hex.EncodeToString(b[:]))
}

// ValidateTraceID strictly validates trace IDs against path traversal, flags, and control chars.
func ValidateTraceID(id string) error {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" || trimmed != id {
		return fmt.Errorf("%w: %q", ErrInvalidTraceID, id)
	}
	if strings.Contains(trimmed, "..") || strings.ContainsAny(trimmed, `/\`+"\x00") {
		return fmt.Errorf("%w: %q", ErrInvalidTraceID, id)
	}
	if !traceIDRe.MatchString(trimmed) {
		return fmt.Errorf("%w: %q", ErrInvalidTraceID, id)
	}
	return nil
}

// NormalizeID strips a known trace extension (.jsonl.zst or .jsonl) if present.
func NormalizeID(idOrFile string) string {
	s := strings.TrimSpace(idOrFile)
	switch {
	case strings.HasSuffix(s, ".jsonl.zst"):
		return strings.TrimSuffix(s, ".jsonl.zst")
	case strings.HasSuffix(s, ".jsonl"):
		return strings.TrimSuffix(s, ".jsonl")
	default:
		return s
	}
}
