package replay

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bonjoski/tinmind/pkg/redact"
	"github.com/bonjoski/tinmind/pkg/trace"
)

// Options controls deterministic TTY playback.
type Options struct {
	Speed        float64       // <=0 means instant playback; 1.0 real-time; 2.0 2x faster
	MaxGap       time.Duration // Caps idle gaps between frames (default 2s when Speed > 0)
	Step         bool          // Pause for Enter between displayed frames
	StepReader   io.Reader     // Reader used when Step is true
	UnsafeRawTTY bool          // Default false: SafeANSI strips OSC-52/DCS/C1/Bidi attacks
	FilterType   string        // Optional event type filter (e.g. "stdout", "finding", "cmd_exit")
	FailuresOnly bool          // Only emit failed commands and security findings
}

// Stats summarizes a completed playback run.
type Stats struct {
	EventsRead    int `json:"events_read"`
	EventsEmitted int `json:"events_emitted"`
}

// Replay streams events from info to out deterministically with Safe-ANSI defense enabled by default.
func Replay(ctx context.Context, info *trace.TraceInfo, out io.Writer, opts Options) (*Stats, error) {
	if opts.MaxGap <= 0 {
		opts.MaxGap = 2 * time.Second
	}
	var stepScanner *bufio.Scanner
	if opts.Step && opts.StepReader != nil {
		stepScanner = bufio.NewScanner(opts.StepReader)
	}

	filter := strings.ToLower(strings.TrimSpace(opts.FilterType))
	var prevTS time.Time
	stats := &Stats{}

	err := trace.StreamEvents(info, trace.DefaultMaxDecompressedBytes, func(ev trace.Event) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		stats.EventsRead++

		if filter != "" && strings.ToLower(ev.Type) != filter {
			return nil
		}
		if opts.FailuresOnly && !isFailureEvent(ev) {
			return nil
		}

		rendered := formatEvent(ev, opts.UnsafeRawTTY)
		if rendered == "" {
			return nil
		}

		// Respect recorded timing delta when Speed > 0.
		if opts.Speed > 0 && !prevTS.IsZero() && !ev.TS.IsZero() && ev.TS.After(prevTS) {
			delta := time.Duration(float64(ev.TS.Sub(prevTS)) / opts.Speed)
			if delta > opts.MaxGap {
				delta = opts.MaxGap
			}
			if delta > 0 {
				timer := time.NewTimer(delta)
				select {
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				case <-timer.C:
				}
			}
		}
		if !ev.TS.IsZero() {
			prevTS = ev.TS
		}

		if _, err := io.WriteString(out, rendered); err != nil {
			return err
		}
		stats.EventsEmitted++

		if opts.Step && stepScanner != nil {
			if _, err := io.WriteString(out, "\n[step: press Enter to continue] "); err != nil {
				return err
			}
			if !stepScanner.Scan() {
				return io.EOF
			}
		}
		return nil
	})
	if err == io.EOF {
		return stats, nil
	}
	return stats, err
}

func isFailureEvent(ev trace.Event) bool {
	if ev.ExitCode != nil && *ev.ExitCode != 0 {
		return true
	}
	switch ev.Type {
	case trace.TypeFinding, trace.TypeStderr:
		return true
	default:
		return false
	}
}

func formatEvent(ev trace.Event, unsafeRaw bool) string {
	sanitize := func(s string, ptyMode bool) string {
		if unsafeRaw {
			return s
		}
		if ptyMode {
			return redact.SafeANSI(s)
		}
		return redact.StripAllANSI(s)
	}

	switch ev.Type {
	case trace.TypeStdout, trace.TypeStderr:
		return sanitize(ev.Data, true)
	case trace.TypeSessionStart:
		cmd := sanitize(ev.Command, false)
		if cmd == "" {
			return ""
		}
		return fmt.Sprintf("▶ session %s | cmd: %s\n", sanitize(ev.SessionID, false), cmd)
	case trace.TypeCmdExit:
		code := 0
		if ev.ExitCode != nil {
			code = *ev.ExitCode
		}
		return fmt.Sprintf("\n■ exit %d | cmd: %s\n", code, sanitize(ev.Command, false))
	case trace.TypeProbe, trace.TypeFinding, trace.TypeKataStep, trace.TypeMCPCall:
		label := strings.ToUpper(sanitize(ev.Type, false))
		meta := ""
		if ev.ProbeID != "" {
			meta += " [" + sanitize(ev.ProbeID, false) + "]"
		}
		if ev.Category != "" {
			meta += " (" + sanitize(ev.Category, false) + ")"
		}
		if ev.Tool != "" {
			meta += " tool=" + sanitize(ev.Tool, false)
		}
		return fmt.Sprintf("[%s]%s %s\n", label, meta, sanitize(ev.Data, false))
	case trace.TypeSignal:
		return fmt.Sprintf("\n[SIGNAL] %s\n", sanitize(ev.Data, false))
	default:
		if ev.Data != "" {
			return sanitize(ev.Data, false) + "\n"
		}
		return ""
	}
}
