package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bonjoski/tinmind/pkg/ptyrec"
	"github.com/bonjoski/tinmind/pkg/receipt"
	"github.com/bonjoski/tinmind/pkg/redact"
	"github.com/bonjoski/tinmind/pkg/replay"
	"github.com/bonjoski/tinmind/pkg/trace"
	"github.com/bonjoski/tinmind/pkg/ux"
	"github.com/bonjoski/tinmind/pkg/version"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printHelp(stdout)
		return ux.ExitOK
	}

	sub := args[0]
	rest := args[1:]
	switch sub {
	case "-h", "--help", "help":
		printHelp(stdout)
		return ux.ExitOK
	case "-v", "--version", "version":
		return cmdVersion(rest, stdout)
	case "record", "rec":
		return cmdRecord(rest, stdin, stdout, stderr)
	case "replay", "play":
		return cmdReplay(rest, stdin, stdout, stderr)
	case "list", "ls":
		return cmdList(rest, stdout, stderr)
	case "inspect", "show":
		return cmdInspect(rest, stdout, stderr)
	case "export":
		return cmdExport(rest, stdout, stderr)
	case "prune":
		return cmdPrune(rest, stdout, stderr)
	case "doctor":
		return cmdDoctor(rest, stdout, stderr)
	default:
		ff := &ux.FixForwardError{
			Tool:           "tinmind",
			Code:           "TINMIND_UNKNOWN_COMMAND",
			Summary:        fmt.Sprintf("unknown command %q", sub),
			RemediationCmd: "tinmind --help",
			WhyOneLiner:    "Supported commands: record, replay, list, inspect, export, prune, doctor, version.",
			ExitCode:       ux.ExitUsageErr,
		}
		_ = ff.Render(stderr, hasFlag(rest, "--json"), hasFlag(rest, "--why"))
		return ff.ExitCode
	}
}

func printHelp(w io.Writer) {
	_, _ = fmt.Fprintf(w, `tinmind v%s — Sovereign local PTY flight recorder & deterministic replay

Usage:
  tinmind record [flags] -- <command> [args...]   Record a command/agent session with pre-disk secret redaction
  tinmind replay <trace-id> [flags]               Replay a recorded or Aegisbox trace safely (--safe-ansi default)
  tinmind list [--limit N] [--json]               List local traces (including legacy ~/.flightdeck/traces)
  tinmind inspect <trace-id> [--failures-only]    Summarize events, exit codes, and security findings
  tinmind export <trace-id> --for-coppermind      Export clean <=16 MiB JSONL for coppermind ingest-flightdeck
  tinmind prune [--max-mb 500] [--max-days 7]     Enforce FIFO disk quota and retention window
  tinmind doctor [--json]                         Verify trace directory safety, quota, and legacy discovery
  tinmind version [--json]                        Print version

`, version.Version)
}

func cmdVersion(args []string, stdout io.Writer) int {
	if hasFlag(args, "--json") {
		_ = json.NewEncoder(stdout).Encode(map[string]string{
			"tool":    "tinmind",
			"version": version.Version,
		})
		return ux.ExitOK
	}
	_, _ = fmt.Fprintf(stdout, "tinmind v%s\n", version.Version)
	return ux.ExitOK
}

func cmdRecord(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	// Strict '--' delimiter separation prevents child command flags from colliding with tinmind flags.
	flagArgs, childArgs := splitDashDash(args)

	fs := flag.NewFlagSet("record", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	sessionID := fs.String("session-id", "", "custom trace/session ID")
	format := fs.String("format", trace.FormatZstd, "trace format: zstd or jsonl")
	traceDir := fs.String("trace-dir", "", "override trace directory")
	recordStdin := fs.Bool("record-stdin", false, "also record stdin keystrokes (default false)")
	emitReceipt := fs.Bool("receipt", false, "emit a BLPR-v1 DSSE receipt into .fabrial/receipts/")
	asJSON := fs.Bool("json", false, "emit summary as JSON on stderr")
	showWhy := fs.Bool("why", false, "show deep explanation on error")

	if err := fs.Parse(flagArgs); err != nil {
		return renderUsageErr(stderr, "TINMIND_RECORD_FLAGS", err.Error(), "tinmind record -- go test ./...", *asJSON, *showWhy)
	}
	if len(childArgs) == 0 {
		// Reject unseparated positional args fail-closed so flags cannot be smuggled.
		return renderFixForward(stderr, &ux.FixForwardError{
			Tool:           "tinmind",
			Code:           "TINMIND_MISSING_COMMAND_DELIMITER",
			Summary:        "missing command after '--' delimiter",
			RemediationCmd: "tinmind record -- go test ./...",
			WhyOneLiner:    "tinmind requires '--' before the target command to prevent flag-injection ambiguity.",
			DeepWhy:        "Without a strict '--' delimiter, child command flags (such as --format or --trace-dir) could be misinterpreted as recorder flags during autonomous agent invocations.",
			ExitCode:       ux.ExitUsageErr,
		}, *asJSON, *showWhy)
	}

	dir, err := resolvePrimaryDir(*traceDir)
	if err != nil {
		return renderTraceErr(stderr, err, *asJSON, *showWhy)
	}

	res, err := ptyrec.Record(context.Background(), childArgs, ptyrec.Options{
		TraceDir:    dir,
		TraceID:     *sessionID,
		Format:      *format,
		Stdin:       stdin,
		Stdout:      stdout,
		RecordStdin: *recordStdin,
	})
	if err != nil {
		return renderTraceErr(stderr, err, *asJSON, *showWhy)
	}

	// Best-effort non-blocking FIFO prune after recording completes.
	_, _ = trace.Prune(dir, trace.DefaultQuotaBytes, trace.DefaultRetention)

	var receiptPath string
	if *emitReceipt || strings.TrimSpace(os.Getenv("FABRIAL_SESSION_ID")) != "" {
		if rp, _, rerr := receipt.Emit(res.Summary, receipt.EmitOptions{}); rerr == nil {
			receiptPath = rp
		}
	}

	if *asJSON {
		payload := map[string]any{
			"summary":      res.Summary,
			"exit_code":    res.ExitCode,
			"receipt_path": receiptPath,
		}
		_ = json.NewEncoder(stderr).Encode(payload)
	} else {
		_, _ = fmt.Fprintf(stderr, "● tinmind: recorded %s (%d events, exit %d)\n  Replay: tinmind replay %s\n",
			res.Summary.TraceID, res.Summary.EventCount, res.ExitCode, res.Summary.TraceID)
		if res.Summary.DroppedChunks > 0 {
			_, _ = fmt.Fprintf(stderr, "  Note:   %d chunk(s) dropped under ring backpressure (child PTY stayed unblocked)\n", res.Summary.DroppedChunks)
		}
	}
	return res.ExitCode
}

func cmdReplay(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	speed := fs.Float64("speed", 0, "playback speed multiplier (0 = instant, 1.0 = real-time, 2.0 = 2x)")
	step := fs.Bool("step", false, "pause for Enter after each event")
	safeANSI := fs.Bool("safe-ansi", true, "strip OSC-52/DCS/C1/Bidi attacks while keeping colors")
	unsafeRaw := fs.Bool("unsafe-raw-tty", false, "disable Safe-ANSI filter (unsafe for untrusted traces)")
	filter := fs.String("filter", "", "only show events of this type (stdout, finding, cmd_exit, ...)")
	failuresOnly := fs.Bool("failures-only", false, "only display failed commands and findings")
	traceDir := fs.String("trace-dir", "", "override trace directory")
	asJSON := fs.Bool("json", false, "emit error/stats as JSON")
	showWhy := fs.Bool("why", false, "show deep explanation on error")

	traceArg, flagArgs := extractFirstPositional(args)
	if err := fs.Parse(flagArgs); err != nil {
		return renderUsageErr(stderr, "TINMIND_REPLAY_FLAGS", err.Error(), "tinmind replay <trace-id>", *asJSON, *showWhy)
	}
	if traceArg == "" && fs.NArg() > 0 {
		traceArg = fs.Arg(0)
	}
	if traceArg == "" {
		return renderUsageErr(stderr, "TINMIND_MISSING_TRACE_ID", "trace ID is required", "tinmind list", *asJSON, *showWhy)
	}

	dir, err := resolvePrimaryDir(*traceDir)
	if err != nil {
		return renderTraceErr(stderr, err, *asJSON, *showWhy)
	}
	info, err := trace.ResolveTrace(dir, traceArg, fallbackDirs(*traceDir)...)
	if err != nil {
		return renderTraceErr(stderr, err, *asJSON, *showWhy)
	}

	useRaw := *unsafeRaw || !*safeANSI
	stats, err := replay.Replay(context.Background(), info, stdout, replay.Options{
		Speed:        *speed,
		Step:         *step,
		StepReader:   stdin,
		UnsafeRawTTY: useRaw,
		FilterType:   *filter,
		FailuresOnly: *failuresOnly,
	})
	if err != nil {
		return renderTraceErr(stderr, err, *asJSON, *showWhy)
	}
	if *asJSON {
		_ = json.NewEncoder(stderr).Encode(stats)
	}
	return ux.ExitOK
}

func cmdList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	limit := fs.Int("limit", 25, "maximum traces to list")
	traceDir := fs.String("trace-dir", "", "override trace directory")
	asJSON := fs.Bool("json", false, "output JSON")
	showWhy := fs.Bool("why", false, "show deep explanation on error")

	if err := fs.Parse(args); err != nil {
		return renderUsageErr(stderr, "TINMIND_LIST_FLAGS", err.Error(), "tinmind list", *asJSON, *showWhy)
	}
	dir, err := resolvePrimaryDir(*traceDir)
	if err != nil {
		return renderTraceErr(stderr, err, *asJSON, *showWhy)
	}
	traces, err := trace.ListTraces(dir, fallbackDirs(*traceDir)...)
	if err != nil {
		return renderTraceErr(stderr, err, *asJSON, *showWhy)
	}
	if *limit > 0 && len(traces) > *limit {
		traces = traces[:*limit]
	}

	if *asJSON {
		if traces == nil {
			traces = []trace.TraceInfo{}
		}
		_ = json.NewEncoder(stdout).Encode(traces)
		return ux.ExitOK
	}
	if len(traces) == 0 {
		_, _ = fmt.Fprintf(stdout, "No traces recorded yet. Run `tinmind record -- <command>` to capture a session.\n")
		return ux.ExitOK
	}
	for _, t := range traces {
		tag := "zst"
		if !t.Compressed {
			tag = "jsonl"
		}
		if t.Legacy {
			tag += ",legacy"
		}
		_, _ = fmt.Fprintf(stdout, "%-24s  %8d B  %-12s  %s\n",
			t.ID, t.SizeBytes, tag, t.ModTime.Format(time.RFC3339))
	}
	return ux.ExitOK
}

func cmdInspect(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	failuresOnly := fs.Bool("failures-only", false, "include only failures and findings")
	traceDir := fs.String("trace-dir", "", "override trace directory")
	asJSON := fs.Bool("json", false, "output JSON")
	showWhy := fs.Bool("why", false, "show deep explanation on error")

	traceArg, flagArgs := extractFirstPositional(args)
	if err := fs.Parse(flagArgs); err != nil {
		return renderUsageErr(stderr, "TINMIND_INSPECT_FLAGS", err.Error(), "tinmind inspect <trace-id>", *asJSON, *showWhy)
	}
	if traceArg == "" && fs.NArg() > 0 {
		traceArg = fs.Arg(0)
	}
	if traceArg == "" {
		return renderUsageErr(stderr, "TINMIND_MISSING_TRACE_ID", "trace ID is required", "tinmind list", *asJSON, *showWhy)
	}

	dir, err := resolvePrimaryDir(*traceDir)
	if err != nil {
		return renderTraceErr(stderr, err, *asJSON, *showWhy)
	}
	info, err := trace.ResolveTrace(dir, traceArg, fallbackDirs(*traceDir)...)
	if err != nil {
		return renderTraceErr(stderr, err, *asJSON, *showWhy)
	}

	summary := trace.Summary{
		TraceID:   info.ID,
		Path:      info.Path,
		SizeBytes: info.SizeBytes,
	}
	var highlights []trace.Event

	err = trace.StreamEvents(info, trace.DefaultMaxDecompressedBytes, func(ev trace.Event) error {
		summary.EventCount++
		if !ev.TS.IsZero() {
			if summary.StartTime.IsZero() || ev.TS.Before(summary.StartTime) {
				summary.StartTime = ev.TS
			}
			if ev.TS.After(summary.EndTime) {
				summary.EndTime = ev.TS
			}
		}
		if ev.Command != "" && summary.Command == "" {
			summary.Command = redact.StripAllANSI(ev.Command)
		}
		if ev.DroppedChunks > summary.DroppedChunks {
			summary.DroppedChunks = ev.DroppedChunks
		}
		if ev.ExitCode != nil {
			code := *ev.ExitCode
			summary.ExitCode = &code
			if code != 0 && ev.Type == trace.TypeCmdExit {
				summary.FailureCount++
				highlights = append(highlights, ev)
			}
		}
		if ev.Type == trace.TypeFinding {
			summary.FindingCount++
			highlights = append(highlights, ev)
		} else if !*failuresOnly && (ev.Type == trace.TypeCmdExit || ev.Type == trace.TypeMCPCall) {
			highlights = append(highlights, ev)
		}
		return nil
	})
	if err != nil {
		return renderTraceErr(stderr, err, *asJSON, *showWhy)
	}
	if !summary.StartTime.IsZero() && !summary.EndTime.IsZero() {
		summary.Duration = summary.EndTime.Sub(summary.StartTime)
	}

	if *asJSON {
		_ = json.NewEncoder(stdout).Encode(map[string]any{
			"summary":    summary,
			"highlights": highlights,
		})
		return ux.ExitOK
	}

	exitStr := "n/a"
	if summary.ExitCode != nil {
		exitStr = fmt.Sprintf("%d", *summary.ExitCode)
	}
	_, _ = fmt.Fprintf(stdout, "Trace %s | events=%d failures=%d findings=%d exit=%s duration=%s\n",
		summary.TraceID, summary.EventCount, summary.FailureCount, summary.FindingCount, exitStr, summary.Duration.Round(time.Millisecond))
	if summary.Command != "" {
		_, _ = fmt.Fprintf(stdout, "  Cmd: %s\n", ux.SanitizeSingleLine(summary.Command))
	}
	for _, h := range highlights {
		msg := ux.SanitizeSingleLine(h.Data)
		if msg == "" {
			msg = ux.SanitizeSingleLine(h.Command)
		}
		if len(msg) > 120 {
			msg = msg[:117] + "..."
		}
		_, _ = fmt.Fprintf(stdout, "  [%s] %s\n", ux.SanitizeSingleLine(h.Type), msg)
	}
	return ux.ExitOK
}

func cmdExport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	forCoppermind := fs.Bool("for-coppermind", true, "export <=16 MiB ANSI-stripped JSONL for coppermind")
	outPath := fs.String("o", "", "output file path (default stdout)")
	traceDir := fs.String("trace-dir", "", "override trace directory")
	asJSON := fs.Bool("json", false, "output metadata as JSON (when writing to -o)")
	showWhy := fs.Bool("why", false, "show deep explanation on error")

	traceArg, flagArgs := extractFirstPositional(args)
	if err := fs.Parse(flagArgs); err != nil {
		return renderUsageErr(stderr, "TINMIND_EXPORT_FLAGS", err.Error(), "tinmind export <trace-id> --for-coppermind", *asJSON, *showWhy)
	}
	if traceArg == "" && fs.NArg() > 0 {
		traceArg = fs.Arg(0)
	}
	if traceArg == "" {
		return renderUsageErr(stderr, "TINMIND_MISSING_TRACE_ID", "trace ID is required", "tinmind list", *asJSON, *showWhy)
	}
	_ = *forCoppermind

	dir, err := resolvePrimaryDir(*traceDir)
	if err != nil {
		return renderTraceErr(stderr, err, *asJSON, *showWhy)
	}
	info, err := trace.ResolveTrace(dir, traceArg, fallbackDirs(*traceDir)...)
	if err != nil {
		return renderTraceErr(stderr, err, *asJSON, *showWhy)
	}

	var dst io.Writer = stdout
	var outFile *os.File
	var outRoot *os.Root
	if strings.TrimSpace(*outPath) != "" {
		absOut, err := filepath.Abs(*outPath)
		if err != nil {
			return renderTraceErr(stderr, err, *asJSON, *showWhy)
		}
		parent := filepath.Dir(absOut)
		base := filepath.Base(absOut)
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return renderTraceErr(stderr, err, *asJSON, *showWhy)
		}
		outRoot, err = os.OpenRoot(parent)
		if err != nil {
			return renderTraceErr(stderr, err, *asJSON, *showWhy)
		}
		defer func() { _ = outRoot.Close() }()
		if fi, serr := outRoot.Lstat(base); serr == nil && fi.Mode()&os.ModeSymlink != 0 {
			return renderTraceErr(stderr, fmt.Errorf("%w: %s", trace.ErrSymlinkRefused, absOut), *asJSON, *showWhy)
		}
		outFile, err = outRoot.OpenFile(base, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return renderTraceErr(stderr, err, *asJSON, *showWhy)
		}
		defer func() { _ = outFile.Close() }()
		dst = outFile
	}

	written, count, err := trace.ExportForCoppermind(info, dst)
	if err != nil {
		return renderTraceErr(stderr, err, *asJSON, *showWhy)
	}
	if outFile != nil {
		if *asJSON {
			_ = json.NewEncoder(stdout).Encode(map[string]any{
				"trace_id":      info.ID,
				"output_path":   *outPath,
				"events":        count,
				"bytes_written": written,
			})
		} else {
			_, _ = fmt.Fprintf(stdout, "Exported %s (%d events, %d bytes) -> %s\n", info.ID, count, written, *outPath)
		}
	}
	return ux.ExitOK
}

func cmdPrune(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("prune", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	maxMB := fs.Int64("max-mb", 500, "maximum total trace storage in MiB")
	maxDays := fs.Int("max-days", 7, "maximum trace age in days")
	traceDir := fs.String("trace-dir", "", "override trace directory")
	asJSON := fs.Bool("json", false, "output JSON")
	showWhy := fs.Bool("why", false, "show deep explanation on error")

	if err := fs.Parse(args); err != nil {
		return renderUsageErr(stderr, "TINMIND_PRUNE_FLAGS", err.Error(), "tinmind prune --max-mb 500 --max-days 7", *asJSON, *showWhy)
	}
	dir, err := resolvePrimaryDir(*traceDir)
	if err != nil {
		return renderTraceErr(stderr, err, *asJSON, *showWhy)
	}
	res, err := trace.Prune(dir, *maxMB*1024*1024, time.Duration(*maxDays)*24*time.Hour)
	if err != nil {
		return renderTraceErr(stderr, err, *asJSON, *showWhy)
	}
	if *asJSON {
		_ = json.NewEncoder(stdout).Encode(res)
		return ux.ExitOK
	}
	_, _ = fmt.Fprintf(stdout, "Pruned %d trace(s) (%d bytes freed); %d kept (%d bytes remaining)\n",
		res.RemovedFiles, res.FreedBytes, res.KeptFiles, res.RemainingB)
	return ux.ExitOK
}

func cmdDoctor(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	traceDir := fs.String("trace-dir", "", "override trace directory")
	asJSON := fs.Bool("json", false, "output JSON")
	showWhy := fs.Bool("why", false, "show deep explanation on error")

	if err := fs.Parse(args); err != nil {
		return renderUsageErr(stderr, "TINMIND_DOCTOR_FLAGS", err.Error(), "tinmind doctor", *asJSON, *showWhy)
	}
	dir, err := resolvePrimaryDir(*traceDir)
	if err != nil {
		return renderTraceErr(stderr, err, *asJSON, *showWhy)
	}
	if err := trace.EnsureSafeTraceDir(dir); err != nil {
		return renderTraceErr(stderr, err, *asJSON, *showWhy)
	}
	traces, err := trace.ListTraces(dir, fallbackDirs(*traceDir)...)
	if err != nil {
		return renderTraceErr(stderr, err, *asJSON, *showWhy)
	}

	var totalBytes int64
	legacyCount := 0
	for _, t := range traces {
		totalBytes += t.SizeBytes
		if t.Legacy {
			legacyCount++
		}
	}

	status := map[string]any{
		"tool":            "tinmind",
		"version":         version.Version,
		"status":          "ok",
		"trace_dir":       dir,
		"trace_count":     len(traces),
		"legacy_traces":   legacyCount,
		"total_bytes":     totalBytes,
		"quota_bytes":     trace.DefaultQuotaBytes,
		"safe_ansi_mode":  "default-on",
		"network_sockets": 0,
	}
	if *asJSON {
		_ = json.NewEncoder(stdout).Encode(status)
		return ux.ExitOK
	}
	_, _ = fmt.Fprintf(stdout, "✓ tinmind v%s healthy | dir=%s | traces=%d (legacy=%d) | size=%d B / 500 MiB\n",
		version.Version, dir, len(traces), legacyCount, totalBytes)
	return ux.ExitOK
}

func resolvePrimaryDir(override string) (string, error) {
	if strings.TrimSpace(override) != "" {
		return filepath.Abs(override)
	}
	return trace.DefaultTraceDir()
}

func fallbackDirs(override string) []string {
	if strings.TrimSpace(override) != "" || strings.TrimSpace(os.Getenv("TINMIND_TRACE_DIR")) != "" {
		return nil
	}
	if legacy := trace.LegacyFlightdeckTraceDir(); legacy != "" {
		return []string{legacy}
	}
	return nil
}

func splitDashDash(args []string) (flags []string, child []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

// extractFirstPositional allows both `tinmind replay <id> --speed 2` and `tinmind replay --speed 2 <id>`.
func extractFirstPositional(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name || strings.HasPrefix(a, name+"=") {
			return true
		}
	}
	return false
}

func renderUsageErr(w io.Writer, code, msg, fix string, asJSON, showWhy bool) int {
	return renderFixForward(w, &ux.FixForwardError{
		Tool:           "tinmind",
		Code:           code,
		Summary:        msg,
		RemediationCmd: fix,
		WhyOneLiner:    "Run `tinmind --help` to see all supported commands and flags.",
		ExitCode:       ux.ExitUsageErr,
	}, asJSON, showWhy)
}

func renderTraceErr(w io.Writer, err error, asJSON, showWhy bool) int {
	ff := &ux.FixForwardError{
		Tool:           "tinmind",
		Code:           "TINMIND_ERROR",
		Summary:        err.Error(),
		RemediationCmd: "tinmind doctor",
		WhyOneLiner:    "Verify trace IDs and trace directory permissions.",
		ExitCode:       ux.ExitGeneralErr,
	}
	switch {
	case errors.Is(err, trace.ErrSymlinkRefused):
		ff.Code = "TINMIND_SYMLINK_REFUSED"
		ff.RemediationCmd = "rm <symlink> && tinmind doctor"
		ff.WhyOneLiner = "Symlinked trace files or directories are refused fail-closed to prevent host file disclosure."
		ff.DeepWhy = "Tinmind confines all trace I/O with os.OpenRoot and Lstat symlink checks so a hostile agent or untrusted trace cannot trick replay/export into reading ~/.ssh or overwriting arbitrary files."
		ff.ExitCode = ux.ExitSecurityErr
	case errors.Is(err, trace.ErrUnsafeTraceDir):
		ff.Code = "TINMIND_UNSAFE_TRACE_DIR"
		ff.RemediationCmd = "chmod 0700 ~/.tinmind/traces && tinmind doctor"
		ff.WhyOneLiner = "Trace directories must be regular, user-owned directories without group/world write bits."
		ff.ExitCode = ux.ExitSecurityErr
	case errors.Is(err, trace.ErrInvalidTraceID):
		ff.Code = "TINMIND_INVALID_TRACE_ID"
		ff.RemediationCmd = "tinmind list"
		ff.WhyOneLiner = "Trace IDs must be alphanumeric (plus . _ -) with no path separators or '..'."
		ff.ExitCode = ux.ExitPolicyDeny
	case errors.Is(err, trace.ErrTraceNotFound):
		ff.Code = "TINMIND_TRACE_NOT_FOUND"
		ff.RemediationCmd = "tinmind list"
		ff.WhyOneLiner = "Check available trace IDs in ~/.tinmind/traces (and legacy ~/.flightdeck/traces)."
		ff.ExitCode = ux.ExitNotFound
	case errors.Is(err, trace.ErrDecompressLimit), errors.Is(err, trace.ErrLineTooLong):
		ff.Code = "TINMIND_BOMB_LIMIT_EXCEEDED"
		ff.RemediationCmd = "tinmind inspect <trace-id>"
		ff.WhyOneLiner = "Trace exceeded safe streaming bounds (64 MiB decompressed / 1 MiB line cap)."
		ff.DeepWhy = "Decompression and line caps prevent malicious zstd bombs from exhausting workstation memory during replay or export."
		ff.ExitCode = ux.ExitPolicyDeny
	}
	return renderFixForward(w, ff, asJSON, showWhy)
}

func renderFixForward(w io.Writer, ff *ux.FixForwardError, asJSON, showWhy bool) int {
	_ = ff.Render(w, asJSON, showWhy)
	return ff.ExitCode
}
