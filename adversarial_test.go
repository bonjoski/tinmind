package tinmind_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bonjoski/tinmind/pkg/ptyrec"
	"github.com/bonjoski/tinmind/pkg/receipt"
	"github.com/bonjoski/tinmind/pkg/redact"
	"github.com/bonjoski/tinmind/pkg/replay"
	"github.com/bonjoski/tinmind/pkg/trace"
	"github.com/bonjoski/tinmind/pkg/ux"
	"github.com/klauspost/compress/zstd"
)

// TestAdversarial_SecretRedactionBeforeDiskWrite proves zero raw secrets ever touch disk,
// including PEM keys, Anthropic/OpenAI/AWS/GitHub/Bearer/JWT tokens, high-entropy tokens,
// and secrets smuggled across ANSI SGR color boundaries.
func TestAdversarial_SecretRedactionBeforeDiskWrite(t *testing.T) {
	dir := t.TempDir()
	w, err := trace.NewWriter(trace.WriterOptions{
		TraceDir:     dir,
		TraceID:      "tm-20261127-sec1",
		Format:       trace.FormatJSONL,
		ExtraSecrets: []string{"CustomExtraSecret99887766"},
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	secrets := []string{
		"sk-ant-api03-1234567890abcdef1234567890abcdef",
		"sk-proj-AAAABBBBCCCCDDDDEEEEFFFF11112222",
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_1234567890abcdef1234567890abcdef1234",
		"AIzaSyD-1234567890abcdefghijklmnopqrs",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		"CustomExtraSecret99887766",
		"q9Z!kL8#mP2$vN5%wR7^xT4&yB6*cF3@", // won't match non-token chars; test clean high-entropy below
		"aB9xK2mQ7vP4zR8nL5wT1yF6cH3jD0sG",
	}
	pemBlock := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAtestkeymaterial1234567890\n-----END RSA PRIVATE KEY-----"
	// Smuggled secret split across SGR color escapes
	sgrSplit := "\x1b[31msk-proj-\x1b[32mSPLITSECRET1234567890abcdef\x1b[0m"

	payloads := []string{
		"ANTHROPIC_API_KEY=" + secrets[0],
		"OPENAI=" + secrets[1],
		"AWS=" + secrets[2],
		"GITHUB=" + secrets[3],
		"GEMINI=" + secrets[4],
		"Authorization: Bearer " + secrets[5],
		"EXTRA=" + secrets[6],
		"HIGH_ENTROPY=" + secrets[8],
		pemBlock,
		sgrSplit,
		"git commit 0123456789abcdef0123456789abcdef01234567", // 40-char git SHA must NOT be falsely redacted
	}

	for _, p := range payloads {
		if err := w.WriteEvent(trace.Event{Type: trace.TypeStdout, Data: p}); err != nil {
			t.Fatalf("WriteEvent: %v", err)
		}
	}
	if _, _, err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	rawBytes, err := os.ReadFile(w.Path())
	if err != nil {
		t.Fatalf("read trace file: %v", err)
	}
	disk := string(rawBytes)

	mustNotAppear := []string{
		secrets[0], secrets[1], secrets[2], secrets[3], secrets[4], secrets[5], secrets[6], secrets[8],
		"MIIEpAIBAAKCAQEAtestkeymaterial",
		"SPLITSECRET1234567890abcdef",
	}
	for _, needle := range mustNotAppear {
		if strings.Contains(disk, needle) {
			t.Fatalf("raw secret %q leaked to disk!\n%s", needle, disk)
		}
	}
	if !strings.Contains(disk, redact.Placeholder) {
		t.Fatalf("expected %q placeholder on disk", redact.Placeholder)
	}
	if !strings.Contains(disk, "0123456789abcdef0123456789abcdef01234567") {
		t.Fatalf("40-char hex git SHA was falsely redacted")
	}

	// Verify 0600 file permissions.
	fi, err := os.Stat(w.Path())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("trace file perm = %04o, want 0600", fi.Mode().Perm())
	}
}

// TestAdversarial_ReplayStripsOSC52AndControlInjection verifies that hand-crafted malicious
// traces embedding OSC-52 clipboard writes, DCS/APC, 8-bit C1 controls, CSI window ops, and
// Unicode Bidi overrides are neutralized during default Safe-ANSI replay while preserving colors.
func TestAdversarial_ReplayStripsOSC52AndControlInjection(t *testing.T) {
	dir := t.TempDir()
	maliciousFile := filepath.Join(dir, "tm-20261127-evilansi.jsonl")

	// Hand-craft raw JSONL bypassing Writer to simulate an attacker-planted trace file.
	ev := trace.Event{
		TS:   time.Now().UTC(),
		Type: trace.TypeStdout,
		Data: "\x1b[32mGREEN_OK\x1b[0m" +
			"\x1b]52;c;ZXZpbF9jbGlwYm9hcmQ=\x07" + // OSC-52 clipboard write (BEL)
			"\x1b]0;PWNED_TITLE\x1b\\" + // OSC-0 window title (ST)
			"\x1bP+q544e\x1b\\" + // DCS
			"\x1b_APC_PAYLOAD\x1b\\" + // APC
			"\x1b[8;50;120t" + // CSI window resize attack
			"\x1b[6n" + // CSI device status report query
			"\u009d52;c;QzFfT1ND\u009c" + // 8-bit C1 OSC-52
			"safe\u202eevil\u2066text", // Unicode Bidi overrides
	}
	raw, _ := json.Marshal(&ev)
	if err := os.WriteFile(maliciousFile, append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("write malicious trace: %v", err)
	}

	info, err := trace.ResolveTrace(dir, "tm-20261127-evilansi")
	if err != nil {
		t.Fatalf("ResolveTrace: %v", err)
	}

	var out bytes.Buffer
	if _, err := replay.Replay(context.Background(), info, &out, replay.Options{}); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	got := out.String()

	if !strings.Contains(got, "\x1b[32mGREEN_OK\x1b[0m") {
		t.Fatalf("Safe-ANSI should preserve benign SGR colors; got %q", got)
	}
	for _, forbidden := range []string{
		"ZXZpbF9jbGlwYm9hcmQ=",
		"PWNED_TITLE",
		"APC_PAYLOAD",
		"544e",
		"\x1b[8;50;120t",
		"\x1b[6n",
		"QzFfT1ND",
		"\u202e",
		"\u2066",
	} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("Safe-ANSI failed to strip %q; got %q", forbidden, got)
		}
	}
}

// TestAdversarial_SymlinkAndPathTraversalRefused verifies os.OpenRoot + Lstat refusal of
// symlinked trace files, symlinked trace dirs, and path-traversal / flag-injected trace IDs.
func TestAdversarial_SymlinkAndPathTraversalRefused(t *testing.T) {
	dir := t.TempDir()
	secretTarget := filepath.Join(t.TempDir(), "host_secret.txt")
	if err := os.WriteFile(secretTarget, []byte("TOP_SECRET_SSH_KEY"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}

	// 1. Symlink planted as a trace file inside traceDir.
	symlinkTrace := filepath.Join(dir, "fd-evil.jsonl")
	if err := os.Symlink(secretTarget, symlinkTrace); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := trace.ResolveTrace(dir, "fd-evil"); !errors.Is(err, trace.ErrSymlinkRefused) {
		t.Fatalf("expected ErrSymlinkRefused on symlinked trace, got %v", err)
	}

	// 2. Path traversal and invalid trace IDs refused fail-closed.
	badIDs := []string{
		"../etc/passwd",
		"../../.ssh/id_rsa",
		"a/b",
		"-rf",
		".hidden",
		"foo..bar",
		"bad\x00id",
		"",
	}
	for _, id := range badIDs {
		if err := trace.ValidateTraceID(id); !errors.Is(err, trace.ErrInvalidTraceID) {
			t.Fatalf("ValidateTraceID(%q) = %v, want ErrInvalidTraceID", id, err)
		}
		if _, err := trace.ResolveTrace(dir, id); !errors.Is(err, trace.ErrInvalidTraceID) {
			t.Fatalf("ResolveTrace(%q) = %v, want ErrInvalidTraceID", id, err)
		}
	}

	// 3. Symlinked trace directory refused fail-closed.
	symDir := filepath.Join(t.TempDir(), "linked-traces")
	if err := os.Symlink(dir, symDir); err != nil {
		t.Fatalf("symlink dir: %v", err)
	}
	if err := trace.EnsureSafeTraceDir(symDir); !errors.Is(err, trace.ErrSymlinkRefused) {
		t.Fatalf("EnsureSafeTraceDir(symlink) = %v, want ErrSymlinkRefused", err)
	}

	// 4. Pruner must never follow or delete symlink targets.
	if _, err := trace.Prune(dir, 1, time.Nanosecond); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if _, err := os.Stat(secretTarget); err != nil {
		t.Fatalf("Prune touched external symlink target: %v", err)
	}
}

// TestAdversarial_ZstdDecompressionBombAndFloodBounds proves a small zstd decompression bomb
// fails closed at the decompressed byte cap, and ring buffer flooding never stalls.
func TestAdversarial_ZstdDecompressionBombAndFloodBounds(t *testing.T) {
	dir := t.TempDir()
	bombPath := filepath.Join(dir, "tm-20261127-bomb.jsonl.zst")

	// Craft a ~10 KiB zstd stream that expands to > 4 MiB of JSONL lines, then read with 1 MiB cap.
	var compressed bytes.Buffer
	enc, err := zstd.NewWriter(&compressed, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	if err != nil {
		t.Fatalf("zstd.NewWriter: %v", err)
	}
	line := []byte(`{"ts":"2026-11-27T00:00:00Z","type":"stdout","data":"` + strings.Repeat("A", 4000) + `"}` + "\n")
	for i := 0; i < 1200; i++ { // ~4.8 MiB uncompressed
		if _, err := enc.Write(line); err != nil {
			t.Fatalf("enc.Write: %v", err)
		}
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("enc.Close: %v", err)
	}
	if err := os.WriteFile(bombPath, compressed.Bytes(), 0o600); err != nil {
		t.Fatalf("write bomb: %v", err)
	}

	info, err := trace.ResolveTrace(dir, "tm-20261127-bomb")
	if err != nil {
		t.Fatalf("ResolveTrace: %v", err)
	}
	err = trace.StreamEvents(info, 1024*1024, func(_ trace.Event) error { return nil })
	if !errors.Is(err, trace.ErrDecompressLimit) {
		t.Fatalf("expected ErrDecompressLimit on zstd bomb, got %v", err)
	}

	// Ring buffer flood test: push 200 KiB into a 16 KiB ring without a reader — must never block.
	rb := ptyrec.NewRingBuffer(16 * 1024)
	chunk := strings.Repeat("X", 4096)
	for i := 0; i < 50; i++ {
		rb.Push(trace.Event{Type: trace.TypeStdout, Data: chunk})
	}
	if rb.DroppedChunks() == 0 {
		t.Fatalf("expected ring buffer to drop excess chunks under flood backpressure")
	}
	rb.Close()
}

// TestAdversarial_ArgInjectionAndTraceDirValidation verifies world-writable trace dir refusal
// and UB-CLI-v2 remediation token allowlisting.
func TestAdversarial_ArgInjectionAndTraceDirValidation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "world-writable")
	if err := os.MkdirAll(dir, 0o777); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := trace.EnsureSafeTraceDir(dir); !errors.Is(err, trace.ErrUnsafeTraceDir) {
		t.Fatalf("expected ErrUnsafeTraceDir for 0777 dir, got %v", err)
	}

	// Remediation token validation blocks shell injection.
	if ux.ValidateRemediationToken("tm-1; rm -rf /") {
		t.Fatalf("ValidateRemediationToken allowed shell metacharacters")
	}
	if !ux.ValidateRemediationToken("tm-20261127-a81c") {
		t.Fatalf("ValidateRemediationToken rejected valid trace ID")
	}
}

// TestReplayAegisboxFixtureAndZstdFixture verifies FD-02 transparent replay of both
// Aegisbox uncompressed JSONL fixtures and Tinmind streaming .jsonl.zst traces.
func TestReplayAegisboxFixtureAndZstdFixture(t *testing.T) {
	legacyDir := t.TempDir()
	primaryDir := t.TempDir()

	// Exact schema emitted by aegisbox/pkg/aisafety/redact.go
	aegisJSONL := strings.Join([]string{
		`{"ts":"2026-11-25T10:00:00Z","type":"kata_step","probe_id":"KATA-01","category":"prompt-injection","data":"Step 1: attempting indirect prompt injection"}`,
		`{"ts":"2026-11-25T10:00:01Z","type":"finding","probe_id":"KATA-01","category":"prompt-injection","data":"BLOCKED by Stormcage delimiter fence"}`,
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(legacyDir, "fd-20261125-a81c.jsonl"), []byte(aegisJSONL), 0o600); err != nil {
		t.Fatalf("write aegisbox fixture: %v", err)
	}

	// Resolve from legacy dir when not in primaryDir.
	info, err := trace.ResolveTrace(primaryDir, "fd-20261125-a81c", legacyDir)
	if err != nil {
		t.Fatalf("ResolveTrace(aegisbox): %v", err)
	}
	if !info.Legacy || info.Compressed {
		t.Fatalf("unexpected TraceInfo: %+v", info)
	}

	var out bytes.Buffer
	stats, err := replay.Replay(context.Background(), info, &out, replay.Options{})
	if err != nil {
		t.Fatalf("Replay(aegisbox): %v", err)
	}
	if stats.EventsEmitted != 2 || !strings.Contains(out.String(), "[FINDING] [KATA-01]") {
		t.Fatalf("unexpected aegisbox replay output (%+v): %q", stats, out.String())
	}

	// Write a compressed zstd trace via trace.Writer and replay it.
	w, err := trace.NewWriter(trace.WriterOptions{TraceDir: primaryDir, TraceID: "tm-20261127-zst1", Format: trace.FormatZstd})
	if err != nil {
		t.Fatalf("NewWriter zstd: %v", err)
	}
	_ = w.WriteEvent(trace.Event{Type: trace.TypeStdout, Data: "hello zstd replay\n"})
	if _, _, err := w.Close(); err != nil {
		t.Fatalf("Close zstd: %v", err)
	}
	zinfo, err := trace.ResolveTrace(primaryDir, "tm-20261127-zst1")
	if err != nil {
		t.Fatalf("ResolveTrace zstd: %v", err)
	}
	if !zinfo.Compressed {
		t.Fatalf("expected compressed=true for .jsonl.zst")
	}
	out.Reset()
	if _, err := replay.Replay(context.Background(), zinfo, &out, replay.Options{}); err != nil {
		t.Fatalf("Replay zstd: %v", err)
	}
	if !strings.Contains(out.String(), "hello zstd replay") {
		t.Fatalf("unexpected zstd replay output: %q", out.String())
	}
}

// TestExportForCoppermindContract verifies FD-03 compatibility with coppermind/pkg/flightdeck/ingest.go.
func TestExportForCoppermindContract(t *testing.T) {
	dir := t.TempDir()
	w, err := trace.NewWriter(trace.WriterOptions{TraceDir: dir, TraceID: "tm-20261127-cm1", Format: trace.FormatZstd})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	failCode := 1
	okCode := 0
	_ = w.WriteEvent(trace.Event{
		Type:     trace.TypeCmdExit,
		Command:  "go test ./...",
		ExitCode: &failCode,
		Stderr:   "\x1b[31mFAIL: undefined foo\x1b[0m sk-proj-SECRETVALUE1234567890",
		Cwd:      "/work/demo",
		Repo:     "demo",
	})
	_ = w.WriteEvent(trace.Event{
		Type:     trace.TypeCmdExit,
		Command:  "go test -tags=fix ./...",
		ExitCode: &okCode,
		Stdout:   "PASS",
		Cwd:      "/work/demo",
		Repo:     "demo",
	})
	if _, _, err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	info, err := trace.ResolveTrace(dir, "tm-20261127-cm1")
	if err != nil {
		t.Fatalf("ResolveTrace: %v", err)
	}
	var buf bytes.Buffer
	written, count, err := trace.ExportForCoppermind(info, &buf)
	if err != nil {
		t.Fatalf("ExportForCoppermind: %v", err)
	}
	if count != 2 || written <= 0 || written > trace.CoppermindMaxTraceBytes {
		t.Fatalf("unexpected export stats: count=%d written=%d", count, written)
	}

	// Parse each line with the exact coppermind/pkg/flightdeck.TraceEvent JSON contract.
	type coppermindEvent struct {
		TS       string `json:"ts"`
		Command  string `json:"command"`
		ExitCode *int   `json:"exit_code"`
		Stderr   string `json:"stderr"`
		Stdout   string `json:"stdout"`
		Cwd      string `json:"cwd"`
		Repo     string `json:"repo"`
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 JSONL lines, got %d", len(lines))
	}
	var e0, e1 coppermindEvent
	if err := json.Unmarshal([]byte(lines[0]), &e0); err != nil {
		t.Fatalf("unmarshal line 0: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &e1); err != nil {
		t.Fatalf("unmarshal line 1: %v", err)
	}
	if e0.ExitCode == nil || *e0.ExitCode != 1 || e1.ExitCode == nil || *e1.ExitCode != 0 {
		t.Fatalf("exit_code mismatch: e0=%v e1=%v", e0.ExitCode, e1.ExitCode)
	}
	if strings.Contains(e0.Stderr, "\x1b[") || strings.Contains(e0.Stderr, "SECRETVALUE1234567890") {
		t.Fatalf("exported stderr was not ANSI/secret scrubbed: %q", e0.Stderr)
	}
}

// TestFixForwardAndReceiptContract verifies FD-07 UB-CLI-v2 rendering and BLPR-v1 DSSE signing + symlink defense.
func TestFixForwardAndReceiptContract(t *testing.T) {
	ff := &ux.FixForwardError{
		Tool:           "tinmind",
		Code:           "TINMIND_SYMLINK_REFUSED",
		Summary:        "symlink detected \x1b]52;c;evil\x07",
		RemediationCmd: "tinmind doctor",
		WhyOneLiner:    "Symlinks are refused fail-closed.",
		DeepWhy:        "Detailed explanation.",
		ExitCode:       ux.ExitSecurityErr,
	}
	var calm, deep, js bytes.Buffer
	_ = ff.Render(&calm, false, false)
	_ = ff.Render(&deep, false, true)
	_ = ff.Render(&js, true, false)

	if strings.Contains(calm.String(), "evil") || len(strings.Split(strings.TrimSpace(calm.String()), "\n")) > 3 {
		t.Fatalf("calm output violated <=3-line or sanitization invariant:\n%s", calm.String())
	}
	if !strings.Contains(deep.String(), "Detailed explanation.") {
		t.Fatalf("expected --why deep dive block:\n%s", deep.String())
	}
	var decoded ux.FixForwardError
	if err := json.Unmarshal(js.Bytes(), &decoded); err != nil || decoded.Code != "TINMIND_SYMLINK_REFUSED" {
		t.Fatalf("invalid JSON FixForwardError: %v (%s)", err, js.String())
	}

	// Emit and cryptographically verify BLPR-v1 receipt.
	worktree := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	exit0 := 0
	summary := trace.Summary{
		TraceID:    "tm-20261127-rcpt1",
		Path:       filepath.Join(worktree, "tm-20261127-rcpt1.jsonl.zst"),
		EventCount: 5,
		ExitCode:   &exit0,
		SHA256:     strings.Repeat("a", 64),
		SizeBytes:  1024,
	}
	rp, env, err := receipt.Emit(summary, receipt.EmitOptions{
		WorktreeRoot: worktree,
		SessionID:    "sess_test1234",
		SigningKey:   priv,
	})
	if err != nil {
		t.Fatalf("receipt.Emit: %v", err)
	}
	if _, err := os.Stat(rp); err != nil {
		t.Fatalf("receipt file missing: %v", err)
	}
	stmt, err := receipt.Verify(env, pub)
	if err != nil {
		t.Fatalf("receipt.Verify: %v", err)
	}
	if stmt.Predicate.Producer.Tool != "tinmind" || !stmt.Predicate.Proven {
		t.Fatalf("unexpected BLPR-v1 statement: %+v", stmt.Predicate)
	}

	// Symlinked .fabrial dir must fail closed.
	evilWT := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(evilWT, ".fabrial")); err != nil {
		t.Fatalf("symlink .fabrial: %v", err)
	}
	if _, _, err := receipt.Emit(summary, receipt.EmitOptions{WorktreeRoot: evilWT, SessionID: "sess_evil1"}); !errors.Is(err, receipt.ErrSymlinkDetected) {
		t.Fatalf("expected ErrSymlinkDetected for symlinked .fabrial, got %v", err)
	}
}

// TestConcurrent8WorktreesRaceFree verifies FD-06: N=8 parallel PTY recordings + concurrent
// FIFO prunes execute race-free with zero lock contention or trace collisions.
func TestConcurrent8WorktreesRaceFree(t *testing.T) {
	dir := t.TempDir()
	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers*2)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var stdout bytes.Buffer
			res, err := ptyrec.Record(context.Background(), []string{"/bin/sh", "-c", fmt.Sprintf("echo worker-%d-ok", idx)}, ptyrec.Options{
				TraceDir: dir,
				Format:   trace.FormatZstd,
				Stdout:   &stdout,
			})
			if err != nil {
				errs <- fmt.Errorf("worker %d record: %w", idx, err)
				return
			}
			if res.ExitCode != 0 {
				errs <- fmt.Errorf("worker %d exit=%d", idx, res.ExitCode)
				return
			}
			if _, perr := trace.Prune(dir, trace.DefaultQuotaBytes, trace.DefaultRetention); perr != nil {
				errs <- fmt.Errorf("worker %d prune: %w", idx, perr)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	traces, err := trace.ListTraces(dir)
	if err != nil {
		t.Fatalf("ListTraces: %v", err)
	}
	if len(traces) != workers {
		t.Fatalf("expected %d unique traces across N=8 worktrees, got %d", workers, len(traces))
	}
}
