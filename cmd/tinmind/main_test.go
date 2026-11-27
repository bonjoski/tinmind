package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bonjoski/tinmind/pkg/ux"
)

func TestCLI_RecordInspectReplayExportPruneDoctor(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer

	// 1. Missing '--' delimiter fails closed with UB-CLI-v2 FixForwardError.
	code := run([]string{"record", "--trace-dir", dir, "echo", "hi"}, nil, &stdout, &stderr)
	if code != ux.ExitUsageErr || !strings.Contains(stderr.String(), "Fix:") {
		t.Fatalf("expected ExitUsageErr + FixForwardError, got code=%d stderr=%q", code, stderr.String())
	}

	// 2. Record with strict '--' delimiter.
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"record", "--trace-dir", dir, "--session-id", "tm-cli-01", "--", "/bin/sh", "-c", "echo cli-works"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("record exit=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "cli-works") {
		t.Fatalf("expected child stdout, got %q", stdout.String())
	}

	// 3. List JSON.
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"list", "--trace-dir", dir, "--json"}, nil, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "tm-cli-01") {
		t.Fatalf("list exit=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}

	// 4. Inspect JSON.
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"inspect", "tm-cli-01", "--trace-dir", dir, "--json"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("inspect exit=%d err=%q", code, stderr.String())
	}
	var inspected map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &inspected); err != nil {
		t.Fatalf("inspect json: %v", err)
	}

	// 5. Replay.
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"replay", "tm-cli-01", "--trace-dir", dir}, nil, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "cli-works") {
		t.Fatalf("replay exit=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}

	// 6. Export for Coppermind (and reject symlinked -o target!).
	expFile := filepath.Join(t.TempDir(), "out.jsonl")
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"export", "tm-cli-01", "--trace-dir", dir, "--for-coppermind", "-o", expFile}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("export exit=%d err=%q", code, stderr.String())
	}
	raw, err := os.ReadFile(expFile)
	if err != nil || !strings.Contains(string(raw), "cli-works") {
		t.Fatalf("exported file invalid: err=%v body=%q", err, string(raw))
	}

	symOut := filepath.Join(t.TempDir(), "sym.jsonl")
	_ = os.Symlink(expFile, symOut)
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"export", "tm-cli-01", "--trace-dir", dir, "-o", symOut}, nil, &stdout, &stderr)
	if code != ux.ExitSecurityErr {
		t.Fatalf("expected ExitSecurityErr on symlinked -o export target, got %d (%q)", code, stderr.String())
	}

	// 7. Doctor & Prune & Version.
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"doctor", "--trace-dir", dir, "--json"}, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("doctor exit=%d err=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"prune", "--trace-dir", dir, "--json"}, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("prune exit=%d err=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"version"}, nil, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "tinmind v0.1.0") {
		t.Fatalf("version exit=%d out=%q", code, stdout.String())
	}
}
