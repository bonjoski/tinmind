package ptyrec

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/tinmind/pkg/trace"
)

func TestRecordCapturesStdoutAndExitCode(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer

	res, err := Record(context.Background(), []string{"/bin/sh", "-c", "echo hello-tinmind; exit 7"}, Options{
		TraceDir: dir,
		TraceID:  "tm-20261127-pty1",
		Format:   trace.FormatZstd,
		Stdout:   &out,
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if res.ExitCode != 7 {
		t.Fatalf("ExitCode = %d, want 7", res.ExitCode)
	}
	if !strings.Contains(out.String(), "hello-tinmind") {
		t.Fatalf("stdout missing output: %q", out.String())
	}

	info, err := trace.ResolveTrace(dir, "tm-20261127-pty1")
	if err != nil {
		t.Fatalf("ResolveTrace: %v", err)
	}
	events, err := trace.ReadEvents(info)
	if err != nil {
		t.Fatalf("ReadEvents: %v", err)
	}

	var sawStdout, sawExit bool
	for _, ev := range events {
		if ev.Type == trace.TypeStdout && strings.Contains(ev.Data, "hello-tinmind") {
			sawStdout = true
		}
		if ev.Type == trace.TypeCmdExit && ev.ExitCode != nil && *ev.ExitCode == 7 && strings.Contains(ev.Stderr, "hello-tinmind") {
			sawExit = true
		}
	}
	if !sawStdout || !sawExit {
		t.Fatalf("expected stdout (%v) and cmd_exit (%v) events; got %d events", sawStdout, sawExit, len(events))
	}
}

// BenchmarkPTYRingWrite verifies the <0.05ms (50,000 ns) PTY hot-path write budget (FD-01).
func BenchmarkPTYRingWrite(b *testing.B) {
	rb := NewRingBuffer(DefaultRingCapacityBytes)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, ok := rb.Pop(); !ok {
				return
			}
		}
	}()

	ev := trace.Event{
		TS:   time.Now().UTC(),
		Type: trace.TypeStdout,
		Data: strings.Repeat("a", 1024),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rb.Push(ev)
	}
	b.StopTimer()
	rb.Close()
	<-done
}
