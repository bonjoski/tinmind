//go:build unix

package ptyrec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bonjoski/tinmind/pkg/trace"
	"github.com/creack/pty"
	"golang.org/x/term"
)

// Options configures a single PTY recording session.
type Options struct {
	TraceDir     string
	TraceID      string
	Format       string // "zstd" or "jsonl"
	RingBytes    int    // Defaults to 16 MiB
	WorkDir      string
	ExtraSecrets []string
	Stdin        io.Reader
	Stdout       io.Writer
	RecordStdin  bool // Disabled by default to avoid recording password prompts unnecessarily
}

// Result returns the recorded trace summary and child exit status.
type Result struct {
	Summary  trace.Summary
	ExitCode int
}

// Record launches args inside a Unix PTY, forwards terminal I/O and SIGWINCH transparently,
// restores host termios cleanly on exit, and streams redacted Event Envelope v1 frames
// through a non-blocking 16 MiB ring buffer to disk.
func Record(ctx context.Context, args []string, opts Options) (*Result, error) {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return nil, errors.New("command is required after '--'")
	}

	cwd := opts.WorkDir
	if strings.TrimSpace(cwd) == "" {
		var err error
		cwd, err = os.Getwd()
		if err != nil {
			cwd = "."
		}
	}
	repoName := detectRepoName(cwd)

	tw, err := trace.NewWriter(trace.WriterOptions{
		TraceDir:     opts.TraceDir,
		TraceID:      opts.TraceID,
		Format:       opts.Format,
		ExtraSecrets: opts.ExtraSecrets,
	})
	if err != nil {
		return nil, err
	}

	ring := NewRingBuffer(opts.RingBytes)
	var flushErrMu sync.Mutex
	var flushErr error
	var flushWG sync.WaitGroup
	flushWG.Add(1)
	go func() {
		defer flushWG.Done()
		for {
			ev, ok := ring.Pop()
			if !ok {
				return
			}
			if werr := tw.WriteEvent(ev); werr != nil {
				flushErrMu.Lock()
				if flushErr == nil {
					flushErr = werr
				}
				flushErrMu.Unlock()
			}
		}
	}()

	cmdStr := formatCommand(args)
	startTime := time.Now().UTC()
	ring.Push(trace.Event{
		TS:      startTime,
		Type:    trace.TypeSessionStart,
		Command: cmdStr,
		Cwd:     cwd,
		Repo:    repoName,
	})

	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), "TINMIND_SESSION_ID="+tw.TraceID())

	// Start child in a new PTY + session (Setsid + Setctty isolates child PGID).
	ptmx, err := pty.Start(cmd)
	if err != nil {
		ring.Close()
		flushWG.Wait()
		_, _, _ = tw.Close()
		return nil, fmt.Errorf("start pty for %q: %w", args[0], err)
	}
	defer func() { _ = ptmx.Close() }()

	// If host stdin is an interactive TTY, mirror size, handle SIGWINCH, and enter raw mode
	// with guaranteed termios restore on exit.
	var stdinFile *os.File
	if opts.Stdin == nil {
		stdinFile = os.Stdin
	} else if f, ok := opts.Stdin.(*os.File); ok {
		stdinFile = f
	}

	if stdinFile != nil && term.IsTerminal(int(stdinFile.Fd())) {
		fd := int(stdinFile.Fd())
		if cols, rows, szErr := term.GetSize(fd); szErr == nil {
			_ = pty.Setsize(ptmx, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
			ring.Push(trace.Event{
				TS:   time.Now().UTC(),
				Type: trace.TypeResize,
				Cols: uint16(cols),
				Rows: uint16(rows),
			})
		}

		oldState, rawErr := term.MakeRaw(fd)
		if rawErr == nil {
			defer func() { _ = term.Restore(fd, oldState) }()
		}

		winchCh := make(chan os.Signal, 2)
		signal.Notify(winchCh, syscall.SIGWINCH)
		defer signal.Stop(winchCh)
		go func() {
			for range winchCh {
				if cols, rows, err := term.GetSize(fd); err == nil {
					_ = pty.Setsize(ptmx, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
					ring.Push(trace.Event{
						TS:   time.Now().UTC(),
						Type: trace.TypeResize,
						Cols: uint16(cols),
						Rows: uint16(rows),
					})
				}
			}
		}()
	}

	// Forward SIGINT / SIGTERM strictly to the recorded child process group (-pid).
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sigDone := make(chan struct{})
	go func() {
		defer close(sigDone)
		for sig := range sigCh {
			if cmd.Process != nil {
				if sysSig, ok := sig.(syscall.Signal); ok {
					ring.Push(trace.Event{
						TS:   time.Now().UTC(),
						Type: trace.TypeSignal,
						Data: sysSig.String(),
					})
					_ = syscall.Kill(-cmd.Process.Pid, sysSig)
				}
			}
		}
	}()

	// Forward stdin -> PTY master when interactive or explicit non-nil reader supplied.
	if opts.Stdin != nil || (stdinFile != nil && term.IsTerminal(int(stdinFile.Fd()))) {
		reader := opts.Stdin
		if reader == nil {
			reader = stdinFile
		}
		go func() {
			buf := make([]byte, 4096)
			for {
				n, rerr := reader.Read(buf)
				if n > 0 {
					chunk := make([]byte, n)
					copy(chunk, buf[:n])
					_, _ = ptmx.Write(chunk)
					if opts.RecordStdin {
						ring.Push(trace.Event{
							TS:   time.Now().UTC(),
							Type: trace.TypeStdin,
							Data: string(chunk),
						})
					}
				}
				if rerr != nil {
					return
				}
			}
		}()
	}

	outWriter := opts.Stdout
	if outWriter == nil {
		outWriter = os.Stdout
	}

	// Read PTY master -> user stdout + non-blocking ring buffer + bounded tail for cmd_exit.
	var tailBuf boundedTail
	tailBuf.max = 32 * 1024
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 32*1024)
		for {
			n, rerr := ptmx.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				_, _ = outWriter.Write(chunk)
				tailBuf.Append(chunk)
				ring.Push(trace.Event{
					TS:   time.Now().UTC(),
					Type: trace.TypeStdout,
					Data: string(chunk),
				})
			}
			if rerr != nil {
				return
			}
		}
	}()

	waitErr := cmd.Wait()
	signal.Stop(sigCh)
	close(sigCh)
	<-sigDone
	_ = ptmx.Close()
	<-readDone

	exitCode := 0
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	endTime := time.Now().UTC()
	tailText := tailBuf.String()
	cmdExitEv := trace.Event{
		TS:       endTime,
		Type:     trace.TypeCmdExit,
		Command:  cmdStr,
		ExitCode: &exitCode,
		Cwd:      cwd,
		Repo:     repoName,
	}
	if exitCode != 0 {
		cmdExitEv.Stderr = tailText
	} else {
		cmdExitEv.Stdout = tailText
	}
	ring.Push(cmdExitEv)
	ring.Push(trace.Event{
		TS:            endTime,
		Type:          trace.TypeSessionEnd,
		ExitCode:      &exitCode,
		DroppedChunks: ring.DroppedChunks(),
	})

	ring.Close()
	flushWG.Wait()

	shaHex, sizeBytes, closeErr := tw.Close()
	if closeErr != nil {
		return nil, fmt.Errorf("close trace: %w", closeErr)
	}
	flushErrMu.Lock()
	fErr := flushErr
	flushErrMu.Unlock()
	if fErr != nil {
		return nil, fmt.Errorf("write trace events: %w", fErr)
	}

	failCount := 0
	if exitCode != 0 {
		failCount = 1
	}
	return &Result{
		ExitCode: exitCode,
		Summary: trace.Summary{
			TraceID:       tw.TraceID(),
			Path:          tw.Path(),
			EventCount:    int(ring.WrittenChunks()),
			FailureCount:  failCount,
			DroppedChunks: ring.DroppedChunks(),
			StartTime:     startTime,
			EndTime:       endTime,
			Duration:      endTime.Sub(startTime),
			ExitCode:      &exitCode,
			Command:       cmdStr,
			SHA256:        shaHex,
			SizeBytes:     sizeBytes,
		},
	}, nil
}

type boundedTail struct {
	buf bytes.Buffer
	max int
}

func (b *boundedTail) Append(p []byte) {
	if b.max <= 0 {
		return
	}
	if len(p) >= b.max {
		b.buf.Reset()
		_, _ = b.buf.Write(p[len(p)-b.max:])
		return
	}
	if b.buf.Len()+len(p) > b.max {
		drop := b.buf.Len() + len(p) - b.max
		b.buf.Next(drop)
	}
	_, _ = b.buf.Write(p)
}

func (b *boundedTail) String() string {
	return b.buf.String()
}

func formatCommand(args []string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		if strings.ContainsAny(a, " \t\n\"'") {
			quoted[i] = fmt.Sprintf("%q", a)
		} else {
			quoted[i] = a
		}
	}
	return strings.Join(quoted, " ")
}

func detectRepoName(cwd string) string {
	dir, err := filepath.Abs(cwd)
	if err != nil {
		return ""
	}
	for i := 0; i < 16; i++ {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return filepath.Base(dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}
