//go:build !unix

package ptyrec

import (
	"context"
	"errors"
	"io"

	"github.com/bonjoski/tinmind/pkg/trace"
)

type Options struct {
	TraceDir     string
	TraceID      string
	Format       string
	RingBytes    int
	WorkDir      string
	ExtraSecrets []string
	Stdin        io.Reader
	Stdout       io.Writer
	RecordStdin  bool
}

type Result struct {
	Summary  trace.Summary
	ExitCode int
}

func Record(_ context.Context, _ []string, _ Options) (*Result, error) {
	return nil, errors.New("tinmind PTY recording requires a Unix host (macOS or Linux)")
}
