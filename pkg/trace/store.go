package trace

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bonjoski/tinmind/pkg/redact"
	"github.com/klauspost/compress/zstd"
)

var zstdMagic = []byte{0x28, 0xB5, 0x2F, 0xFD}

// DefaultTraceDir returns the active trace directory: TINMIND_TRACE_DIR if set,
// otherwise ~/.tinmind/traces.
func DefaultTraceDir() (string, error) {
	if env := strings.TrimSpace(os.Getenv("TINMIND_TRACE_DIR")); env != "" {
		abs, err := filepath.Abs(env)
		if err != nil {
			return "", fmt.Errorf("%w: invalid TINMIND_TRACE_DIR: %v", ErrUnsafeTraceDir, err)
		}
		return abs, nil
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return "", fmt.Errorf("%w: cannot determine home directory", ErrUnsafeTraceDir)
	}
	return filepath.Join(home, ".tinmind", "traces"), nil
}

// LegacyFlightdeckTraceDir returns ~/.flightdeck/traces if HOME is available, enabling
// seamless Day-1 replay of traces written by aegisbox learn / aegisbox test --ai-safety.
func LegacyFlightdeckTraceDir() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return ""
	}
	return filepath.Join(home, ".flightdeck", "traces")
}

// EnsureSafeTraceDir creates (0700) and validates traceDir, failing closed if the target
// or its immediate parent is a symlink, non-directory, wrong owner, or group/world writable.
func EnsureSafeTraceDir(traceDir string) error {
	if strings.TrimSpace(traceDir) == "" {
		return fmt.Errorf("%w: empty trace directory", ErrUnsafeTraceDir)
	}
	abs, err := filepath.Abs(traceDir)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnsafeTraceDir, err)
	}

	// Refuse symlinked target or immediate parent before creating.
	if err := checkNoSymlinkIfExists(filepath.Dir(abs)); err != nil {
		return err
	}
	if err := checkNoSymlinkIfExists(abs); err != nil {
		return err
	}

	if err := os.MkdirAll(abs, 0o700); err != nil {
		return fmt.Errorf("%w: mkdir %q: %v", ErrUnsafeTraceDir, abs, err)
	}

	fi, err := os.Lstat(abs)
	if err != nil {
		return fmt.Errorf("%w: lstat %q: %v", ErrUnsafeTraceDir, abs, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: trace directory %q is a symlink", ErrSymlinkRefused, abs)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %q is not a directory", ErrUnsafeTraceDir, abs)
	}
	return verifyDirOwnership(abs, fi)
}

func checkNoSymlinkIfExists(p string) error {
	fi, err := os.Lstat(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("%w: lstat %q: %v", ErrUnsafeTraceDir, p, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %q is a symlink", ErrSymlinkRefused, p)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %q is not a directory", ErrUnsafeTraceDir, p)
	}
	return nil
}

// WriterOptions configures a new confined TraceWriter.
type WriterOptions struct {
	TraceDir     string
	TraceID      string
	Format       string // "zstd" (default) or "jsonl"
	ExtraSecrets []string
}

// Writer streams redacted Event Envelope v1 lines to an os.OpenRoot-confined file (0600).
type Writer struct {
	mu           sync.Mutex
	traceID      string
	path         string
	compressed   bool
	extraSecrets []string

	root   *os.Root
	file   *os.File
	hasher io.Writer
	sum    interface{ Sum([]byte) []byte }
	zenc   *zstd.Encoder
	bw     *bufio.Writer

	seq    uint64
	events int
	closed bool
}

// NewWriter opens a brand-new trace file using O_CREATE|O_EXCL inside os.OpenRoot.
func NewWriter(opts WriterOptions) (*Writer, error) {
	traceDir := opts.TraceDir
	if strings.TrimSpace(traceDir) == "" {
		var err error
		traceDir, err = DefaultTraceDir()
		if err != nil {
			return nil, err
		}
	}
	if err := EnsureSafeTraceDir(traceDir); err != nil {
		return nil, err
	}

	traceID := opts.TraceID
	if strings.TrimSpace(traceID) == "" {
		traceID = NewTraceID()
	}
	if err := ValidateTraceID(traceID); err != nil {
		return nil, err
	}

	format := strings.ToLower(strings.TrimSpace(opts.Format))
	if format == "" {
		format = FormatZstd
	}
	if format != FormatZstd && format != FormatJSONL {
		return nil, fmt.Errorf("unsupported trace format %q (want %q or %q)", format, FormatZstd, FormatJSONL)
	}
	compressed := format == FormatZstd
	filename := traceID + ".jsonl"
	if compressed {
		filename += ".zst"
	}

	root, err := os.OpenRoot(traceDir)
	if err != nil {
		return nil, fmt.Errorf("open trace root: %w", err)
	}

	f, err := root.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("create trace file %q: %w", filename, err)
	}

	h := sha256.New()
	mw := io.MultiWriter(f, h)
	w := &Writer{
		traceID:      traceID,
		path:         filepath.Join(traceDir, filename),
		compressed:   compressed,
		extraSecrets: append([]string(nil), opts.ExtraSecrets...),
		root:         root,
		file:         f,
		hasher:       mw,
		sum:          h,
	}
	if compressed {
		zenc, err := zstd.NewWriter(mw, zstd.WithEncoderLevel(zstd.SpeedFastest))
		if err != nil {
			_ = f.Close()
			_ = root.Close()
			return nil, fmt.Errorf("init zstd writer: %w", err)
		}
		w.zenc = zenc
		w.bw = bufio.NewWriterSize(zenc, 32*1024)
	} else {
		w.bw = bufio.NewWriterSize(mw, 32*1024)
	}
	return w, nil
}

// TraceID returns the trace identifier.
func (w *Writer) TraceID() string { return w.traceID }

// Path returns the absolute on-disk trace path.
func (w *Writer) Path() string { return w.path }

// WriteEvent redacts secrets and unsafe terminal escapes before serializing ev to disk.
func (w *Writer) WriteEvent(ev Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return errors.New("trace writer is closed")
	}

	w.seq++
	clean := sanitizeEventForDisk(ev, w.seq, w.traceID, w.extraSecrets)

	raw, err := json.Marshal(&clean)
	if err != nil {
		return fmt.Errorf("marshal trace event: %w", err)
	}
	if len(raw) > DefaultMaxLineBytes {
		// Truncate oversized data deterministically rather than failing mid-stream.
		clean.Data = clean.Data[:min(len(clean.Data), 256*1024)]
		clean.Stdout = clean.Stdout[:min(len(clean.Stdout), 128*1024)]
		clean.Stderr = clean.Stderr[:min(len(clean.Stderr), 128*1024)]
		raw, err = json.Marshal(&clean)
		if err != nil {
			return fmt.Errorf("marshal truncated trace event: %w", err)
		}
	}
	if _, err := w.bw.Write(raw); err != nil {
		return err
	}
	if err := w.bw.WriteByte('\n'); err != nil {
		return err
	}
	w.events++
	return nil
}

// Close flushes buffers, closes zstd stream and file, and returns final size & SHA-256 digest.
func (w *Writer) Close() (sha256Hex string, sizeBytes int64, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return hex.EncodeToString(w.sum.Sum(nil)), 0, nil
	}
	w.closed = true

	var firstErr error
	if w.bw != nil {
		if ferr := w.bw.Flush(); ferr != nil && firstErr == nil {
			firstErr = ferr
		}
	}
	if w.zenc != nil {
		if zerr := w.zenc.Close(); zerr != nil && firstErr == nil {
			firstErr = zerr
		}
	}
	if w.file != nil {
		if st, serr := w.file.Stat(); serr == nil {
			sizeBytes = st.Size()
		}
		if cerr := w.file.Close(); cerr != nil && firstErr == nil {
			firstErr = cerr
		}
	}
	if w.root != nil {
		_ = w.root.Close()
	}
	return hex.EncodeToString(w.sum.Sum(nil)), sizeBytes, firstErr
}

func sanitizeEventForDisk(ev Event, seq uint64, traceID string, extraSecrets []string) Event {
	if ev.TS.IsZero() {
		ev.TS = time.Now().UTC()
	} else {
		ev.TS = ev.TS.UTC()
	}
	if ev.Seq == 0 {
		ev.Seq = seq
	}
	if ev.SessionID == "" {
		ev.SessionID = traceID
	}
	ev.Type = redact.StripAllANSI(ev.Type)
	ev.Command = redact.ScrubText(ev.Command, extraSecrets...)
	ev.Tool = redact.ScrubText(ev.Tool, extraSecrets...)
	ev.Stderr = redact.ScrubText(ev.Stderr, extraSecrets...)
	ev.Stdout = redact.ScrubText(ev.Stdout, extraSecrets...)
	ev.Cwd = redact.StripAllANSI(ev.Cwd)
	ev.Repo = redact.StripAllANSI(ev.Repo)
	ev.ProbeID = redact.StripAllANSI(ev.ProbeID)
	ev.Category = redact.StripAllANSI(ev.Category)

	// Preserve safe SGR/cursor escapes on PTY stdout while scrubbing secrets & OSC-52.
	if ev.Type == TypeStdout {
		ev.Data = redact.ScrubPTY(ev.Data, extraSecrets...)
	} else {
		ev.Data = redact.ScrubText(ev.Data, extraSecrets...)
	}
	return ev
}

// ResolveTrace locates traceID across primaryDir and optional extraDirs (e.g. legacy ~/.flightdeck/traces).
// Strictly validates traceID and refuses symlinked files fail-closed.
func ResolveTrace(primaryDir, traceID string, extraDirs ...string) (*TraceInfo, error) {
	norm := NormalizeID(traceID)
	if err := ValidateTraceID(norm); err != nil {
		return nil, err
	}

	dirs := make([]struct {
		dir    string
		legacy bool
	}, 0, 1+len(extraDirs))
	if strings.TrimSpace(primaryDir) != "" {
		dirs = append(dirs, struct {
			dir    string
			legacy bool
		}{dir: primaryDir, legacy: false})
	}
	for _, d := range extraDirs {
		if strings.TrimSpace(d) != "" && d != primaryDir {
			dirs = append(dirs, struct {
				dir    string
				legacy bool
			}{dir: d, legacy: true})
		}
	}

	candidates := []string{norm + ".jsonl.zst", norm + ".jsonl"}
	if strings.HasSuffix(traceID, ".jsonl") {
		candidates = []string{norm + ".jsonl", norm + ".jsonl.zst"}
	}

	for _, entry := range dirs {
		fiDir, err := os.Lstat(entry.dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		if fiDir.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: trace dir %q", ErrSymlinkRefused, entry.dir)
		}
		if !fiDir.IsDir() {
			continue
		}

		root, err := os.OpenRoot(entry.dir)
		if err != nil {
			continue
		}
		for _, fname := range candidates {
			fi, err := root.Lstat(fname)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				_ = root.Close()
				return nil, err
			}
			if fi.Mode()&os.ModeSymlink != 0 {
				_ = root.Close()
				return nil, fmt.Errorf("%w: %s", ErrSymlinkRefused, filepath.Join(entry.dir, fname))
			}
			if !fi.Mode().IsRegular() {
				continue
			}
			_ = root.Close()
			return &TraceInfo{
				ID:         norm,
				Filename:   fname,
				Path:       filepath.Join(entry.dir, fname),
				Dir:        entry.dir,
				Compressed: strings.HasSuffix(fname, ".zst"),
				SizeBytes:  fi.Size(),
				ModTime:    fi.ModTime().UTC(),
				Legacy:     entry.legacy,
			}, nil
		}
		_ = root.Close()
	}

	return nil, fmt.Errorf("%w: %s", ErrTraceNotFound, norm)
}

// ListTraces lists regular .jsonl and .jsonl.zst traces across primaryDir and optional legacy dirs,
// sorted newest-first. Symlinks are silently skipped on list (and refused fail-closed on open).
func ListTraces(primaryDir string, extraDirs ...string) ([]TraceInfo, error) {
	seen := make(map[string]struct{})
	var out []TraceInfo

	scanDir := func(dir string, legacy bool) error {
		if strings.TrimSpace(dir) == "" {
			return nil
		}
		fiDir, err := os.Lstat(dir)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if fiDir.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: trace directory %q", ErrSymlinkRefused, dir)
		}
		if !fiDir.IsDir() {
			return nil
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			return err
		}
		defer func() { _ = root.Close() }()

		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".jsonl") && !strings.HasSuffix(name, ".jsonl.zst") {
				continue
			}
			id := NormalizeID(name)
			if err := ValidateTraceID(id); err != nil {
				continue
			}
			if _, dup := seen[id]; dup {
				continue
			}
			fi, err := root.Lstat(name)
			if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, TraceInfo{
				ID:         id,
				Filename:   name,
				Path:       filepath.Join(dir, name),
				Dir:        dir,
				Compressed: strings.HasSuffix(name, ".zst"),
				SizeBytes:  fi.Size(),
				ModTime:    fi.ModTime().UTC(),
				Legacy:     legacy,
			})
		}
		return nil
	}

	if err := scanDir(primaryDir, false); err != nil {
		return nil, err
	}
	for _, d := range extraDirs {
		if d != primaryDir {
			if err := scanDir(d, true); err != nil {
				return nil, err
			}
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].ModTime.Equal(out[j].ModTime) {
			return out[i].ID > out[j].ID
		}
		return out[i].ModTime.After(out[j].ModTime)
	})
	return out, nil
}

// StreamEvents opens a trace safely inside os.OpenRoot, auto-detects Zstandard magic bytes,
// enforces the maxDecompressedBytes anti-bomb cap and 1 MiB line cap, and invokes fn per Event.
func StreamEvents(info *TraceInfo, maxDecompressedBytes int64, fn func(Event) error) error {
	if info == nil {
		return errors.New("nil TraceInfo")
	}
	if maxDecompressedBytes <= 0 {
		maxDecompressedBytes = DefaultMaxDecompressedBytes
	}
	if err := ValidateTraceID(NormalizeID(info.Filename)); err != nil {
		return err
	}

	fiDir, err := os.Lstat(info.Dir)
	if err != nil {
		return err
	}
	if fiDir.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrSymlinkRefused, info.Dir)
	}

	root, err := os.OpenRoot(info.Dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()

	fi, err := root.Lstat(info.Filename)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrSymlinkRefused, info.Path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("trace %q is not a regular file", info.Path)
	}

	f, err := root.Open(info.Filename)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	br := bufio.NewReaderSize(f, 32*1024)
	magic, err := br.Peek(4)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
		return err
	}

	var rawReader io.Reader = br
	if len(magic) == 4 && bytes.Equal(magic, zstdMagic) {
		dec, err := zstd.NewReader(br)
		if err != nil {
			return fmt.Errorf("open zstd trace: %w", err)
		}
		defer dec.Close()
		rawReader = dec
	}

	limited := &io.LimitedReader{R: rawReader, N: maxDecompressedBytes + 1}
	lineReader := bufio.NewReaderSize(limited, 64*1024)

	for {
		line, err := readBoundedLine(lineReader, DefaultMaxLineBytes)
		if limited.N <= 0 {
			return fmt.Errorf("%w (limit %d bytes)", ErrDecompressLimit, maxDecompressedBytes)
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) > 0 {
			var ev Event
			if jerr := json.Unmarshal(trimmed, &ev); jerr == nil {
				if cbErr := fn(ev); cbErr != nil {
					return cbErr
				}
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
	}
	return nil
}

func readBoundedLine(r *bufio.Reader, maxLen int) ([]byte, error) {
	var buf []byte
	for {
		frag, isPrefix, err := r.ReadLine()
		if len(buf)+len(frag) > maxLen {
			return nil, ErrLineTooLong
		}
		buf = append(buf, frag...)
		if err != nil {
			return buf, err
		}
		if !isPrefix {
			return buf, nil
		}
	}
}

// ReadEvents loads all events from info into memory (bounded by DefaultMaxDecompressedBytes).
func ReadEvents(info *TraceInfo) ([]Event, error) {
	var events []Event
	err := StreamEvents(info, DefaultMaxDecompressedBytes, func(ev Event) error {
		events = append(events, ev)
		return nil
	})
	return events, err
}

// ExportForCoppermind writes a clean, ANSI-stripped, secret-redacted uncompressed JSONL stream
// strictly bounded by CoppermindMaxTraceBytes (16 MiB) for `coppermind ingest-flightdeck`.
func ExportForCoppermind(info *TraceInfo, out io.Writer) (int64, int, error) {
	var written int64
	var count int
	err := StreamEvents(info, DefaultMaxDecompressedBytes, func(ev Event) error {
		clean := Event{
			TS:        ev.TS.UTC(),
			Seq:       ev.Seq,
			SessionID: redact.StripAllANSI(ev.SessionID),
			Type:      redact.StripAllANSI(ev.Type),
			Data:      redact.ScrubText(ev.Data),
			Command:   redact.ScrubText(ev.Command),
			Tool:      redact.ScrubText(ev.Tool),
			ExitCode:  ev.ExitCode,
			Stderr:    redact.ScrubText(ev.Stderr),
			Stdout:    redact.ScrubText(ev.Stdout),
			Cwd:       redact.StripAllANSI(ev.Cwd),
			Repo:      redact.StripAllANSI(ev.Repo),
			ProbeID:   redact.StripAllANSI(ev.ProbeID),
			Category:  redact.StripAllANSI(ev.Category),
		}
		raw, err := json.Marshal(&clean)
		if err != nil {
			return err
		}
		raw = append(raw, '\n')
		if written+int64(len(raw)) > CoppermindMaxTraceBytes {
			return fmt.Errorf("export truncated at Coppermind 16 MiB cap (%d events written)", count)
		}
		n, err := out.Write(raw)
		written += int64(n)
		if err != nil {
			return err
		}
		count++
		return nil
	})
	return written, count, err
}

// PruneResult summarizes a FIFO retention & quota sweep.
type PruneResult struct {
	RemovedFiles int   `json:"removed_files"`
	FreedBytes   int64 `json:"freed_bytes"`
	KeptFiles    int   `json:"kept_files"`
	RemainingB   int64 `json:"remaining_bytes"`
	SkippedLock  bool  `json:"skipped_lock,omitempty"`
}

// Prune enforces the rolling retention TTL (7 days default) and total byte quota (500 MiB default)
// inside traceDir using non-blocking flock + os.OpenRoot (never follows symlinks).
func Prune(traceDir string, maxBytes int64, maxAge time.Duration) (*PruneResult, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultQuotaBytes
	}
	if maxAge <= 0 {
		maxAge = DefaultRetention
	}
	if _, err := os.Lstat(traceDir); os.IsNotExist(err) {
		return &PruneResult{}, nil
	}
	if err := EnsureSafeTraceDir(traceDir); err != nil {
		return nil, err
	}

	root, err := os.OpenRoot(traceDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()

	// Non-blocking lock so N=8 parallel subagents never contend on pruning.
	lockFile, err := root.OpenFile(".prune.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	defer func() { _ = lockFile.Close() }()

	acquired, err := tryNonBlockingLock(lockFile)
	if err != nil {
		return nil, err
	}
	if !acquired {
		return &PruneResult{SkippedLock: true}, nil
	}
	defer unlockFile(lockFile)

	entries, err := os.ReadDir(traceDir)
	if err != nil {
		return nil, err
	}

	type candidate struct {
		name    string
		size    int64
		modTime time.Time
	}
	var files []candidate
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".jsonl") && !strings.HasSuffix(name, ".jsonl.zst") {
			continue
		}
		fi, err := root.Lstat(name)
		if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
			continue
		}
		files = append(files, candidate{name: name, size: fi.Size(), modTime: fi.ModTime()})
	}

	// Oldest first for FIFO eviction.
	sort.Slice(files, func(i, j int) bool {
		if files[i].modTime.Equal(files[j].modTime) {
			return files[i].name < files[j].name
		}
		return files[i].modTime.Before(files[j].modTime)
	})

	cutoff := time.Now().Add(-maxAge)
	res := &PruneResult{}
	var kept []candidate
	var totalBytes int64

	// Pass 1: Evict expired files older than maxAge.
	for _, f := range files {
		if f.modTime.Before(cutoff) {
			if err := root.Remove(f.name); err == nil {
				res.RemovedFiles++
				res.FreedBytes += f.size
				continue
			}
		}
		kept = append(kept, f)
		totalBytes += f.size
	}

	// Pass 2: Evict oldest remaining files until totalBytes <= maxBytes.
	idx := 0
	for totalBytes > maxBytes && idx < len(kept) {
		f := kept[idx]
		idx++
		if err := root.Remove(f.name); err == nil {
			res.RemovedFiles++
			res.FreedBytes += f.size
			totalBytes -= f.size
		}
	}

	res.KeptFiles = len(kept) - idx
	res.RemainingB = totalBytes
	return res, nil
}
