# `tinmind` AI Agent Guidelines

> **Repository:** `bonjoski/tinmind` (🟢 `PUBLIC_OSS` Safe Harbor)  
> **Scope:** `bonjoski/tinmind` (`.coppermind.yaml`)  
> **Parent Blueprint:** `spanreed/docs/plans/accepted/2026-11-25-flightdeck-construction-plan-and-rtm.md` (`RFC-2026-11-25-60`)

## Architectural Invariants

1. **Zero Cloud / Zero Network:** `tinmind` must never open outbound network sockets or transmit telemetry.
2. **Pre-Disk Redaction (`pkg/redact`):** Every event written to disk must pass through `redact.ScrubPTY` / `redact.ScrubText` (including ANSI-split secret smuggling defense and Shannon entropy `>4.2`).
3. **Safe-ANSI Default (`pkg/replay`):** `--safe-ansi` is ALWAYS on by default; OSC-52, DCS, APC, PM, C1, and Bidi overrides are stripped unless `--unsafe-raw-tty` is explicitly passed.
4. **Fail-Closed Path Confinement (`pkg/trace`):** All trace reads, writes, exports, and FIFO prunes use `os.OpenRoot` + `Lstat` non-symlink enforcement + strict trace-ID validation.
5. **$N=8$ Concurrency & `<0.05ms` Hop Tax:** Per-session `O_CREAT|O_EXCL` files, bounded 16 MiB non-blocking ring buffer, non-blocking `flock` on `.prune.lock`, zero Touch ID prompts.
6. **Commit & Release Discipline:** Never `git commit` without explicit user approval; sign all commits (`git commit -S`, GPG key `7BB5B44244E586B0`); bump `VERSION` + `pkg/version/version.go` and sync `bonjoski/homebrew-tap` on release.

## Commands

```bash
go test -race ./...
go test -bench=BenchmarkPTYRingWrite ./pkg/ptyrec/...
```
