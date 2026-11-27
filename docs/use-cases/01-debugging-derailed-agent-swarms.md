# Use Case 01: Debugging Derailed Autonomous Agent Swarms

## Scenario

You are running $N=8$ parallel coding agents across isolated git worktrees. One subagent gets stuck in a failing test loop, triggers an `aegisbox` AI-safety finding, or exits with a cryptic error after 200 lines of scrollback. You want to:

1. See **exactly** what happened without re-running destructive mutations.
2. Be certain no leaked API keys were saved to disk and no malicious `OSC-52` escape sequence hijacks your clipboard during replay.
3. Distill the failure → recovery sequence into persistent `coppermind` memory so future agents avoid the same dead end.

---

## Workflow

### Step 1: Record Agent Loops Zero-Overhead

```bash
tinmind record --session-id wt-auth-01 -- go test ./...
```

- Output streams normally to your terminal with `<0.05ms` ring-buffer overhead.
- If the agent prints `ANTHROPIC_API_KEY=sk-ant-...` or a PEM private key, `tinmind` replaces it with `[REDACTED_SECRET]` **before** bytes touch `~/.tinmind/traces/wt-auth-01.jsonl.zst` (`0600`).
- If `FABRIAL_SESSION_ID` is set (or `--receipt` is passed), a signed `BLPR-v1` DSSE receipt is atomically written into `.fabrial/receipts/<session_id>/`.

### Step 2: Triage Failures in Milliseconds

```bash
tinmind inspect wt-auth-01 --failures-only
```

Or step through the recorded terminal output deterministically:

```bash
tinmind replay wt-auth-01 --speed 2.0
tinmind replay wt-auth-01 --step --safe-ansi
```

`--safe-ansi` is enabled by default, preserving colors and layout while stripping `OSC-52` clipboard writes, window-manipulation sequences, and Unicode Bidi overrides.

### Step 3: Replay `aegisbox` Security Katas & AI-Safety Traces

`tinmind` automatically discovers uncompressed traces written by `aegisbox learn` and `aegisbox test --ai-safety` in `~/.flightdeck/traces/`:

```bash
tinmind list
tinmind replay fd-20261127-a81c --failures-only
```

### Step 4: Distill Lessons into `coppermind`

```bash
tinmind export wt-auth-01 --for-coppermind -o /tmp/wt-auth-01.jsonl && \
  coppermind ingest-flightdeck /tmp/wt-auth-01.jsonl
```

`export --for-coppermind` strips ANSI escapes, re-scrubs secrets, and enforces the 16 MiB `coppermind` ingestion cap so `coppermind` can safely extract linked `dead_end` → `troubleshooting` graph edges.
