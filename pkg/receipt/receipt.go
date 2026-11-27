package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/bonjoski/tinmind/pkg/trace"
	"github.com/bonjoski/tinmind/pkg/version"
)

const (
	StatementTypeV1     = "https://in-toto.io/Statement/v1"
	PredicateTypeV1     = "https://bonjoski.dev/attestation/paved-road/v1"
	DSSEPayloadType     = "application/vnd.in-toto+json"
	SchemaVersionV1     = "1.0.0"
	SPIFFESessionPrefix = "spiffe://bonjoski.local/session/"
	StageTesting        = "testing_validation"
)

var (
	sessionIDRe = regexp.MustCompile(`^sess_[0-9A-Za-z]+$`)
	headSHARe   = regexp.MustCompile(`^[a-f0-9]{7,64}$`)
	sha256HexRe = regexp.MustCompile(`^[a-f0-9]{64}$`)

	ErrInvalidSessionID = errors.New("invalid BLPR-v1 session ID")
	ErrSymlinkDetected  = errors.New("symlink detected in receipt storage path (fail-closed)")
)

// Subject is an in-toto Statement v1 subject entry.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// SessionLineage captures ambient session & worktree metadata.
type SessionLineage struct {
	SessionID       string `json:"session_id"`
	ParentSessionID string `json:"parent_session_id,omitempty"`
	ActorMode       string `json:"actor_mode"`
	WorktreeHeadSHA string `json:"worktree_head_sha"`
}

// Producer identifies the tool emitting the BLPR-v1 receipt.
type Producer struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	Stage   string `json:"stage"`
}

// Predicate is the BLPR-v1 predicate body inside an in-toto Statement v1.
type Predicate struct {
	SchemaVersion string          `json:"schema_version"`
	ReceiptID     string          `json:"receipt_id"`
	Timestamp     time.Time       `json:"timestamp"`
	Session       SessionLineage  `json:"session"`
	Producer      Producer        `json:"producer"`
	Verdict       string          `json:"verdict"`
	Proven        bool            `json:"proven"`
	Claims        json.RawMessage `json:"claims"`
}

// Statement is a standards-compliant in-toto Statement v1.
type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

// DSSESignature is a single DSSE signature entry bound to a SPIFFE session keyID.
type DSSESignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// DSSEEnvelope wraps a base64-encoded in-toto Statement v1.
type DSSEEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []DSSESignature `json:"signatures"`
}

// EmitOptions configures local BLPR-v1 receipt creation.
type EmitOptions struct {
	WorktreeRoot    string
	SessionID       string
	WorktreeHeadSHA string
	ActorMode       string             // "sdlc" or "aidlc"
	SigningKey      ed25519.PrivateKey // Ephemeral key generated if nil
}

// Emit writes a signed BLPR-v1 DSSE receipt attesting a recorded Tinmind trace into
// <WorktreeRoot>/.fabrial/receipts/<session_id>/<unix_ms>-tinmind-<rcpt_id>.dsse.json (0600)
// via os.OpenRoot, refusing any symlink along the path.
func Emit(summary trace.Summary, opts EmitOptions) (string, *DSSEEnvelope, error) {
	worktree := strings.TrimSpace(opts.WorktreeRoot)
	if worktree == "" {
		var err error
		worktree, err = os.Getwd()
		if err != nil {
			return "", nil, err
		}
	}
	absRoot, err := filepath.Abs(worktree)
	if err != nil {
		return "", nil, err
	}

	sessionID := strings.TrimSpace(opts.SessionID)
	if sessionID == "" {
		sessionID = strings.TrimSpace(os.Getenv("FABRIAL_SESSION_ID"))
	}
	if sessionID == "" {
		var b [12]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", nil, err
		}
		sessionID = "sess_" + hex.EncodeToString(b[:])
	}
	if !sessionIDRe.MatchString(sessionID) {
		return "", nil, fmt.Errorf("%w: %q", ErrInvalidSessionID, sessionID)
	}

	headSHA := strings.TrimSpace(opts.WorktreeHeadSHA)
	if !headSHARe.MatchString(headSHA) {
		headSHA = "0000000"
	}

	actorMode := strings.TrimSpace(opts.ActorMode)
	if actorMode != "sdlc" && actorMode != "aidlc" {
		actorMode = "aidlc"
	}

	digest := strings.ToLower(strings.TrimSpace(summary.SHA256))
	if !sha256HexRe.MatchString(digest) {
		return "", nil, fmt.Errorf("invalid trace sha256 digest %q", digest)
	}

	var rcptBytes [12]byte
	if _, err := rand.Read(rcptBytes[:]); err != nil {
		return "", nil, err
	}
	rcptID := "rcpt_" + hex.EncodeToString(rcptBytes[:])

	verdict := "allow"
	if summary.FailureCount > 0 || (summary.ExitCode != nil && *summary.ExitCode != 0) {
		verdict = "warn"
	}

	claimsObj := map[string]any{
		"trace_id":       summary.TraceID,
		"event_count":    summary.EventCount,
		"failure_count":  summary.FailureCount,
		"dropped_chunks": summary.DroppedChunks,
		"size_bytes":     summary.SizeBytes,
	}
	if summary.ExitCode != nil {
		claimsObj["exit_code"] = *summary.ExitCode
	}
	claimsRaw, err := json.Marshal(claimsObj)
	if err != nil {
		return "", nil, err
	}

	stmt := Statement{
		Type: StatementTypeV1,
		Subject: []Subject{{
			Name:   filepath.Base(summary.Path),
			Digest: map[string]string{"sha256": digest},
		}},
		PredicateType: PredicateTypeV1,
		Predicate: Predicate{
			SchemaVersion: SchemaVersionV1,
			ReceiptID:     rcptID,
			Timestamp:     time.Now().UTC(),
			Session: SessionLineage{
				SessionID:       sessionID,
				ActorMode:       actorMode,
				WorktreeHeadSHA: headSHA,
			},
			Producer: Producer{
				Tool:    "tinmind",
				Version: version.Version,
				Stage:   StageTesting,
			},
			Verdict: verdict,
			Proven:  true,
			Claims:  claimsRaw,
		},
	}

	payload, err := json.Marshal(&stmt)
	if err != nil {
		return "", nil, err
	}

	priv := opts.SigningKey
	if len(priv) != ed25519.PrivateKeySize {
		_, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return "", nil, err
		}
	}

	pae := dssePAE(DSSEPayloadType, payload)
	sig := ed25519.Sign(priv, pae)

	env := &DSSEEnvelope{
		PayloadType: DSSEPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []DSSESignature{{
			KeyID: SPIFFESessionPrefix + sessionID,
			Sig:   base64.StdEncoding.EncodeToString(sig),
		}},
	}

	outPath, err := writeAtomic(absRoot, sessionID, rcptID, env)
	if err != nil {
		return "", nil, err
	}
	return outPath, env, nil
}

// Verify checks the Ed25519 DSSE signature on env against pub.
func Verify(env *DSSEEnvelope, pub ed25519.PublicKey) (*Statement, error) {
	if env == nil || len(env.Signatures) == 0 {
		return nil, errors.New("empty DSSE envelope")
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		return nil, fmt.Errorf("decode sig: %w", err)
	}
	pae := dssePAE(env.PayloadType, payload)
	if !ed25519.Verify(pub, pae, sig) {
		return nil, errors.New("DSSE signature verification failed")
	}
	var stmt Statement
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return nil, fmt.Errorf("unmarshal statement: %w", err)
	}
	return &stmt, nil
}

// dssePAE implements the standard DSSE Pre-Authentication Encoding.
func dssePAE(payloadType string, payload []byte) []byte {
	header := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	out := make([]byte, 0, len(header)+len(payload))
	out = append(out, header...)
	out = append(out, payload...)
	return out
}

func writeAtomic(absRoot, sessionID, rcptID string, env *DSSEEnvelope) (string, error) {
	root, err := os.OpenRoot(absRoot)
	if err != nil {
		return "", fmt.Errorf("open worktree root: %w", err)
	}
	defer func() { _ = root.Close() }()

	parts := []string{".fabrial", "receipts", sessionID}
	cur := ""
	for _, p := range parts {
		if cur == "" {
			cur = p
		} else {
			cur = filepath.Join(cur, p)
		}
		fi, err := root.Lstat(cur)
		if err != nil {
			if os.IsNotExist(err) {
				if mkErr := root.Mkdir(cur, 0o700); mkErr != nil && !os.IsExist(mkErr) {
					return "", fmt.Errorf("mkdir %s: %w", cur, mkErr)
				}
				continue
			}
			return "", err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%w: %s", ErrSymlinkDetected, cur)
		}
		if !fi.IsDir() {
			return "", fmt.Errorf("%s is not a directory", cur)
		}
	}

	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return "", err
	}
	data = append(data, '\n')

	finalName := fmt.Sprintf("%d-tinmind-%s.dsse.json", time.Now().UTC().UnixMilli(), rcptID)
	finalRel := filepath.Join(cur, finalName)

	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	tmpRel := filepath.Join(cur, fmt.Sprintf(".%s.%s.tmp", finalName, hex.EncodeToString(nonce[:])))

	f, err := root.OpenFile(tmpRel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = root.Remove(tmpRel)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = root.Remove(tmpRel)
		return "", err
	}
	if err := root.Rename(tmpRel, finalRel); err != nil {
		_ = root.Remove(tmpRel)
		return "", err
	}
	return filepath.Join(absRoot, finalRel), nil
}
