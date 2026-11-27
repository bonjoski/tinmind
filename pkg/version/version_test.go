package version

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionMatchesFile(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "VERSION"))
	if err != nil {
		t.Fatalf("read VERSION file: %v", err)
	}
	want := strings.TrimSpace(string(raw))
	if Version != want {
		t.Fatalf("pkg/version.Version = %q, want %q (from VERSION file)", Version, want)
	}
}
