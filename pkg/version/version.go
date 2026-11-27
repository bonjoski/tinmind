package version

// Version is the canonical semantic version of tinmind.
// Overridden at build time via -ldflags "-X github.com/bonjoski/tinmind/pkg/version.Version=..."
var Version = "0.1.1"
