// Package version holds the build version of the MiBee Steward binary.
//
// The value is injected at build time via -ldflags:
//
//	go build -ldflags "-X mibee-steward/internal/version.Version=v0.1.0"
//
// When built without ldflags (e.g. `go run`), Version stays "dev".
package version

// Version is the build version. Overridden by ldflags at release build time.
var Version = "dev"
