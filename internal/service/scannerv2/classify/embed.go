package classify

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

//go:embed all:fingerprint-assets
var embeddedFingerprints embed.FS

// LoadEmbeddedDefaults populates the RuleClassifier from the fingerprint YAML
// files compiled into the binary (configs/fingerprints/*.yaml, embedded under
// fingerprint-assets/). This is the zero-config path: even when no
// FingerprintPath is configured, the engine still gets the shipped rule set.
//
// The embed uses `all:` so dotfiles/underscores aren't skipped (same lesson as
// web/embed.go's `//go:embed all:dist`).
func (r *RuleClassifier) LoadEmbeddedDefaults() error {
	if r == nil {
		return nil
	}
	r.rules = nil
	r.loaded = false
	tmp, err := os.MkdirTemp("", "mibee-fp-*")
	if err != nil {
		return fmt.Errorf("embed load: %w", err)
	}
	defer os.RemoveAll(tmp)
	// Walk the embedded tree and copy each .yaml to a temp dir, then LoadFromDir.
	// (LoadFromDir reads from the OS filesystem; copying to a temp dir reuses it
	// rather than duplicating the parser. This keeps one code path for loading.)
	err = fs.WalkDir(embeddedFingerprints, "fingerprint-assets", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		b, rerr := embeddedFingerprints.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		// Strip the "fingerprint-assets/" prefix to get the original filename.
		name := filepath.Base(path)
		return os.WriteFile(filepath.Join(tmp, name), b, 0o644)
	})
	if err != nil {
		return fmt.Errorf("embed load: %w", err)
	}
	return r.LoadFromDir(tmp)
}
