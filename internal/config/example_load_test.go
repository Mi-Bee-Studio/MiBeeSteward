package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExampleYAML_Loads verifies the committed configs/config.example.yaml
// parses cleanly through Load() and the documented keys are read. This guards
// against doc/yaml drift (issue #131).
func TestExampleYAML_Loads(t *testing.T) {
	root, _ := os.Getwd()
	// walk up to repo root (internal/config -> repo root)
	for !fileExists(filepath.Join(root, "go.mod")) {
		root = filepath.Dir(root)
	}
	path := filepath.Join(root, "configs", "config.example.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("config.example.yaml not found at %s: %v", path, err)
	}
	// Substitute the two REQUIRED placeholders so validation passes.
	s := string(raw)
	s = strings.Replace(s, `jwt_secret: "change-me-in-production"`,
		`jwt_secret: "this-is-definitely-32-chars-long!!"`, 1)
	s = strings.Replace(s, `initial_admin_password: "change-me"`,
		`initial_admin_password: "Admin@2026"`, 1)
	tmp, _ := os.CreateTemp("", "cfg-*.yaml")
	tmp.WriteString(s)
	tmp.Close()
	defer os.Remove(tmp.Name())

	cfg, err := Load(tmp.Name())
	if err != nil {
		t.Fatalf("Load(config.example.yaml) error: %v", err)
	}
	// Spot-check the keys this test was added to guard (issue #131).
	if cfg.Scanner.ReconcileInterval == "" {
		t.Error("scanner.reconcile_interval not parsed (empty)")
	}
	if cfg.Retention.DeviceLivenessDays == 0 && !strings.Contains(s, "device_liveness_days") {
		t.Error("retention.device_liveness_days missing from example")
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
