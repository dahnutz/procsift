package explain

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSharedStartupSearchFindsTwoImagesAndGeneratedUnit(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"etc/init.d/first":                          "#!/bin/sh\n/usr/local/bin/first\n",
		"etc/init.d/second":                         "#!/bin/sh\n/usr/local/bin/second\n",
		"run/systemd/generator.late/second.service": "[Service]\nExecStart=/etc/init.d/second start\n",
	}
	for rel, body := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	results, gaps := FindStartupMany(root, []string{"/usr/local/bin/first", "/usr/local/bin/second"})
	if len(gaps) != 0 {
		t.Fatal(gaps)
	}
	for _, target := range []string{"/usr/local/bin/first", "/usr/local/bin/second"} {
		if results[target].Status != "complete" || len(results[target].Exact) != 1 {
			t.Fatalf("%s: %+v", target, results[target])
		}
	}
	unit := ReadUnit(root, "second.service")
	if unit.UnitFile == "" || len(unit.ExecStart) != 1 {
		t.Fatalf("generated unit: %+v", unit)
	}
}
