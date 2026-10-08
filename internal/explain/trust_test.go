package explain

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTrustManifest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest")
	body := "d41d8cd98f00b204e9800998ecf8427e  /bin/true\n# comment\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadTrustManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if got["/bin/true"] != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Fatalf("%v", got)
	}
}
