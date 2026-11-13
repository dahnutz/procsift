package explain

import (
	"crypto/sha256"
	"encoding/hex"
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
	got, digest, err := LoadTrustManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if got["/bin/true"] != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Fatalf("%v", got)
	}
	sum := sha256.Sum256([]byte(body))
	if digest != hex.EncodeToString(sum[:]) {
		t.Fatalf("digest %s", digest)
	}
}

// A symlinked manifest is applied by the loader, so it must also be identified;
// otherwise reports that used it could never be compared.
func TestLoadTrustManifestSymlinkIsIdentified(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	body := "d41d8cd98f00b204e9800998ecf8427e  /bin/true\n"
	if err := os.WriteFile(real, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	got, digest, err := LoadTrustManifest(link)
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v err %v", got, err)
	}
	sum := sha256.Sum256([]byte(body))
	if digest != hex.EncodeToString(sum[:]) {
		t.Fatalf("digest %s", digest)
	}
}

func TestLoadTrustManifestRejectedFileHasNoDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad")
	if err := os.WriteFile(path, []byte("not an entry\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, digest, err := LoadTrustManifest(path); err == nil || digest != "" {
		t.Fatalf("digest %q err %v", digest, err)
	}
}
