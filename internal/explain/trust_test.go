package explain

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadTrustManifest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest")
	body := "d41d8cd98f00b204e9800998ecf8427e  /bin/true\n# comment\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, digest, err := ReadTrustManifest(f)
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

func TestReadTrustManifestRejectedFileHasNoDigest(t *testing.T) {
	if _, digest, err := ReadTrustManifest(strings.NewReader("not an entry\n")); err == nil || digest != "" {
		t.Fatalf("digest %q err %v", digest, err)
	}
}
