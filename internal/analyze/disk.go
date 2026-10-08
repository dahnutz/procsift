package analyze

import (
	"fmt"

	"github.com/dahnutz/procsift/internal/model"
)

func fileFindings(s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, file := range s.FileChecks {
		if file.State != "mismatch" {
			continue
		}
		out = append(out, model.Finding{
			Rule: "FILE-PKG-MISMATCH", Severity: model.SevMedium, Category: "file",
			Subject:  file.Path,
			Summary:  "on-disk utility differs from its local package manifest",
			Detail:   "The utility need not be running. Its full MD5 differs from the local dpkg entry; that database is not independently trusted. The file was read, not executed.",
			Evidence: []string{"package " + file.Package, fmt.Sprintf("md5 %s manifest %s bytes %d", file.MD5, file.Manifest, file.Bytes), "sha256 " + file.SHA256},
		})
	}
	return out
}
