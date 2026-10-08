package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dahnutz/procsift/internal/model"
)

func TestCoverageSurvivesTextAndJSON(t *testing.T) {
	s := &model.Snapshot{MapsUnreadable: 2, MapsDenied: 1, SweepUsed: true, PIDMax: 100, SweepProbed: 4, SweepComplete: false, Coverage: []model.ReadIssue{{Source: "/proc/42/maps", State: "truncated", Detail: "limit reached"}}}
	r := Build(s, nil, Options{})
	if r.Objects.MapsUnreadable != 2 {
		t.Fatal("unreadable maps excluded")
	}
	var text strings.Builder
	if err := Write(&text, r, "text"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Collection coverage", "truncated", "4 of 99 IDs probed, complete=false"} {
		if !strings.Contains(text.String(), want) {
			t.Fatalf("missing %q in %s", want, text.String())
		}
	}
	var output strings.Builder
	if err := Write(&output, r, "json"); err != nil {
		t.Fatal(err)
	}
	var decoded model.Report
	if err := json.Unmarshal([]byte(output.String()), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Coverage) != 1 || decoded.Coverage[0].State != "truncated" || decoded.Host.SweepComplete || decoded.Host.SweepProbed != 4 {
		t.Fatalf("report %+v", decoded)
	}
}
