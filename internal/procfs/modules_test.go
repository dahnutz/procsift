package procfs

import "testing"

func TestParseModules(t *testing.T) {
	text := "nvidia 54321 2 drm,foo Live 0xffffffffc0ab0000 (POE)\n" +
		"snd 16384 0 - Live 0xffffffffc1234000\n" +
		"short line\n"
	mods := ParseModules(text)
	if len(mods) != 2 {
		t.Fatalf("%d mods", len(mods))
	}
	if mods[0].Name != "nvidia" || mods[0].Size != 54321 || mods[0].Refcnt != 2 || mods[0].Taints != "POE" || mods[0].State != "Live" {
		t.Fatalf("%+v", mods[0])
	}
	if mods[1].Taints != "" || mods[1].Address != "0xffffffffc1234000" {
		t.Fatalf("%+v", mods[1])
	}
}
