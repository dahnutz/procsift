package procfs

import "testing"

func TestParseMaps(t *testing.T) {
	text := "" +
		"00400000-00452000 r-xp 00000000 08:01 12345                      /usr/bin/app\n" +
		"00600000-00601000 rwxp 00000000 00:00 0 \n" +
		"7fff00000000-7fff00021000 r-xp 00000000 00:00 9                  /tmp/my file (deleted)\n" +
		"7f0000000000-7f0000001000 r-xp 00000000 00:00 1                   /memfd:payload (deleted)\n" +
		"bad line\n"
	regs := ParseMaps(text)
	if len(regs) != 4 {
		t.Fatalf("got %d regions", len(regs))
	}
	if regs[0].Path != "/usr/bin/app" || regs[0].Perms != "r-xp" || regs[0].Inode != 12345 {
		t.Fatalf("%+v", regs[0])
	}
	if regs[0].Size() != 0x52000 {
		t.Fatalf("size %x", regs[0].Size())
	}
	if regs[1].Path != "" || regs[1].Perms != "rwxp" {
		t.Fatalf("%+v", regs[1])
	}
	if regs[2].Path != "/tmp/my file (deleted)" {
		t.Fatalf("path %q", regs[2].Path)
	}
	if regs[3].Path != "/memfd:payload (deleted)" {
		t.Fatalf("path %q", regs[3].Path)
	}
}
