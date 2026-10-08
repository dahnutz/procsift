package procfs

import "testing"

func TestParseSysVSHM(t *testing.T) {
	text := "       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap\n" +
		"         0          6  1600                524288  2227  2095      2  1000  1000  1000  1000 1791375902          0 1791375902                  8192                     0\n" +
		"        -1          9   777                    4096     1     1      0     0     0     0     0          0          0          0                     0                     0\n"
	rows := ParseSysVSHM(text)
	if len(rows) != 2 {
		t.Fatalf("%d", len(rows))
	}
	if rows[0].ID != 6 || rows[0].Size != 524288 || rows[0].Nattch != 2 {
		t.Fatalf("%+v", rows[0])
	}
	// 1600 octal is sticky plus owner read/write, not execute.
	if rows[0].Perms&0111 != 0 {
		t.Fatalf("perms %#o", rows[0].Perms)
	}
	if rows[1].Perms&0111 == 0 || rows[1].Nattch != 0 || rows[1].Key != -1 {
		t.Fatalf("%+v", rows[1])
	}
}
