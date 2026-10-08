package procfs

import "testing"

func TestParseNetIPv4(t *testing.T) {
	text := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4242 1 00000000 100 0 0 10 0\n" +
		"   1: 0100A8C0:0050 0200A8C0:01BB 01 00000000:00000000 00:00000000 00000000     0        0 7777 1 00000000 100 0 0 10 0\n"
	rows := ParseNet("tcp", text)
	if len(rows) != 2 {
		t.Fatalf("%d rows", len(rows))
	}
	if rows[0].Local != "127.0.0.1:8080" || rows[0].State != "LISTEN" || rows[0].Inode != 4242 || rows[0].UID != 1000 {
		t.Fatalf("%+v", rows[0])
	}
	if rows[1].Local != "192.168.0.1:80" || rows[1].Remote != "192.168.0.2:443" || rows[1].State != "ESTABLISHED" || rows[1].Inode != 7777 {
		t.Fatalf("%+v", rows[1])
	}
}

func TestDecodeIPv6Loopback(t *testing.T) {
	text := "   0: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 9 1 0 100 0 0 10 0\n"
	rows := ParseNet("tcp6", text)
	if len(rows) != 1 {
		t.Fatal(len(rows))
	}
	if rows[0].Local != "::1:80" {
		t.Fatalf("local %q", rows[0].Local)
	}
}
