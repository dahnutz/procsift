package procfs

import "testing"

func TestParseStatus(t *testing.T) {
	text := "Name:\tevil bin\nState:\tS (sleeping)\nTgid:\t42\nPid:\t42\nPPid:\t7\nTracerPid:\t9\nUid:\t1000\t1000\t1000\t1000\nThreads:\t3\nVmRSS:\t     128 kB\nKthread:\t0\n"
	st, err := ParseStatus(text)
	if err != nil {
		t.Fatal(err)
	}
	if st.Name != "evil bin" || st.PID != 42 || st.TGID != 42 || st.PPID != 7 || st.TracerPID != 9 {
		t.Fatalf("%+v", st)
	}
	if st.UID != 1000 || st.Threads != 3 || st.VmRSSKiB != 128 || st.Kthread || !st.KthreadKnown {
		t.Fatalf("%+v", st)
	}
	missing, err := ParseStatus("Name:\tkthreadd\nState:\tS (sleeping)\nPid:\t2\nTgid:\t2\nPPid:\t0\n")
	if err != nil {
		t.Fatal(err)
	}
	if missing.KthreadKnown || missing.Kthread {
		t.Fatalf("absent Kthread field is unknown, not false: %+v", missing)
	}
	if _, err := ParseStatus("Name:\tnone\n"); err == nil {
		t.Fatal("expected missing pid error")
	}
}
