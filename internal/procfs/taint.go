package procfs

import "fmt"

// taintNames follows include/linux/panic.h. Bits the table does not name are
// reported as bit-N so a newer kernel still shows up in the report.
var taintNames = []string{
	"proprietary-module",
	"forced-module",
	"cpu-out-of-spec",
	"forced-unload",
	"machine-check",
	"bad-page",
	"userspace-taint",
	"died-recently",
	"acpi-overridden",
	"warning",
	"staging-module",
	"firmware-workaround",
	"out-of-tree-module",
	"unsigned-module",
	"soft-lockup",
	"live-patch",
	"auxiliary",
	"randstruct",
}

// TaintFlags decodes /proc/sys/kernel/tainted.
func TaintFlags(mask uint64) []string {
	var out []string
	for i, name := range taintNames {
		if mask&(1<<uint(i)) != 0 {
			out = append(out, name)
		}
	}
	for i := len(taintNames); i < 64; i++ {
		if mask&(1<<uint(i)) != 0 {
			out = append(out, fmt.Sprintf("bit-%d", i))
		}
	}
	return out
}
