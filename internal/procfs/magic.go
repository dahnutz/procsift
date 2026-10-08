package procfs

// ClassifyMagic identifies an object header at the start of a mapping.
// Only ELF, PE (MZ), and script shebangs are recognized. The bytes themselves
// are not returned to callers of the scanner.
func ClassifyMagic(b []byte) string {
	if len(b) >= 4 && b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F' {
		return "elf"
	}
	if len(b) >= 2 && b[0] == 'M' && b[1] == 'Z' {
		return "mz"
	}
	if len(b) >= 2 && b[0] == '#' && b[1] == '!' {
		return "shebang"
	}
	return ""
}
