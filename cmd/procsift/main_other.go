//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "procsift supports Linux only. It reads /proc and /sys, which are Linux kernel interfaces.")
	os.Exit(2)
}
