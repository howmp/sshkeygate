//go:build ignore

// Command mksyso turns a Mach-O object file into a Go .syso, an archive
// holding one member, which the Go build links into a package.
//
// The Go toolchain reads .syso files as ar archives whose members are the
// object files of each architecture; a member named __.PKGDEF or _.a is
// skipped. A universal object, which lipo produced, is one member here, and
// the linker picks its slice.
//
//	go run tools/sectrustcompat/mksyso.go <input.o> <output.syso>
package main

import (
	"debug/macho"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: mksyso <input.o> <output.syso>")
		os.Exit(2)
	}
	object, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	if _, err := macho.Open(os.Args[1]); err != nil {
		if _, ferr := macho.OpenFat(os.Args[1]); ferr != nil {
			fmt.Fprintf(os.Stderr, "%s is not a Mach-O object: %v\n", os.Args[1], err)
			os.Exit(1)
		}
	}
	if err := os.WriteFile(os.Args[2], archive(object), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%d bytes)\n", filepath.Base(os.Args[2]), len(archive(object)))
}

// archive wraps object in an ar archive with one member.
func archive(object []byte) []byte {
	member := objName()
	header := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8s%-10d`\n",
		member, 0, 0, 0, "100644", len(object))
	out := []byte("!<arch>\n")
	out = append(out, header...)
	out = append(out, object...)
	if len(object)%2 == 1 {
		out = append(out, '\n') // members are padded to an even length
	}
	return out
}

// objName is the member's name, which the Go linker reads as the object.
func objName() string { return "sectrust_compat.o/" }
