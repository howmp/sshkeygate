//go:build ignore

// Command machoinfo reports the architectures of a Mach-O file and the
// deployment target each slice was linked for.
//
// The deployment target is the minimum macOS version dyld accepts: a binary
// linked for 13.0 refuses to start on 11.x, whatever its Info.plist says.
// The value is read from the load commands, which debug/macho does not
// expose for LC_BUILD_VERSION.
//
//	go run tools/machoinfo/main.go <path-to-binary>
package main

import (
	"fmt"
	"os"
)

const (
	// Load commands that carry the deployment target.
	lcBuildVersion     = 0x32
	lcVersionMinMacOSX = 0x24

	// Fat headers use big-endian fields; a thin file's own header uses its
	// byte order, which these fields name.
	fatMagic    = 0xCAFEBABE
	fatMagic64  = 0xCAFEBABF
	machMagic64 = 0xFEEDFACF
	machCigam64 = 0xCFFAEDFE
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: machoinfo <binary>")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	if len(data) < 32 {
		fmt.Fprintln(os.Stderr, "not a Mach-O file")
		os.Exit(1)
	}

	magic := be32(data, 0)
	if magic == fatMagic || magic == fatMagic64 {
		count := be32(data, 4)
		entrySize := 20
		if magic == fatMagic64 {
			entrySize = 32
		}
		for i := uint32(0); i < count; i++ {
			entry := 8 + int(i)*entrySize
			cpu := be32(data, entry)
			off := be32(data, entry+8)
			if int(off) >= len(data) {
				continue
			}
			report(data[off:], cpu)
		}
		return
	}
	report(data, le32(data, 4))
}

// report prints one slice's architecture and deployment target.
func report(slice []byte, cpu uint32) {
	fmt.Printf("%-7s", cpuName(cpu))
	if target := deploymentTarget(slice); target != "" {
		fmt.Println(" " + target)
		return
	}
	fmt.Println(" (no deployment target)")
}

// deploymentTarget reads the load commands of a thin Mach-O slice.
func deploymentTarget(slice []byte) string {
	if len(slice) < 32 {
		return ""
	}
	// Apple's 64-bit Mach-O files are little-endian on both architectures.
	if be32(slice, 0) != machCigam64 && le32(slice, 0) != machMagic64 {
		return ""
	}
	ncmds := le32(slice, 16)
	off := 32
	for i := uint32(0); i < ncmds; i++ {
		if off+8 > len(slice) {
			return ""
		}
		cmd := le32(slice, off)
		size := le32(slice, off+4)
		switch cmd {
		case lcBuildVersion:
			if off+24 > len(slice) {
				return ""
			}
			if platform := le32(slice, off+8); platform != 1 { // 1 is macOS
				continue
			}
			return fmt.Sprintf("minos=%s sdk=%s",
				version(le32(slice, off+12)), version(le32(slice, off+16)))
		case lcVersionMinMacOSX:
			if off+16 > len(slice) {
				return ""
			}
			return fmt.Sprintf("minos=%s sdk=%s (LC_VERSION_MIN_MACOSX)",
				version(le32(slice, off+8)), version(le32(slice, off+12)))
		}
		if size < 8 {
			return ""
		}
		off += int(size)
	}
	return ""
}

func cpuName(cpu uint32) string {
	switch cpu {
	case 0x0100000C:
		return "arm64"
	case 0x01000007:
		return "x86_64"
	}
	return fmt.Sprintf("cpu=0x%X", cpu)
}

func be32(b []byte, o int) uint32 {
	if o+4 > len(b) {
		return 0
	}
	return uint32(b[o])<<24 | uint32(b[o+1])<<16 | uint32(b[o+2])<<8 | uint32(b[o+3])
}

func le32(b []byte, o int) uint32 {
	if o+4 > len(b) {
		return 0
	}
	return uint32(b[o]) | uint32(b[o+1])<<8 | uint32(b[o+2])<<16 | uint32(b[o+3])<<24
}

func version(v uint32) string {
	return fmt.Sprintf("%d.%d", v>>16, (v>>8)&0xff)
}
