//go:build ignore

// A stand-in for the system SSH agent: it holds the agent pipe so the app's
// conflict detection can be checked by hand.
package main

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows"
)

func main() {
	name, _ := windows.UTF16PtrFromString(`\\.\pipe\openssh-ssh-agent`)
	h, err := windows.CreateNamedPipe(name,
		windows.PIPE_ACCESS_DUPLEX,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT,
		windows.PIPE_UNLIMITED_INSTANCES, 64*1024, 64*1024, 0, nil)
	if err != nil {
		fmt.Println("create:", err)
		return
	}
	fmt.Println("holding the agent pipe; ctrl-c to stop")
	for {
		if err := windows.ConnectNamedPipe(h, nil); err != nil && err != windows.ERROR_PIPE_CONNECTED {
			fmt.Println("connect:", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
