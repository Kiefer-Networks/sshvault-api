package main

import "os/exec"

func newShellCmd(cmdStr string) *exec.Cmd {
	return exec.Command("sh", "-c", cmdStr)
}
