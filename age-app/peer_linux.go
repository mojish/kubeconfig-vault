//go:build linux

package main

import (
	"golang.org/x/sys/unix"
	"net"
	"os"
)

func samePeer(c *net.UnixConn) bool {
	r, err := c.SyscallConn()
	if err != nil {
		return false
	}
	ok := false
	err = r.Control(func(fd uintptr) {
		cred, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		ok = e == nil && cred.Uid == uint32(os.Getuid())
	})
	return err == nil && ok
}

func renameNew(src, dst string) error {
	return unix.Renameat2(unix.AT_FDCWD, src, unix.AT_FDCWD, dst, unix.RENAME_NOREPLACE)
}
