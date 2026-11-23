//go:build darwin

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
		cred, e := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		ok = e == nil && cred.Uid == uint32(os.Getuid())
	})
	return err == nil && ok
}

func renameNew(src, dst string) error { return unix.RenamexNp(src, dst, unix.RENAME_EXCL) }
