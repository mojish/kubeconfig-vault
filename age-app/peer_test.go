package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Exercise each OS's real peer-credential syscall in both IPC directions.
// Keep the temporary name short enough for macOS Unix socket paths.
func TestSamePeerOnNativeSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "kua-peer-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	addr := &net.UnixAddr{Name: filepath.Join(dir, "peer.sock"), Net: "unix"}
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("unix", addr.Name, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client := conn.(*net.UnixConn)
	t.Cleanup(func() { _ = client.Close() })
	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	for name, conn := range map[string]*net.UnixConn{"client": client, "server": server} {
		t.Run(name, func(t *testing.T) {
			if !samePeer(conn) {
				t.Fatal("same-user peer rejected by native credential lookup")
			}
		})
	}
	for name, conn := range map[string]*net.UnixConn{"client": client, "server": server} {
		t.Run(name+"-closed", func(t *testing.T) {
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			if samePeer(conn) {
				t.Fatal("closed socket accepted after credential lookup failed")
			}
		})
	}
}
