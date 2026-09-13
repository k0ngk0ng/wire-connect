//go:build windows

package nethelper

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/go-winio"
	"golang.org/x/sys/windows"
)

func TestPipeSecurityDescriptorUsesMinimalClientRights(t *testing.T) {
	sid, err := currentSID()
	if err != nil {
		t.Fatal(err)
	}
	sddl := pipeSecurityDescriptor(sid)
	if strings.Contains(sddl, "GA;;;"+sid) {
		t.Fatalf("pipe security descriptor grants generic all to client: %q", sddl)
	}
	if !strings.Contains(sddl, pipeClientRights+";;;"+sid) {
		t.Fatalf("pipe security descriptor does not grant client read/write rights: %q", sddl)
	}
	if _, err := windows.SecurityDescriptorFromString(sddl); err != nil {
		t.Fatalf("pipe security descriptor is invalid SDDL: %v", err)
	}
}

func TestAuthenticateUsesConnectedPipeClientSID(t *testing.T) {
	sid, err := currentSID()
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf(`\\.\pipe\wire-connect-nethelper-test-%d-%d`, windows.GetCurrentProcessId(), time.Now().UnixNano())
	listener, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: pipeSecurityDescriptor(sid)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientResult := make(chan struct {
		conn net.Conn
		err  error
	}, 1)
	go func() {
		conn, err := winio.DialPipeContext(ctx, name)
		clientResult <- struct {
			conn net.Conn
			err  error
		}{conn: conn, err: err}
	}()

	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	client := <-clientResult
	if client.err != nil {
		t.Fatal(client.err)
	}
	defer client.conn.Close()

	if err := authenticate(serverConn, sid); err != nil {
		t.Fatalf("authenticate current client: %v", err)
	}
	wantWrongSID := "S-1-5-18"
	if sid == wantWrongSID {
		wantWrongSID = "S-1-5-19"
	}
	if err := authenticate(serverConn, wantWrongSID); err == nil {
		t.Fatal("authenticate accepted a mismatched expected SID")
	}
}

func TestPipeHandleSecurityInfoUsesFileObject(t *testing.T) {
	sid, err := currentSID()
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf(`\\.\pipe\wire-connect-nethelper-security-%d-%d`, windows.GetCurrentProcessId(), time.Now().UnixNano())
	listener, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: pipeSecurityDescriptor(sid)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientResult := make(chan struct {
		conn net.Conn
		err  error
	}, 1)
	go func() {
		conn, err := winio.DialPipeContext(ctx, name)
		clientResult <- struct {
			conn net.Conn
			err  error
		}{conn: conn, err: err}
	}()
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	client := <-clientResult
	if client.err != nil {
		t.Fatal(client.err)
	}
	defer client.conn.Close()
	f, ok := serverConn.(interface{ Fd() uintptr })
	if !ok {
		t.Fatal("accepted pipe has no inspectable handle")
	}
	if _, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION); err != nil {
		t.Fatalf("GetSecurityInfo(SE_FILE_OBJECT): %v", err)
	}
}
