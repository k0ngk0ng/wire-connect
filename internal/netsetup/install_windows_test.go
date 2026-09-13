//go:build windows && amd64

package netsetup

import (
	"context"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func TestWindowsStatusUsesReadOnlyServiceAccess(t *testing.T) {
	identity := testIdentity()
	oldManager, oldService, oldQuery := openWindowsStatusManagerFn, openWindowsStatusServiceFn, queryWindowsStatusServiceFn
	oldCloseManager, oldCloseService := closeWindowsStatusManagerFn, closeWindowsStatusServiceFn
	t.Cleanup(func() {
		openWindowsStatusManagerFn = oldManager
		openWindowsStatusServiceFn = oldService
		queryWindowsStatusServiceFn = oldQuery
		closeWindowsStatusManagerFn = oldCloseManager
		closeWindowsStatusServiceFn = oldCloseService
	})

	var managerAccess, serviceAccess uint32
	openWindowsStatusManagerFn = func(access uint32) (windows.Handle, error) {
		managerAccess = access
		return windows.InvalidHandle, nil
	}
	openWindowsStatusServiceFn = func(manager windows.Handle, name *uint16, access uint32) (windows.Handle, error) {
		if manager != windows.InvalidHandle {
			t.Fatalf("service opened with manager handle %#x; want %#x", manager, windows.InvalidHandle)
		}
		if windows.UTF16PtrToString(name) != windowsNativeHelperServiceName(HelperName(identity)) {
			t.Fatalf("service name = %q", windows.UTF16PtrToString(name))
		}
		serviceAccess = access
		return windows.InvalidHandle, nil
	}
	queryWindowsStatusServiceFn = func(service *mgr.Service) (svc.Status, error) {
		return svc.Status{State: svc.Running}, nil
	}
	closeWindowsStatusManagerFn = func(*mgr.Mgr) error { return nil }
	closeWindowsStatusServiceFn = func(*mgr.Service) error { return nil }

	got, err := statusPlatform(context.Background(), identity)
	if err != nil {
		t.Fatalf("statusPlatform: %v", err)
	}
	if got != "running" {
		t.Fatalf("status = %q; want running", got)
	}
	if managerAccess != windows.SC_MANAGER_CONNECT {
		t.Fatalf("SCM access = %#x; want %#x", managerAccess, uint32(windows.SC_MANAGER_CONNECT))
	}
	if serviceAccess != windows.SERVICE_QUERY_STATUS {
		t.Fatalf("service access = %#x; want %#x", serviceAccess, uint32(windows.SERVICE_QUERY_STATUS))
	}
}

func TestWindowsHelperServiceSDDLGrantsIdentityQueryOnly(t *testing.T) {
	identity := testIdentity()
	sddl, err := windowsHelperServiceSDDL(identity)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("parse service ACL: %v", err)
	}
	if sd.String() == "" {
		t.Fatal("service ACL did not produce a valid descriptor")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("read service ACL: %v", err)
	}
	var identityACE int
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatalf("read service ACL entry %d: %v", i, err)
		}
		header := (*windows.ACE_HEADER)(unsafe.Pointer(ace))
		if header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.String() != identity {
			continue
		}
		identityACE++
		if uint32(ace.Mask) != windows.SERVICE_QUERY_STATUS {
			t.Fatalf("identity service mask = %#x; want SERVICE_QUERY_STATUS (%#x)", uint32(ace.Mask), uint32(windows.SERVICE_QUERY_STATUS))
		}
	}
	if identityACE != 1 {
		t.Fatalf("identity query-status ACE count = %d; want 1", identityACE)
	}
}

func TestWindowsHelperServiceSDDLRejectsNonCanonicalIdentity(t *testing.T) {
	identity := testIdentity()
	if _, err := windowsHelperServiceSDDL(strings.ToLower(identity)); err == nil {
		t.Fatal("lowercase SID accepted")
	}
	if _, err := windowsHelperServiceSDDL(identity + ";"); err == nil {
		t.Fatal("SDDL injection input accepted")
	}
	if _, err := windowsHelperServiceSDDL(""); err == nil {
		t.Fatal("empty identity accepted")
	}
}
