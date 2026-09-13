//go:build windows && amd64

package netsetup

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func TestWindowsStatusUsesReadOnlyServiceAccess(t *testing.T) {
	identity := testIdentity()
	oldManager, oldService, oldQuery := openWindowsStatusManagerFn, openWindowsStatusServiceFn, queryWindowsStatusServiceFn
	t.Cleanup(func() {
		openWindowsStatusManagerFn = oldManager
		openWindowsStatusServiceFn = oldService
		queryWindowsStatusServiceFn = oldQuery
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
	if !strings.Contains(sddl, "(A;;LC;;;"+identity+")") {
		t.Fatalf("service ACL = %q; missing identity query-status ACE", sddl)
	}
	if strings.Contains(sddl, "(A;;CCLC") || strings.Contains(sddl, "(A;;CCDCLC") {
		t.Fatalf("service ACL grants identity broader rights: %q", sddl)
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("parse service ACL: %v", err)
	}
	if sd.String() == "" {
		t.Fatal("service ACL did not produce a valid descriptor")
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
