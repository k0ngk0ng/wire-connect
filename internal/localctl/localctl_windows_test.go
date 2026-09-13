//go:build windows

package localctl

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsExistingDirectoryACLIsNotRewritten(t *testing.T) {
	dir := testDirectory(t)
	before, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	beforeSDDL := before.String()
	if _, err := validateDirectory(dir); err != nil {
		t.Fatal(err)
	}
	after, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if got := after.String(); got != beforeSDDL {
		t.Fatalf("directory ACL changed during validation: before=%q after=%q", beforeSDDL, got)
	}
}

func TestWindowsPipeSecurityDescriptorPolicy(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if user == nil || user.User.Sid == nil {
		t.Fatal("current token has no user SID")
	}
	got := pipeSecurityDescriptorFor(user.User.Sid)
	if _, err := windows.SecurityDescriptorFromString(got); err != nil {
		t.Fatalf("foreground pipe SDDL is invalid: %q: %v", got, err)
	}
	if !strings.Contains(got, ";;;SY)") {
		t.Fatalf("foreground pipe SDDL does not grant SYSTEM: %q", got)
	}
	if user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		if got != "D:P(A;;GA;;;BA)(A;;GA;;;SY)" {
			t.Fatalf("SYSTEM pipe SDDL = %q", got)
		}
		return
	}
	if !strings.Contains(got, ";;;"+user.User.Sid.String()+")") {
		t.Fatalf("foreground pipe SDDL does not grant current user: %q", got)
	}
	if strings.Contains(got, ";;;BA)") {
		t.Fatalf("foreground pipe SDDL unexpectedly grants Administrators: %q", got)
	}
}

func TestWindowsSystemPipeSecurityDescriptorGrantsAdministrators(t *testing.T) {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	got := pipeSecurityDescriptorFor(system)
	if got != "D:P(A;;GA;;;BA)(A;;GA;;;SY)" {
		t.Fatalf("SYSTEM pipe SDDL = %q, want administrator and SYSTEM grants", got)
	}
	if _, err := windows.SecurityDescriptorFromString(got); err != nil {
		t.Fatalf("SYSTEM pipe SDDL is invalid: %v", err)
	}
}
