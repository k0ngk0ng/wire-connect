//go:build windows

package config

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestValidateWindowsACLAllowsAdministratorAndService(t *testing.T) {
	admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.StringToSid("S-1-5-21-111111111-222222222-333333333-1001")
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}

	// An elevated administrator can open a state created by another elevated
	// administrator through the built-in Administrators ACE.
	if err := validateWindowsACL(sd, windowsPrincipals{
		user: user, system: system, admins: admin, isAdmin: true,
	}); err != nil {
		t.Fatalf("elevated administrator rejected: %v", err)
	}
	// The LocalSystem service sees the same owner and DACL and must be able to
	// read and replace profiles created by an administrator.
	if err := validateWindowsACL(sd, windowsPrincipals{
		user: system, system: system, admins: admin,
	}); err != nil {
		t.Fatalf("LocalSystem rejected: %v", err)
	}
}

func TestValidateWindowsACLRejectsBroadACE(t *testing.T) {
	admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.StringToSid("S-1-5-21-111111111-222222222-333333333-1001")
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsACL(sd, windowsPrincipals{
		user: user, system: system, admins: admin, isAdmin: true,
	}); err == nil {
		t.Fatal("accepted a DACL containing Everyone")
	}
}
