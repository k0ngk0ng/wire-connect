//go:build windows && amd64

package update

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestValidateWindowsUpdateSecurityDescriptorPolicies(t *testing.T) {
	principals := testWindowsUpdatePrincipals(t)
	user := principals.user.String()

	tests := []struct {
		name       string
		sddl       string
		directory  bool
		target     bool
		elevated   bool
		ancestor   bool
		wantReject string
	}{
		{
			name:   "private user target",
			sddl:   fmt.Sprintf("O:%sG:%sD:(A;;FA;;;%s)(A;;FA;;;SY)(A;;FA;;;BA)", user, user, user),
			target: true,
		},
		{
			name:       "other user can write target",
			sddl:       fmt.Sprintf("O:%sG:%sD:(A;;FA;;;%s)(A;;FA;;;BU)(A;;FA;;;SY)", user, user, user),
			target:     true,
			wantReject: "untrusted principal",
		},
		{
			name:     "protected administrator target",
			sddl:     "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)",
			target:   true,
			elevated: true,
		},
		{
			name:       "elevated staging directory requires protected dacl",
			sddl:       "O:SYG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)",
			directory:  true,
			elevated:   true,
			wantReject: "protected DACL",
		},
		{
			name:       "elevated target requires trusted owner",
			sddl:       fmt.Sprintf("O:%sG:%sD:P(A;;FA;;;%s)(A;;FA;;;SY)(A;;FA;;;BA)", user, user, user),
			target:     true,
			elevated:   true,
			wantReject: "owned by SYSTEM or Administrators",
		},
		{
			name:      "private ancestor may be user owned",
			sddl:      fmt.Sprintf("O:%sG:%sD:(A;;FA;;;%s)(A;;FA;;;SY)", user, user, user),
			directory: true,
		},
		{
			name:       "private ancestor rejects untrusted inherited write",
			sddl:       fmt.Sprintf("O:%sG:%sD:(A;OICIIO;FA;;;BU)(A;;FA;;;%s)(A;;FA;;;SY)", user, user, user),
			directory:  true,
			wantReject: "untrusted principal",
		},
		{
			name:      "system ancestor may allow creating unrelated child",
			sddl:      "O:SYG:SYD:(A;OICIIO;CC;;;BU)(A;;FA;;;SY)(A;;FA;;;BA)",
			directory: true,
			elevated:  true,
			ancestor:  true,
		},
		{
			name:       "system ancestor cannot delete existing child",
			sddl:       "O:SYG:SYD:(A;;0x00000040;;;BU)(A;;FA;;;SY)(A;;FA;;;BA)",
			directory:  true,
			elevated:   true,
			ancestor:   true,
			wantReject: "untrusted principal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tt.sddl)
			if err != nil {
				t.Fatalf("build security descriptor: %v", err)
			}
			p := principals
			p.elevated = tt.elevated
			if tt.ancestor {
				err = validateWindowsUpdateSecurityDescriptorPolicy(sd, `C:\wire-connect\wirectl-connect.exe`, tt.directory, false, false, p)
			} else {
				err = validateWindowsUpdateSecurityDescriptor(sd, `C:\wire-connect\wirectl-connect.exe`, tt.directory, tt.target, p)
			}
			if tt.wantReject == "" {
				if err != nil {
					t.Fatalf("validate security descriptor: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantReject) {
				t.Fatalf("validation error = %v; want substring %q", err, tt.wantReject)
			}
		})
	}
}

func TestWindowsUpdateModifyMaskIncludesReplacementRights(t *testing.T) {
	for _, mask := range []windows.ACCESS_MASK{
		windows.FILE_WRITE_DATA,
		windows.FILE_WRITE_ATTRIBUTES,
		windows.DELETE,
		windows.WRITE_DAC,
		windows.WRITE_OWNER,
		windowsUpdateFileAddSubdirectory,
		windowsUpdateFileDeleteChild,
	} {
		if !windowsUpdateWriteOrReplaceMask(mask) {
			t.Fatalf("mask %#x was not classified as modifying", uint32(mask))
		}
	}
	for _, mask := range []windows.ACCESS_MASK{
		windows.FILE_READ_DATA,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_EXECUTE,
		windows.SYNCHRONIZE,
	} {
		if windowsUpdateWriteOrReplaceMask(mask) {
			t.Fatalf("mask %#x was classified as modifying", uint32(mask))
		}
	}
}

func testWindowsUpdatePrincipals(t *testing.T) windowsUpdatePrincipals {
	t.Helper()
	userInfo, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || userInfo == nil || userInfo.User.Sid == nil {
		t.Fatalf("get current user SID: %v", err)
	}
	newSID := func(kind windows.WELL_KNOWN_SID_TYPE) *windows.SID {
		sid, err := windows.CreateWellKnownSid(kind)
		if err != nil {
			t.Fatalf("create SID %d: %v", kind, err)
		}
		return sid
	}
	trusted, err := windows.StringToSid(windowsTrustedInstallerSID)
	if err != nil {
		t.Fatal(err)
	}
	return windowsUpdatePrincipals{
		user:           userInfo.User.Sid,
		system:         newSID(windows.WinLocalSystemSid),
		admins:         newSID(windows.WinBuiltinAdministratorsSid),
		creatorOwner:   newSID(windows.WinCreatorOwnerSid),
		ownerRights:    newSID(windows.WinCreatorOwnerRightsSid),
		trustedInstall: trusted,
	}
}
