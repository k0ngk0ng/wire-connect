//go:build windows

package config

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// protect is used only for objects created by this package. Existing state
// directories and files are inspected by checkPrivate/checkPrivateDir and are
// never rewritten merely because a caller opened the store.
func protect(path string, dir bool) error {
	principals, err := currentWindowsPrincipals()
	if err != nil {
		return err
	}
	inherit := ""
	if dir {
		inherit = "OICI"
	}
	// An elevated administrator (and LocalSystem, which creates state on
	// behalf of an installed service) gets the same BA+SY policy used by the
	// service installer. This lets an administrator-created profile be opened
	// by the LocalSystem service without relying on the creator's user SID.
	// A non-administrator keeps a user+SY policy so that a user-owned state
	// directory remains usable by its owner.
	adminPolicy := principals.isAdmin || sameWindowsSID(principals.user, principals.system)
	sddl := "D:P(A;" + inherit + ";FA;;;" + principals.user.String() + ")(A;" + inherit + ";FA;;;SY)"
	securityInfo := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	var owner *windows.SID
	if adminPolicy {
		sddl = "O:BAG:BAD:P(A;" + inherit + ";FA;;;BA)(A;" + inherit + ";FA;;;SY)"
		securityInfo |= windows.OWNER_SECURITY_INFORMATION
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if adminPolicy {
		owner, _, err = sd.Owner()
		if err != nil || owner == nil {
			if err == nil {
				err = errors.New("descriptor has no administrator owner")
			}
			return err
		}
	}
	access := uint32(windows.READ_CONTROL | windows.WRITE_DAC | windows.FILE_READ_ATTRIBUTES)
	if adminPolicy {
		access |= windows.WRITE_OWNER
	}
	h, err := openStateObject(path, dir, access)
	if err != nil {
		return err
	}
	defer windows.Close(h)
	return windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT,
		securityInfo, owner, nil, dacl, nil)
}

func checkPrivateDir(path string, _ os.FileInfo) error {
	if err := checkWindowsACL(path, true); err != nil {
		return fmt.Errorf("state directory %q is not private: %w", path, err)
	}
	return nil
}

func checkPrivate(path string, _ os.FileInfo) error {
	if err := checkWindowsACL(path, false); err != nil {
		return fmt.Errorf("state file %q is not private: %w", path, err)
	}
	return nil
}

func syncDir(string) error { return nil }

// replaceFile uses the Windows atomic replacement primitive. os.Rename does
// not replace an existing file on all supported Windows versions.
func replaceFile(oldPath, newPath string) error {
	oldName, err := windows.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	newName, err := windows.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(oldName, newName, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

type windowsPrincipals struct {
	user    *windows.SID
	system  *windows.SID
	admins  *windows.SID
	isAdmin bool
}

func currentWindowsPrincipals() (windowsPrincipals, error) {
	processToken := windows.GetCurrentProcessToken()
	userInfo, err := processToken.GetTokenUser()
	if err != nil || userInfo == nil || userInfo.User.Sid == nil {
		if err == nil {
			err = errors.New("token has no user SID")
		}
		return windowsPrincipals{}, fmt.Errorf("get current Windows user SID: %w", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return windowsPrincipals{}, fmt.Errorf("create LocalSystem SID: %w", err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return windowsPrincipals{}, fmt.Errorf("create Administrators SID: %w", err)
	}
	// CheckTokenMembership expects a token handle or NULL. Passing the
	// process pseudo-handle returned by GetCurrentProcessToken can fail with
	// ERROR_NO_IMPERSONATION_TOKEN on some Windows versions; a zero token asks
	// Windows to evaluate the effective thread/process token directly.
	isAdmin, err := windows.Token(0).IsMember(admins)
	if err != nil {
		return windowsPrincipals{}, fmt.Errorf("check Administrators membership: %w", err)
	}
	return windowsPrincipals{user: userInfo.User.Sid, system: system, admins: admins, isAdmin: isAdmin}, nil
}

func openStateObject(path string, dir bool, access uint32) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if dir {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	h, err := windows.CreateFile(name, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return windows.InvalidHandle, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		_ = windows.Close(h)
		return windows.InvalidHandle, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.Close(h)
		return windows.InvalidHandle, errors.New("path is a reparse point")
	}
	if dir && info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		_ = windows.Close(h)
		return windows.InvalidHandle, errors.New("path is not a directory")
	}
	if !dir && info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		_ = windows.Close(h)
		return windows.InvalidHandle, errors.New("path is a directory")
	}
	return h, nil
}

func checkWindowsACL(path string, dir bool) error {
	principals, err := currentWindowsPrincipals()
	if err != nil {
		return err
	}
	h, err := openStateObject(path, dir, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return err
	}
	defer windows.Close(h)
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read security descriptor: %w", err)
	}
	if sd == nil {
		return errors.New("object has no security descriptor")
	}
	return validateWindowsACL(sd, principals)
}

func validateWindowsACL(sd *windows.SECURITY_DESCRIPTOR, principals windowsPrincipals) error {
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		if err == nil {
			err = errors.New("descriptor has no owner")
		}
		return err
	}
	if !sameWindowsSID(owner, principals.user) && !sameWindowsSID(owner, principals.system) && !sameWindowsSID(owner, principals.admins) {
		return errors.New("owner is neither the current user, LocalSystem, nor Administrators")
	}
	control, _, err := sd.Control()
	if err != nil {
		return fmt.Errorf("read security descriptor control: %w", err)
	}
	if control&windows.SE_DACL_PRESENT == 0 {
		return errors.New("descriptor has no DACL")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		if err == nil {
			err = errors.New("descriptor has an empty or missing DACL")
		}
		return err
	}

	userID := principals.user.String()
	systemID := principals.system.String()
	adminID := principals.admins.String()
	const required = uint32(windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE)
	grants := make(map[string]uint32, 3)
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil {
			if err == nil {
				err = errors.New("missing ACE")
			}
			return fmt.Errorf("read DACL ACE %d: %w", i, err)
		}
		header := (*windows.ACE_HEADER)(unsafe.Pointer(ace))
		if header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("DACL ACE %d is not an allow ACE", i)
		}
		// An inherit-only ACE does not grant this object access. It is still
		// allowed for one of the trusted principals, but does not satisfy the
		// read/write requirement below.
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() {
			return fmt.Errorf("DACL ACE %d contains an invalid SID", i)
		}
		id := sid.String()
		if id != userID && id != systemID && id != adminID {
			return fmt.Errorf("DACL ACE %d grants access to an untrusted SID %s", i, id)
		}
		if header.AceFlags&windows.INHERIT_ONLY_ACE == 0 {
			grants[id] |= uint32(ace.Mask)
		}
	}
	if grants[systemID]&required != required {
		return errors.New("LocalSystem lacks read/write access")
	}
	if grants[userID]&required != required {
		if !principals.isAdmin || grants[adminID]&required != required {
			return errors.New("current user lacks read/write access")
		}
	}
	// An Administrators ACE is optional for a user-owned profile, but when it
	// exists it must not be a partial grant that creates an ambiguous policy.
	if grants[adminID] != 0 && grants[adminID]&required != required {
		return errors.New("Administrators lacks complete read/write access")
	}
	return nil
}

func sameWindowsSID(a, b *windows.SID) bool {
	return a != nil && b != nil && a.Equals(b)
}
