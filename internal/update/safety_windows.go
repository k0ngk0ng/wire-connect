//go:build windows

package update

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// validateUpdateDestinationSecurity verifies every object which can affect a
// Windows update destination. The updater stages the image beside the current
// executable and then replaces the destination by name. A path check which
// follows reparse points, or only checks the final file, would let a different
// user redirect or modify that handoff between verification and replacement.
//
// A non-elevated process may update a destination owned by its current user.
// SYSTEM and Administrators remain trusted principals because they cannot be
// used by an unprivileged user to race the update. An elevated process has a
// stronger boundary: the destination and its staging parent must be owned by
// SYSTEM or the built-in Administrators group, with a protected staging DACL;
// higher ancestors may be system-owned inherited paths as long as they cannot
// remove or replace an existing component.
func validateUpdateDestinationSecurity(path string) error {
	if path == "" {
		return errors.New("wire-connect: update destination is empty")
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("wire-connect: update destination %q must be absolute", path)
	}
	path = filepath.Clean(path)

	principals, err := currentWindowsUpdatePrincipals()
	if err != nil {
		return err
	}

	// The running executable normally exists. Keep the missing-file case safe
	// as well: the parent chain is still checked, and the caller can decide
	// whether creating the target is otherwise valid.
	exists := true
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		exists = false
	} else if err != nil {
		return fmt.Errorf("wire-connect: inspect update destination %q: %w", path, err)
	} else if st.IsDir() {
		return fmt.Errorf("wire-connect: update destination %q must be a regular file", path)
	}

	if exists {
		if err := validateWindowsUpdateObject(path, false, true, true, principals); err != nil {
			return err
		}
	}

	// Check the parent and every ancestor independently. The immediate parent
	// is also the directory in which the updater creates its staging files, so
	// no untrusted write permission is safe there. Higher ancestors only need
	// to be unable to remove/replace an already-existing path component; the
	// ability to create an unrelated child is harmless and is common on Windows
	// system roots.
	stagingParent := filepath.Dir(path)
	for current := stagingParent; ; current = filepath.Dir(current) {
		strict := current == stagingParent
		if err := validateWindowsUpdateObject(current, true, false, strict, principals); err != nil {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return nil
}

type windowsUpdatePrincipals struct {
	user           *windows.SID
	system         *windows.SID
	admins         *windows.SID
	creatorOwner   *windows.SID
	ownerRights    *windows.SID
	trustedInstall *windows.SID
	elevated       bool
}

func currentWindowsUpdatePrincipals() (windowsUpdatePrincipals, error) {
	token := windows.GetCurrentProcessToken()
	userInfo, err := token.GetTokenUser()
	if err != nil {
		return windowsUpdatePrincipals{}, fmt.Errorf("wire-connect: get current Windows user SID: %w", err)
	}
	if userInfo == nil || userInfo.User.Sid == nil {
		return windowsUpdatePrincipals{}, errors.New("wire-connect: current Windows token has no user SID")
	}

	newSID := func(kind windows.WELL_KNOWN_SID_TYPE) (*windows.SID, error) {
		sid, err := windows.CreateWellKnownSid(kind)
		if err != nil {
			return nil, err
		}
		return sid, nil
	}
	system, err := newSID(windows.WinLocalSystemSid)
	if err != nil {
		return windowsUpdatePrincipals{}, fmt.Errorf("wire-connect: create SYSTEM SID: %w", err)
	}
	admins, err := newSID(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return windowsUpdatePrincipals{}, fmt.Errorf("wire-connect: create Administrators SID: %w", err)
	}
	creatorOwner, err := newSID(windows.WinCreatorOwnerSid)
	if err != nil {
		return windowsUpdatePrincipals{}, fmt.Errorf("wire-connect: create Creator Owner SID: %w", err)
	}
	ownerRights, err := newSID(windows.WinCreatorOwnerRightsSid)
	if err != nil {
		return windowsUpdatePrincipals{}, fmt.Errorf("wire-connect: create Owner Rights SID: %w", err)
	}
	// The Windows volume and system directories are commonly owned by the
	// TrustedInstaller service. It is a protected OS principal, rather than a
	// user which can race an unelevated update.
	trustedInstall, err := windows.StringToSid(windowsTrustedInstallerSID)
	if err != nil {
		return windowsUpdatePrincipals{}, fmt.Errorf("wire-connect: create TrustedInstaller SID: %w", err)
	}

	return windowsUpdatePrincipals{
		user:           userInfo.User.Sid,
		system:         system,
		admins:         admins,
		creatorOwner:   creatorOwner,
		ownerRights:    ownerRights,
		trustedInstall: trustedInstall,
		elevated:       token.IsElevated(),
	}, nil
}

const windowsTrustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

func validateWindowsUpdateObject(path string, directory, target, strict bool, principals windowsUpdatePrincipals) error {
	h, attrs, err := openWindowsUpdateObject(path)
	if err != nil {
		return fmt.Errorf("wire-connect: inspect update path %q: %w", path, err)
	}
	defer windows.Close(h)

	isDirectory := attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if isDirectory != directory {
		if directory {
			return fmt.Errorf("wire-connect: update ancestor %q is not a directory", path)
		}
		return fmt.Errorf("wire-connect: update destination %q must be a regular file", path)
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("wire-connect: update path %q is a reparse point", path)
	}

	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("wire-connect: inspect ACL for update path %q: %w", path, err)
	}
	if sd == nil {
		return fmt.Errorf("wire-connect: update path %q has no security descriptor", path)
	}
	return validateWindowsUpdateSecurityDescriptorPolicy(sd, path, directory, target, strict, principals)
}

func openWindowsUpdateObject(path string) (windows.Handle, uint32, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, 0, err
	}
	// OPEN_REPARSE_POINT prevents the final path component from being
	// followed. BACKUP_SEMANTICS is required when the component is a directory
	// and is harmless for a regular file.
	h, err := windows.CreateFile(name,
		windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0)
	if err != nil {
		return windows.InvalidHandle, 0, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		_ = windows.Close(h)
		return windows.InvalidHandle, 0, err
	}
	return h, info.FileAttributes, nil
}

// validateWindowsUpdateSecurityDescriptor retains the strict policy used by
// the target and its staging directory. The policy-aware form is used for
// higher ancestors, where ordinary create-child permissions do not redirect
// an existing path.
func validateWindowsUpdateSecurityDescriptor(sd *windows.SECURITY_DESCRIPTOR, path string, directory, target bool, principals windowsUpdatePrincipals) error {
	return validateWindowsUpdateSecurityDescriptorPolicy(sd, path, directory, target, true, principals)
}

func validateWindowsUpdateSecurityDescriptorPolicy(sd *windows.SECURITY_DESCRIPTOR, path string, directory, target, strict bool, principals windowsUpdatePrincipals) error {
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		if err == nil {
			err = errors.New("descriptor has no owner")
		}
		return fmt.Errorf("wire-connect: inspect owner for update path %q: %w", path, err)
	}

	if principals.elevated {
		if strict || target {
			if !sameWindowsUpdateSID(owner, principals.system) && !sameWindowsUpdateSID(owner, principals.admins) {
				return fmt.Errorf("wire-connect: elevated update path %q must be owned by SYSTEM or Administrators", path)
			}
		} else if !windowsUpdateTrustedSystemOwner(owner, principals) {
			return fmt.Errorf("wire-connect: elevated update ancestor %q has an untrusted owner", path)
		}
	} else if target {
		if !sameWindowsUpdateSID(owner, principals.user) {
			return fmt.Errorf("wire-connect: update destination %q must be owned by the current user", path)
		}
	} else if !windowsUpdateTrustedAncestorOwner(owner, principals) {
		return fmt.Errorf("wire-connect: update ancestor %q has an untrusted owner", path)
	}

	control, _, err := sd.Control()
	if err != nil {
		return fmt.Errorf("wire-connect: inspect ACL control for update path %q: %w", path, err)
	}
	if control&windows.SE_DACL_PRESENT == 0 {
		return fmt.Errorf("wire-connect: update path %q has no DACL", path)
	}
	if principals.elevated && strict && directory && control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("wire-connect: elevated update path %q must have a protected DACL", path)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		if err == nil {
			err = errors.New("descriptor has an empty DACL")
		}
		return fmt.Errorf("wire-connect: inspect ACL for update path %q: %w", path, err)
	}

	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("wire-connect: read ACL entry %d for update path %q: %w", i, path, err)
		}
		if ace == nil {
			return fmt.Errorf("wire-connect: ACL entry %d for update path %q is empty", i, path)
		}
		allow, mask, sid, inheritOnly, err := decodeWindowsUpdateACE(ace)
		if err != nil {
			return fmt.Errorf("wire-connect: read ACL entry %d for update path %q: %w", i, path, err)
		}
		if !allow {
			continue
		}
		// An inherit-only entry on the immediate parent can modify the staged
		// file created there, so it is relevant even though it does not grant
		// access to the parent directory itself. Higher ancestors are checked
		// only for their ability to replace existing path components, while the
		// effective ACL inherited by the target and staging parent is checked
		// directly below; their inherit-only entries are therefore irrelevant.
		if inheritOnly && (target || !strict) {
			continue
		}
		modify := windowsUpdateWriteOrReplaceMask(mask)
		if !strict {
			modify = windowsUpdateAncestorReplaceMask(mask)
		}
		if !windowsUpdateSIDTrusted(sid, owner, principals) && modify {
			return fmt.Errorf("wire-connect: update path %q grants an untrusted principal write or replacement access", path)
		}
	}
	return nil
}

func windowsUpdateTrustedAncestorOwner(owner *windows.SID, principals windowsUpdatePrincipals) bool {
	if principals.elevated {
		return windowsUpdateTrustedSystemOwner(owner, principals)
	}
	return sameWindowsUpdateSID(owner, principals.user) ||
		sameWindowsUpdateSID(owner, principals.system) ||
		sameWindowsUpdateSID(owner, principals.admins) ||
		sameWindowsUpdateSID(owner, principals.trustedInstall)
}

func windowsUpdateTrustedSystemOwner(owner *windows.SID, principals windowsUpdatePrincipals) bool {
	return sameWindowsUpdateSID(owner, principals.system) ||
		sameWindowsUpdateSID(owner, principals.admins) ||
		sameWindowsUpdateSID(owner, principals.trustedInstall)
}

func windowsUpdateSIDTrusted(sid, owner *windows.SID, principals windowsUpdatePrincipals) bool {
	if sameWindowsUpdateSID(sid, principals.system) || sameWindowsUpdateSID(sid, principals.admins) {
		return true
	}
	if !principals.elevated && sameWindowsUpdateSID(sid, principals.user) {
		return true
	}
	// These two SIDs resolve to the object's owner. They are safe only when
	// that owner has already passed the policy above.
	if sameWindowsUpdateSID(sid, principals.creatorOwner) || sameWindowsUpdateSID(sid, principals.ownerRights) {
		return windowsUpdateTrustedOwner(owner, principals)
	}
	return false
}

func windowsUpdateTrustedOwner(owner *windows.SID, principals windowsUpdatePrincipals) bool {
	return sameWindowsUpdateSID(owner, principals.user) ||
		sameWindowsUpdateSID(owner, principals.system) ||
		sameWindowsUpdateSID(owner, principals.admins) ||
		sameWindowsUpdateSID(owner, principals.trustedInstall)
}

func sameWindowsUpdateSID(a, b *windows.SID) bool {
	return a != nil && b != nil && a.Equals(b)
}

// These values are defined by WinNT.h but are not exported by x/sys/windows.
const (
	windowsUpdateFileAddSubdirectory = 0x00000004
	windowsUpdateFileDeleteChild     = 0x00000040

	windowsUpdateAccessAllowedACEType            = 0
	windowsUpdateAccessDeniedACEType             = 1
	windowsUpdateSystemAuditACEType              = 2
	windowsUpdateSystemAlarmACEType              = 3
	windowsUpdateAccessAllowedCompoundACEType    = 4
	windowsUpdateAccessAllowedObjectACEType      = 5
	windowsUpdateAccessDeniedObjectACEType       = 6
	windowsUpdateSystemAuditObjectACEType        = 7
	windowsUpdateSystemAlarmObjectACEType        = 8
	windowsUpdateAccessAllowedCallbackACEType    = 9
	windowsUpdateAccessDeniedCallbackACEType     = 10
	windowsUpdateAccessAllowedCallbackObjectType = 11
	windowsUpdateAccessDeniedCallbackObjectType  = 12
	windowsUpdateSystemAuditCallbackACEType      = 13
	windowsUpdateSystemAlarmCallbackACEType      = 14
	windowsUpdateSystemAuditCallbackObjectType   = 15
	windowsUpdateSystemAlarmCallbackObjectType   = 16
	windowsUpdateSystemMandatoryLabelACEType     = 17
	windowsUpdateSystemResourceAttributeACEType  = 18
	windowsUpdateSystemScopedPolicyIDACEType     = 19
	windowsUpdateSystemProcessTrustLabelACEType  = 20
	windowsUpdateSystemAccessFilterACEType       = 21
)

func windowsUpdateWriteOrReplaceMask(mask windows.ACCESS_MASK) bool {
	const modify = uint32(
		windows.FILE_WRITE_DATA |
			windows.FILE_APPEND_DATA |
			windows.FILE_WRITE_EA |
			windows.FILE_WRITE_ATTRIBUTES |
			windows.DELETE |
			windows.WRITE_DAC |
			windows.WRITE_OWNER |
			windows.ACCESS_SYSTEM_SECURITY |
			windows.GENERIC_WRITE |
			windows.GENERIC_ALL |
			windowsUpdateFileAddSubdirectory |
			windowsUpdateFileDeleteChild)
	return uint32(mask)&modify != 0
}

func windowsUpdateAncestorReplaceMask(mask windows.ACCESS_MASK) bool {
	const replace = uint32(
		windows.DELETE |
			windows.WRITE_DAC |
			windows.WRITE_OWNER |
			windows.GENERIC_ALL |
			windowsUpdateFileDeleteChild)
	return uint32(mask)&replace != 0
}

func decodeWindowsUpdateACE(ace *windows.ACCESS_ALLOWED_ACE) (allow bool, mask windows.ACCESS_MASK, sid *windows.SID, inheritOnly bool, err error) {
	header := (*windows.ACE_HEADER)(unsafe.Pointer(ace))
	if header.AceSize < uint16(unsafe.Sizeof(windows.ACE_HEADER{})) {
		return false, 0, nil, false, errors.New("ACL entry is shorter than its header")
	}
	data := unsafe.Slice((*byte)(unsafe.Pointer(ace)), int(header.AceSize))
	inheritOnly = header.AceFlags&windows.INHERIT_ONLY_ACE != 0

	sidOffset := 0
	switch header.AceType {
	case windowsUpdateAccessAllowedACEType, windowsUpdateAccessAllowedCallbackACEType:
		allow = true
		sidOffset = 8 // ACE_HEADER + ACCESS_MASK
	case windowsUpdateAccessDeniedACEType, windowsUpdateAccessDeniedCallbackACEType:
		return false, 0, nil, inheritOnly, nil
	case windowsUpdateAccessAllowedObjectACEType, windowsUpdateAccessAllowedCallbackObjectType:
		allow = true
		if len(data) < 12 {
			return false, 0, nil, inheritOnly, errors.New("object ACL entry is truncated")
		}
		flags := binary.LittleEndian.Uint32(data[8:12])
		if flags&^(uint32(windows.ACE_OBJECT_TYPE_PRESENT)|uint32(windows.ACE_INHERITED_OBJECT_TYPE_PRESENT)) != 0 {
			return false, 0, nil, inheritOnly, errors.New("object ACL entry has unknown flags")
		}
		sidOffset = 12
		if flags&uint32(windows.ACE_OBJECT_TYPE_PRESENT) != 0 {
			sidOffset += 16
		}
		if flags&uint32(windows.ACE_INHERITED_OBJECT_TYPE_PRESENT) != 0 {
			sidOffset += 16
		}
	case windowsUpdateAccessDeniedObjectACEType, windowsUpdateAccessDeniedCallbackObjectType:
		return false, 0, nil, inheritOnly, nil
	case windowsUpdateSystemAuditACEType,
		windowsUpdateSystemAlarmACEType,
		windowsUpdateSystemAuditObjectACEType,
		windowsUpdateSystemAlarmObjectACEType,
		windowsUpdateSystemAuditCallbackACEType,
		windowsUpdateSystemAlarmCallbackACEType,
		windowsUpdateSystemAuditCallbackObjectType,
		windowsUpdateSystemAlarmCallbackObjectType,
		windowsUpdateSystemMandatoryLabelACEType,
		windowsUpdateSystemResourceAttributeACEType,
		windowsUpdateSystemScopedPolicyIDACEType,
		windowsUpdateSystemProcessTrustLabelACEType,
		windowsUpdateSystemAccessFilterACEType:
		return false, 0, nil, inheritOnly, nil
	default:
		// Unknown ACE types are rejected rather than treated as harmless. An
		// unrecognised allow-like ACE must never bypass this policy.
		return false, 0, nil, inheritOnly, fmt.Errorf("unsupported ACL entry type %d", header.AceType)
	}

	if len(data) < 8 || sidOffset < 8 || sidOffset+8 > len(data) {
		return false, 0, nil, inheritOnly, errors.New("ACL entry has no complete SID")
	}
	mask = windows.ACCESS_MASK(binary.LittleEndian.Uint32(data[4:8]))
	// Validate the SID length before constructing a pointer into the ACE. This
	// keeps malformed ACL data from making IsValid read past AceSize.
	sidBytes := data[sidOffset:]
	if sidBytes[0] != 1 || int(sidBytes[1]) > 15 {
		return false, 0, nil, inheritOnly, errors.New("ACL entry contains an invalid SID header")
	}
	sidLen := 8 + int(sidBytes[1])*4
	if sidLen > len(sidBytes) {
		return false, 0, nil, inheritOnly, errors.New("ACL entry contains a truncated SID")
	}
	sid = (*windows.SID)(unsafe.Pointer(&data[sidOffset]))
	if !sid.IsValid() {
		return false, 0, nil, inheritOnly, errors.New("ACL entry contains an invalid SID")
	}
	return allow, mask, sid, inheritOnly, nil
}
