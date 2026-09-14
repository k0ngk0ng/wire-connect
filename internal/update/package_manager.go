package update

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	packageManagerMarkerName = ".wire-connect-package-manager"
	packageManagerHomebrew   = "homebrew"
	packageManagerScoop      = "scoop"
	packageManagerMarkerMax  = 64
)

var (
	// ErrPackageManagerManaged means that the executable belongs to an
	// external package manager and must be upgraded by that manager.
	ErrPackageManagerManaged       = errors.New("wire-connect: installation is managed by a package manager")
	ErrInvalidPackageManagerMarker = errors.New("wire-connect: invalid package manager marker")
)

// detectPackageManager reads the marker next to the resolved executable. The
// marker is an opt-out for self-update, so malformed or unsafe marker files
// fail closed instead of allowing an updater to modify a managed prefix.
func detectPackageManager(executable string) (string, error) {
	if executable == "" {
		return "", errors.New("wire-connect: executable path is empty")
	}
	abs, err := filepath.Abs(executable)
	if err != nil {
		return "", fmt.Errorf("wire-connect: resolve executable for package manager detection: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(abs))
	if err != nil {
		return "", fmt.Errorf("wire-connect: resolve executable for package manager detection: %w", err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("wire-connect: resolve executable for package manager detection: %w", err)
	}
	st, err := os.Lstat(filepath.Clean(resolved))
	if err != nil {
		return "", fmt.Errorf("wire-connect: inspect executable for package manager detection: %w", err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return "", fmt.Errorf("%w: executable must be a regular file", ErrInvalidPackageManagerMarker)
	}

	marker := filepath.Join(filepath.Dir(resolved), packageManagerMarkerName)
	markerInfo, err := os.Lstat(marker)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("%w: inspect %q: %v", ErrInvalidPackageManagerMarker, marker, err)
	}
	if markerInfo.Mode()&os.ModeSymlink != 0 || !markerInfo.Mode().IsRegular() {
		return "", fmt.Errorf("%w: %q must be a regular file", ErrInvalidPackageManagerMarker, marker)
	}
	f, err := os.Open(marker)
	if err != nil {
		return "", fmt.Errorf("%w: read %q: %v", ErrInvalidPackageManagerMarker, marker, err)
	}
	b, readErr := io.ReadAll(io.LimitReader(f, packageManagerMarkerMax+1))
	closeErr := f.Close()
	if readErr != nil {
		return "", fmt.Errorf("%w: read %q: %v", ErrInvalidPackageManagerMarker, marker, readErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("%w: close %q: %v", ErrInvalidPackageManagerMarker, marker, closeErr)
	}
	if len(b) > packageManagerMarkerMax {
		return "", fmt.Errorf("%w: %q is too large", ErrInvalidPackageManagerMarker, marker)
	}
	// Accept the exact token with no decoration and the line endings produced
	// by common package-manager formula/manifest installers. Do not trim
	// arbitrary whitespace: an unknown marker must fail closed.
	switch string(b) {
	case packageManagerHomebrew, packageManagerHomebrew + "\n", packageManagerHomebrew + "\r\n":
		return packageManagerHomebrew, nil
	case packageManagerScoop, packageManagerScoop + "\n", packageManagerScoop + "\r\n":
		return packageManagerScoop, nil
	default:
		return "", fmt.Errorf("%w: %q contains unsupported manager value", ErrInvalidPackageManagerMarker, marker)
	}
}

func packageManagerUpdateError(manager string) error {
	switch manager {
	case packageManagerHomebrew:
		return fmt.Errorf("%w: run `brew upgrade k0ngk0ng/tap/wire-connect`", ErrPackageManagerManaged)
	case packageManagerScoop:
		return fmt.Errorf("%w: run `scoop update wire-connect`", ErrPackageManagerManaged)
	default:
		return fmt.Errorf("%w: use the package manager to upgrade this installation", ErrPackageManagerManaged)
	}
}

func ensureSelfUpdateAllowed(executable string) error {
	manager, err := detectPackageManager(executable)
	if err != nil {
		return err
	}
	if manager != "" {
		return packageManagerUpdateError(manager)
	}
	return nil
}
