package installpath

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// Resolve asks Windows for the final path of an opened file or directory.
// Package managers such as Scoop use directory junctions for their current
// version. Resolve those through the filesystem instead of walking and
// interpreting individual reparse-point targets in userspace.
func Resolve(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	name, err := windows.UTF16PtrFromString(absolute)
	if err != nil {
		return "", err
	}
	handle, err := windows.CreateFile(name, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", fmt.Errorf("open installed path: %w", err)
	}
	defer windows.CloseHandle(handle)
	for size := uint32(512); size <= 32768; {
		buffer := make([]uint16, size)
		n, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], size, 0)
		if err != nil {
			return "", fmt.Errorf("resolve installed path: %w", err)
		}
		if n >= size {
			size = n + 1
			continue
		}
		resolved := windows.UTF16ToString(buffer[:n])
		if strings.HasPrefix(resolved, `\\?\UNC\`) {
			resolved = `\\` + strings.TrimPrefix(resolved, `\\?\UNC\`)
		} else {
			resolved = strings.TrimPrefix(resolved, `\\?\`)
		}
		if !filepath.IsAbs(resolved) {
			return "", fmt.Errorf("Windows returned a non-absolute installed path")
		}
		return filepath.Clean(resolved), nil
	}
	return "", fmt.Errorf("installed path exceeds Windows path limit")
}
