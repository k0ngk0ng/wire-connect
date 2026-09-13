//go:build !windows

package update

import (
	"context"
	"os"
)

// installStagedExecutable is an atomic same-directory rename on Unix.  The
// caller has already checked the target and staged file; keeping this small
// platform hook makes the Windows self-update handoff explicit.
func installStagedExecutable(_ context.Context, source, target, _ string, _ extractedPackage, _ string) (bool, error) {
	return false, os.Rename(source, target)
}

func runtimeFilesMatch(_ string, _ extractedPackage) (bool, error) {
	return true, nil
}
