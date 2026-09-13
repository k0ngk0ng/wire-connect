//go:build linux && (amd64 || arm64)

package service

func integrationInstalledArtifacts(name string) (bool, error) {
	unit, err := linuxServiceRecordExists(name)
	if err != nil {
		return false, err
	}
	dir, err := linuxInstalledDirExists(name)
	return unit || dir, err
}
