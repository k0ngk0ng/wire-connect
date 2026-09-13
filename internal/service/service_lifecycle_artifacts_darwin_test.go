//go:build darwin && (amd64 || arm64)

package service

func integrationInstalledArtifacts(name string) (bool, error) {
	plist, err := darwinServiceRecordExists(name)
	if err != nil {
		return false, err
	}
	dir, err := darwinInstalledDirExists(name)
	return plist || dir, err
}
