package update

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractExecutableBytesKeepsVerifiedArchiveSnapshot(t *testing.T) {
	target := Target{GOOS: "linux", GOARCH: "amd64"}
	version := "9.8.7"
	archiveName := expectedArchiveName(version, target)
	verifiedArchive := makeTarGz(t, map[string][]byte{
		expectedBinaryName(target): []byte("verified executable"),
	})
	replacementArchive := makeTarGz(t, map[string][]byte{
		expectedBinaryName(target): []byte("replacement executable"),
	})

	archivePath := filepath.Join(t.TempDir(), archiveName)
	if err := os.WriteFile(archivePath, verifiedArchive, 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := readRegularFile(archivePath, int64(len(verifiedArchive)))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := digestBytes(snapshot), digestBytes(verifiedArchive); got != want {
		t.Fatalf("snapshot digest = %s; want %s", got, want)
	}

	// The path may change after verification. Extraction must continue using
	// the already verified snapshot held by Run, rather than reopening it.
	if err := os.WriteFile(archivePath, replacementArchive, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := extractExecutableBytes(snapshot, archiveName, target, limits{
		maxArchive:   int64(len(verifiedArchive)),
		maxExtracted: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Executable, []byte("verified executable")) {
		t.Fatalf("extracted executable = %q; want verified snapshot", got.Executable)
	}
}
