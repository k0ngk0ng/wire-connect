package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestRunOnlineVerifiesGitHubDigestsAndReplacesResolvedExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("successful self replacement is covered by the native Windows handoff test")
	}
	target, err := CurrentTarget()
	if err != nil {
		t.Skip(err)
	}
	version := "1.2.3"
	archiveName := expectedArchiveName(version, target)
	payload := []byte("new executable image")
	archive := makeTarGz(t, map[string][]byte{expectedBinaryName(target): payload})
	sums := []byte(fmt.Sprintf("%s  ./%s\n", digestBytes(archive), archiveName))
	archiveDigest := digestBytes(archive)
	sumsDigest := digestBytes(sums)
	release := release{
		TagName: "v" + version,
		Assets: []releaseAsset{
			{Name: archiveName, URL: "https://api.github.com/repos/" + Repository + "/releases/assets/1", Digest: "sha256:" + archiveDigest, Size: int64(len(archive))},
			{Name: "SHA256SUMS", URL: "https://api.github.com/repos/" + Repository + "/releases/assets/2", Digest: "sha256:" + sumsDigest, Size: int64(len(sums))},
		},
	}
	releaseJSON, err := json.Marshal(release)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		var body []byte
		switch req.URL.Path {
		case "/repos/" + Repository + "/releases/latest", "/repos/" + Repository + "/releases/tags/v" + version:
			body = releaseJSON
		case "/repos/" + Repository + "/releases/assets/1":
			body = archive
		case "/repos/" + Repository + "/releases/assets/2":
			body = sums
		default:
			return nil, fmt.Errorf("unexpected request %s", req.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
	})}

	root := t.TempDir()
	actual := filepath.Join(root, "installed", filepath.Base("wirectl-connect"))
	if runtime.GOOS == "windows" {
		actual = filepath.Join(root, "installed", "wirectl-connect.exe")
	}
	if err := os.MkdirAll(filepath.Dir(actual), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(actual, []byte("old executable image"), 0755); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		alias := filepath.Join(root, "launcher")
		if err := os.Symlink(actual, alias); err != nil {
			t.Fatal(err)
		}
		actual = alias
	}
	result, err := Run(context.Background(), Options{
		Version:    "v" + version,
		Executable: actual,
		HTTPClient: client,
		TempDir:    root,
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !result.PublisherVerified || result.Offline || result.AlreadyUpToDate {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.InstalledPath != filepath.Join(root, "installed", filepath.Base(result.InstalledPath)) {
		t.Fatalf("installed path = %q; want resolved target under installed", result.InstalledPath)
	}
	got, err := os.ReadFile(result.InstalledPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("installed bytes = %q; want %q", got, payload)
	}
}

func TestRunOfflineRequiresExplicitChecksumAndMarksBoundary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("successful self replacement is covered by the native Windows handoff test")
	}
	target, err := CurrentTarget()
	if err != nil {
		t.Skip(err)
	}
	version := "2.0.0"
	name := expectedArchiveName(version, target)
	archive := makeTarGz(t, map[string][]byte{expectedBinaryName(target): []byte("offline image")})
	root := t.TempDir()
	archivePath := filepath.Join(root, name)
	if err := os.WriteFile(archivePath, archive, 0600); err != nil {
		t.Fatal(err)
	}
	sumsPath := filepath.Join(root, "SHA256SUMS")
	sums := []byte(fmt.Sprintf("%s *%s\n", digestBytes(archive), name))
	if err := os.WriteFile(sumsPath, sums, 0600); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, "installed", filepath.Base(name))
	if err := os.MkdirAll(filepath.Dir(executable), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("before"), 0755); err != nil {
		t.Fatal(err)
	}
	result, err := Run(context.Background(), Options{
		Version:       version,
		ArchivePath:   archivePath,
		ChecksumsPath: sumsPath,
		Executable:    executable,
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Offline || result.PublisherVerified {
		t.Fatalf("offline authenticity result = %+v", result)
	}
	if got, err := os.ReadFile(result.InstalledPath); err != nil {
		t.Fatal(err)
	} else if string(got) != "offline image" {
		t.Fatalf("installed offline image = %q", got)
	}
	if _, err := Run(context.Background(), Options{ArchivePath: archivePath, Executable: executable}, io.Discard); err == nil {
		t.Fatal("offline update accepted an archive without checksums")
	}
}

func TestRunRejectsChecksumMismatchBeforeReplacing(t *testing.T) {
	target, err := CurrentTarget()
	if err != nil {
		t.Skip(err)
	}
	name := expectedArchiveName("3.0.0", target)
	archive := makeTarGz(t, map[string][]byte{expectedBinaryName(target): []byte("bad checksum")})
	root := t.TempDir()
	archivePath := filepath.Join(root, name)
	checksumsPath := filepath.Join(root, "SHA256SUMS")
	if err := os.WriteFile(archivePath, archive, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(checksumsPath, []byte(strings.Repeat("0", 64)+"  "+name+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, "wirectl-connect")
	if err := os.WriteFile(executable, []byte("must survive"), 0755); err != nil {
		t.Fatal(err)
	}
	_, err = Run(context.Background(), Options{ArchivePath: archivePath, ChecksumsPath: checksumsPath, Executable: executable}, io.Discard)
	if err == nil || !errors.Is(err, ErrInvalidRelease) {
		t.Fatalf("checksum mismatch error = %v; want ErrInvalidRelease", err)
	}
	got, readErr := os.ReadFile(executable)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "must survive" {
		t.Fatalf("executable changed after failed verification: %q", got)
	}
}

func TestArchiveRejectsTraversalLinksDuplicatesAndMissingBinary(t *testing.T) {
	tests := []struct {
		name string
		make func(*testing.T) []byte
	}{
		{name: "traversal", make: func(t *testing.T) []byte {
			return makeTarEntries(t, []tarTestEntry{{name: "../bin/wirectl-connect", body: []byte("x")}})
		}},
		{name: "duplicate", make: func(t *testing.T) []byte {
			return makeTarEntries(t, []tarTestEntry{{name: "bin/wirectl-connect", body: []byte("x")}, {name: "bin/wirectl-connect", body: []byte("y")}})
		}},
		{name: "missing", make: func(t *testing.T) []byte {
			return makeTarGz(t, map[string][]byte{"README.md": []byte("x")})
		}},
	}
	target := Target{GOOS: "linux", GOARCH: "amd64"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			archive := tt.make(t)
			path := filepath.Join(t.TempDir(), "archive.tar.gz")
			if err := os.WriteFile(path, archive, 0600); err != nil {
				t.Fatal(err)
			}
			_, err := extractExecutable(path, "wire-connect-1.0.0-linux-amd64.tar.gz", target, limits{1 << 20, 1 << 20, 4 << 20})
			if err == nil || !errors.Is(err, ErrInvalidRelease) {
				t.Fatalf("extract error = %v; want ErrInvalidRelease", err)
			}
		})
	}
}

func TestWindowsArchiveRequiresWintunAndLicense(t *testing.T) {
	target := Target{GOOS: "windows", GOARCH: "amd64"}
	archive := makeZip(t, map[string][]byte{"bin/wirectl-connect.exe": []byte("exe")})
	path := filepath.Join(t.TempDir(), "archive.zip")
	if err := os.WriteFile(path, archive, 0600); err != nil {
		t.Fatal(err)
	}
	_, err := extractExecutable(path, "wire-connect-1.0.0-windows-amd64.zip", target, limits{1 << 20, 1 << 20, 4 << 20})
	if err == nil || !errors.Is(err, ErrInvalidRelease) {
		t.Fatalf("missing Wintun error = %v; want ErrInvalidRelease", err)
	}

	archive = makeZip(t, map[string][]byte{
		"bin/wirectl-connect.exe": []byte("exe"),
		"bin/wintun.dll":          []byte("dll"),
		"bin/WINTUN-LICENSE.txt":  []byte("license"),
	})
	if err := os.WriteFile(path, archive, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := extractExecutable(path, "wire-connect-1.0.0-windows-amd64.zip", target, limits{1 << 20, 1 << 20, 4 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Executable) != "exe" {
		t.Fatalf("Windows executable = %q", got.Executable)
	}
	if string(got.Wintun) != "dll" || string(got.WintunLicense) != "license" {
		t.Fatalf("Windows runtime = (%q, %q)", got.Wintun, got.WintunLicense)
	}
}

func TestURLPolicyRejectsNonGitHubHosts(t *testing.T) {
	for _, raw := range []string{
		"http://api.github.com/repos/" + Repository + "/releases/latest",
		"https://evil.example/repos/" + Repository + "/releases/latest",
		"https://github.com/other/release/download/v1/a.tar.gz",
	} {
		u, err := parseURL(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateGitHubURL(u); err == nil {
			t.Fatalf("accepted untrusted URL %s", raw)
		}
	}
}

func TestSemverComparisonAndMinimumVersion(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{a: "1.2.0-rc.1", b: "1.2.0", want: -1},
		{a: "1.10.0", b: "1.2.0", want: 1},
		{a: "1.2.0+build.1", b: "1.2.0+build.2", want: 0},
		{a: "1.0.0-alpha", b: "1.0.0-alpha.1", want: -1},
		{a: "1.0.0-alpha.1", b: "1.0.0-alpha.beta", want: -1},
	}
	for _, tt := range tests {
		got, err := compareSemver(tt.a, tt.b)
		if err != nil {
			t.Fatalf("compareSemver(%q, %q): %v", tt.a, tt.b, err)
		}
		if got != tt.want {
			t.Errorf("compareSemver(%q, %q) = %d; want %d", tt.a, tt.b, got, tt.want)
		}
	}
	if err := ensureMinimumVersion("1.2.0-rc.1", MinimumSafeVersion); err == nil || !errors.Is(err, ErrVersionTooOld) {
		t.Fatalf("pre-release below minimum error = %v; want ErrVersionTooOld", err)
	}
	if err := ensureMinimumVersion(MinimumSafeVersion, MinimumSafeVersion); err != nil {
		t.Fatalf("minimum version rejected itself: %v", err)
	}
	if _, err := normalizeMinimumVersion("1.1.9"); err == nil {
		t.Fatal("minimum update version lowered the safety floor")
	}
}

func parseURL(raw string) (*url.URL, error) {
	return url.Parse(raw)
}

type tarTestEntry struct {
	name string
	body []byte
}

func makeTarEntries(t *testing.T, entries []tarTestEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0600, Size: int64(len(entry.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func makeTarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	entries := make([]tarTestEntry, 0, len(files))
	for name, body := range files {
		entries = append(entries, tarTestEntry{name: name, body: body})
	}
	return makeTarEntries(t, entries)
}

func makeZip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
