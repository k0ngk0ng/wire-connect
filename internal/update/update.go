// Package update downloads and installs a verified wire-connect client.
//
// The package deliberately has no service-manager or privilege-escalation
// code.  Run verifies the release before touching the current executable and
// reports permission or in-use errors to its caller.  The CLI is responsible
// for updating any protected service copies after Run succeeds.
package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/k0ngk0ng/wire-connect/internal/installpath"
)

const (
	Repository        = "k0ngk0ng/wire-connect"
	DefaultAPIBaseURL = "https://api.github.com"

	// These limits are deliberately finite even when GitHub reports a smaller
	// asset size.  A response is always copied through a limit reader, so a
	// malicious or broken server cannot turn an update into an unbounded disk
	// or memory write.
	DefaultMaxArchiveBytes    int64 = 128 << 20
	DefaultMaxChecksumsBytes  int64 = 2 << 20
	DefaultMaxExtractedBytes  int64 = 256 << 20
	DefaultMaxExecutableBytes int64 = 64 << 20
	DefaultMaxArchiveEntries        = 512
	DefaultHTTPTimeout              = 45 * time.Second
)

var (
	// ErrUnsupportedPlatform means that the current GOOS/GOARCH is outside
	// the release matrix published by this project.
	ErrUnsupportedPlatform = errors.New("wire-connect: updates are unsupported on this platform")
	// ErrInvalidRelease is returned when the release metadata or package does
	// not have the exact shape expected by the project.
	ErrInvalidRelease = errors.New("wire-connect: invalid release")
	// ErrNeedsAdmin means that the current executable cannot be replaced by the
	// invoking user.  No privilege escalation is attempted by this package.
	ErrNeedsAdmin = errors.New("wire-connect: administrator privileges are required to replace the executable")
	// ErrExecutableInUse is used where the operating system keeps the current
	// executable open (most commonly Windows).
	ErrExecutableInUse = errors.New("wire-connect: the executable is in use")
	// ErrRequiresAdmin is a descriptive alias for callers that prefer the
	// wording used by their command-line UI.
	ErrRequiresAdmin = ErrNeedsAdmin
	// ErrInUse is a short alias for ErrExecutableInUse.
	ErrInUse = ErrExecutableInUse
	// ErrUpdateRollback means that a Windows handoff failed and restoring the
	// previous executable or runtime files also failed.  Callers should surface
	// this distinctly because the installation may need operator attention.
	ErrUpdateRollback = errors.New("wire-connect: update rollback failed")
	// ErrVersionTooOld means that a verified release predates the minimum
	// version whose update handoff and runtime contract this binary supports.
	ErrVersionTooOld = errors.New("wire-connect: release is older than the minimum supported update version")
)

// MinimumSafeVersion is the first release with the complete self-update
// handoff contract.  Older archives are valid releases but cannot safely
// replace a running installation because they do not implement the current
// refresh/update entry points.
const MinimumSafeVersion = "1.2.0"

// Options controls one update operation.  With no ArchivePath, Run fetches
// the requested release from GitHub.  ArchivePath and ChecksumsPath together
// select explicit offline mode; they are never mixed with a network download.
//
// APIBaseURL and HTTPClient are useful for tests and for an application that
// supplies a transport with its own network policy.  APIBaseURL is still
// required to be the official api.github.com HTTPS endpoint.  HTTPClient's
// redirect chain is checked by Run before every redirected request.
type Options struct {
	Version string
	// MinimumVersion overrides the minimum release version accepted by this
	// updater.  Empty uses MinimumSafeVersion.  It is primarily useful to a
	// distributor that has a newer handoff contract; normal CLI callers should
	// leave it empty.
	MinimumVersion string
	// RefreshStateDir is passed to the post-install refresh command on Windows,
	// where a detached helper performs the replacement after this process exits.
	// Empty lets the refreshed binary use its normal platform default.
	RefreshStateDir string

	ArchivePath   string
	ChecksumsPath string
	// ManifestPath is an optional operator-trusted offline release manifest.
	// It supplies a second, separately obtained digest for the archive and the
	// checksums file.  It does not turn offline bytes into GitHub publisher
	// attestation; Result.PublisherVerified remains false offline.
	ManifestPath string
	// TrustedManifestPath is an alias retained for callers that want to make
	// the operator-trust boundary explicit.  It must not be used together with
	// ManifestPath.
	TrustedManifestPath string

	// Executable overrides os.Executable.  It is intended for tests and for a
	// caller that has already resolved its own launcher.  An empty value uses
	// os.Executable and follows symlinks to the real installation target.
	Executable string

	APIBaseURL string
	HTTPClient *http.Client
	// TempDir is retained for callers that used older updater options. Archive
	// downloads are now kept in memory and verified/extracted from the same
	// byte slice, so this option is ignored.
	TempDir string

	MaxArchiveBytes   int64
	MaxChecksumsBytes int64
	MaxExtractedBytes int64
}

// Result describes the verified update.  InstalledPath is the resolved real
// path that was atomically replaced.  PublisherVerified is true only for an
// online release whose GitHub asset digest and SHA256SUMS digest both
// matched; it is deliberately false for offline checksum-only updates.
type Result struct {
	Version           string
	Tag               string
	Target            string
	Asset             string
	InstalledPath     string
	ArchiveSHA256     string
	ChecksumsSHA256   string
	PublisherVerified bool
	Offline           bool
	AlreadyUpToDate   bool
	// Pending is true on Windows when a small helper has been started and is
	// waiting for this process to exit before replacing the executable.  The
	// caller must return promptly so the helper can complete the handoff.
	Pending bool
}

// extractedPackage contains the only files that are allowed to leave an
// archive.  Release documentation and inventory files are inspected for
// safe archive structure but are never installed.  Windows needs the
// adjacent official Wintun runtime copied along with the executable so a
// self-update cannot leave a mixed client/runtime pair.
type extractedPackage struct {
	Executable    []byte
	Wintun        []byte
	WintunLicense []byte
}

// Target is a supported release target.
type Target struct {
	GOOS   string
	GOARCH string
}

func (t Target) String() string {
	return t.GOOS + "-" + t.GOARCH
}

// CurrentTarget returns the target represented by this process.
func CurrentTarget() (Target, error) {
	t := Target{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
	if !supportedTarget(t) {
		return Target{}, fmt.Errorf("%w: %s", ErrUnsupportedPlatform, t.String())
	}
	return t, nil
}

func supportedTarget(t Target) bool {
	switch t.GOOS + "/" + t.GOARCH {
	case "linux/amd64", "linux/arm64", "darwin/arm64", "windows/amd64":
		return true
	default:
		return false
	}
}

type release struct {
	TagName string         `json:"tag_name"`
	Draft   bool           `json:"draft"`
	Assets  []releaseAsset `json:"assets"`
}

type releaseAsset struct {
	Name               string `json:"name"`
	URL                string `json:"url"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Digest             string `json:"digest"`
	Size               int64  `json:"size"`
}

type offlineManifest struct {
	Repository      string `json:"repository"`
	Tag             string `json:"tag"`
	Asset           string `json:"asset"`
	AssetSHA256     string `json:"asset_sha256"`
	Checksums       string `json:"checksums"`
	ChecksumsSHA256 string `json:"checksums_sha256"`
}

var semverRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9A-Za-z-]*[0-9A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[0-9A-Za-z-][0-9A-Za-z-]*))*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

// Run downloads (or reads) a release, verifies it, safely extracts exactly
// the current target's client executable, and atomically replaces the real
// executable path.  out is reserved for a caller's progress sink; Run does
// not print credentials, URLs containing credentials, or package contents.
func Run(ctx context.Context, opts Options, out io.Writer) (Result, error) {
	if ctx == nil {
		return Result{}, errors.New("wire-connect: nil context")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	target, err := CurrentTarget()
	if err != nil {
		return Result{}, err
	}
	// Resolve and inspect the real executable before any release metadata or
	// asset request. Homebrew and Scoop own their installation prefixes and
	// must remain the sole writers of those files.
	installationPath, err := executablePath(opts.Executable)
	if err != nil {
		return Result{}, err
	}
	if err := ensureSelfUpdateAllowed(installationPath); err != nil {
		return Result{}, err
	}
	limits, err := normalizeLimits(opts)
	if err != nil {
		return Result{}, err
	}
	minimumVersion, err := normalizeMinimumVersion(opts.MinimumVersion)
	if err != nil {
		return Result{}, err
	}

	offline := opts.ArchivePath != "" || opts.ChecksumsPath != ""
	if offline && (opts.ArchivePath == "" || opts.ChecksumsPath == "") {
		return Result{}, fmt.Errorf("%w: offline mode requires both --archive and --checksums", ErrInvalidRelease)
	}
	if offline && opts.APIBaseURL != "" {
		return Result{}, fmt.Errorf("%w: offline mode cannot use an API endpoint", ErrInvalidRelease)
	}
	manifestPath := opts.ManifestPath
	if opts.TrustedManifestPath != "" {
		if manifestPath != "" {
			return Result{}, fmt.Errorf("%w: specify only one offline manifest", ErrInvalidRelease)
		}
		manifestPath = opts.TrustedManifestPath
	}
	if !offline && manifestPath != "" {
		return Result{}, fmt.Errorf("%w: a manifest is only valid with offline archive and checksums", ErrInvalidRelease)
	}

	var (
		archivePath       string
		archiveBytes      []byte
		archiveName       string
		checksums         []byte
		archiveDigest     string
		checksumsDigest   string
		version           string
		tag               string
		publisherVerified bool
	)
	if offline {
		archivePath, archiveName, version, err = prepareOffline(opts, target, limits)
		if err != nil {
			return Result{}, err
		}
		if err := ensureMinimumVersion(version, minimumVersion); err != nil {
			return Result{}, err
		}
		// Read the offline archive once. The digest and extraction below both use
		// these exact bytes; reopening archivePath after verification would allow
		// a path replacement to change what gets installed.
		archiveBytes, err = readRegularFile(archivePath, limits.maxArchive)
		if err != nil {
			return Result{}, fmt.Errorf("wire-connect: read offline archive: %w", err)
		}
		archiveDigest = digestBytes(archiveBytes)
		checksums, err = readRegularFile(opts.ChecksumsPath, limits.maxChecksums)
		if err != nil {
			return Result{}, fmt.Errorf("wire-connect: read offline checksums: %w", err)
		}
		checksumsDigest = digestBytes(checksums)
		if err := verifyChecksumEntry(checksums, archiveName, archiveDigest); err != nil {
			return Result{}, err
		}
		if manifestPath != "" {
			manifest, err := readManifest(manifestPath, limits.maxChecksums)
			if err != nil {
				return Result{}, err
			}
			if err := verifyManifest(manifest, tagForVersion(version), archiveName, archiveDigest, checksumsDigest); err != nil {
				return Result{}, err
			}
			tag = manifest.Tag
		}
	} else {
		apiBase, err := normalizeAPIBase(opts.APIBaseURL)
		if err != nil {
			return Result{}, err
		}
		client := secureHTTPClient(opts.HTTPClient)
		rel, err := fetchRelease(ctx, client, apiBase, opts.Version)
		if err != nil {
			return Result{}, err
		}
		version, tag, err = releaseVersion(rel, opts.Version)
		if err != nil {
			return Result{}, err
		}
		if err := ensureMinimumVersion(version, minimumVersion); err != nil {
			return Result{}, err
		}
		archiveName = expectedArchiveName(version, target)
		archiveAsset, checksumAsset, err := selectAssets(rel, archiveName)
		if err != nil {
			return Result{}, err
		}
		if err := validateAssetDigest(archiveAsset, archiveName); err != nil {
			return Result{}, err
		}
		if err := validateAssetDigest(checksumAsset, "SHA256SUMS"); err != nil {
			return Result{}, err
		}
		// Keep the downloaded archive in memory so the digest check and archive
		// extraction operate on one immutable snapshot. Staging a pathname and
		// reopening it after verification creates a replacement race, especially
		// when an elevated updater inherits a user-writable temporary directory.
		archiveBytes, err = downloadBytes(ctx, client, archiveAsset, limits.maxArchive)
		if err != nil {
			return Result{}, err
		}
		archiveDigest = digestBytes(archiveBytes)
		expectedArchiveDigest, _ := parseSHA256Digest(archiveAsset.Digest)
		if archiveDigest != expectedArchiveDigest {
			return Result{}, fmt.Errorf("%w: archive %s digest mismatch (GitHub %s, downloaded %s)", ErrInvalidRelease, archiveName, expectedArchiveDigest, archiveDigest)
		}
		checksums, err = downloadBytes(ctx, client, checksumAsset, limits.maxChecksums)
		if err != nil {
			return Result{}, err
		}
		checksumsDigest = digestBytes(checksums)
		expectedChecksumsDigest, _ := parseSHA256Digest(checksumAsset.Digest)
		if checksumsDigest != expectedChecksumsDigest {
			return Result{}, fmt.Errorf("%w: SHA256SUMS digest mismatch (GitHub %s, downloaded %s)", ErrInvalidRelease, expectedChecksumsDigest, checksumsDigest)
		}
		if err := verifyChecksumEntry(checksums, archiveName, archiveDigest); err != nil {
			return Result{}, err
		}
		publisherVerified = true
	}

	packageFiles, err := extractExecutableBytes(archiveBytes, archiveName, target, limits)
	if err != nil {
		return Result{}, err
	}
	// The marker is checked again immediately before replacement in case a
	// package-manager installation became active while the archive was being
	// fetched and verified.
	if err := ensureSelfUpdateAllowed(installationPath); err != nil {
		return Result{}, err
	}
	installedPath, already, pending, err := replaceCurrentExecutable(ctx, opts.Executable, packageFiles, opts.RefreshStateDir)
	if err != nil {
		return Result{}, err
	}
	return Result{
		Version:           version,
		Tag:               tag,
		Target:            target.String(),
		Asset:             archiveName,
		InstalledPath:     installedPath,
		ArchiveSHA256:     archiveDigest,
		ChecksumsSHA256:   checksumsDigest,
		PublisherVerified: publisherVerified,
		Offline:           offline,
		AlreadyUpToDate:   already,
		Pending:           pending,
	}, nil
}

type limits struct {
	maxArchive   int64
	maxChecksums int64
	maxExtracted int64
}

func normalizeLimits(opts Options) (limits, error) {
	l := limits{DefaultMaxArchiveBytes, DefaultMaxChecksumsBytes, DefaultMaxExtractedBytes}
	if opts.MaxArchiveBytes != 0 {
		l.maxArchive = opts.MaxArchiveBytes
	}
	if opts.MaxChecksumsBytes != 0 {
		l.maxChecksums = opts.MaxChecksumsBytes
	}
	if opts.MaxExtractedBytes != 0 {
		l.maxExtracted = opts.MaxExtractedBytes
	}
	if l.maxArchive <= 0 || l.maxChecksums <= 0 || l.maxExtracted <= 0 || l.maxArchive > 1<<30 || l.maxChecksums > 64<<20 || l.maxExtracted > 2<<30 {
		return limits{}, fmt.Errorf("%w: invalid update size limits", ErrInvalidRelease)
	}
	return l, nil
}

func normalizeAPIBase(raw string) (*url.URL, error) {
	if raw == "" {
		raw = DefaultAPIBaseURL
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Hostname() != "api.github.com" || u.Port() != "" {
		return nil, fmt.Errorf("%w: API endpoint must be https://api.github.com", ErrInvalidRelease)
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("%w: API endpoint must not include a path", ErrInvalidRelease)
	}
	u.Path = ""
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u, nil
}

func secureHTTPClient(input *http.Client) *http.Client {
	var c http.Client
	if input != nil {
		c = *input
	} else {
		c = http.Client{}
	}
	if c.Timeout == 0 {
		c.Timeout = DefaultHTTPTimeout
	}
	original := c.CheckRedirect
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := validateGitHubURL(req.URL); err != nil {
			return err
		}
		if len(via) >= 10 {
			return errors.New("wire-connect: too many GitHub redirects")
		}
		if original != nil {
			return original(req, via)
		}
		return nil
	}
	return &c
}

func validateGitHubURL(u *url.URL) error {
	if u == nil || u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return fmt.Errorf("%w: release download must use HTTPS without credentials", ErrInvalidRelease)
	}
	host := strings.ToLower(u.Hostname())
	switch host {
	case "api.github.com":
		if !strings.HasPrefix(u.Path, "/repos/"+Repository+"/") {
			return fmt.Errorf("%w: API URL is outside %s", ErrInvalidRelease, Repository)
		}
	case "github.com":
		if !strings.HasPrefix(u.Path, "/"+Repository+"/releases/") {
			return fmt.Errorf("%w: release URL is outside %s", ErrInvalidRelease, Repository)
		}
	case "release-assets.githubusercontent.com", "objects.githubusercontent.com", "github-releases.githubusercontent.com":
		// GitHub may redirect a release asset to one of these exact hosts.
	default:
		return fmt.Errorf("%w: download host %q is not an approved GitHub host", ErrInvalidRelease, host)
	}
	return nil
}

func fetchRelease(ctx context.Context, client *http.Client, base *url.URL, version string) (release, error) {
	u := *base
	if version == "" {
		u.Path = "/repos/" + Repository + "/releases/latest"
	} else {
		v, err := normalizeVersion(version)
		if err != nil {
			return release{}, err
		}
		u.Path = "/repos/" + Repository + "/releases/tags/v" + v
	}
	if err := validateGitHubURL(&u); err != nil {
		return release{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return release{}, fmt.Errorf("wire-connect: create GitHub release request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "wire-connect-updater")
	resp, err := client.Do(req)
	if err != nil {
		return release{}, fmt.Errorf("wire-connect: fetch GitHub release: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return release{}, httpStatusError("fetch GitHub release", resp)
	}
	var rel release
	dec := json.NewDecoder(io.LimitReader(resp.Body, 4<<20))
	if err := dec.Decode(&rel); err != nil {
		return release{}, fmt.Errorf("%w: decode GitHub release: %v", ErrInvalidRelease, err)
	}
	if err := ctx.Err(); err != nil {
		return release{}, err
	}
	return rel, nil
}

func releaseVersion(rel release, requested string) (version, tag string, err error) {
	if rel.Draft {
		return "", "", fmt.Errorf("%w: draft releases cannot be installed", ErrInvalidRelease)
	}
	tag = rel.TagName
	if tag == "" {
		return "", "", fmt.Errorf("%w: release has no tag", ErrInvalidRelease)
	}
	version = strings.TrimPrefix(tag, "v")
	if !semverRE.MatchString(version) {
		return "", "", fmt.Errorf("%w: release tag %q is not a supported SemVer", ErrInvalidRelease, tag)
	}
	if requested != "" {
		req, reqErr := normalizeVersion(requested)
		if reqErr != nil {
			return "", "", reqErr
		}
		if req != version {
			return "", "", fmt.Errorf("%w: requested version %s but GitHub returned tag %s", ErrInvalidRelease, req, tag)
		}
	}
	return version, tag, nil
}

func normalizeVersion(raw string) (string, error) {
	v := strings.TrimPrefix(strings.TrimSpace(raw), "v")
	if v == "" || !semverRE.MatchString(v) {
		return "", fmt.Errorf("%w: version %q must be SemVer such as v1.2.3", ErrInvalidRelease, raw)
	}
	return v, nil
}

type semverValue struct {
	core       [3]string
	prerelease []string
}

func normalizeMinimumVersion(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		raw = MinimumSafeVersion
	}
	v, err := normalizeVersion(raw)
	if err != nil {
		return "", fmt.Errorf("%w: invalid minimum update version: %v", ErrInvalidRelease, err)
	}
	if safe, safeErr := normalizeVersion(MinimumSafeVersion); safeErr != nil {
		return "", safeErr
	} else if comparison, compareErr := compareSemver(v, safe); compareErr != nil {
		return "", compareErr
	} else if comparison < 0 {
		return "", fmt.Errorf("%w: minimum update version cannot be below %s", ErrInvalidRelease, safe)
	}
	return v, nil
}

func parseSemverValue(raw string) (semverValue, error) {
	v, err := normalizeVersion(raw)
	if err != nil {
		return semverValue{}, err
	}
	withoutBuild := strings.SplitN(v, "+", 2)[0]
	coreText, preText, hasPre := strings.Cut(withoutBuild, "-")
	core := strings.Split(coreText, ".")
	if len(core) != 3 {
		return semverValue{}, fmt.Errorf("invalid SemVer core %q", coreText)
	}
	parsed := semverValue{core: [3]string{core[0], core[1], core[2]}}
	if hasPre {
		parsed.prerelease = strings.Split(preText, ".")
	}
	return parsed, nil
}

// compareSemver returns -1, 0, or 1 according to SemVer precedence.  Core
// numeric identifiers are compared as decimal strings so a very large but
// valid SemVer cannot overflow a machine integer during validation.
func compareSemver(a, b string) (int, error) {
	av, err := parseSemverValue(a)
	if err != nil {
		return 0, err
	}
	bv, err := parseSemverValue(b)
	if err != nil {
		return 0, err
	}
	for i := range av.core {
		if c := compareNumericIdentifier(av.core[i], bv.core[i]); c != 0 {
			return c, nil
		}
	}
	if len(av.prerelease) == 0 && len(bv.prerelease) == 0 {
		return 0, nil
	}
	if len(av.prerelease) == 0 {
		return 1, nil
	}
	if len(bv.prerelease) == 0 {
		return -1, nil
	}
	for i := 0; i < len(av.prerelease) && i < len(bv.prerelease); i++ {
		if c := comparePrereleaseIdentifier(av.prerelease[i], bv.prerelease[i]); c != 0 {
			return c, nil
		}
	}
	if len(av.prerelease) < len(bv.prerelease) {
		return -1, nil
	}
	if len(av.prerelease) > len(bv.prerelease) {
		return 1, nil
	}
	return 0, nil
}

func compareNumericIdentifier(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if a == "" {
		a = "0"
	}
	if b == "" {
		b = "0"
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return strings.Compare(a, b)
}

func isNumericIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func comparePrereleaseIdentifier(a, b string) int {
	aNumeric := isNumericIdentifier(a)
	bNumeric := isNumericIdentifier(b)
	switch {
	case aNumeric && bNumeric:
		return compareNumericIdentifier(a, b)
	case aNumeric:
		return -1
	case bNumeric:
		return 1
	default:
		return strings.Compare(a, b)
	}
}

func ensureMinimumVersion(version, minimum string) error {
	comparison, err := compareSemver(version, minimum)
	if err != nil {
		return fmt.Errorf("%w: compare release and minimum versions: %v", ErrInvalidRelease, err)
	}
	if comparison < 0 {
		return fmt.Errorf("%w: %w: release %s is older than minimum supported version %s", ErrInvalidRelease, ErrVersionTooOld, version, minimum)
	}
	return nil
}

func tagForVersion(version string) string {
	if version == "" {
		return ""
	}
	return "v" + version
}

func expectedArchiveName(version string, target Target) string {
	ext := ".tar.gz"
	if target.GOOS == "windows" {
		ext = ".zip"
	}
	return "wire-connect-" + version + "-" + target.String() + ext
}

func selectAssets(rel release, archiveName string) (releaseAsset, releaseAsset, error) {
	var archive, sums releaseAsset
	seen := map[string]bool{}
	for _, asset := range rel.Assets {
		if asset.Name == "" {
			return releaseAsset{}, releaseAsset{}, fmt.Errorf("%w: release contains an unnamed asset", ErrInvalidRelease)
		}
		if seen[asset.Name] {
			return releaseAsset{}, releaseAsset{}, fmt.Errorf("%w: release contains duplicate asset %q", ErrInvalidRelease, asset.Name)
		}
		seen[asset.Name] = true
		switch asset.Name {
		case archiveName:
			archive = asset
		case "SHA256SUMS":
			sums = asset
		}
	}
	if archive.Name == "" || sums.Name == "" {
		return releaseAsset{}, releaseAsset{}, fmt.Errorf("%w: release is missing %s or SHA256SUMS", ErrInvalidRelease, archiveName)
	}
	return archive, sums, nil
}

func validateAssetDigest(asset releaseAsset, label string) error {
	if asset.Name != label {
		return fmt.Errorf("%w: unexpected asset %q", ErrInvalidRelease, asset.Name)
	}
	if asset.Size < 0 || asset.Size > DefaultMaxArchiveBytes {
		return fmt.Errorf("%w: asset %q exceeds the update size limit", ErrInvalidRelease, label)
	}
	if _, err := parseSHA256Digest(asset.Digest); err != nil {
		return fmt.Errorf("%w: asset %q has no valid GitHub SHA-256 digest: %v", ErrInvalidRelease, label, err)
	}
	for _, raw := range []string{asset.URL, asset.BrowserDownloadURL} {
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			return fmt.Errorf("%w: invalid URL for asset %q: %v", ErrInvalidRelease, label, err)
		}
		if err := validateGitHubURL(u); err != nil {
			return fmt.Errorf("%w: asset %q URL: %v", ErrInvalidRelease, label, err)
		}
	}
	if asset.URL == "" && asset.BrowserDownloadURL == "" {
		return fmt.Errorf("%w: asset %q has no download URL", ErrInvalidRelease, label)
	}
	return nil
}

func parseSHA256Digest(raw string) (string, error) {
	if !strings.HasPrefix(strings.ToLower(raw), "sha256:") {
		return "", errors.New("digest must use sha256:<64 hexadecimal characters>")
	}
	hexDigest := strings.TrimSpace(raw[len("sha256:"):])
	if len(hexDigest) != sha256.Size*2 {
		return "", errors.New("digest must contain 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(hexDigest); err != nil {
		return "", errors.New("digest contains non-hexadecimal characters")
	}
	return strings.ToLower(hexDigest), nil
}

func downloadBytes(ctx context.Context, client *http.Client, asset releaseAsset, limit int64) ([]byte, error) {
	u, err := assetURL(asset)
	if err != nil {
		return nil, err
	}
	if asset.Size > limit {
		return nil, fmt.Errorf("%w: asset %q is larger than the size limit", ErrInvalidRelease, asset.Name)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("wire-connect: create asset request: %w", err)
	}
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("User-Agent", "wire-connect-updater")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wire-connect: download %s: %w", asset.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, httpStatusError("download "+asset.Name, resp)
	}
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("%w: asset %q response exceeds the size limit", ErrInvalidRelease, asset.Name)
	}
	if limit > int64(int(^uint(0)>>1)) {
		return nil, fmt.Errorf("%w: asset size limit is too large", ErrInvalidRelease)
	}
	var b bytes.Buffer
	if resp.ContentLength > 0 {
		b.Grow(int(resp.ContentLength))
	}
	if err := copyLimited(ctx, &b, resp.Body, limit); err != nil {
		return nil, fmt.Errorf("wire-connect: read %s: %w", asset.Name, err)
	}
	return b.Bytes(), nil
}

func assetURL(asset releaseAsset) (*url.URL, error) {
	raw := asset.URL
	if raw == "" {
		raw = asset.BrowserDownloadURL
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid asset URL: %v", ErrInvalidRelease, err)
	}
	if err := validateGitHubURL(u); err != nil {
		return nil, err
	}
	return u, nil
}

func copyLimited(ctx context.Context, dst io.Writer, src io.Reader, limit int64) error {
	if limit <= 0 {
		return errors.New("invalid copy limit")
	}
	n, err := io.Copy(dst, io.LimitReader(src, limit+1))
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if n > limit {
		return fmt.Errorf("response exceeds %d bytes", limit)
	}
	return nil
}

func httpStatusError(operation string, resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	detail := strings.TrimSpace(string(b))
	if detail == "" {
		return fmt.Errorf("wire-connect: %s: HTTP %s", operation, resp.Status)
	}
	return fmt.Errorf("wire-connect: %s: HTTP %s: %s", operation, resp.Status, detail)
}

func prepareOffline(opts Options, target Target, limits limits) (archivePath, archiveName, version string, err error) {
	archivePath, err = filepath.Abs(opts.ArchivePath)
	if err != nil {
		return "", "", "", err
	}
	archivePath = filepath.Clean(archivePath)
	if err := validateRegularNoSymlink(archivePath); err != nil {
		return "", "", "", fmt.Errorf("wire-connect: offline archive: %w", err)
	}
	archiveName = filepath.Base(archivePath)
	version, err = offlineArchiveVersion(archiveName, target)
	if err != nil {
		return "", "", "", err
	}
	if opts.Version != "" {
		requested, reqErr := normalizeVersion(opts.Version)
		if reqErr != nil {
			return "", "", "", reqErr
		}
		if requested != version {
			return "", "", "", fmt.Errorf("%w: archive version %s does not match requested version %s", ErrInvalidRelease, version, requested)
		}
	}
	st, err := os.Stat(archivePath)
	if err != nil {
		return "", "", "", err
	}
	if st.Size() > limits.maxArchive {
		return "", "", "", fmt.Errorf("%w: offline archive exceeds the size limit", ErrInvalidRelease)
	}
	if err := validateRegularNoSymlink(opts.ChecksumsPath); err != nil {
		return "", "", "", fmt.Errorf("wire-connect: offline checksums: %w", err)
	}
	return archivePath, archiveName, version, nil
}

func offlineArchiveVersion(name string, target Target) (string, error) {
	suffix := "-" + target.String() + ".tar.gz"
	if target.GOOS == "windows" {
		suffix = "-" + target.String() + ".zip"
	}
	prefix := "wire-connect-"
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
		return "", fmt.Errorf("%w: offline archive must be named %s", ErrInvalidRelease, expectedArchiveName("<version>", target))
	}
	version := strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix)
	if _, err := normalizeVersion(version); err != nil {
		return "", fmt.Errorf("%w: invalid offline archive version: %v", ErrInvalidRelease, err)
	}
	return version, nil
}

func readRegularFile(name string, limit int64) ([]byte, error) {
	if err := validateRegularNoSymlink(name); err != nil {
		return nil, err
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readLimited(f, limit)
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("invalid read limit")
	}
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return b, nil
}

func validateRegularNoSymlink(name string) error {
	if name == "" {
		return errors.New("path is empty")
	}
	st, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return fmt.Errorf("path %q must be a regular file and not a symlink", name)
	}
	return nil
}

func readManifest(name string, limit int64) (offlineManifest, error) {
	b, err := readRegularFile(name, limit)
	if err != nil {
		return offlineManifest{}, fmt.Errorf("wire-connect: read offline manifest: %w", err)
	}
	var m offlineManifest
	if err := json.Unmarshal(b, &m); err != nil {
		return offlineManifest{}, fmt.Errorf("%w: decode offline manifest: %v", ErrInvalidRelease, err)
	}
	return m, nil
}

func verifyManifest(m offlineManifest, tag, archiveName, archiveDigest, checksumsDigest string) error {
	if m.Repository != Repository {
		return fmt.Errorf("%w: offline manifest repository is %q", ErrInvalidRelease, m.Repository)
	}
	if m.Tag == "" || (m.Tag != tag && strings.TrimPrefix(m.Tag, "v") != strings.TrimPrefix(tag, "v")) {
		return fmt.Errorf("%w: offline manifest tag does not match archive", ErrInvalidRelease)
	}
	if m.Asset != archiveName {
		return fmt.Errorf("%w: offline manifest asset does not match archive", ErrInvalidRelease)
	}
	manifestArchiveDigest, err := parsePlainSHA256(m.AssetSHA256)
	if err != nil || manifestArchiveDigest != archiveDigest {
		return fmt.Errorf("%w: offline manifest archive digest mismatch", ErrInvalidRelease)
	}
	if m.Checksums != "SHA256SUMS" {
		return fmt.Errorf("%w: offline manifest must identify SHA256SUMS", ErrInvalidRelease)
	}
	manifestChecksumsDigest, err := parsePlainSHA256(m.ChecksumsSHA256)
	if err != nil || manifestChecksumsDigest != checksumsDigest {
		return fmt.Errorf("%w: offline manifest checksums digest mismatch", ErrInvalidRelease)
	}
	return nil
}

func parsePlainSHA256(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) != sha256.Size*2 {
		return "", errors.New("SHA-256 must contain 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(raw); err != nil {
		return "", errors.New("SHA-256 contains non-hexadecimal characters")
	}
	return strings.ToLower(raw), nil
}

func verifyChecksumEntry(data []byte, archiveName, archiveDigest string) error {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	found := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return fmt.Errorf("%w: malformed SHA256SUMS line", ErrInvalidRelease)
		}
		digest, err := parsePlainSHA256(fields[0])
		if err != nil {
			return fmt.Errorf("%w: malformed SHA256SUMS digest: %v", ErrInvalidRelease, err)
		}
		name := strings.TrimPrefix(fields[1], "*")
		name = strings.TrimPrefix(name, "./")
		if name == archiveName {
			if found != "" {
				return fmt.Errorf("%w: SHA256SUMS contains duplicate %s entries", ErrInvalidRelease, archiveName)
			}
			found = digest
		}
	}
	if found == "" {
		return fmt.Errorf("%w: SHA256SUMS has no entry for %s", ErrInvalidRelease, archiveName)
	}
	if found != strings.ToLower(archiveDigest) {
		return fmt.Errorf("%w: SHA256SUMS digest mismatch for %s", ErrInvalidRelease, archiveName)
	}
	return nil
}

type archiveEntry struct {
	name string
	dir  bool
}

func extractExecutable(archivePath, archiveName string, target Target, limits limits) (extractedPackage, error) {
	archive, err := readRegularFile(archivePath, limits.maxArchive)
	if err != nil {
		return extractedPackage{}, fmt.Errorf("wire-connect: open verified archive: %w", err)
	}
	return extractExecutableBytes(archive, archiveName, target, limits)
}

// extractExecutableBytes parses the exact archive snapshot that Run verified.
// Keeping extraction on []byte avoids reopening a pathname after its digest has
// been checked, which would permit a local replacement race to change the
// installed image.
func extractExecutableBytes(archive []byte, archiveName string, target Target, limits limits) (extractedPackage, error) {
	if int64(len(archive)) > limits.maxArchive {
		return extractedPackage{}, fmt.Errorf("%w: verified archive exceeds the size limit", ErrInvalidRelease)
	}
	r := bytes.NewReader(archive)
	if strings.HasSuffix(archiveName, ".zip") {
		return extractZipReader(r, int64(len(archive)), target, limits)
	}
	return extractTarGzReader(r, target, limits)
}

func extractTarGz(f *os.File, target Target, limits limits) (extractedPackage, error) {
	return extractTarGzReader(f, target, limits)
}

func extractTarGzReader(r io.Reader, target Target, limits limits) (extractedPackage, error) {
	gz, err := gzip.NewReader(io.LimitReader(r, limits.maxArchive))
	if err != nil {
		return extractedPackage{}, fmt.Errorf("%w: open gzip archive: %v", ErrInvalidRelease, err)
	}
	defer gz.Close()
	tr := tar.NewReader(&countingReader{r: gz, limit: limits.maxExtracted})
	entries := map[string]archiveEntry{}
	var executable []byte
	var wintun, wintunLicense []byte
	count := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return extractedPackage{}, fmt.Errorf("%w: read tar archive: %v", ErrInvalidRelease, err)
		}
		count++
		if count > DefaultMaxArchiveEntries {
			return extractedPackage{}, fmt.Errorf("%w: archive contains too many entries", ErrInvalidRelease)
		}
		name, dir, err := cleanArchiveName(h.Name)
		if err != nil {
			return extractedPackage{}, err
		}
		if _, exists := entries[name]; exists {
			return extractedPackage{}, fmt.Errorf("%w: archive contains duplicate entry %q", ErrInvalidRelease, name)
		}
		entries[name] = archiveEntry{name: name, dir: dir}
		if h.Typeflag == tar.TypeSymlink || h.Typeflag == tar.TypeLink {
			return extractedPackage{}, fmt.Errorf("%w: archive contains a link %q", ErrInvalidRelease, name)
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA && h.Typeflag != tar.TypeDir {
			return extractedPackage{}, fmt.Errorf("%w: archive contains unsupported entry %q", ErrInvalidRelease, name)
		}
		if dir {
			if h.Typeflag != tar.TypeDir {
				return extractedPackage{}, fmt.Errorf("%w: archive directory %q has a non-directory type", ErrInvalidRelease, name)
			}
			continue
		}
		if h.Size < 0 || h.Size > DefaultMaxExtractedBytes || h.Size > limits.maxExtracted {
			return extractedPackage{}, fmt.Errorf("%w: archive entry %q exceeds the size limit", ErrInvalidRelease, name)
		}
		if err := ensureParents(entries, name); err != nil {
			return extractedPackage{}, err
		}
		want := expectedBinaryName(target)
		if name == want {
			if executable != nil {
				return extractedPackage{}, fmt.Errorf("%w: archive contains duplicate executable", ErrInvalidRelease)
			}
			executable, err = readLimited(tr, min64(h.Size, DefaultMaxExecutableBytes))
			if err != nil {
				return extractedPackage{}, fmt.Errorf("%w: read executable: %v", ErrInvalidRelease, err)
			}
			if int64(len(executable)) != h.Size {
				return extractedPackage{}, fmt.Errorf("%w: truncated executable entry", ErrInvalidRelease)
			}
		} else if target.GOOS == "windows" && name == "bin/wintun.dll" {
			if h.Size == 0 || h.Size > DefaultMaxExecutableBytes {
				return extractedPackage{}, fmt.Errorf("%w: Wintun runtime has an invalid size", ErrInvalidRelease)
			}
			wintun, err = readLimited(tr, h.Size)
			if err != nil || int64(len(wintun)) != h.Size {
				return extractedPackage{}, fmt.Errorf("%w: read Wintun runtime", ErrInvalidRelease)
			}
		} else if target.GOOS == "windows" && name == "bin/WINTUN-LICENSE.txt" {
			if h.Size == 0 || h.Size > DefaultMaxExecutableBytes {
				return extractedPackage{}, fmt.Errorf("%w: Wintun license has an invalid size", ErrInvalidRelease)
			}
			wintunLicense, err = readLimited(tr, h.Size)
			if err != nil || int64(len(wintunLicense)) != h.Size {
				return extractedPackage{}, fmt.Errorf("%w: read Wintun license", ErrInvalidRelease)
			}
		} else {
			if _, err := io.Copy(io.Discard, io.LimitReader(tr, h.Size)); err != nil {
				return extractedPackage{}, fmt.Errorf("%w: read archive entry: %v", ErrInvalidRelease, err)
			}
		}
	}
	if err := gz.Close(); err != nil {
		return extractedPackage{}, fmt.Errorf("%w: close gzip archive: %v", ErrInvalidRelease, err)
	}
	return finishExtraction(executable, target, wintun, wintunLicense)
}

func extractZip(f *os.File, target Target, limits limits) (extractedPackage, error) {
	st, err := f.Stat()
	if err != nil {
		return extractedPackage{}, fmt.Errorf("wire-connect: stat zip archive: %w", err)
	}
	if st.Size() > limits.maxArchive {
		return extractedPackage{}, fmt.Errorf("%w: zip archive exceeds the size limit", ErrInvalidRelease)
	}
	return extractZipReader(f, st.Size(), target, limits)
}

func extractZipReader(r io.ReaderAt, size int64, target Target, limits limits) (extractedPackage, error) {
	if size > limits.maxArchive {
		return extractedPackage{}, fmt.Errorf("%w: zip archive exceeds the size limit", ErrInvalidRelease)
	}
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return extractedPackage{}, fmt.Errorf("%w: open zip archive: %v", ErrInvalidRelease, err)
	}
	entries := map[string]archiveEntry{}
	var executable []byte
	var wintun, wintunLicense []byte
	var total int64
	for i, zf := range zr.File {
		if i >= DefaultMaxArchiveEntries {
			return extractedPackage{}, fmt.Errorf("%w: archive contains too many entries", ErrInvalidRelease)
		}
		name, dir, err := cleanArchiveName(zf.Name)
		if err != nil {
			return extractedPackage{}, err
		}
		key := name
		if target.GOOS == "windows" {
			key = strings.ToLower(name)
		}
		if _, exists := entries[key]; exists {
			return extractedPackage{}, fmt.Errorf("%w: archive contains duplicate entry %q", ErrInvalidRelease, name)
		}
		entries[key] = archiveEntry{name: name, dir: dir}
		mode := zf.Mode()
		if mode&os.ModeSymlink != 0 {
			return extractedPackage{}, fmt.Errorf("%w: archive contains a link %q", ErrInvalidRelease, name)
		}
		if dir {
			if !zf.FileInfo().IsDir() {
				return extractedPackage{}, fmt.Errorf("%w: archive directory %q has a non-directory type", ErrInvalidRelease, name)
			}
			continue
		}
		if !zf.FileInfo().Mode().IsRegular() && mode != 0 {
			return extractedPackage{}, fmt.Errorf("%w: archive contains unsupported entry %q", ErrInvalidRelease, name)
		}
		if zf.UncompressedSize64 > uint64(limits.maxExtracted) || zf.UncompressedSize64 > uint64(DefaultMaxExecutableBytes)<<32 {
			return extractedPackage{}, fmt.Errorf("%w: archive entry %q exceeds the size limit", ErrInvalidRelease, name)
		}
		if zf.UncompressedSize64 > uint64(limits.maxExtracted)-uint64(min64(total, limits.maxExtracted)) {
			return extractedPackage{}, fmt.Errorf("%w: archive contents exceed the size limit", ErrInvalidRelease)
		}
		total += int64(zf.UncompressedSize64)
		if err := ensureParents(entries, name); err != nil {
			return extractedPackage{}, err
		}
		reader, err := zf.Open()
		if err != nil {
			return extractedPackage{}, fmt.Errorf("%w: open archive entry %q: %v", ErrInvalidRelease, name, err)
		}
		want := expectedBinaryName(target)
		if name == want {
			if executable != nil {
				reader.Close()
				return extractedPackage{}, fmt.Errorf("%w: archive contains duplicate executable", ErrInvalidRelease)
			}
			executable, err = readLimited(reader, min64(int64(zf.UncompressedSize64), DefaultMaxExecutableBytes))
			reader.Close()
			if err != nil {
				return extractedPackage{}, fmt.Errorf("%w: read executable: %v", ErrInvalidRelease, err)
			}
			if uint64(len(executable)) != zf.UncompressedSize64 {
				return extractedPackage{}, fmt.Errorf("%w: truncated executable entry", ErrInvalidRelease)
			}
		} else if target.GOOS == "windows" && name == "bin/wintun.dll" {
			if zf.UncompressedSize64 == 0 || zf.UncompressedSize64 > uint64(DefaultMaxExecutableBytes) {
				reader.Close()
				return extractedPackage{}, fmt.Errorf("%w: Wintun runtime has an invalid size", ErrInvalidRelease)
			}
			wintun, err = readLimited(reader, int64(zf.UncompressedSize64))
			closeErr := reader.Close()
			if err != nil || closeErr != nil || uint64(len(wintun)) != zf.UncompressedSize64 {
				return extractedPackage{}, fmt.Errorf("%w: read Wintun runtime", ErrInvalidRelease)
			}
		} else if target.GOOS == "windows" && name == "bin/WINTUN-LICENSE.txt" {
			if zf.UncompressedSize64 == 0 || zf.UncompressedSize64 > uint64(DefaultMaxExecutableBytes) {
				reader.Close()
				return extractedPackage{}, fmt.Errorf("%w: Wintun license has an invalid size", ErrInvalidRelease)
			}
			wintunLicense, err = readLimited(reader, int64(zf.UncompressedSize64))
			closeErr := reader.Close()
			if err != nil || closeErr != nil || uint64(len(wintunLicense)) != zf.UncompressedSize64 {
				return extractedPackage{}, fmt.Errorf("%w: read Wintun license", ErrInvalidRelease)
			}
		} else {
			_, copyErr := io.Copy(io.Discard, io.LimitReader(reader, limits.maxExtracted+1))
			closeErr := reader.Close()
			if copyErr != nil || closeErr != nil {
				return extractedPackage{}, fmt.Errorf("%w: read archive entry %q", ErrInvalidRelease, name)
			}
		}
	}
	return finishExtraction(executable, target, wintun, wintunLicense)
}

func expectedBinaryName(target Target) string {
	if target.GOOS == "windows" {
		return "bin/wirectl-connect.exe"
	}
	return "bin/wirectl-connect"
}

func finishExtraction(executable []byte, target Target, wintun, wintunLicense []byte) (extractedPackage, error) {
	if len(executable) == 0 {
		return extractedPackage{}, fmt.Errorf("%w: archive has no %s", ErrInvalidRelease, expectedBinaryName(target))
	}
	if target.GOOS == "windows" && (len(wintun) == 0 || len(wintunLicense) == 0) {
		return extractedPackage{}, fmt.Errorf("%w: Windows archive must contain official bin/wintun.dll and bin/WINTUN-LICENSE.txt", ErrInvalidRelease)
	}
	return extractedPackage{Executable: executable, Wintun: wintun, WintunLicense: wintunLicense}, nil
}

func cleanArchiveName(raw string) (name string, dir bool, err error) {
	if raw == "" || strings.IndexByte(raw, 0) >= 0 || strings.Contains(raw, "\\") {
		return "", false, fmt.Errorf("%w: archive contains an unsafe path %q", ErrInvalidRelease, raw)
	}
	dir = strings.HasSuffix(raw, "/")
	name = strings.TrimSuffix(raw, "/")
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, ":") {
		return "", false, fmt.Errorf("%w: archive contains an unsafe path %q", ErrInvalidRelease, raw)
	}
	clean := path.Clean(name)
	if clean != name || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false, fmt.Errorf("%w: archive contains a path traversal entry %q", ErrInvalidRelease, raw)
	}
	return name, dir, nil
}

func ensureParents(entries map[string]archiveEntry, name string) error {
	parts := strings.Split(name, "/")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[:i], "/")
		entry, ok := entries[parent]
		if !ok {
			// tar and zip writers are allowed to omit explicit directory
			// entries; an absent parent is therefore fine.
			continue
		}
		if !entry.dir {
			return fmt.Errorf("%w: archive path %q is beneath a regular file", ErrInvalidRelease, name)
		}
	}
	return nil
}

type countingReader struct {
	r     io.Reader
	limit int64
	n     int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	if r.n >= r.limit {
		return 0, fmt.Errorf("archive contents exceed %d bytes", r.limit)
	}
	remaining := r.limit - r.n
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := r.r.Read(p)
	r.n += int64(n)
	if r.n >= r.limit && err == nil {
		// Let the next read produce the limit error, so an archive that ends
		// exactly at the configured limit remains valid.
	}
	return n, err
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func digestFile(name string, limit int64) (string, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if err := copyLimited(context.Background(), h, f, limit); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func digestBytes(b []byte) string {
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

func replaceCurrentExecutable(ctx context.Context, override string, packageFiles extractedPackage, refreshStateDir string) (string, bool, bool, error) {
	if err := ctx.Err(); err != nil {
		return "", false, false, err
	}
	path, err := executablePath(override)
	if err != nil {
		return "", false, false, err
	}
	// Re-resolve the override immediately before touching the installation. A
	// launcher symlink may have changed while the release was being fetched;
	// the final path must still be allowed for self-update.
	if err := ensureSelfUpdateAllowed(path); err != nil {
		return "", false, false, err
	}
	if err := validateInstallTarget(path); err != nil {
		return "", false, false, err
	}
	current, err := os.ReadFile(path)
	if err != nil {
		return "", false, false, fmt.Errorf("wire-connect: read current executable: %w", err)
	}
	if digestBytes(current) == digestBytes(packageFiles.Executable) {
		runtimeMatch, err := runtimeFilesMatch(path, packageFiles)
		if err != nil {
			return "", false, false, err
		}
		if runtimeMatch {
			return path, true, false, nil
		}
	}
	st, err := os.Stat(path)
	if err != nil {
		return "", false, false, fmt.Errorf("wire-connect: inspect current executable: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".wire-connect-executable-*")
	if err != nil {
		return "", false, false, classifyInstallError("create replacement", err)
	}
	tmpPath := tmp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(st.Mode().Perm()); err != nil {
		_ = tmp.Close()
		return "", false, false, classifyInstallError("set replacement permissions", err)
	}
	if _, err := tmp.Write(packageFiles.Executable); err != nil {
		_ = tmp.Close()
		return "", false, false, classifyInstallError("write replacement", err)
	}
	if err := ctx.Err(); err != nil {
		_ = tmp.Close()
		return "", false, false, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", false, false, classifyInstallError("sync replacement", err)
	}
	if err := tmp.Close(); err != nil {
		return "", false, false, classifyInstallError("close replacement", err)
	}
	// Refuse to follow a path changed after the initial validation.  The
	// destination is resolved and checked again immediately before Rename.
	if err := validateInstallTarget(path); err != nil {
		return "", false, false, err
	}
	pending, err := installStagedExecutable(ctx, tmpPath, path, digestBytes(packageFiles.Executable), packageFiles, refreshStateDir)
	if err != nil {
		return "", false, false, classifyInstallError("replace executable", err)
	}
	if pending {
		// The Windows helper owns this path from now on.  Removing it here
		// would leave the helper with a missing source after this process exits.
		removeTemp = false
		return path, false, true, nil
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return "", false, false, classifyInstallError("sync executable directory", err)
	}
	return path, false, false, nil
}

func executablePath(override string) (string, error) {
	p := override
	if p == "" {
		var err error
		p, err = os.Executable()
		if err != nil {
			return "", fmt.Errorf("wire-connect: locate current executable: %w", err)
		}
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("wire-connect: resolve current executable: %w", err)
	}
	abs = filepath.Clean(abs)
	resolved, err := installpath.Resolve(abs)
	if err != nil {
		return "", fmt.Errorf("wire-connect: resolve executable symlink: %w", err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("wire-connect: resolve executable target: %w", err)
	}
	if filepath.Base(resolved) == "" || resolved == string(filepath.Separator) {
		return "", fmt.Errorf("%w: executable target is invalid", ErrInvalidRelease)
	}
	return filepath.Clean(resolved), nil
}

func validateInstallTarget(name string) error {
	if err := validateUpdateDestinationSecurity(name); err != nil {
		return err
	}
	st, err := os.Lstat(name)
	if err != nil {
		return fmt.Errorf("wire-connect: inspect installation target: %w", err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return fmt.Errorf("wire-connect: installation target must be a regular file, not a symlink")
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("wire-connect: installation target is not executable")
	}
	if st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("wire-connect: refusing to replace an executable with special permission bits")
	}
	// EvalSymlinks has already resolved the launcher path.  Check the entire
	// remaining directory chain as well, so a writable or replaced ancestor
	// cannot redirect the atomic rename to an unintended location.
	for current := filepath.Dir(name); ; current = filepath.Dir(current) {
		pst, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("wire-connect: inspect executable directory: %w", err)
		}
		if pst.Mode()&os.ModeSymlink != 0 || !pst.IsDir() {
			return fmt.Errorf("wire-connect: executable directory must be a real directory")
		}
		if runtime.GOOS != "windows" && pst.Mode().Perm()&0022 != 0 && pst.Mode().Perm()&01000 == 0 {
			return fmt.Errorf("wire-connect: refusing to update from a group/world-writable executable directory")
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	return nil
}

func syncDirectory(name string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func classifyInstallError(operation string, err error) error {
	if err == nil {
		return nil
	}
	lower := strings.ToLower(err.Error())
	if errors.Is(err, os.ErrPermission) || strings.Contains(lower, "permission denied") || strings.Contains(lower, "access is denied") {
		return fmt.Errorf("%w: %s: %v", ErrNeedsAdmin, operation, err)
	}
	if strings.Contains(lower, "text file busy") || strings.Contains(lower, "sharing violation") || strings.Contains(lower, "used by another process") {
		return fmt.Errorf("%w: %s: %v; stop the background service and close other instances, then retry", ErrExecutableInUse, operation, err)
	}
	return fmt.Errorf("wire-connect: %s: %w", operation, err)
}
