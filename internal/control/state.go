package control

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"unicode/utf8"
)

// diskState intentionally contains no fields for plaintext credentials.  A
// strict decoder makes accidentally introducing such a field a state format
// error instead of silently accepting it.
type diskState struct {
	Version        int          `json:"version"`
	EnrollmentHash string       `json:"enrollment_hash"`
	Devices        []diskDevice `json:"devices"`
	Pairs          []diskPair   `json:"pairs"`
}

type diskDevice struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	TokenHash string `json:"token_hash"`
	Revoked   bool   `json:"revoked,omitempty"`
}

type diskPair struct {
	ID          string `json:"id"`
	HostDevice  string `json:"host_device"`
	GuestDevice string `json:"guest_device"`
}

func prepareStateDir(path string) (string, error) {
	path = filepath.Clean(path)
	if path == "." || path == string(filepath.Separator) {
		return "", ErrStateInsecure
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0700); err != nil {
			return "", fmt.Errorf("create state directory: %w", err)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return "", fmt.Errorf("inspect state directory: %w", err)
	}
	if !privateDirInfo(info) {
		return "", ErrStateInsecure
	}
	return path, nil
}

func (s *Server) loadState() (bool, error) {
	info, err := os.Lstat(s.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect state file: %w", err)
	}
	if !privateFileInfo(info) {
		return false, ErrStateInsecure
	}
	f, err := os.Open(s.statePath)
	if err != nil {
		return false, fmt.Errorf("open state file: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxStateBytes+1))
	if err != nil {
		return false, fmt.Errorf("read state file: %w", err)
	}
	if len(data) > maxStateBytes {
		return false, errors.New("control: state file is too large")
	}
	var disk diskState
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&disk); err != nil {
		return false, fmt.Errorf("decode state file: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return false, errors.New("control: state file has trailing data")
	}
	if disk.Version != stateVersion {
		return false, fmt.Errorf("control: unsupported state version %d", disk.Version)
	}
	enrollment, ok := normalizeHex(disk.EnrollmentHash, 64)
	if !ok {
		return false, errors.New("control: invalid enrollment hash in state")
	}
	if !s.enrollmentConfigured {
		decoded, err := hex.DecodeString(enrollment)
		if err != nil || len(decoded) != len(s.enrollmentHash) {
			return false, errors.New("control: invalid enrollment hash in state")
		}
		copy(s.enrollmentHash[:], decoded)
	} else if !secureEqual([]byte(enrollment), []byte(hex.EncodeToString(s.enrollmentHash[:]))) {
		return false, ErrEnrollmentMismatch
	}
	if len(disk.Devices) > maxDevices {
		return false, errors.New("control: state has too many devices")
	}
	if len(disk.Pairs) > maxPairs {
		return false, errors.New("control: state has too many pairs")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	pairDeviceCounts := make(map[string]int)
	for _, pd := range disk.Devices {
		id, validID := normalizeHex(pd.ID, 32)
		tokenHash, validHash := normalizeHex(pd.TokenHash, 64)
		if !validID || !validHash || len(pd.Name) > 128 || !utf8.ValidString(pd.Name) {
			return false, errors.New("control: invalid device in state")
		}
		if _, exists := s.devices[id]; exists {
			return false, errors.New("control: duplicate device in state")
		}
		if _, exists := s.byTokenHash[tokenHash]; exists {
			return false, errors.New("control: duplicate device token hash in state")
		}
		d := &device{ID: id, Name: pd.Name, TokenHash: tokenHash, Revoked: pd.Revoked}
		s.devices[id] = d
		s.byTokenHash[tokenHash] = id
	}
	for _, pp := range disk.Pairs {
		id, validID := normalizeHex(pp.ID, 64)
		host, validHost := normalizeHex(pp.HostDevice, 32)
		guest, validGuest := normalizeHex(pp.GuestDevice, 32)
		if !validID || !validHost || !validGuest || host == guest {
			return false, errors.New("control: invalid pair in state")
		}
		if s.devices[host] == nil || s.devices[guest] == nil {
			return false, errors.New("control: pair references unknown device")
		}
		if _, exists := s.pairs[id]; exists {
			return false, errors.New("control: duplicate pair in state")
		}
		if pairDeviceCounts[host] >= maxPairsPerDevice || pairDeviceCounts[guest] >= maxPairsPerDevice {
			return false, errors.New("control: device has too many pairs in state")
		}
		s.pairs[id] = &pairState{Pair: Pair{ID: id, HostDevice: host, GuestDevice: guest}}
		pairDeviceCounts[host]++
		pairDeviceCounts[guest]++
	}
	return true, nil
}

func (s *Server) saveStateLocked() error {
	if info, err := os.Lstat(s.cfg.StateDir); err != nil || !privateDirInfo(info) {
		if err != nil {
			return fmt.Errorf("inspect state directory: %w", err)
		}
		return ErrStateInsecure
	}
	if info, err := os.Lstat(s.statePath); err == nil {
		if !privateFileInfo(info) {
			return ErrStateInsecure
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect state file: %w", err)
	}
	disk := diskState{
		Version:        stateVersion,
		EnrollmentHash: hex.EncodeToString(s.enrollmentHash[:]),
		Devices:        make([]diskDevice, 0, len(s.devices)),
		Pairs:          make([]diskPair, 0, len(s.pairs)),
	}
	deviceIDs := make([]string, 0, len(s.devices))
	for id := range s.devices {
		deviceIDs = append(deviceIDs, id)
	}
	sort.Strings(deviceIDs)
	for _, id := range deviceIDs {
		d := s.devices[id]
		disk.Devices = append(disk.Devices, diskDevice{ID: d.ID, Name: d.Name, TokenHash: d.TokenHash, Revoked: d.Revoked})
	}
	pairIDs := make([]string, 0, len(s.pairs))
	for id := range s.pairs {
		pairIDs = append(pairIDs, id)
	}
	sort.Strings(pairIDs)
	for _, id := range pairIDs {
		p := s.pairs[id]
		disk.Pairs = append(disk.Pairs, diskPair{ID: p.ID, HostDevice: p.HostDevice, GuestDevice: p.GuestDevice})
	}
	data, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	data = append(data, '\n')

	// O_EXCL prevents following a pre-existing symlink.  A random suffix is
	// not secret; it only avoids colliding with another process's temp file.
	tmpID, err := randomDeviceID()
	if err != nil {
		return fmt.Errorf("create state temp name: %w", err)
	}
	tmpPath := filepath.Join(s.cfg.StateDir, ".state-"+tmpID+".tmp")
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create state temp file: %w", err)
	}
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		return fmt.Errorf("protect state temp file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write state temp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync state temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close state temp file: %w", err)
	}
	if err := os.Rename(tmpPath, s.statePath); err != nil {
		return fmt.Errorf("replace state file: %w", err)
	}
	removeTemp = false
	// Syncing the directory makes the rename durable on Unix.  Some Windows
	// filesystems do not permit opening a directory; the atomic rename remains
	// the important invariant there.
	if dir, err := os.Open(s.cfg.StateDir); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func privateDirInfo(info os.FileInfo) bool {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false
	}
	// Windows ACLs are not represented by Unix permission bits.  The service
	// still rejects reparse-point symlinks, while native ACLs remain the OS
	// authority for access control.
	if runtime.GOOS == "windows" {
		return true
	}
	return info.Mode().Perm()&0077 == 0 && info.Mode().Perm()&0700 == 0700
}

func privateFileInfo(info os.FileInfo) bool {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return info.Mode().Perm() == 0600
}
