// Package config stores client credentials and paired device identities.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

type Credential struct {
	Token             string `json:"token"`
	DeviceID          string `json:"device_id"`
	CertificateSHA256 string `json:"certificate_sha256,omitempty"`
}

type Profile struct {
	Server          string `json:"server"`
	PairID          string `json:"pair_id"`
	Host            bool   `json:"host"`
	Secret          []byte `json:"secret"`
	WirePrivate     []byte `json:"wire_private"`
	RelayPrivate    string `json:"relay_private"`
	PeerWirePublic  string `json:"peer_wire_public"`
	PeerRelayPublic string `json:"peer_relay_public"`
	LocalIP         string `json:"local_ip"`
	PeerIP          string `json:"peer_ip"`
	Interface       string `json:"interface,omitempty"`
	MTU             int    `json:"mtu,omitempty"`
	STUNURL         string `json:"stun_url,omitempty"`
	RelayOnly       bool   `json:"relay_only,omitempty"`
}

type Store struct{ Dir string }

func DefaultDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "wire-connect"), nil
}

func (s Store) Init() error {
	if s.Dir == "" {
		return errors.New("empty state directory")
	}
	dir := filepath.Clean(s.Dir)
	if isRootDirectory(dir) {
		return fmt.Errorf("state directory %q must be a dedicated directory, not a filesystem root", dir)
	}

	st, err := os.Lstat(dir)
	if err == nil {
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return errors.New("state directory must be a real directory")
		}
		// Existing directories are caller-owned. Never silently change an
		// unknown directory's permissions or ACL; accept it only when it is
		// already private according to the platform policy.
		return checkPrivateDir(dir, st)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	// Create the final directory with an atomic Mkdir after preparing its
	// parent. If another process wins the race, its directory is treated as
	// existing and validated instead of having its permissions rewritten.
	if err := os.MkdirAll(filepath.Dir(dir), 0700); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		st, statErr := os.Lstat(dir)
		if statErr != nil {
			return statErr
		}
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return errors.New("state directory must be a real directory")
		}
		return checkPrivateDir(dir, st)
	}
	if err := protect(dir, true); err != nil {
		return fmt.Errorf("protect new state directory: %w", err)
	}
	st, err = os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return errors.New("state directory must be a real directory")
	}
	return checkPrivateDir(dir, st)
}

var validName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

func (s Store) path(name string) (string, error) {
	if !validName.MatchString(name) {
		return "", errors.New("invalid state name")
	}
	return filepath.Join(s.Dir, name+".json"), nil
}

func (s Store) Read(name string, dst any) error {
	if err := s.Init(); err != nil {
		return err
	}
	p, err := s.path(name)
	if err != nil {
		return err
	}
	st, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return errors.New("state file must be a regular file")
	}
	if err := checkPrivate(p, st); err != nil {
		return err
	}
	if st.Size() > 1<<20 {
		return errors.New("state file exceeds size limit")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, dst); err != nil {
		return fmt.Errorf("invalid state %s: %w", name, err)
	}
	return nil
}

func (s Store) Write(name string, value any) error {
	if err := s.Init(); err != nil {
		return err
	}
	p, err := s.path(name)
	if err != nil {
		return err
	}
	// Recheck the parent immediately before creating the temporary file. This
	// keeps an atomic write from following a replaced directory/symlink after
	// Init has already validated it.
	dirInfo, err := os.Lstat(s.Dir)
	if err != nil {
		return err
	}
	if !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("state directory must be a real directory")
	}
	if err := checkPrivateDir(s.Dir, dirInfo); err != nil {
		return err
	}
	if st, err := os.Lstat(p); err == nil {
		if !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
			return errors.New("refusing to replace non-regular state file")
		}
		if err := checkPrivate(p, st); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.Dir, ".state-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = protect(tmp, false); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(append(b, '\n')); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := replaceFile(tmp, p); err != nil {
		return err
	}
	return syncDir(s.Dir)
}

func isRootDirectory(path string) bool {
	clean := filepath.Clean(path)
	volume := filepath.VolumeName(clean)
	if volume == "" {
		return clean == string(filepath.Separator)
	}
	return clean == volume+string(filepath.Separator)
}

func (s Store) Credentials() (map[string]Credential, error) {
	m := map[string]Credential{}
	err := s.Read("credentials", &m)
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return m, err
}

// Remove deletes only the named state file, preserving all other profiles and
// credentials. Missing files are already removed; unsafe paths are rejected.
func (s Store) Remove(name string) error {
	if err := s.Init(); err != nil {
		return err
	}
	p, err := s.path(name)
	if err != nil {
		return err
	}
	st, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return errors.New("refusing to remove non-regular state file")
	}
	if err := checkPrivate(p, st); err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(s.Dir)
}
