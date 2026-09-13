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
	if err := os.MkdirAll(s.Dir, 0700); err != nil {
		return err
	}
	st, err := os.Lstat(s.Dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return errors.New("state directory must be a real directory")
	}
	return protect(s.Dir, true)
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
	if err := checkPrivate(st); err != nil {
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
	if st, err := os.Lstat(p); err == nil && !st.Mode().IsRegular() {
		return errors.New("refusing to replace non-regular state file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
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
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	return syncDir(s.Dir)
}

func (s Store) Credentials() (map[string]Credential, error) {
	m := map[string]Credential{}
	err := s.Read("credentials", &m)
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return m, err
}
