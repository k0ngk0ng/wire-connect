package control

import (
	"errors"
	"fmt"
	"os"
	"sync"
)

// ErrStateLocked means another control service currently owns the state
// directory.  Returning this error instead of waiting forever prevents a
// second accidental service launch from serving a stale view of the state.
var ErrStateLocked = errors.New("control: state directory is already locked")

type stateLock struct {
	file *os.File
	once sync.Once
	err  error
}

func acquireStateLock(path string) (*stateLock, error) {
	if info, err := os.Lstat(path); err == nil {
		if !privateFileInfo(info) {
			return nil, ErrStateInsecure
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect state lock: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, fmt.Errorf("open state lock: %w", err)
	}
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("protect state lock: %w", err)
	}
	if err := lockFile(f); err != nil {
		_ = f.Close()
		if errors.Is(err, ErrStateLocked) {
			return nil, ErrStateLocked
		}
		return nil, fmt.Errorf("lock state: %w", err)
	}
	return &stateLock{file: f}, nil
}

func (l *stateLock) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		if err := unlockFile(l.file); err != nil {
			l.err = err
		}
		if err := l.file.Close(); err != nil && l.err == nil {
			l.err = err
		}
	})
	return l.err
}
