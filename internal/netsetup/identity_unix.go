//go:build (linux && (amd64 || arm64)) || (darwin && arm64)

package netsetup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
)

func currentIdentity() (string, error) {
	// Use the effective uid: the helper endpoint and the privilege decision
	// both operate on the identity that owns the running process, including a
	// deliberately installed setuid wrapper.
	uid := os.Geteuid()
	if uid < 0 {
		return "", errors.New("wire-connect: operating system returned an invalid uid")
	}
	return strconv.Itoa(uid), nil
}

func normalizeIdentity(identity string) (string, error) {
	if identity == "" {
		return "", errors.New("wire-connect: helper identity is required")
	}
	uid, err := strconv.ParseUint(identity, 10, 32)
	if err != nil {
		return "", fmt.Errorf("wire-connect: helper identity %q must be a decimal uid", identity)
	}
	canonical := strconv.FormatUint(uid, 10)
	if identity != canonical {
		return "", fmt.Errorf("wire-connect: helper identity %q is not canonical", identity)
	}
	return canonical, nil
}

func validateExecutablePlatform(st os.FileInfo) error {
	if st.Mode()&0111 == 0 {
		return errors.New("wire-connect: helper executable is not executable")
	}
	return nil
}

func elevated() bool { return os.Geteuid() == 0 }

func requestElevation(ctx context.Context, executable, identity string, in io.Reader, out, errOut io.Writer) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	sudo, err := trustedSudo()
	if err != nil {
		return err
	}
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = io.Discard
	}
	if errOut == nil {
		errOut = os.Stderr
	}

	// The command and executable are both absolute paths.  No shell, PATH
	// lookup, or inherited user command is involved.  sudo's normal terminal
	// interaction remains available through the supplied streams.
	cmd := exec.CommandContext(ctx, sudo, "--", executable, "__setup-network", "--identity", identity)
	cmd.Stdin = in
	cmd.Stdout = out
	cmd.Stderr = errOut
	// The elevated operation does not need the caller's environment.  Keep a
	// small fixed PATH for programs which inspect it, and a neutral HOME so a
	// one-shot installer cannot redirect state through user environment data.
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/"}
	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return ctx.Err()
		}
		return fmt.Errorf("wire-connect: request administrator authorization with sudo: %w", err)
	}
	return nil
}

func trustedSudo() (string, error) {
	for _, path := range []string{"/usr/bin/sudo", "/bin/sudo"} {
		st, err := os.Lstat(path)
		if err != nil {
			continue
		}
		if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() || st.Mode()&0111 == 0 {
			continue
		}
		return path, nil
	}
	return "", errors.New("wire-connect: sudo was not found at /usr/bin/sudo or /bin/sudo")
}
