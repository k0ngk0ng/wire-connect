package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/k0ngk0ng/wire-connect/internal/client"
	"github.com/k0ngk0ng/wire-connect/internal/config"
	"github.com/k0ngk0ng/wire-connect/internal/installpath"
	"github.com/k0ngk0ng/wire-connect/internal/localctl"
	"github.com/k0ngk0ng/wire-connect/internal/nethelper"
	"github.com/k0ngk0ng/wire-connect/internal/netsetup"
	"github.com/k0ngk0ng/wire-connect/internal/platform"
	"github.com/k0ngk0ng/wire-connect/internal/service"
	"github.com/k0ngk0ng/wire-connect/internal/update"
	"golang.org/x/term"
	"golang.zx2c4.com/wireguard/tun"
)

func currentExecutable() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	return installpath.Resolve(p)
}
func (a app) ensureNetwork(ctx context.Context) error {
	err := platform.Check(ctx)
	if err == nil {
		return nil
	}
	if netsetup.Elevated() {
		return err
	}
	in, ok := a.in.(*os.File)
	if !ok || !term.IsTerminal(int(in.Fd())) {
		return fmt.Errorf("%w; initialize network access with wirectl connect setup from an interactive terminal", err)
	}
	return a.setup(ctx, nil)
}
func (a app) setup(ctx context.Context, args []string) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(a.out, "Usage: wirectl connect setup\nInstall the network helper for this account with administrator authorization.")
		return nil
	}
	if len(args) != 0 {
		return errors.New("usage: wirectl connect setup")
	}
	exe, err := currentExecutable()
	if err != nil {
		return err
	}
	id, err := netsetup.CurrentIdentity()
	if err != nil {
		return err
	}
	fmt.Fprintln(a.errOut, "Installing the network helper. Administrator authorization is needed; credentials stay with your current account.")
	if err := netsetup.Ensure(ctx, exe, id, a.in, a.out, a.errOut); err != nil {
		return err
	}
	waitCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	for {
		if err := nethelper.Check(waitCtx); err == nil {
			fmt.Fprintln(a.out, "Network helper ready. Run connect with your current account.")
			return nil
		}
		select {
		case <-waitCtx.Done():
			return errors.New("network helper did not become ready after installation")
		case <-time.After(200 * time.Millisecond):
		}
	}
}
func (a app) networkCommand(ctx context.Context, args []string, install bool) error {
	f := flag.NewFlagSet("network-helper", flag.ContinueOnError)
	f.SetOutput(a.errOut)
	id := f.String("identity", "", "authorized OS identity")
	name := f.String("name", "", "native service name")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || netsetup.HelperName(*id) == "" {
		return errors.New("invalid helper identity")
	}
	if !netsetup.Elevated() {
		return netsetup.ErrElevationRequired
	}
	if install {
		exe, err := currentExecutable()
		if err != nil {
			return err
		}
		return netsetup.Install(ctx, netsetup.Config{Executable: exe, Identity: *id})
	}
	if *name != netsetup.HelperName(*id) {
		return errors.New("network helper service name does not match identity")
	}
	return nethelper.Serve(ctx, *id, func(ctx context.Context, cfg nethelper.Config) (tun.Device, func() error, error) {
		local, err := netip.ParseAddr(cfg.Local)
		if err != nil {
			return nil, nil, err
		}
		peer, err := netip.ParseAddr(cfg.Peer)
		if err != nil {
			return nil, nil, err
		}
		return platform.Open(ctx, platform.Config{Name: cfg.Name, Local: local, Peer: peer, MTU: cfg.MTU})
	})
}
func installClient(ctx context.Context, cfg service.Config) error {
	if netsetup.Elevated() {
		return service.Install(ctx, cfg)
	}
	return service.UserInstall(ctx, cfg)
}
func stopClient(ctx context.Context, name string, uninstall bool) error {
	if netsetup.Elevated() {
		if uninstall {
			return service.Uninstall(ctx, name)
		}
		return service.Stop(ctx, name)
	}
	if uninstall {
		return service.UserUninstall(ctx, name)
	}
	return service.UserStop(ctx, name)
}
func clientServiceStatus(ctx context.Context, name string) (string, error) {
	if netsetup.Elevated() {
		return service.Status(ctx, name)
	}
	return service.UserStatus(ctx, name)
}

func (a app) waitBackground(ctx context.Context, s config.Store, name string) error {
	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		var st client.Status
		if err := localctl.Status(waitCtx, s.Dir, name, &st); err == nil && st.Running && !st.LastHandshake.IsZero() {
			fmt.Fprintln(a.out, "Connected in background")
			printConnections(a.out, []connectionStatus{{Name: name, Status: st}}, statusColor(a.out))
			fmt.Fprintf(a.out, "You may close this terminal.\n  Status: wirectl connect status\n  Stop:   wirectl connect stop --name %s\n", name)
			return nil
		}
		select {
		case <-waitCtx.Done():
			if ctx.Err() != nil {
				return ctx.Err()
			}
			checkCtx, checkCancel := context.WithTimeout(ctx, 3*time.Second)
			defer checkCancel()
			if err := localctl.Status(checkCtx, s.Dir, name, &st); err != nil {
				state, serviceErr := clientServiceStatus(checkCtx, name)
				return fmt.Errorf("background connection did not become ready (service %q): %w; inspect the service logs or run resume --foreground", state, errors.Join(err, serviceErr))
			}
			if st.Running {
				fmt.Fprintln(a.out, "Background connection is running; still waiting for the peer. You may close this terminal. Use: wirectl connect status")
			} else {
				fmt.Fprintln(a.out, "Background service is still initializing. You may close this terminal. Use: wirectl connect status")
			}
			return nil
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (a app) update(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("update", flag.ContinueOnError)
	f.SetOutput(a.errOut)
	version := f.String("version", "", "release version (default: latest)")
	archive := f.String("archive", "", "offline release archive")
	checksums := f.String("checksums", "", "offline SHA256SUMS file")
	manifest := f.String("manifest", "", "independently trusted offline release digest manifest")
	stateDir := f.String("state-dir", "", "refresh background connections using this private state directory")
	if err := parse(f, args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("update takes options only")
	}
	fmt.Fprintln(a.out, "Checking and verifying the release…")
	result, err := update.Run(ctx, update.Options{Version: *version, ArchivePath: *archive, ChecksumsPath: *checksums, ManifestPath: *manifest, RefreshStateDir: *stateDir}, a.out)
	if err != nil {
		return err
	}
	if result.Pending {
		fmt.Fprintf(a.out, "Verified %s. The Windows updater will finish after this command exits; then check wirectl connect version.\n", result.Version)
		return nil
	}
	if result.AlreadyUpToDate {
		fmt.Fprintf(a.out, "Already up to date: %s.\n", result.Version)
		return nil
	}
	// Let the new version refresh its own helper and saved service copies.
	refreshArgs := []string{"__refresh-update"}
	if *stateDir != "" {
		refreshArgs = append(refreshArgs, "--state-dir", *stateDir)
	}
	cmd := exec.CommandContext(ctx, result.InstalledPath, refreshArgs...)
	cmd.Stdin = a.in
	cmd.Stdout = a.out
	cmd.Stderr = a.errOut
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("CLI updated, but background components need attention: %w; run wirectl connect setup and resume", err)
	}
	fmt.Fprintf(a.out, "Updated wirectl connect to %s.\n", result.Version)
	return nil
}
func (a app) refreshUpdate(ctx context.Context, args []string) error {
	f, c, err := a.flags("refresh-update")
	if err != nil {
		return err
	}
	if err := parse(f, args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("refresh-update takes options only")
	}
	exe, err := currentExecutable()
	if err != nil {
		return err
	}
	id, err := netsetup.CurrentIdentity()
	if err != nil {
		return err
	}
	refreshHelper := func() error {
		if _, err := netsetup.Status(ctx, id); err == nil {
			return netsetup.Ensure(ctx, exe, id, a.in, a.out, a.errOut)
		} else if !errors.Is(err, netsetup.ErrNotInstalled) {
			return err
		}
		return nil
	}
	dir, err := c.stateDir()
	if err != nil {
		return err
	}
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return refreshHelper()
	} else if err != nil {
		return err
	}
	s, err := (&common{dir: dir, name: "default"}).store()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return err
	}
	var active []string
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "profile-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		name = strings.TrimSuffix(strings.TrimPrefix(name, "profile-"), ".json")
		if !profileName.MatchString(name) {
			continue
		}
		state, err := clientServiceStatus(ctx, name)
		if errors.Is(err, service.ErrNotInstalled) {
			continue
		}
		if err != nil {
			return err
		}
		if state == "stopped" || state == "disabled" || state == "inactive" || state == "exited" {
			continue
		}
		active = append(active, name)
	}
	// Snapshot active jobs before restarting the helper, which briefly closes
	// their TUN sessions. A stopped profile stays stopped until explicit resume.
	if err := refreshHelper(); err != nil {
		return err
	}
	for _, name := range active {
		if err := installClient(ctx, service.Config{Executable: exe, StateDir: s.Dir, Name: name}); err != nil {
			return err
		}
		fmt.Fprintf(a.out, "Updated background connection %s.\n", name)
	}
	return nil
}
