// Package cli implements the small standalone and wirectl-plugin command.
package cli

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/k0ngk0ng/wire-connect/internal/client"
	"github.com/k0ngk0ng/wire-connect/internal/config"
	"github.com/k0ngk0ng/wire-connect/internal/endpoint"
	"github.com/k0ngk0ng/wire-connect/internal/localctl"
	"github.com/k0ngk0ng/wire-connect/internal/platform"
	"github.com/k0ngk0ng/wire-connect/internal/server"
	"github.com/k0ngk0ng/wire-connect/internal/service"
	"golang.org/x/term"
)

const help = `Encrypted point-to-point networking.

Usage:
  wirectl connect login <server>               Authorize this device once
  wirectl connect <server>                     Create a short pairing code
  wirectl connect <server> <code>              Join the other device
  wirectl connect resume                       Reconnect a saved pair
  wirectl connect status                      Show connection state
  wirectl connect stop                        Stop the connection
  wirectl connect doctor [server]              Check network prerequisites
  wirectl connect serve --domain <hostname>    Run the Linux public server

Options:
  --state-dir <path>   Private credentials and profiles directory
  --name <name>        Saved connection name (default: default)
  --background        Install and start an operating-system service
  --network <CIDR>     Virtual address range (default: 100.64.0.0/10)
  --relay-only        Use the encrypted HTTPS relay without UDP probing
  --verbose           Show connection diagnostics

The standalone wirectl-connect executable accepts the same arguments.
Creating a virtual interface requires administrator privileges.
`

type app struct {
	in          io.Reader
	out, errOut io.Writer
	version     string
}

func Run(ctx context.Context, args []string, version string, in io.Reader, out, errOut io.Writer) error {
	a := app{in: in, out: out, errOut: errOut, version: version}
	if len(args) == 0 {
		fmt.Fprint(out, help)
		return nil
	}
	var err error
	switch args[0] {
	case "help", "--help", "-h":
		fmt.Fprint(out, help)
		return nil
	case "version", "--version":
		fmt.Fprintln(out, version)
		return nil
	case "login":
		err = a.login(ctx, args[1:])
	case "serve":
		err = a.serve(ctx, args[1:])
	case "status":
		err = a.status(ctx, args[1:])
	case "stop":
		err = a.stop(ctx, args[1:])
	case "doctor":
		err = a.doctor(ctx, args[1:])
	case "resume":
		err = a.connect(ctx, args[1:], true)
	default:
		err = a.connect(ctx, args, false)
	}
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return err
}

type common struct{ dir, name string }

func (a app) flags(command string) (*flag.FlagSet, *common, error) {
	dir, err := config.DefaultDir()
	if err != nil {
		return nil, nil, err
	}
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	f.SetOutput(a.errOut)
	c := &common{}
	f.StringVar(&c.dir, "state-dir", dir, "private state directory")
	f.StringVar(&c.name, "name", "default", "saved connection name")
	return f, c, nil
}

var profileName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

func (c *common) store() (config.Store, error) {
	if !profileName.MatchString(c.name) {
		return config.Store{}, errors.New("name must be 1-32 lowercase letters, digits or hyphens, starting with a letter")
	}
	dir, err := filepath.Abs(c.dir)
	if err != nil {
		return config.Store{}, err
	}
	s := config.Store{Dir: dir}
	if err := s.Init(); err != nil {
		return config.Store{}, err
	}
	// Resolve platform aliases such as macOS /var after validating the final
	// state directory, so services and local IPC use the same canonical path.
	s.Dir, err = filepath.EvalSymlinks(dir)
	return s, err
}

// parse accepts options before or after the two positional arguments without
// adding a framework dependency. Flag values are never interpreted as code.
func parse(f *flag.FlagSet, args []string) error {
	var options, positional []string
	for i := 0; i < len(args); i++ {
		x := args[i]
		if x == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(x, "-") || x == "-" {
			positional = append(positional, x)
			continue
		}
		options = append(options, x)
		name, _, hasValue := strings.Cut(strings.TrimLeft(x, "-"), "=")
		fl := f.Lookup(name)
		if fl == nil || hasValue {
			continue
		}
		if b, ok := fl.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			i++
			options = append(options, args[i])
		}
	}
	return f.Parse(append(append(options, "--"), positional...))
}

func (a app) login(ctx context.Context, args []string) error {
	f, c, err := a.flags("login")
	if err != nil {
		return err
	}
	pin := f.String("pin", "", "SHA-256 certificate fingerprint for a private TLS certificate")
	if err := parse(f, args); err != nil {
		return err
	}
	if f.NArg() != 1 {
		return errors.New("usage: wirectl connect login <server> [--pin <SHA256>]")
	}
	s, err := c.store()
	if err != nil {
		return err
	}
	api, err := client.New(f.Arg(0), config.Credential{CertificateSHA256: *pin})
	if err != nil {
		return err
	}
	fmt.Fprint(a.errOut, "Server enrollment token: ")
	token, err := readSecret(a.in)
	fmt.Fprintln(a.errOut)
	if err != nil {
		return err
	}
	if token == "" {
		return errors.New("empty enrollment token")
	}
	host, _ := os.Hostname()
	cred, err := api.Login(ctx, token, host)
	if err != nil {
		return err
	}
	credentials, err := s.Credentials()
	if err != nil {
		return err
	}
	credentials[api.Server] = cred
	if err := s.Write("credentials", credentials); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Authorized %s\n", api.Server)
	return nil
}

func readSecret(r io.Reader) (string, error) {
	if f, ok := r.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		b, err := term.ReadPassword(int(f.Fd()))
		defer clear(b)
		return strings.TrimSpace(string(b)), err
	}
	b, err := bufio.NewReader(io.LimitReader(r, 4097)).ReadString('\n')
	if len(b) > 4096 {
		return "", errors.New("input exceeds size limit")
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(b), nil
}

func (a app) connect(ctx context.Context, args []string, resume bool) error {
	f, c, err := a.flags("connect")
	if err != nil {
		return err
	}
	background := f.Bool("background", false, "install and start a background service")
	network := f.String("network", "100.64.0.0/10", "private virtual address range")
	iface := f.String("interface", "", "virtual interface name")
	mtu := f.Int("mtu", 1420, "virtual interface MTU")
	stun := f.String("stun", "", "STUN URL override")
	relayOnly := f.Bool("relay-only", false, "disable UDP direct connectivity")
	verbose := f.Bool("verbose", false, "show connection diagnostics")
	codeFlag := f.String("code", "", "create a room using this pairing code")
	replace := f.Bool("replace", false, "replace this saved pair after authenticating a new peer")
	_ = f.Bool("service", false, "internal operating-system service mode")
	if err := parse(f, args); err != nil {
		return err
	}
	s, err := c.store()
	if err != nil {
		return err
	}
	var p config.Profile
	if resume {
		if f.NArg() != 0 {
			return errors.New("resume takes no positional arguments")
		}
		if err := s.Read("profile-"+c.name, &p); err != nil {
			return fmt.Errorf("load paired profile: %w", err)
		}
		set := map[string]bool{}
		f.Visit(func(fl *flag.Flag) { set[fl.Name] = true })
		if !set["interface"] {
			*iface = p.Interface
		}
		if !set["mtu"] && p.MTU != 0 {
			*mtu = p.MTU
		}
		if !set["stun"] {
			*stun = p.STUNURL
		}
		if !set["relay-only"] {
			*relayOnly = p.RelayOnly
		}
	} else {
		if f.NArg() < 1 || f.NArg() > 2 {
			return errors.New("usage: wirectl connect <server> [code]")
		}
		if err := platform.Check(ctx); err != nil {
			return err
		}
		var previous config.Profile
		if err := s.Read("profile-"+c.name, &previous); err == nil && !*replace {
			return errors.New("this name is already paired; use resume, --name <another-name>, or --replace")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		api, err := authorized(s, f.Arg(0))
		if err != nil {
			return err
		}
		prefix, err := netip.ParsePrefix(*network)
		if err != nil {
			return fmt.Errorf("invalid network: %w", err)
		}
		code := *codeFlag
		host := f.NArg() == 1
		if !host {
			if code != "" {
				return errors.New("use either a positional join code or --code for creation")
			}
			code = f.Arg(1)
		}
		p, err = api.Pair(ctx, client.PairOptions{Host: host, Code: code, Network: prefix, OnCode: func(code string) { fmt.Fprintf(a.out, "Pairing code: %s\nWaiting for the other device…\n", code) }})
		if err != nil {
			return err
		}
		*iface = defaultInterface(*iface, c.name)
		p.Interface, p.MTU, p.STUNURL, p.RelayOnly = *iface, *mtu, *stun, *relayOnly
		if err := s.Write("profile-"+c.name, p); err != nil {
			return err
		}
		fmt.Fprintf(a.out, "Paired · local %s · peer %s\n", p.LocalIP, p.PeerIP)
	}
	*iface = defaultInterface(*iface, c.name)
	if *background {
		p.Interface, p.MTU, p.STUNURL, p.RelayOnly = *iface, *mtu, *stun, *relayOnly
		if err := s.Write("profile-"+c.name, p); err != nil {
			return err
		}
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if err := service.Install(ctx, service.Config{Executable: exe, StateDir: s.Dir, Name: c.name}); err != nil {
			return err
		}
		fmt.Fprintln(a.out, "Background service started.")
		return nil
	}
	api, err := authorized(s, p.Server)
	if err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var mu sync.RWMutex
	status := client.Status{LocalIP: p.LocalIP, PeerIP: p.PeerIP, Updated: time.Now().UTC()}
	local, err := localctl.Listen(runCtx, s.Dir, c.name, func() any { mu.RLock(); defer mu.RUnlock(); return status }, cancel)
	if err != nil {
		return err
	}
	defer local.Close()
	level := slog.LevelWarn
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(a.errOut, &slog.HandlerOptions{Level: level}))
	lastMode := ""
	return api.Run(runCtx, p, client.RunOptions{Interface: *iface, MTU: *mtu, STUNURL: *stun, RelayOnly: *relayOnly, Log: log, OnStatus: func(next client.Status) {
		mu.Lock()
		status = next
		mu.Unlock()
		if !next.LastHandshake.IsZero() && next.Mode != lastMode {
			fmt.Fprintf(a.out, "Connected · %s · %s ↔ %s\n", next.Mode, next.LocalIP, next.PeerIP)
			lastMode = next.Mode
		}
	}})
}

func defaultInterface(requested, name string) string {
	if requested != "" || name == "default" || runtime.GOOS == "darwin" {
		return requested
	}
	// Give named connections independent interfaces while staying within
	// Linux's 15-byte limit. macOS allocates utun numbers itself.
	digest := sha256.Sum256([]byte(name))
	return fmt.Sprintf("wc%x", digest[:6])
}

func authorized(s config.Store, server string) (*client.Client, error) {
	u, err := endpoint.Parse(server)
	if err != nil {
		return nil, err
	}
	credentials, err := s.Credentials()
	if err != nil {
		return nil, err
	}
	cred, ok := credentials[u.String()]
	if !ok {
		return nil, fmt.Errorf("server is not authorized; run: wirectl connect login %s", u.String())
	}
	return client.New(u.String(), cred)
}

func (a app) status(ctx context.Context, args []string) error {
	f, c, err := a.flags("status")
	if err != nil {
		return err
	}
	if err := parse(f, args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("status takes no positional arguments")
	}
	s, err := c.store()
	if err != nil {
		return err
	}
	var st client.Status
	if err := localctl.Status(ctx, s.Dir, c.name, &st); err != nil {
		return fmt.Errorf("connection is not running or is owned by another user: %w", err)
	}
	fmt.Fprintf(a.out, "%s · %s ↔ %s\nSent %d bytes · received %d bytes\n", st.Mode, st.LocalIP, st.PeerIP, st.Sent, st.Received)
	if !st.LastHandshake.IsZero() {
		fmt.Fprintf(a.out, "Last handshake: %s\n", st.LastHandshake.Format(time.RFC3339))
	}
	return nil
}

func (a app) stop(ctx context.Context, args []string) error {
	f, c, err := a.flags("stop")
	if err != nil {
		return err
	}
	remove := f.Bool("uninstall", false, "also remove the operating-system service")
	if err := parse(f, args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("stop takes no positional arguments")
	}
	s, err := c.store()
	if err != nil {
		return err
	}
	ipcErr := localctl.Stop(ctx, s.Dir, c.name)
	serviceErr := service.Stop(ctx, c.name)
	if *remove {
		serviceErr = service.Uninstall(ctx, c.name)
	}
	if serviceErr != nil && !errors.Is(serviceErr, service.ErrNotInstalled) {
		return serviceErr
	}
	if ipcErr != nil && serviceErr != nil {
		return errors.Join(ipcErr, serviceErr)
	}
	fmt.Fprintln(a.out, "Stopped.")
	return nil
}

func (a app) doctor(ctx context.Context, args []string) error {
	f, c, err := a.flags("doctor")
	if err != nil {
		return err
	}
	if err := parse(f, args); err != nil {
		return err
	}
	if f.NArg() > 1 {
		return errors.New("doctor accepts at most one server")
	}
	fmt.Fprintf(a.out, "Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	var issues []error
	if err := platform.Check(ctx); err != nil {
		fmt.Fprintln(a.out, "Tunnel:", err)
		issues = append(issues, err)
	} else {
		fmt.Fprintln(a.out, "Tunnel prerequisites: ready")
	}
	if f.NArg() == 1 {
		s, err := c.store()
		if err != nil {
			return err
		}
		api, err := authorized(s, f.Arg(0))
		if err != nil {
			return err
		}
		if err := api.Health(ctx); err != nil {
			fmt.Fprintln(a.out, "Server:", err)
			issues = append(issues, err)
		} else {
			fmt.Fprintln(a.out, "Server HTTPS: reachable")
		}
		if addr, rtt, err := api.ProbeSTUN(ctx); err != nil {
			fmt.Fprintln(a.out, "Direct UDP:", err)
			fmt.Fprintln(a.out, "Connections will try the HTTPS relay when UDP is unavailable.")
		} else {
			fmt.Fprintf(a.out, "STUN: %s · RTT %s\n", addr, rtt.Round(time.Millisecond))
		}
	}
	return errors.Join(issues...)
}

func (a app) serve(ctx context.Context, args []string) error {
	if runtime.GOOS != "linux" {
		return errors.New("the public server command is supported on Linux")
	}
	f, c, err := a.flags("serve")
	if err != nil {
		return err
	}
	domain := f.String("domain", "", "public hostname for automatic TLS certificates")
	listen := f.String("listen", ":443", "HTTPS listen address")
	stun := f.String("stun-listen", ":3478", "STUN UDP listen address")
	cert := f.String("cert", "", "TLS certificate file")
	key := f.String("key", "", "TLS private key file")
	tokenFile := f.String("enrollment-token-file", "", "read initial enrollment token from a private file")
	initOnly := f.Bool("init", false, "initialize server identity and show enrollment token, then exit")
	relayLimit := f.Uint64("relay-bytes-per-second", 10<<20, "per-client relay bandwidth limit")
	connections := f.Int("max-relay-connections", 256, "maximum concurrent relay connections")
	if err := parse(f, args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("serve takes options only")
	}
	s, err := c.store()
	if err != nil {
		return err
	}
	token := ""
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return err
		}
		token = strings.TrimSpace(string(b))
		clear(b)
		if len(token) < 32 || len(token) > 256 {
			return errors.New("enrollment token must contain 32-256 characters")
		}
	}
	cfg := server.Config{Domain: *domain, Listen: *listen, STUNListen: *stun, StateDir: s.Dir, CertFile: *cert, KeyFile: *key, EnrollmentToken: token, RelayBytesPerSecond: *relayLimit, MaxRelayConnections: *connections, Log: slog.New(slog.NewJSONHandler(a.errOut, nil))}
	if *initOnly {
		cfg.EnrollmentOutput = a.out
		srv, err := server.New(cfg)
		if err != nil {
			return err
		}
		defer srv.Close()
		fmt.Fprintln(a.out, "Server initialized.")
		return nil
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "control", "state.json")); errors.Is(err, os.ErrNotExist) && token == "" {
		return errors.New("initialize the server first with serve --init --state-dir <path>; save the enrollment token")
	}
	return server.Serve(ctx, cfg)
}
