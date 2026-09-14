package cli

import (
	"bytes"
	"context"
	"flag"
	"github.com/k0ngk0ng/wire-connect/internal/netsetup"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInterspersedFlags(t *testing.T) {
	f := flag.NewFlagSet("test", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	name := f.String("name", "default", "")
	background := f.Bool("background", false, "")
	mtu := f.Int("mtu", 1420, "")
	if err := parse(f, []string{"vpn.example.com", "--background", "7k3m-f8q2-h6tw", "--name", "office", "--mtu=1280"}); err != nil {
		t.Fatal(err)
	}
	if *name != "office" || !*background || *mtu != 1280 || f.NArg() != 2 || f.Arg(1) != "7k3m-f8q2-h6tw" {
		t.Fatal("incorrect options or positional arguments")
	}
}

func TestHelpAndVersionDoNotNeedState(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"version"}, {"setup", "--help"}, {"completion", "bash"}, {"completion", "zsh"}} {
		var out, errOut bytes.Buffer
		if err := Run(context.Background(), args, "1.2.3", bytes.NewReader(nil), &out, &errOut); err != nil {
			t.Fatal(err)
		}
		if out.Len() == 0 {
			t.Fatal("no output")
		}
	}
}

func TestInvalidFlagsFail(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run(context.Background(), []string{"vpn.example.com", "--does-not-exist"}, "test", bytes.NewReader(nil), &out, &errOut); err == nil {
		t.Fatal("accepted unknown flag")
	}
}

func TestExplicitStateDirWorksWithoutUserConfigEnvironment(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux systemd services may not provide HOME or XDG_CONFIG_HOME")
	}
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	dir := filepath.Join(t.TempDir(), "wire-connect")
	var out, errOut bytes.Buffer
	if err := Run(context.Background(), []string{"status", "--state-dir", dir}, "test", bytes.NewReader(nil), &out, &errOut); err != nil {
		t.Fatalf("explicit state directory failed without user config environment: %v", err)
	}
	if !strings.Contains(out.String(), "No saved connections") {
		t.Fatalf("status did not use explicit state directory: %s", out.String())
	}
}

func TestImplicitStateDirStillReportsMissingUserConfig(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux systemd services may not provide HOME or XDG_CONFIG_HOME")
	}
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	var out, errOut bytes.Buffer
	err := Run(context.Background(), []string{"status"}, "test", bytes.NewReader(nil), &out, &errOut)
	if err == nil {
		t.Fatal("implicit state directory unexpectedly succeeded without user config environment")
	}
	if !strings.Contains(err.Error(), "neither $XDG_CONFIG_HOME nor $HOME are defined") {
		t.Fatalf("implicit state directory error = %v; want missing user config diagnostic", err)
	}
}

func TestNamedConnectionsUseIndependentInterfaces(t *testing.T) {
	if got := defaultInterface("custom0", "office"); got != "custom0" {
		t.Fatalf("explicit interface changed to %q", got)
	}
	if got := defaultInterface("", "default"); (runtime.GOOS == "darwin" || netsetup.Elevated()) && got != "" {
		t.Fatalf("default interface changed to %q", got)
	}
	a, b := defaultInterface("", "office"), defaultInterface("", "home")
	if runtime.GOOS == "darwin" {
		if a != "" || b != "" {
			t.Fatal("macOS must retain dynamic utun allocation")
		}
		return
	}
	if a == "" || b == "" || a == b || len(a) > 15 || len(b) > 15 {
		t.Fatalf("invalid independent interfaces: %q, %q", a, b)
	}
	if a != defaultInterface("", "office") {
		t.Fatal("resuming a named connection must select the same interface")
	}
}

func TestServeListenDefaults(t *testing.T) {
	if got, err := serveListenAddress(true, "", false); err != nil || got != "127.0.0.1:8080" {
		t.Fatalf("HTTP default listen = %q, %v", got, err)
	}
	if got, err := serveListenAddress(false, "", false); err != nil || got != ":443" {
		t.Fatalf("HTTPS default listen = %q, %v", got, err)
	}
	if got, err := serveListenAddress(true, "127.0.0.1:18088", true); err != nil || got != "127.0.0.1:18088" {
		t.Fatalf("explicit HTTP listen = %q, %v", got, err)
	}
}

func TestServeHTTPRejectsExplicitEmptyListen(t *testing.T) {
	if _, err := serveListenAddress(true, "", true); err == nil {
		t.Fatal("accepted an explicitly empty HTTP listen address")
	}
}

func TestServeInvalidHTTPLeavesNoState(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("server CLI runs on Linux")
	}
	for _, listen := range []string{"0.0.0.0:8080", "localhost:8080", ":8080", "192.168.1.1:8080"} {
		dir := filepath.Join(t.TempDir(), "state")
		var out, errOut bytes.Buffer
		err := Run(context.Background(), []string{"serve", "--http", "--listen", listen, "--state-dir", dir, "--init"}, "test", bytes.NewReader(nil), &out, &errOut)
		if err == nil {
			t.Fatalf("accepted HTTP listener %q", listen)
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("invalid listener %q touched state: %v", listen, err)
		}
	}
}
