package cli

import (
	"bytes"
	"context"
	"flag"
	"io"
	"runtime"
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
	for _, args := range [][]string{{"--help"}, {"version"}} {
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

func TestNamedConnectionsUseIndependentInterfaces(t *testing.T) {
	if got := defaultInterface("custom0", "office"); got != "custom0" {
		t.Fatalf("explicit interface changed to %q", got)
	}
	if got := defaultInterface("", "default"); got != "" {
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
