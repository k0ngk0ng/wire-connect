package cli

import (
	"bytes"
	"context"
	"flag"
	"io"
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
