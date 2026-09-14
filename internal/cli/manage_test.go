package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/k0ngk0ng/wire-connect/internal/client"
	"github.com/k0ngk0ng/wire-connect/internal/config"
	"github.com/k0ngk0ng/wire-connect/internal/localctl"
)

type cancelWriter struct {
	bytes.Buffer
	cancel context.CancelFunc
}

func (w *cancelWriter) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	w.cancel()
	return n, err
}

func TestStatusWatchCancellationLeavesConnectionRunning(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	base := filepath.Join(filepath.Dir(file), "..", "..", ".cache", "ct")
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatal(err)
	}
	temp, err := os.MkdirTemp(base, "s")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(temp)
	// Let Store create the private directory with the platform's native ACL.
	// os.MkdirTemp inherits the runner's Windows ACL, which is not private.
	dir := filepath.Join(temp, "state")
	if err := (config.Store{Dir: dir}).Init(); err != nil {
		t.Fatal(err)
	}
	st := client.Status{Running: true, Mode: "direct", LocalIP: "100.64.0.1", PeerIP: "100.64.0.2", DirectSent: 4096, DirectReceived: 2048, RelaySent: 128, RelayReceived: 64, DirectRemote: "203.0.113.8:34781", LastHandshake: time.Now().UTC()}
	var stops atomic.Int32
	server, err := localctl.Listen(context.Background(), dir, "default", func() any { return st }, func() { stops.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := &cancelWriter{cancel: cancel}
	err = Run(ctx, []string{"status", "--state-dir", dir, "--watch", "--json"}, "test", strings.NewReader(""), out, &bytes.Buffer{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("watch returned %v", err)
	}
	var got client.Status
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.DirectSent != 4096 || got.RelaySent != 128 || got.DirectRemote != st.DirectRemote {
		t.Fatalf("lost path evidence: %+v", got)
	}
	if err := localctl.Status(context.Background(), dir, "default", &got); err != nil {
		t.Fatalf("connection stopped after closing watch: %v", err)
	}
	if stops.Load() != 0 || !got.Running {
		t.Fatal("watch cancellation stopped connection")
	}
	var text bytes.Buffer
	printConnections(&text, []connectionStatus{{Name: "default", Status: got}}, false)
	for _, want := range []string{"UDP endpoint: 203.0.113.8:34781", "Direct:  ↑ 4.0 KiB sent", "Relay:   ↑ 128 B sent", "Last handshake:", "[CONNECTED · DIRECT]", "Connections: 1 | Connected: 1 | Waiting: 0 | Unconfirmed: 0 | Stopped: 0 | Other: 0"} {
		if !strings.Contains(text.String(), want) {
			t.Fatalf("status missing %q: %s", want, text.String())
		}
	}
}
