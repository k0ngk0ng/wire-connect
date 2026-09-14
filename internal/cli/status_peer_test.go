package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/k0ngk0ng/wire-connect/internal/client"
	"github.com/k0ngk0ng/wire-connect/internal/config"
)

func TestPeerReadinessRequiresHandshake(t *testing.T) {
	now := time.Date(2026, 9, 14, 19, 39, 32, 0, time.UTC)
	for _, mode := range []string{"direct", "relay"} {
		t.Run(mode, func(t *testing.T) {
			row := connectionStatus{Name: "default", Status: client.Status{Running: true, Mode: mode, LocalIP: "100.113.200.14", PeerIP: "100.113.200.13", RelaySent: 3072, DirectReceived: 128, Updated: now}}
			// Receiving transport bytes also does not prove an authenticated session.
			if got := connectionModeAt(row, now); got != "WAITING" {
				t.Fatalf("mode=%s", got)
			}
			var out bytes.Buffer
			printConnectionsAt(&out, []connectionStatus{row}, false, now)
			text := out.String()
			for _, want := range []string{"Connected: 0 | Waiting: 1", "Connected paths: Direct: 0 | Relay: 0", "[NOT CONNECTED]", "no WireGuard handshake yet", "includes handshake attempts"} {
				if !strings.Contains(text, want) {
					t.Fatalf("missing %q:\n%s", want, text)
				}
			}
			if strings.Contains(text, "[CONNECTED") || strings.Contains(text, "use this to access peer services") {
				t.Fatalf("unready peer shown as connected:\n%s", text)
			}
			if mode == "relay" && !strings.Contains(text, "relay server reached; peer handshake pending") {
				t.Fatal(text)
			}
			row.Status.LastHandshake = now.Add(-time.Second)
			if got := connectionModeAt(row, now); got != strings.ToUpper(mode) {
				t.Fatalf("established session=%s", got)
			}
		})
	}
}

func TestOldHandshakeOrSnapshotIsUnconfirmed(t *testing.T) {
	now := time.Date(2026, 9, 14, 19, 39, 32, 0, time.UTC)
	for _, stale := range []string{"handshake", "snapshot", "stale-waiting"} {
		t.Run(stale, func(t *testing.T) {
			st := client.Status{Running: true, Mode: "relay", LastHandshake: now.Add(-time.Second), Updated: now}
			if stale == "handshake" {
				st.LastHandshake = now.Add(-peerHandshakeFreshness - time.Second)
			} else {
				st.Updated = now.Add(-statusFreshness - time.Second)
				if stale == "stale-waiting" {
					st.LastHandshake = time.Time{}
				}
			}
			row := connectionStatus{Name: "default", Status: st}
			if got := connectionModeAt(row, now); got != "UNCONFIRMED" {
				t.Fatal(got)
			}
			var out bytes.Buffer
			printConnectionsAt(&out, []connectionStatus{row}, false, now)
			for _, want := range []string{"Connected: 0", "Unconfirmed: 1", "[UNCONFIRMED]", "Peer connectivity unconfirmed"} {
				if !strings.Contains(out.String(), want) {
					t.Fatal(out.String())
				}
			}
		})
	}
}

func TestNoHandshakeJSONKeepsTransportEvidence(t *testing.T) {
	f := newStatusProfileFixture(t)
	st := client.Status{Running: true, Mode: "relay", RelaySent: 3072, Updated: time.Now()}
	f.add(t, "default", "https://relay.example", st, true)
	raw, err := runStatus(t, f.dir, "--json")
	if err != nil {
		t.Fatal(err)
	}
	var got client.Status
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatal(err)
	}
	if got.Mode != "relay" || !got.Running || !got.LastHandshake.IsZero() || got.RelaySent != 3072 {
		t.Fatalf("raw status changed: %+v", got)
	}
	// The same live endpoint must produce an unambiguous waiting state in text.
	text, err := runStatus(t, f.dir, "--name", "default")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "[NOT CONNECTED]") {
		t.Fatal(text)
	}
	// Viewing either representation must not stop the connection.
	rows, err := collectConnections(context.Background(), config.Store{Dir: f.dir}, "default", false)
	if err != nil || len(rows) != 1 || !rows[0].Status.Running {
		t.Fatalf("status changed connection: %v %v", rows, err)
	}
}
