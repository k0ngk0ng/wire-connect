package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/k0ngk0ng/wire-connect/internal/client"
	"github.com/k0ngk0ng/wire-connect/internal/config"
	"github.com/k0ngk0ng/wire-connect/internal/localctl"
	"github.com/k0ngk0ng/wire-connect/internal/service"
	"golang.org/x/term"
)

type connectionStatus struct {
	Name   string        `json:"name"`
	Server string        `json:"server,omitempty"`
	Status client.Status `json:"status"`
	Error  string        `json:"error,omitempty"`
}

// statusServiceStatus is a seam for status tests and keeps the service
// manager query in one place. A missing local endpoint is only STOPPED when
// the native service manager independently reports an inactive state. This
// avoids showing a just-starting service as stopped while its IPC endpoint is
// still being created.
var statusServiceStatus = clientServiceStatus

func (a app) status(ctx context.Context, args []string) error {
	f, c, err := a.flags("status")
	if err != nil {
		return err
	}
	watch := f.Bool("watch", false, "refresh connection status once per second")
	asJSON := f.Bool("json", false, "print one status object; use --all for an array (JSON lines when watching)")
	all := f.Bool("all", false, "show all saved connections (default for text without --name)")
	if err := parse(f, args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("status takes no positional arguments")
	}
	named := false
	f.Visit(func(fl *flag.Flag) {
		if fl.Name == "name" {
			named = true
		}
	})
	if *all && named {
		return errors.New("use either --all or --name")
	}
	s, err := c.store()
	if err != nil {
		return err
	}
	showAll := *all || (!named && !*asJSON)
	if *watch && !*asJSON && statusTerminal(a.out) {
		fmt.Fprint(a.out, "\x1b[?1049h")
		defer fmt.Fprint(a.out, "\x1b[?1049l")
	}
	for {
		rows, err := collectConnections(ctx, s, c.name, showAll)
		if err != nil {
			return err
		}
		if *asJSON {
			var value any = rows
			if !showAll {
				if rows[0].Error != "" {
					return fmt.Errorf("connection %s is unavailable: %s", c.name, rows[0].Error)
				}
				value = rows[0].Status
			}
			if err := json.NewEncoder(a.out).Encode(value); err != nil {
				return err
			}
		} else {
			// An alternate screen keeps watch from flooding scrollback and restores
			// the original terminal even when the context is cancelled.
			if *watch && statusTerminal(a.out) {
				fmt.Fprint(a.out, "\x1b[H\x1b[2J")
			}
			printConnections(a.out, rows, statusColor(a.out))
		}
		if !*watch {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func collectConnections(ctx context.Context, s config.Store, name string, all bool) ([]connectionStatus, error) {
	names := []string{name}
	if all {
		names = nil
		entries, err := os.ReadDir(s.Dir)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			file := entry.Name()
			if entry.IsDir() || !strings.HasPrefix(file, "profile-") || !strings.HasSuffix(file, ".json") {
				continue
			}
			n := strings.TrimSuffix(strings.TrimPrefix(file, "profile-"), ".json")
			if profileName.MatchString(n) {
				names = append(names, n)
			}
		}
		sort.Strings(names)
	}
	rows := make([]connectionStatus, 0, len(names))
	for _, n := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		row := connectionStatus{Name: n}
		saved := false
		var p config.Profile
		if err := s.Read("profile-"+n, &p); err == nil {
			saved = true
			row.Server = p.Server
			row.Status.LocalIP, row.Status.PeerIP = p.LocalIP, p.PeerIP
		}
		var live client.Status
		if err := localctl.Status(ctx, s.Dir, n, &live); err != nil {
			row.Error = err.Error()
			if saved && localctl.IsNotRunning(err) {
				state, stateErr := statusServiceStatus(ctx, n)
				if (stateErr == nil && stoppedServiceState(state)) || errors.Is(stateErr, service.ErrNotInstalled) {
					row.Error = ""
					row.Status.Running = false
					row.Status.Mode = "stopped"
					row.Status.ModeReason = "service_stopped"
				}
			}
		} else {
			row.Status = live
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func stoppedServiceState(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "stopped", "inactive", "disabled", "exited", "deactivated", "dead":
		return true
	default:
		return false
	}
}

func statusTerminal(out io.Writer) bool {
	f, ok := out.(*os.File)
	return ok && term.IsTerminal(int(f.Fd())) && os.Getenv("TERM") != "dumb"
}

func statusColor(out io.Writer) bool {
	return statusTerminal(out) && os.Getenv("NO_COLOR") == ""
}

// A recent handshake is evidence of a peer session, not proof that every
// application on the peer is reachable. Old handshakes are shown as uncertain.
const peerHandshakeFreshness = 3 * time.Minute
const statusFreshness = 15 * time.Second

func connectionMode(row connectionStatus) string {
	return connectionModeAt(row, time.Now())
}

func connectionModeAt(row connectionStatus, now time.Time) string {
	if row.Error != "" {
		return "UNAVAILABLE"
	}
	if row.Status.Mode == "stopped" {
		return "STOPPED"
	}
	if !row.Status.Running || row.Status.Mode == "closed" {
		return "CLOSED"
	}
	if !row.Status.Updated.IsZero() && now.Sub(row.Status.Updated) > statusFreshness {
		return "UNCONFIRMED"
	}
	if row.Status.Mode != "direct" && row.Status.Mode != "relay" {
		return "WAITING"
	}
	if row.Status.LastHandshake.IsZero() {
		return "WAITING"
	}
	if now.Sub(row.Status.LastHandshake) > peerHandshakeFreshness {
		return "UNCONFIRMED"
	}
	switch row.Status.Mode {
	case "direct":
		return "DIRECT"
	case "relay":
		return "RELAY"
	default:
		return "WAITING"
	}
}

func printConnections(out io.Writer, rows []connectionStatus, color bool) {
	printConnectionsAt(out, rows, color, time.Now())
}

func printConnectionsAt(out io.Writer, rows []connectionStatus, color bool, now time.Time) {
	paint := func(code, text string) string {
		if color {
			return "\x1b[" + code + "m" + text + "\x1b[0m"
		}
		return text
	}
	direct, relay, waiting, unconfirmed, stopped := 0, 0, 0, 0, 0
	for _, row := range rows {
		switch connectionModeAt(row, now) {
		case "DIRECT":
			direct++
		case "RELAY":
			relay++
		case "WAITING":
			waiting++
		case "UNCONFIRMED":
			unconfirmed++
		case "STOPPED":
			stopped++
		}
	}
	fmt.Fprintf(out, "\n%s\nConnections: %d | Connected: %d | Waiting: %d | Unconfirmed: %d | Stopped: %d | Other: %d\n", paint("1", "WIRE CONNECT"), len(rows), direct+relay, waiting, unconfirmed, stopped, len(rows)-direct-relay-waiting-unconfirmed-stopped)
	fmt.Fprintf(out, "Connected paths: Direct: %d | Relay: %d\n", direct, relay)
	if len(rows) == 0 {
		fmt.Fprintln(out, "\nNo saved connections for this user. Pair a device with wirectl connect <server>.")
		return
	}
	for _, row := range rows {
		st, mode := row.Status, connectionModeAt(row, now)
		code := "33"
		if mode == "DIRECT" || mode == "RELAY" {
			code = "32"
		} else if mode == "STOPPED" {
			code = "90"
		} else if mode == "UNAVAILABLE" || mode == "CLOSED" {
			code = "31"
		}
		label := mode
		if mode == "DIRECT" || mode == "RELAY" {
			label = "CONNECTED · " + mode
		}
		if mode == "WAITING" {
			label = "NOT CONNECTED"
		}
		fmt.Fprintf(out, "\n%s\n%s %s\n", paint("2", "────────────────────────────────────────"), paint("1;36", "Connection: "+row.Name), paint("1;"+code, "["+label+"]"))
		if mode == "STOPPED" {
			fmt.Fprintln(out, "  Stopped. Saved pair retained.")
			fmt.Fprintf(out, "  Resume:       wirectl connect resume --name %s\n  Delete:       wirectl connect delete --name %s\n", row.Name, row.Name)
			continue
		}
		switch mode {
		case "WAITING":
			if st.LastHandshake.IsZero() {
				fmt.Fprintln(out, paint("1;33", "  Not connected to peer — no WireGuard handshake yet."))
			} else {
				fmt.Fprintln(out, paint("1;33", "  No active transport path — waiting to reconnect."))
			}
			fmt.Fprintln(out, "  Next step: Check that the other device has resumed its paired connection.")
		case "UNCONFIRMED":
			if !st.Updated.IsZero() && now.Sub(st.Updated) > statusFreshness {
				fmt.Fprintln(out, paint("1;33", "  Peer connectivity unconfirmed — status is more than 15 seconds old."))
			} else {
				fmt.Fprintln(out, paint("1;33", "  Peer connectivity unconfirmed — no handshake in the last 3 minutes."))
			}
		case "DIRECT", "RELAY":
			fmt.Fprintln(out, "  Peer session: Recent WireGuard handshake established.")
		}
		if row.Server != "" {
			fmt.Fprintf(out, "  Server:       %s\n", terminalText(row.Server))
		}
		peerHint := "paired address"
		if mode == "DIRECT" || mode == "RELAY" {
			peerHint = "use this to access peer services"
		}
		fmt.Fprintf(out, "  Local IP:     %s (this device)\n  Peer IP:      %s (%s)\n", terminalText(st.LocalIP), terminalText(st.PeerIP), peerHint)
		if row.Error != "" {
			fmt.Fprintln(out, "  Status:       Live status unavailable.")
			fmt.Fprintf(out, "  Details:      %s\n  Resume:       wirectl connect resume --name %s\n", terminalText(row.Error), row.Name)
			continue
		}
		description := "No active transport path"
		if st.Mode == "direct" {
			description = "DIRECT — device to device (UDP)"
		}
		if st.Mode == "relay" {
			description = "RELAY — through the server"
		}
		if mode == "WAITING" && st.Mode == "relay" {
			description = "RELAY — relay server reached; peer handshake pending"
		}
		pathColor := "33"
		if st.Mode == "direct" {
			pathColor = "36"
		}
		fmt.Fprintf(out, "  Transport:    %s\n", paint(pathColor, description))
		if st.Mode == "direct" && st.DirectRemote != "" {
			fmt.Fprintf(out, "  UDP endpoint: %s\n", terminalText(st.DirectRemote))
		}
		if !st.ModeSince.IsZero() {
			fmt.Fprintf(out, "  Path since:   %s\n", statusTime(st.ModeSince))
		}
		fmt.Fprintln(out, "\n  Traffic totals since process start (includes handshake attempts and previous paths)")
		fmt.Fprintf(out, "    Direct:  ↑ %s sent   ↓ %s received\n    Relay:   ↑ %s sent   ↓ %s received\n", statusBytes(st.DirectSent), statusBytes(st.DirectReceived), statusBytes(st.RelaySent), statusBytes(st.RelayReceived))
		handshake := "Waiting for the peer (no handshake yet)"
		if !st.LastHandshake.IsZero() {
			handshake = statusTime(st.LastHandshake)
		}
		fmt.Fprintf(out, "\n  Last handshake: %s\n", handshake)
	}
	fmt.Fprintln(out)
}

// Avoid interpreting control characters from server URLs or IPC diagnostics.
func terminalText(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 || (r >= 128 && r < 160) {
			return ' '
		}
		return r
	}, s)
}

func statusTime(t time.Time) string { return t.Local().Format("2006-01-02 15:04:05 MST (UTC-07:00)") }

func statusBytes(n uint64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	v := float64(n)
	for _, unit := range []string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"} {
		v /= 1024
		if v < 1024 || unit == "EiB" {
			return fmt.Sprintf("%.1f %s", v, unit)
		}
	}
	return ""
}
