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
	"golang.org/x/term"
)

type connectionStatus struct {
	Name   string        `json:"name"`
	Server string        `json:"server,omitempty"`
	Status client.Status `json:"status"`
	Error  string        `json:"error,omitempty"`
}

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
		var p config.Profile
		if err := s.Read("profile-"+n, &p); err == nil {
			row.Server = p.Server
			row.Status.LocalIP, row.Status.PeerIP = p.LocalIP, p.PeerIP
		}
		var live client.Status
		if err := localctl.Status(ctx, s.Dir, n, &live); err != nil {
			row.Error = err.Error()
		} else {
			row.Status = live
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func statusTerminal(out io.Writer) bool {
	f, ok := out.(*os.File)
	return ok && term.IsTerminal(int(f.Fd())) && os.Getenv("TERM") != "dumb"
}

func statusColor(out io.Writer) bool {
	return statusTerminal(out) && os.Getenv("NO_COLOR") == ""
}

func connectionMode(row connectionStatus) string {
	if row.Error != "" {
		return "UNAVAILABLE"
	}
	if !row.Status.Running || row.Status.Mode == "closed" {
		return "CLOSED"
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
	paint := func(code, text string) string {
		if color {
			return "\x1b[" + code + "m" + text + "\x1b[0m"
		}
		return text
	}
	direct, relay := 0, 0
	for _, row := range rows {
		switch connectionMode(row) {
		case "DIRECT":
			direct++
		case "RELAY":
			relay++
		}
	}
	fmt.Fprintf(out, "\n%s\nConnections: %d | Direct: %d | Relay: %d | Other: %d\n", paint("1", "WIRE CONNECT"), len(rows), direct, relay, len(rows)-direct-relay)
	if len(rows) == 0 {
		fmt.Fprintln(out, "\nNo saved connections for this user. Pair a device with wirectl connect <server>.")
		return
	}
	for _, row := range rows {
		st, mode := row.Status, connectionMode(row)
		code := "33"
		if mode == "DIRECT" {
			code = "32"
		} else if mode == "UNAVAILABLE" || mode == "CLOSED" {
			code = "31"
		}
		fmt.Fprintf(out, "\n%s\n%s %s\n", paint("2", "────────────────────────────────────────"), paint("1;36", "Connection: "+row.Name), paint("1;"+code, "["+mode+"]"))
		if row.Server != "" {
			fmt.Fprintf(out, "  Server:       %s\n", terminalText(row.Server))
		}
		fmt.Fprintf(out, "  Local IP:     %s (this device)\n  Peer IP:      %s (use this to access peer services)\n", terminalText(st.LocalIP), terminalText(st.PeerIP))
		if row.Error != "" {
			fmt.Fprintln(out, "  Status:       Cannot read live status; connection may be stopped.")
			fmt.Fprintf(out, "  Details:      %s\n  Resume:       wirectl connect resume --name %s\n", terminalText(row.Error), row.Name)
			continue
		}
		description := "No active transport path"
		if mode == "DIRECT" {
			description = "DIRECT — device to device (UDP)"
		}
		if mode == "RELAY" {
			description = "RELAY — through the server"
		}
		fmt.Fprintf(out, "  Current path: %s\n", paint(code, description))
		if mode == "DIRECT" && st.DirectRemote != "" {
			fmt.Fprintf(out, "  UDP endpoint: %s\n", terminalText(st.DirectRemote))
		}
		if !st.ModeSince.IsZero() {
			fmt.Fprintf(out, "  Path since:   %s\n", statusTime(st.ModeSince))
		}
		fmt.Fprintln(out, "\n  Traffic totals since process start (including previous paths)")
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
