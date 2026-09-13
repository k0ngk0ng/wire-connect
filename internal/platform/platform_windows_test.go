//go:build windows && amd64

package platform

import (
	"context"
	"net/netip"
	"reflect"
	"testing"
)

func TestWindowsSetupPlanUsesDocumentedNetshForms(t *testing.T) {
	runner := &recordingRunner{}
	plan := windowsSetupPlanWithBinary(runner, "netsh.exe", "wc0", Config{
		Name:  "wc0",
		Local: netip.MustParseAddr("100.64.0.1"),
		Peer:  netip.MustParseAddr("100.64.0.2"),
		MTU:   DefaultMTU,
	})
	for _, step := range plan.steps {
		if err := step.apply(context.Background()); err != nil {
			t.Fatalf("apply %q: %v", step.label, err)
		}
	}
	for i := len(plan.steps) - 1; i >= 0; i-- {
		if err := plan.steps[i].undo(context.Background()); err != nil {
			t.Fatalf("undo %q: %v", plan.steps[i].label, err)
		}
	}
	want := []recordedCall{
		{name: "netsh.exe", args: []string{"interface", "set", "interface", "name=wc0", "admin=enabled"}},
		{name: "netsh.exe", args: []string{"interface", "ipv4", "set", "subinterface", "interface=wc0", "mtu=1420", "store=active"}},
		{name: "netsh.exe", args: []string{"interface", "ipv4", "add", "address", "name=wc0", "address=100.64.0.1", "mask=255.255.255.255", "store=active"}},
		{name: "netsh.exe", args: []string{"interface", "ipv4", "add", "route", "prefix=100.64.0.2/32", "interface=wc0", "store=active"}},
		{name: "netsh.exe", args: []string{"interface", "ipv4", "delete", "route", "prefix=100.64.0.2/32", "interface=wc0", "store=active"}},
		{name: "netsh.exe", args: []string{"interface", "ipv4", "delete", "address", "name=wc0", "address=100.64.0.1", "store=active"}},
		{name: "netsh.exe", args: []string{"interface", "ipv4", "set", "subinterface", "interface=wc0", "mtu=1500", "store=active"}},
		{name: "netsh.exe", args: []string{"interface", "set", "interface", "name=wc0", "admin=disabled"}},
	}
	if got := runner.calls(); !reflect.DeepEqual(got, want) {
		t.Fatalf("commands = %#v, want %#v", got, want)
	}
	if len(plan.cleanup) != 0 {
		t.Fatalf("platform cleanup actions = %#v, want none because Wintun.Close owns adapter removal", plan.cleanup)
	}
}
