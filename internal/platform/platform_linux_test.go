//go:build linux && (amd64 || arm64)

package platform

import (
	"context"
	"net/netip"
	"reflect"
	"testing"
)

func TestLinuxSetupPlanUsesOnlyScopedIPv4Commands(t *testing.T) {
	runner := &recordingRunner{}
	plan := linuxSetupPlan(runner, "wc0", Config{
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
		{name: "ip", args: []string{"-4", "addr", "add", "100.64.0.1/32", "dev", "wc0"}},
		{name: "ip", args: []string{"link", "set", "dev", "wc0", "up"}},
		{name: "ip", args: []string{"-4", "route", "add", "100.64.0.2/32", "dev", "wc0"}},
		{name: "ip", args: []string{"-4", "route", "del", "100.64.0.2/32", "dev", "wc0"}},
		{name: "ip", args: []string{"link", "set", "dev", "wc0", "down"}},
		{name: "ip", args: []string{"-4", "addr", "del", "100.64.0.1/32", "dev", "wc0"}},
	}
	if got := runner.calls(); !reflect.DeepEqual(got, want) {
		t.Fatalf("commands = %#v, want %#v", got, want)
	}
}
