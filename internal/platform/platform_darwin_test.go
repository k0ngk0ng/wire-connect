//go:build darwin && (amd64 || arm64)

package platform

import (
	"context"
	"net/netip"
	"reflect"
	"testing"
)

func TestDarwinSetupPlanUsesPointToPointAddress(t *testing.T) {
	runner := &recordingRunner{}
	plan := darwinSetupPlan(runner, "utun7", Config{
		Name:  "utun7",
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
		{name: "ifconfig", args: []string{"utun7", "inet", "100.64.0.1", "100.64.0.2", "netmask", "255.255.255.255", "up"}},
		{name: "ifconfig", args: []string{"utun7", "inet", "100.64.0.1", "-alias"}},
	}
	if got := runner.calls(); !reflect.DeepEqual(got, want) {
		t.Fatalf("commands = %#v, want %#v", got, want)
	}
}

func TestDarwinRouteParserSkipsNetstatHeaders(t *testing.T) {
	sample := []byte(`Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.0.2.1          UGScg               en0
10                 10.0.0.1           UGSc                utun0
127                127.0.0.1          UCS                 lo0
192.168.1          link#4             UCS                 en0
192.168.1.42       192.168.1.42       UH                  en0
`)
	routes, err := parseDarwinRoutePrefixes(sample)
	if err != nil {
		t.Fatalf("parse Darwin route table: %v", err)
	}
	if err := checkCandidateRoutes([]netip.Addr{netip.MustParseAddr("192.168.1.90")}, routes); err == nil {
		t.Fatal("expected candidate in abbreviated 192.168.1 route to be rejected")
	}
	if err := checkCandidateRoutes([]netip.Addr{netip.MustParseAddr("198.51.100.10")}, routes); err != nil {
		t.Fatalf("candidate covered only by default route rejected: %v", err)
	}
}
