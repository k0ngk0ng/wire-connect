# Disposable Linux NAT validation

[`scripts/test-nat.sh`](../scripts/test-nat.sh) is the real-network qualification
test for the Linux client. It runs the public server and two clients in fresh
network namespaces, using `198.18.0.0/24` from the RFC 2544 benchmarking range
for the simulated public network; it never sends test packets to the Internet.

The topology is:

```text
client A 10.201.1.2 --- NAT A --- 198.18.0.2 \
                                             public bridge --- server 198.18.0.1
client B 10.202.1.2 --- NAT B --- 198.18.0.3 /
```

Each NAT has its own veth pair on the private side and MASQUERADE plus
conntrack forwarding on the public side. The server binds HTTPS on TCP 443 and
STUN on UDP 3478 inside its namespace. The client commands use the standalone
`wirectl-connect` binary, so the test also exercises the same executable that
is shipped in the Linux release archive.

The routers silently drop unsolicited WAN UDP in INPUT before conntrack
confirmation; packets with an established reverse mapping still traverse
FORWARD. No static port forwarding or permissive inbound FORWARD rule is used.

## What is covered

The first scenario uses ordinary stateful NAT. Both clients enroll, pair with
the fixed disposable fixture code, and must report `direct`. An HTTP service
and a UDP echo service then run behind client B. Client A reaches both services
through the encrypted WireGuard virtual addresses.
After direct mode is established, HTTPS access to the server is blocked at
both NATs throughout these transfers, so relay fallback cannot satisfy the
direct-path traffic assertions. Server access is restored for the relay case.

Both paths also transfer a 4 MiB TCP response with SHA-256 content verification
and echo 1372-byte and 8192-byte UDP payloads, covering a near-MTU datagram and
inner IPv4 fragmentation/reassembly at the default TUN MTU.

The second scenario inserts a UDP egress drop at both NAT boundaries. HTTPS
control and DERP WebSocket traffic remain allowed. `doctor` must report the
STUN failure, the pair must report `relay`, and the same HTTP and UDP virtual
traffic must succeed through the encrypted relay. The UDP test here is inner
WireGuard traffic carried by the HTTPS relay; it does not weaken the simulated
UDP egress restriction.

The test does not claim coverage for symmetric NAT, double NAT, carrier-grade
NAT, IPv6-only networks, HTTP proxies, packet loss, arbitrary path MTUs, or
long-duration load. Those need
separate disposable environments and are deliberately not inferred from this
topology.

## Local or CI invocation

The test is intentionally refused unless it is running as root on Linux and
the explicit opt-in variable is set:

```sh
mkdir -p .cache/nat .cache/go-build .cache/go-mod .cache/tmp
CGO_ENABLED=0 GOCACHE="$PWD/.cache/go-build" \
GOMODCACHE="$PWD/.cache/go-mod" \
GOTMPDIR="$PWD/.cache/tmp" \
TMPDIR="$PWD/.cache/tmp" \
go build -trimpath -buildvcs=false -o .cache/nat/wirectl-connect ./cmd/wirectl-connect
CGO_ENABLED=0 GOCACHE="$PWD/.cache/go-build" \
GOMODCACHE="$PWD/.cache/go-mod" \
GOTMPDIR="$PWD/.cache/tmp" \
TMPDIR="$PWD/.cache/tmp" \
go build -trimpath -buildvcs=false -o .cache/nat/wire-connect-testutil ./cmd/wire-connect-testutil
sudo -H env WIRE_CONNECT_NAT_TEST=1 \
  ./scripts/test-nat.sh .cache/nat/wirectl-connect .cache/nat/wire-connect-testutil
```

The second binary is optional when it is available at
`.cache/wire-connect-testutil`; passing both paths is recommended in CI. The
test helper is not part of a release archive.

An Ubuntu runner needs the following packages:

```sh
sudo apt-get update
sudo -H apt-get install -y iproute2 iptables curl openssl coreutils procps tcpdump
```

Go is needed only to build the two binaries. No external network is used after
the Go module cache has been populated. The runner must permit
network namespace creation by root and must provide
`/dev/net/tun`, since each client creates a real Linux TUN device.

The script creates all state, certificates, logs and temporary files under a
unique `.cache/nat-test.*` directory. Its EXIT trap sends signals to recorded
test processes, removes only the namespaces, links and bridge it created, and
then removes that directory. NAT firewall rules disappear with their
namespaces; the host's iptables tables and default routes are not flushed or
modified.

On failure, diagnostics include namespace addresses/routes, namespace-local
iptables rules, bounded process stderr and packet-header captures when
available. Process stdout is withheld because pairing output can contain the
test fixture code. The enrollment token is generated into a mode-0600
temporary file and is never printed.

## CI evidence

This test is a separate gate from compilation, unit tests and cross-builds. A
CI job should build both Linux helpers, run the command on a disposable
Ubuntu runner with `WIRE_CONNECT_NAT_TEST=1`, and retain only the pass/fail
result (or sanitized stderr) as evidence. A green build or a local loopback
integration test alone is not evidence that either NAT scenario passed.

Both scenarios, including direct traffic with server HTTPS blocked, passed in
the `nat-linux` job of [CI 34757053195](https://github.com/k0ngk0ng/wire-connect/actions/runs/34757053195).
The release workflow runs this gate again for the tagged commit.
