#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# This test intentionally changes network state. It is only for a disposable,
# privileged Linux CI runner. Every firewall rule is installed in a fresh
# network namespace and every namespace/link created below is removed by the
# EXIT trap.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
RUN_ROOT=""
BRIDGE=""
BRIDGE_CREATED=0
PROCESS_TIMEOUT=300s

usage() {
	cat >&2 <<'EOF'
usage: scripts/test-nat.sh CONNECT_BINARY [TESTUTIL_BINARY]

CONNECT_BINARY is a Linux standalone wirectl-connect executable. TESTUTIL_BINARY
is wire-connect-testutil; when omitted, .cache/wire-connect-testutil is used.

This test requires a disposable, privileged Linux runner. Set
WIRE_CONNECT_NAT_TEST=1 explicitly to allow network namespace and iptables
changes. No host firewall tables are modified.
EOF
}

# Refuse before creating even a repository-local temporary directory. This is
# the opt-in guard that keeps an accidental invocation harmless.
if [[ "${WIRE_CONNECT_NAT_TEST:-}" != "1" ]]; then
	echo "refusing NAT test: set WIRE_CONNECT_NAT_TEST=1 on a disposable Linux runner" >&2
	exit 2
fi

if [[ "$(uname -s)" != "Linux" ]]; then
	echo "refusing NAT test: this test only runs on Linux" >&2
	exit 2
fi

if [[ "$(id -u)" != "0" ]]; then
	echo "refusing NAT test: root or equivalent network administration capability is required" >&2
	exit 2
fi

declare -a CREATED_NAMESPACES=()
declare -a CREATED_LINKS=()
declare -a PROCESS_NAMES=()
declare -a STATUS_ENTRIES=()
declare -A PROCESS_PIDS=()
declare -A PROCESS_STDERR=()

if [[ $# -lt 1 || $# -gt 2 ]]; then
	usage
	exit 2
fi

abs_path() {
	local path="$1"
	if [[ "$path" != /* ]]; then
		path="$PWD/$path"
	fi
	if [[ ! -f "$path" ]]; then
		return 1
	fi
	local dir base
	dir="$(cd "$(dirname "$path")" && pwd -P)"
	base="$(basename "$path")"
	printf '%s/%s\n' "$dir" "$base"
}

CONNECT_BIN="$(abs_path "$1")" || { echo "connect binary not found: $1" >&2; exit 2; }
if [[ ! -x "$CONNECT_BIN" ]]; then
	echo "connect binary is not executable: $CONNECT_BIN" >&2
	exit 2
fi
if [[ $# -eq 2 ]]; then
	TESTUTIL_BIN="$(abs_path "$2")" || { echo "testutil binary not found: $2" >&2; exit 2; }
else
	TESTUTIL_BIN="$(abs_path "$ROOT_DIR/.cache/wire-connect-testutil")" || {
		echo "testutil binary not found; pass it as the second argument or build .cache/wire-connect-testutil" >&2
		exit 2
	}
fi
if [[ ! -x "$TESTUTIL_BIN" ]]; then
	echo "testutil binary is not executable: $TESTUTIL_BIN" >&2
	exit 2
fi

for required in ip iptables curl timeout awk grep sed tail sleep mktemp openssl tr sysctl head sha256sum tcpdump; do
	if ! command -v "$required" >/dev/null 2>&1; then
		echo "required command is missing: $required" >&2
		exit 2
	fi
done

mkdir -p "$ROOT_DIR/.cache"
umask 077
RUN_ROOT="$(mktemp -d "$ROOT_DIR/.cache/nat-test.XXXXXX")"
chmod 700 "$RUN_ROOT"

cleanup_done=0
cleanup() {
	local saved_status=$?
	if [[ "$cleanup_done" == "1" ]]; then
		return "$saved_status"
	fi
	cleanup_done=1
	trap - EXIT INT TERM
	set +e

	# The process table is explicit. Namespace pids are only a final cleanup
	# safety net for an ip/netns/timeout child that outlived its recorded parent;
	# they cannot refer to a process outside one of these newly-created
	# namespaces.
	local name pid ns ns_pid
	for name in "${PROCESS_NAMES[@]}"; do
		pid="${PROCESS_PIDS[$name]-}"
		if [[ "$pid" =~ ^[0-9]+$ ]]; then
			kill -TERM "$pid" 2>/dev/null || true
		fi
	done
	for name in "${PROCESS_NAMES[@]}"; do
		pid="${PROCESS_PIDS[$name]-}"
		if [[ "$pid" =~ ^[0-9]+$ ]]; then
			for _ in 1 2 3 4 5; do
				kill -0 "$pid" 2>/dev/null || break
				sleep 0.1
			done
			kill -KILL "$pid" 2>/dev/null || true
			wait "$pid" 2>/dev/null || true
		fi
	done
	for ns in "${CREATED_NAMESPACES[@]}"; do
		while read -r ns_pid; do
			if [[ "$ns_pid" =~ ^[0-9]+$ ]]; then
				kill -KILL "$ns_pid" 2>/dev/null || true
			fi
		done < <(ip netns pids "$ns" 2>/dev/null)
	done
	for ns in "${CREATED_NAMESPACES[@]}"; do
		for _ in 1 2 3 4 5; do
			ip netns del "$ns" 2>/dev/null && break
			while read -r ns_pid; do
				if [[ "$ns_pid" =~ ^[0-9]+$ ]]; then
					kill -KILL "$ns_pid" 2>/dev/null || true
				fi
			done < <(ip netns pids "$ns" 2>/dev/null)
			sleep 0.1
		done
	done
	for link in "${CREATED_LINKS[@]}"; do
		ip link del "$link" 2>/dev/null || true
	done
	if [[ "$BRIDGE_CREATED" == "1" && -n "$BRIDGE" ]]; then
		ip link del "$BRIDGE" 2>/dev/null || true
	fi
	if [[ -n "$RUN_ROOT" && -d "$RUN_ROOT" ]]; then
		rm -rf -- "$RUN_ROOT"
	fi
	return "$saved_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
	echo "NAT integration test failed: $*" >&2
	dump_diagnostics
	exit 1
}

dump_diagnostics() {
	set +e
	echo "--- namespace status ---" >&2
	local ns name
	for ns in "${CREATED_NAMESPACES[@]}"; do
		echo "[$ns]" >&2
		ip netns exec "$ns" ip -brief addr show >&2 2>&1
		ip netns exec "$ns" ip -4 route show >&2 2>&1
		ip netns exec "$ns" iptables -S >&2 2>&1
		ip netns exec "$ns" iptables -t nat -S >&2 2>&1
		ip netns exec "$ns" iptables -nvL FORWARD >&2 2>&1
		ip netns exec "$ns" iptables -t nat -nvL POSTROUTING >&2 2>&1
	done
	echo "--- process stderr (stdout is withheld because it can contain pairing output) ---" >&2
	for name in "${PROCESS_NAMES[@]}"; do
		path="${PROCESS_STDERR[$name]-}"
		if [[ -n "$path" && -f "$path" ]]; then
			echo "[$name]" >&2
			tail -n 120 "$path" >&2
		fi
	done
	# tcpdump uses quiet summaries only: no packet contents, ICE credentials,
	# or pairing output. Keep these separate from client stdout.
	for name in nat-a nat-b; do
		if [[ -f "$RUN_ROOT/$name.headers" ]]; then
			echo "[$name UDP/ICMP headers]" >&2
			tail -n 160 "$RUN_ROOT/$name.headers" >&2
		fi
	done
	echo "--- connection status ---" >&2
	local entry label state
	for entry in "${STATUS_ENTRIES[@]}"; do
		IFS='|' read -r label ns state <<<"$entry"
		echo "[$label $ns]" >&2
		ns_exec "$ns" timeout 5s "$CONNECT_BIN" status --state-dir "$state" --name "$label" >&2 2>&1
	done
}

ns_exec() {
	local ns="$1"
	shift
	ip netns exec "$ns" "$@"
}

iptables_ns() {
	local ns="$1"
	shift
	ns_exec "$ns" iptables -w 5 "$@"
}

new_namespace() {
	local ns="$1"
	ip netns add "$ns" || fail "could not create namespace $ns"
	CREATED_NAMESPACES+=("$ns")
	ns_exec "$ns" ip link set lo up || fail "could not enable loopback in $ns"
	ns_exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0 || fail "could not disable reverse-path filtering in $ns"
	ns_exec "$ns" sysctl -qw net.ipv4.conf.default.rp_filter=0 || fail "could not disable default reverse-path filtering in $ns"
}

new_veth() {
	local ns="$1" inside="$2" outside="$3"
	local peer_tmp="${outside}p"
	# The temporary peer name must be unique in the host namespace. Names such
	# as eth0 and wan0 may already exist on the CI runner and are only assigned
	# after the peer has moved into its isolated namespace.
	ip link add "$outside" type veth peer name "$peer_tmp" || fail "could not create veth $outside"
	CREATED_LINKS+=("$outside")
	ip link set "$peer_tmp" netns "$ns" || fail "could not move $peer_tmp into $ns"
	ip link set "$outside" master "$BRIDGE" || fail "could not attach $outside to $BRIDGE"
	ip link set "$outside" up || fail "could not bring up $outside"
	ns_exec "$ns" ip link set "$peer_tmp" name "$inside" || fail "could not rename $peer_tmp in $ns"
}

configure_interface() {
	local ns="$1" iface="$2" addr="$3"
	ns_exec "$ns" ip addr add "$addr" dev "$iface" || fail "could not assign $addr in $ns"
	ns_exec "$ns" ip link set "$iface" up || fail "could not bring up $iface in $ns"
}

new_private_link() {
	local nat_ns="$1" client_ns="$2" first="$3" second="$4"
	ip link add "$first" type veth peer name "$second" || fail "could not create private link"
	CREATED_LINKS+=("$first" "$second")
	ip link set "$first" netns "$nat_ns" || fail "could not move NAT LAN interface"
	ip link set "$second" netns "$client_ns" || fail "could not move client interface"
	ns_exec "$nat_ns" ip link set "$first" name lan0 || fail "could not name NAT LAN interface"
	ns_exec "$client_ns" ip link set "$second" name eth0 || fail "could not name client interface"
}

configure_nat() {
	local ns="$1" wan_addr="$2" lan_net="$3" lan_addr="$4"
	configure_interface "$ns" wan0 "$wan_addr"
	configure_interface "$ns" lan0 "$lan_addr"
	ns_exec "$ns" sysctl -qw net.ipv4.ip_forward=1 || fail "could not enable forwarding in $ns"
	ns_exec "$ns" ip route add default via 198.18.0.1 dev wan0 || fail "could not add NAT default route in $ns"
	iptables_ns "$ns" -P FORWARD DROP || fail "could not set NAT forwarding policy in $ns"
	iptables_ns "$ns" -t nat -A POSTROUTING -s "$lan_net" -o wan0 -j MASQUERADE || fail "could not install masquerade in $ns"
	iptables_ns "$ns" -A FORWARD -i lan0 -o wan0 -j ACCEPT || fail "could not allow outbound forwarding in $ns"
	iptables_ns "$ns" -A FORWARD -i wan0 -o lan0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || fail "could not allow return forwarding in $ns"
	# Keep the private side explicit even though a new namespace normally has
	# ACCEPT as its default policy. This documents the simulated topology.
	ns_exec "$ns" ip route replace "$lan_net" dev lan0 || fail "could not add NAT LAN route in $ns"
}

configure_client() {
	local ns="$1" addr="$2" gateway="$3"
	configure_interface "$ns" eth0 "$addr"
	ns_exec "$ns" ip route add default via "$gateway" dev eth0 || fail "could not add client default route in $ns"
}

start_process() {
	local name="$1" ns="$2" stdout="$3" stderr="$4"
	shift 4
	if [[ -e "$stdout" || -e "$stderr" ]]; then
		fail "refusing to overwrite process log for $name"
	fi
	# Track the actual timeout process, not a background shell function, so
	# terminating it forwards SIGTERM to the application before the next case.
	ip netns exec "$ns" timeout --foreground "$PROCESS_TIMEOUT" "$@" >"$stdout" 2>"$stderr" &
	local pid=$!
	PROCESS_NAMES+=("$name")
	PROCESS_PIDS["$name"]="$pid"
	PROCESS_STDERR["$name"]="$stderr"
	sleep 0.1
	if ! kill -0 "$pid" 2>/dev/null; then
		fail "$name exited during startup"
	fi
}

stop_process() {
	local pid="${PROCESS_PIDS[$1]-}"
	if [[ ! "$pid" =~ ^[0-9]+$ ]]; then
		return 0
	fi
	kill -TERM "$pid" 2>/dev/null || true
	for _ in {1..50}; do
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.1
	done
	kill -KILL "$pid" 2>/dev/null || true
	wait "$pid" 2>/dev/null || true
	PROCESS_PIDS["$1"]=""
}

wait_for_health() {
	local ns="$1" deadline=$((SECONDS + 20))
	while (( SECONDS < deadline )); do
		if ns_exec "$ns" timeout 3s curl --silent --show-error --fail --insecure --max-time 2 "$SERVER_URL/healthz" >/dev/null 2>>"$RUN_ROOT/health.stderr"; then
			return 0
		fi
		sleep 0.2
	done
	fail "server HTTPS health check did not become ready"
}

login_client() {
	local name="$1" ns="$2" state="$3"
	local stdout="$RUN_ROOT/$name-login.stdout" stderr="$RUN_ROOT/$name-login.stderr"
	mkdir -p "$state"
	chmod 700 "$state"
	PROCESS_NAMES+=("$name-login")
	PROCESS_STDERR["$name-login"]="$stderr"
	if ! printf '%s\n' "$ENROLLMENT_TOKEN" | ns_exec "$ns" timeout 20s "$CONNECT_BIN" login "$SERVER_URL" --pin "$CERT_PIN" --state-dir "$state" >"$stdout" 2>"$stderr"; then
		fail "$name could not enroll (see process stderr)"
	fi
}

wait_for_mode() {
	local name="$1" ns="$2" state="$3" mode="$4" deadline=$((SECONDS + 90)) out pid
	while (( SECONDS < deadline )); do
		out="$(ns_exec "$ns" timeout 5s "$CONNECT_BIN" status --state-dir "$state" --name "$name" 2>/dev/null || true)"
		if printf '%s\n' "$out" | grep -q "^${mode} "; then
			return 0
		fi
		pid="${PROCESS_PIDS["$name-host"]-}"
		if [[ "$pid" =~ ^[0-9]+$ ]] && ! kill -0 "$pid" 2>/dev/null; then
			fail "$name host exited before reaching $mode mode"
		fi
		pid="${PROCESS_PIDS["$name-guest"]-}"
		if [[ "$pid" =~ ^[0-9]+$ ]] && ! kill -0 "$pid" 2>/dev/null; then
			fail "$name guest exited before reaching $mode mode"
		fi
		sleep 0.5
	done
	fail "$name did not reach $mode mode"
}

status_peer() {
	local name="$1" ns="$2" state="$3" line peer
	line="$(ns_exec "$ns" timeout 5s "$CONNECT_BIN" status --state-dir "$state" --name "$name" 2>/dev/null | sed -n '1p')" || return 1
	peer="${line##* ↔ }"
	if [[ ! "$peer" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		return 1
	fi
	printf '%s\n' "$peer"
}

test_inner_traffic() {
	local label="$1" name="$2" ns_client="$3" state="$4" ns_peer="$5" peer="$6"
	local http_name="${label}-http" udp_name="${label}-udp"
	start_process "$http_name" "$ns_peer" "$RUN_ROOT/$http_name.stdout" "$RUN_ROOT/$http_name.stderr" "$TESTUTIL_BIN" http --addr 0.0.0.0:18080
	start_process "$udp_name" "$ns_peer" "$RUN_ROOT/$udp_name.stdout" "$RUN_ROOT/$udp_name.stderr" "$TESTUTIL_BIN" udp --addr 0.0.0.0:18081
	sleep 0.3

	local body="" http_ok=0
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		body="$(ns_exec "$ns_client" timeout 3s curl --silent --show-error --fail --max-time 2 "http://$peer:18080/" 2>>"$RUN_ROOT/$label-http-client.stderr" || true)"
		if [[ "$body" == "wire-connect-nat-http-ok" ]]; then
			http_ok=1
			break
		fi
		sleep 0.3
	done
	[[ "$http_ok" == "1" ]] || fail "$label TCP traffic did not cross the encrypted virtual link"

	local udp_ok=0
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		if ns_exec "$ns_client" timeout 5s "$TESTUTIL_BIN" udp-client --addr "$peer:18081" --payload "wire-connect-$label-udp" >"$RUN_ROOT/$label-udp-client.stdout" 2>"$RUN_ROOT/$label-udp-client.stderr"; then
			udp_ok=1
			break
		fi
		sleep 0.3
	done
	[[ "$udp_ok" == "1" ]] || fail "$label UDP traffic did not cross the encrypted virtual link"

	# Verify a full TCP stream beyond the initial handshake, byte for byte.
	local bulk="$RUN_ROOT/$label-bulk.bin" expected_hash actual_hash
	if ! ns_exec "$ns_client" timeout 35s curl --silent --show-error --fail --max-time 30 "http://$peer:18080/bulk" -o "$bulk" 2>"$RUN_ROOT/$label-bulk.stderr"; then
		fail "$label bulk TCP transfer failed"
	fi
	expected_hash="$(head -c 4194304 /dev/zero | sha256sum | awk '{print $1}')"
	actual_hash="$(sha256sum "$bulk" | awk '{print $1}')"
	[[ "$actual_hash" == "$expected_hash" ]] || fail "$label bulk TCP content mismatch"

	# Check a near-MTU datagram and fragmented inner IPv4 UDP traffic.
	local size payload
	for size in 1372 8192; do
		printf -v payload '%*s' "$size" ''
		if ! ns_exec "$ns_client" timeout 5s "$TESTUTIL_BIN" udp-client --addr "$peer:18081" --payload "$payload" >"$RUN_ROOT/$label-udp-$size.stdout" 2>"$RUN_ROOT/$label-udp-$size.stderr"; then
			fail "$label UDP payload of $size bytes failed"
		fi
	done

	stop_process "$http_name"
	stop_process "$udp_name"
}

run_pair() {
	local label="$1" code="$2" expected_mode="$3" state_a="$4" state_b="$5" network="$6"
	STATUS_ENTRIES+=("$label|$NS_CLIENT_A|$state_a" "$label|$NS_CLIENT_B|$state_b")
	start_process "$label-host" "$NS_CLIENT_A" "$RUN_ROOT/$label-host.stdout" "$RUN_ROOT/$label-host.stderr" "$CONNECT_BIN" "$SERVER_URL" --state-dir "$state_a" --name "$label" --code "$code" --network "$network" --interface "wc$label" --verbose
	local deadline=$((SECONDS + 15))
	until grep -q '^Pairing code:' "$RUN_ROOT/$label-host.stdout"; do
		(( SECONDS < deadline )) || fail "$label host did not create its pairing room"
		kill -0 "${PROCESS_PIDS["$label-host"]}" 2>/dev/null || fail "$label host exited during pairing"
		sleep 0.1
	done
	start_process "$label-guest" "$NS_CLIENT_B" "$RUN_ROOT/$label-guest.stdout" "$RUN_ROOT/$label-guest.stderr" "$CONNECT_BIN" "$SERVER_URL" "$code" --state-dir "$state_b" --name "$label" --network "$network" --interface "wc$label" --verbose
	wait_for_mode "$label" "$NS_CLIENT_A" "$state_a" "$expected_mode"
	wait_for_mode "$label" "$NS_CLIENT_B" "$state_b" "$expected_mode"
}

# Use a short, non-secret suffix only for kernel object names. The pairing
# codes used below are fixed test fixtures so a diagnostic can identify which
# scenario was running without ever printing a user's code.
suffix="$(printf '%04x' "$((RANDOM & 65535))")"
bridge_candidate="wcbr${suffix}"
NS_SERVER="wc-${suffix}-srv"
NS_NAT_A="wc-${suffix}-na"
NS_NAT_B="wc-${suffix}-nb"
NS_CLIENT_A="wc-${suffix}-a"
NS_CLIENT_B="wc-${suffix}-b"
SERVER_URL="https://198.18.0.1"

if ip link show "$bridge_candidate" >/dev/null 2>&1; then
	fail "generated bridge name already exists: $bridge_candidate"
fi
BRIDGE="$bridge_candidate"

new_namespace "$NS_SERVER"
new_namespace "$NS_NAT_A"
new_namespace "$NS_NAT_B"
new_namespace "$NS_CLIENT_A"
new_namespace "$NS_CLIENT_B"

ip link add "$BRIDGE" type bridge || fail "could not create public bridge"
BRIDGE_CREATED=1
ip link set "$BRIDGE" up || fail "could not enable public bridge"

new_veth "$NS_SERVER" eth0 "wcs${suffix}"
new_veth "$NS_NAT_A" wan0 "wcpa${suffix}"
new_veth "$NS_NAT_B" wan0 "wcpb${suffix}"
new_private_link "$NS_NAT_A" "$NS_CLIENT_A" "wcla${suffix}" "wcae${suffix}"
new_private_link "$NS_NAT_B" "$NS_CLIENT_B" "wclb${suffix}" "wcbe${suffix}"

configure_interface "$NS_SERVER" eth0 198.18.0.1/24
configure_nat "$NS_NAT_A" 198.18.0.2/24 10.201.1.0/24 10.201.1.1/24
configure_nat "$NS_NAT_B" 198.18.0.3/24 10.202.1.0/24 10.202.1.1/24
configure_client "$NS_CLIENT_A" 10.201.1.2/24 10.201.1.1
configure_client "$NS_CLIENT_B" 10.202.1.2/24 10.202.1.1

start_process capture-a "$NS_NAT_A" "$RUN_ROOT/nat-a.headers" "$RUN_ROOT/capture-a.stderr" tcpdump -n -q -l -i wan0 'udp or icmp'
start_process capture-b "$NS_NAT_B" "$RUN_ROOT/nat-b.headers" "$RUN_ROOT/capture-b.stderr" tcpdump -n -q -l -i wan0 'udp or icmp'

TOKEN_FILE="$RUN_ROOT/enrollment.token"
CERT_FILE="$RUN_ROOT/server.crt"
KEY_FILE="$RUN_ROOT/server.key"
openssl rand -hex 32 >"$TOKEN_FILE"
chmod 600 "$TOKEN_FILE"
if ! "$TESTUTIL_BIN" cert --ip 198.18.0.1 --cert "$CERT_FILE" --key "$KEY_FILE" >"$RUN_ROOT/cert.fingerprint" 2>"$RUN_ROOT/cert.stderr"; then
	fail "could not create disposable TLS certificate"
fi
CERT_PIN="$(tr -d '[:space:]' <"$RUN_ROOT/cert.fingerprint")"
if [[ ! "$CERT_PIN" =~ ^[0-9a-fA-F]{64}$ ]]; then
	fail "testutil returned an invalid certificate fingerprint"
fi
ENROLLMENT_TOKEN="$(<"$TOKEN_FILE")"

if ! ns_exec "$NS_SERVER" timeout 10s "$CONNECT_BIN" serve --init --state-dir "$RUN_ROOT/server-state" --enrollment-token-file "$TOKEN_FILE" >"$RUN_ROOT/server-init.stdout" 2>"$RUN_ROOT/server-init.stderr"; then
	fail "server initialization failed"
fi
start_process server "$NS_SERVER" "$RUN_ROOT/server.stdout" "$RUN_ROOT/server.stderr" "$CONNECT_BIN" serve --listen 198.18.0.1:443 --cert "$CERT_FILE" --key "$KEY_FILE" --stun-listen 198.18.0.1:3478 --state-dir "$RUN_ROOT/server-state"
wait_for_health "$NS_CLIENT_A"

DIRECT_A="$RUN_ROOT/direct-a"
DIRECT_B="$RUN_ROOT/direct-b"
login_client direct-a "$NS_CLIENT_A" "$DIRECT_A"
login_client direct-b "$NS_CLIENT_B" "$DIRECT_B"

ns_exec "$NS_CLIENT_A" timeout 12s "$CONNECT_BIN" doctor "$SERVER_URL" --state-dir "$DIRECT_A" >"$RUN_ROOT/direct-doctor.stdout" 2>"$RUN_ROOT/direct-doctor.stderr" || fail "direct scenario prerequisites failed"
grep -q '^STUN:' "$RUN_ROOT/direct-doctor.stdout" || fail "direct scenario STUN did not observe a NAT mapping"
cat "$RUN_ROOT/direct-doctor.stdout"

run_pair direct 7k3m-f8q2-h6tw direct "$DIRECT_A" "$DIRECT_B" 10.240.0.0/24
DIRECT_PEER="$(status_peer direct "$NS_CLIENT_A" "$DIRECT_A")" || fail "could not read direct peer address"
test_inner_traffic direct direct "$NS_CLIENT_A" "$DIRECT_A" "$NS_CLIENT_B" "$DIRECT_PEER"
stop_process direct-host
stop_process direct-guest

# Insert the drop before the ordinary forwarding rule. TCP control and DERP
# remain available, while every UDP packet leaving either simulated private
# network is rejected at its own NAT boundary.
iptables_ns "$NS_NAT_A" -I FORWARD 1 -i lan0 -o wan0 -p udp -j DROP || fail "could not block UDP egress from NAT A"
iptables_ns "$NS_NAT_B" -I FORWARD 1 -i lan0 -o wan0 -p udp -j DROP || fail "could not block UDP egress from NAT B"

RELAY_A="$RUN_ROOT/relay-a"
RELAY_B="$RUN_ROOT/relay-b"
login_client relay-a "$NS_CLIENT_A" "$RELAY_A"
login_client relay-b "$NS_CLIENT_B" "$RELAY_B"
DOCTOR_OUT="$RUN_ROOT/relay-doctor.stdout"
DOCTOR_ERR="$RUN_ROOT/relay-doctor.stderr"
PROCESS_NAMES+=(relay-doctor)
PROCESS_STDERR[relay-doctor]="$DOCTOR_ERR"
# UDP unavailability is advisory: doctor can succeed when HTTPS relay is
# available. Assert its actual UDP result rather than treating exit 0 as STUN
# success.
ns_exec "$NS_CLIENT_A" timeout 12s "$CONNECT_BIN" doctor "$SERVER_URL" --state-dir "$RELAY_A" >"$DOCTOR_OUT" 2>"$DOCTOR_ERR" || fail "doctor failed its HTTPS/platform prerequisites"
if ! grep -q "Direct UDP:" "$DOCTOR_OUT"; then
	fail "doctor did not report the simulated UDP egress failure"
fi

run_pair relay 8k4n-g9r3-j7vx relay "$RELAY_A" "$RELAY_B" 10.241.0.0/24
RELAY_PEER="$(status_peer relay "$NS_CLIENT_A" "$RELAY_A")" || fail "could not read relay peer address"
test_inner_traffic relay relay "$NS_CLIENT_A" "$RELAY_A" "$NS_CLIENT_B" "$RELAY_PEER"

echo "NAT integration tests passed: ordinary NAT selected direct mode; UDP-egress-blocked NAT selected relay mode; TCP and UDP virtual traffic succeeded in both scenarios."
