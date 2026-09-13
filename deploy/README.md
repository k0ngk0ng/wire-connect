# Linux server deployment

The release server binary is `wirectl-connect`. Point the public DNS name at
the Linux host before starting it, and allow TCP 443 and UDP 3478 in the host
firewall and cloud security group. The service account does not need a shell
or a home directory.

The checked-in unit starts:

```text
wirectl-connect serve --domain vpn.example.com --state-dir /var/lib/wire-connect
```

The server's normal `serve` defaults are TLS over TCP port 443 and STUN over
UDP port 3478. With no certificate flags, ACME is used for the configured
domain. Certificate issuance requires public DNS and inbound TCP 443; the
state directory is kept private so the account can renew the certificate.

For a certificate managed outside the process, create a systemd drop-in that
replaces `ExecStart` and adds `--cert` and `--key`:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/wirectl-connect serve --domain vpn.example.com --state-dir /var/lib/wire-connect --cert /etc/wire-connect/fullchain.pem --key /etc/wire-connect/privkey.pem
```

Install the binary, service account, and private directories with commands
similar to these. They are instructions for the target host; this repository
does not run them automatically.

```sh
sudo useradd --system --home-dir /var/lib/wire-connect --shell /usr/sbin/nologin wire-connect
sudo install -o root -g root -m 0755 wirectl-connect /usr/local/bin/wirectl-connect
sudo install -d -o wire-connect -g wire-connect -m 0700 /var/lib/wire-connect
sudo install -d -o wire-connect -g wire-connect -m 0700 /etc/wire-connect
sudo install -o root -g root -m 0644 deploy/wirectl-connect.service /etc/systemd/system/wirectl-connect.service
sudo systemctl daemon-reload
# Initialize the server identity before the first service start. The token is
# printed once; save it in the password manager or another private location.
sudo -u wire-connect /usr/local/bin/wirectl-connect serve --init --state-dir /var/lib/wire-connect
sudo systemctl enable --now wirectl-connect.service
```

`StateDirectory=` and `ConfigurationDirectory=` in the unit keep the runtime
state and optional configuration directories private. If a certificate key is
installed manually, keep it readable only by `wire-connect` (for example,
owner `wire-connect:wire-connect`, mode `0600`). Do not put enrollment tokens
or private keys in the unit file or in shell history. The `serve --init`
command above creates the durable server identity and displays the enrollment
token exactly once; subsequent service starts intentionally omit the token and
load only its hash from `/var/lib/wire-connect`.

Check the listeners and logs after startup:

```sh
sudo systemctl status wirectl-connect.service
sudo ss -lntup | grep -E ':(443|3478)\b'
sudo journalctl -u wirectl-connect.service -f
```

## Nginx TLS termination

When Nginx already owns port 443, it can terminate public TLS and proxy both
control and DERP WebSockets to a loopback HTTP backend. The backend does not
need certificate files or access to port 443:

```sh
wirectl-connect serve --http --listen 127.0.0.1:8080 --state-dir /var/lib/wire-connect
```

Initialize the service account and state as above, but install
`deploy/wirectl-connect-nginx.service` as
`/etc/systemd/system/wirectl-connect.service`. Set its loopback port to an unused
port, then use the same port in `deploy/nginx.conf`.

`--http` defaults to `127.0.0.1:8080`. Explicit listeners must use a loopback IP
literal (`127.0.0.1` or `[::1]`, for example). Wildcard, LAN, public, DNS-name and
zoned listeners are rejected before the server creates state. HTTP mode cannot
be combined with `--domain`, `--cert` or `--key`. Client connections to remote
servers still require HTTPS.

For Certbot webroot validation, first enable only the port-80 server block from
`deploy/nginx.conf`, with the redirect replaced by `return 404;` until the
certificate exists. Replace `vpn.example.com` with the desired hostname.
Then create the challenge webroot and request the certificate using your
existing Certbot account:

```sh
sudo install -d -m 0755 /var/lib/letsencrypt/wire-connect/.well-known/acme-challenge
sudo nginx -t && sudo systemctl reload nginx
sudo certbot certonly --webroot -w /var/lib/letsencrypt/wire-connect -d vpn.example.com
```

Once issued, enable the complete `deploy/nginx.conf` template in Nginx's `http`
context. Its `map` and WebSocket upgrade headers are required. The HTTP backend
port must remain bound to loopback; only public TCP 443 and UDP 3478 are needed
for client connections. TCP 80 remains available for Certbot HTTP-01 renewals.

On a host running a transparent proxy or VPN, a wildcard UDP socket can send
STUN replies through that proxy's default route with the wrong source address.
In that case add `--stun-listen <interface-IP>:3478` to the service command,
using the physical interface address that receives the public traffic. On a
cloud host with public-IP NAT this is usually the host's private interface IP,
not the public address. Verify replies from an external network; an open cloud
security-group port alone does not verify the return path.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now wirectl-connect.service
sudo nginx -t && sudo systemctl reload nginx
curl --fail https://vpn.example.com/healthz
```

Keep Certbot's renewal timer enabled and install a deployment hook which runs
`nginx -t` followed by `systemctl reload nginx` after this certificate renews.
The backend needs no restart or certificate copies. Test renewal with
`certbot renew --cert-name vpn.example.com --dry-run`.

The current backend deliberately does not trust forwarded IP headers. Its IP
rate limits therefore aggregate clients behind the proxy; device authentication
and per-device relay limits remain separate. Do not treat this as independent
per-client source-IP enforcement for a large shared deployment.

`TestWireGuardThroughTLSReverseProxy` verifies pairing, WebSocket relay and
bidirectional WireGuard payloads through TLS termination. An explicit
`WIRE_CONNECT_PROXY_TEST_SERVER=https://...` and
`WIRE_CONNECT_PROXY_TEST_TOKEN_FILE=/private/token-file` also enable deployment
qualification against an authorized **disposable** server state; the test
creates two temporary device authorizations and must not be pointed at an
unrelated server. It uses memory TUN devices and does not change local routes.

## Client packages

Verify `SHA256SUMS` before unpacking a release. GitHub artifact provenance can
be checked with `gh attestation verify` against the repository. The packages
do not claim Apple or Windows code signing; no signing certificates are
configured. The Windows package additionally contains the official x64
`wintun.dll` and its `WINTUN-LICENSE.txt` beside `wirectl-connect.exe`.

On Windows, optional Authenticode verification can be run from PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\verify-wintun.ps1 -Path .\bin\wintun.dll
```

The build scripts pin the official Wintun archive URL and SHA-256 digest and
keep its downloaded ZIP under `.cache/wintun`; the DLL and ZIP are never
committed to this repository.
