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
