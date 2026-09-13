# Validation record

Implementation and release qualification are in progress. This file records actual evidence and remaining gates; successful cross-compilation is not counted as native runtime validation.

| Requirement | Current evidence |
|---|---|
| OPAQUE short-code authentication and session encryption | Unit tests, wrong-context and replay tests; root-agent source review |
| Real encrypted application packets over HTTPS/DERP | `internal/client` integration tests use real WireGuard and a local TLS server, with memory TUN at the OS boundary |
| Upgrade from relay to UDP direct path | Same integration suite verifies ICE direct mode and further packet transfer |
| Native TUN/address/route creation and rollback | Passed for Linux amd64/arm64, macOS arm64 and Windows amd64 in the platform jobs of [CI 34756212350](https://github.com/k0ngk0ng/wire-connect/actions/runs/34756212350); real TUN, address/route setup and cleanup |
| Windows amd64 service, SCM lifecycle and Administrator-to-LocalSystem Named Pipe | Passed in the elevated Windows lifecycle job of [CI 34756212350](https://github.com/k0ngk0ng/wire-connect/actions/runs/34756212350) |
| Linux/macOS service installation and lifecycle | Passed in the Linux amd64/arm64 and macOS arm64 lifecycle jobs of [CI 34756212350](https://github.com/k0ngk0ng/wire-connect/actions/runs/34756212350); Unix runs use root-owned disposable state roots because the installer rejects untrusted state-directory ancestors |
| Server restart and path failure recovery | Client tests cover relay recovery after server restart and surviving direct traffic while the server is offline; transport tests cover actual ICE consent loss and DERP reconnect |
| Separate NATs, UDP blocked, bulk TCP and fragmented UDP | Passed in the `nat-linux` job of [CI 34757053195](https://github.com/k0ngk0ng/wire-connect/actions/runs/34757053195): ordinary stateful NAT selected direct; blocking server HTTPS during application transfers ruled out relay fallback; blocked UDP selected relay. Both paths verified 4 MiB TCP by SHA-256 and 1372/8192-byte UDP echoes |
| Public GitHub repository and release artifacts | Public repository created; Actions release and verified release downloads pending |
| Independent third-party cryptographic audit | Not performed |

Native network tests require explicit `WIRE_CONNECT_NETWORK_TEST=1` and the `integration` build tag. They run only on disposable CI runners, not automatically on a developer's machine.

The native service lifecycle test also requires `WIRE_CONNECT_SERVICE_INTEGRATION=1`, an independently built `cmd/wire-connect-service-testutil` helper supplied through `WIRE_CONNECT_SERVICE_HELPER`, and an elevated runner. It installs a unique service, checks the helper's config identity through local control, exercises both localctl stop and native-manager stop, and uninstalls the service while verifying that the profile remains. Windows additionally requires the official x64 `wintun.dll` beside the helper; the helper itself never opens a TUN device.

Real internet NATs, symmetric/double NAT, IPv6-only access, HTTP proxy variants, packet loss, arbitrary path MTUs, and long-duration load have not been qualified. The namespace scenarios are controlled simulations and do not establish universal hole-punch success. macOS Intel and Windows ARM are outside the supported release matrix.
