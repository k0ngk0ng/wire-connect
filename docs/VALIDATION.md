# Validation record

Implementation and release qualification are in progress. This file records actual evidence and remaining gates; successful cross-compilation is not counted as native runtime validation.

| Requirement | Current evidence |
|---|---|
| OPAQUE short-code authentication and session encryption | Unit tests, wrong-context and replay tests; root-agent source review |
| Real encrypted application packets over HTTPS/DERP | `internal/client` integration tests use real WireGuard and a local TLS server, with memory TUN at the OS boundary |
| Upgrade from relay to UDP direct path | Same integration suite verifies ICE direct mode and further packet transfer |
| Native TUN/address/route creation and rollback | Opt-in `internal/platform` integration suite prepared; native CI execution pending |
| Windows amd64 service and Named Pipe | Implementation and native CI verification in progress |
| Linux/macOS service installation | Implementation and isolated validation in progress |
| Server restart, path failure, reconnect and long-lived sessions | Additional integration qualification pending |
| Multiple NAT topologies, packet loss, MTU and sustained load | Qualification pending; local loopback connectivity is not proof of internet NAT behavior |
| Public GitHub repository and release artifacts | Publishing and verified Actions release pending |
| Independent third-party cryptographic audit | Not performed |

Native network tests require explicit `WIRE_CONNECT_NETWORK_TEST=1` and the `integration` build tag. They run only on disposable CI runners, not automatically on a developer's machine.
