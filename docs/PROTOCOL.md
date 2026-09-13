# Protocol and trust boundaries

The CLI is an independently released `wirectl-connect` plugin. The public server combines an authenticated rendezvous API, a DERP WebSocket endpoint and STUN. Neither rendezvous nor relay holds a client's WireGuard private key or pair root secret.

## Enrollment

Server initialization generates a random 256-bit enrollment credential. The public server persists its SHA-256 digest, never the plaintext credential. A device submits the credential over verified HTTPS and receives an independent random bearer credential. Only its digest is retained by the server. Local client credentials are stored in a private state directory. Enrollment and peer pairing are separate operations.

## Pairing

A code contains twelve Crockford symbols. Four public symbols select a room; eight secret symbols provide 40 bits of random password entropy. No hash or verifier of those eight symbols is sent as the room identifier. Human-selected codes are not guaranteed to have the entropy of generated codes.

The host locally performs OPAQUE registration using its code password and temporary OPAQUE server key material. The registration record remains in the host process. The guest performs OPAQUE login with the host over the rendezvous socket; the relay sees KE1/KE2/KE3 and confirmation frames, not the registration record. The implementation uses `github.com/bytemare/opaque` with its standard default configuration.

OPAQUE context includes a fixed protocol domain, normalized server origin, public room ID and ordered host/guest identities. The host verifies KE3 before using the OPAQUE session secret. Both sides derive a root with HKDF and exchange explicit transcript-bound role-specific confirmation MACs. Frames have fixed version/type headers and bounded lengths; malformed, out-of-order and wrong-context exchanges fail closed.

After confirmation, an encrypted control session exchanges WireGuard and DERP public keys and negotiates virtual addresses. Both parties commit the same root-derived pair ID to the rendezvous server. The server persists the pair's two authorized device IDs. Clients persist the root secret and peer public keys. Reconnection uses those saved identities and never reuses the short code as an authorization credential.

## Control encryption

Each socket exchanges root-key-authenticated fresh random challenges. Ordered challenges, role and context derive separate transmission and reception keys and nonce prefixes. Control payloads use XChaCha20-Poly1305 with authenticated headers and sequence numbers. A bounded replay window rejects duplicates. Ciphertexts from an earlier control session or the opposite role do not authenticate in a new session.

## Data plane

`wireguard-go` encrypts IPv4 packets read from TUN. Its peer configuration allows only the authenticated peer's virtual `/32` source. A purpose-separated HKDF output supplies the WireGuard pre-shared key.

The custom `conn.Bind` transports complete encrypted WireGuard datagrams over either a Pion ICE UDP connection or the upstream DERP protocol. DERP itself is carried over a real WebSocket, using the same HTTPS trust and proxy settings as rendezvous. Received relay packets must match the authenticated peer's DERP key. WG authentication remains the authority for inner packet acceptance.

ICE gathers host and server-reflexive candidates, including IPv4 and IPv6. Candidate offers are encrypted through the control session. A stable Bind and virtual IP survive transport changes. A failed direct connection falls back to DERP; renewed ICE offers can replace the failed path. Losing only rendezvous does not intentionally close a working direct path.

## Operational limits

The rendezvous service has bounded room, device, message and queue resources. DERP admits only registered, unexpired device keys and applies connection and bandwidth limits. Authorization is rechecked when DERP connections renew. Revoking server authorization cannot remotely erase a client's saved keys or revoke a direct WireGuard relationship while the two clients remain willing to communicate.

The server is trusted for availability and routing metadata, not confidentiality. It can delay, drop, reorder, replay or refuse control messages and packets. It cannot prevent a device that knows the full code from joining first. Endpoints and their administrator accounts remain trusted.

This describes the implemented composition, not a new cryptographic primitive and not an independent security audit. Cryptographic library tests, local integration tests, native OS tests and real-world NAT qualification provide different kinds of evidence.
