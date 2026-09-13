# Development rules

- Keep all generated files, dependency caches, temporary files and local checkouts inside this repository (`.cache/` and `.work/` are ignored).
- Do not commit credentials, private keys, pairing codes, runtime state or downloaded executable dependencies.
- The root agent owns architecture, integration and verification. Delegate independent work and verify it before merging.
- Support clients on Linux and macOS (amd64/arm64), Windows (amd64); the public server runs on Linux.
- Reuse established cryptographic protocols. Never invent a PAKE, encryption primitive or WireGuard handshake.
- Treat compile checks, unit tests, integration tests and real-network validation as different evidence. Do not claim production validation from compilation alone.
- Run Go tools with GOCACHE, GOMODCACHE and GOTMPDIR under `.cache/`.
