# Third-party notices

`wire-connect` is distributed under the MIT License in the repository
[`LICENSE`](LICENSE). The program statically links Go modules. The runtime and
platform dependencies called out below are pinned by `go.mod` at this
revision; the release build also emits `THIRD_PARTY_INVENTORY.txt` from the
complete `go list -m all` module graph, including transitive modules.

Each link below points to the corresponding upstream source and license at the
same version. The upstream license text remains authoritative. This file is
included in every release archive.

## Go modules pinned for the connect build

| Module | Version | License | Upstream source and license |
| --- | --- | --- | --- |
| `filippo.io/edwards25519` | `v1.2.0` | BSD 3-Clause | [source](https://github.com/FiloSottile/edwards25519) · [LICENSE](https://github.com/FiloSottile/edwards25519/blob/v1.2.0/LICENSE) |
| `filippo.io/nistec` | `v0.0.4` | BSD 3-Clause | [source](https://github.com/FiloSottile/nistec) · [LICENSE](https://github.com/FiloSottile/nistec/blob/v0.0.4/LICENSE) |
| `github.com/bytemare/ecc` | `v0.9.0` | MIT | [source](https://github.com/bytemare/ecc) · [LICENSE](https://github.com/bytemare/ecc/blob/v0.9.0/LICENSE) |
| `github.com/bytemare/hash` | `v0.6.2` | MIT | [source](https://github.com/bytemare/hash) · [LICENSE](https://github.com/bytemare/hash/blob/v0.6.2/LICENSE) |
| `github.com/bytemare/hash2curve` | `v0.5.4` | MIT | [source](https://github.com/bytemare/hash2curve) · [LICENSE](https://github.com/bytemare/hash2curve/blob/v0.5.4/LICENSE) |
| `github.com/bytemare/ksf` | `v0.5.0` | MIT | [source](https://github.com/bytemare/ksf) · [LICENSE](https://github.com/bytemare/ksf/blob/v0.5.0/LICENSE) |
| `github.com/bytemare/opaque` | `v0.18.0` | MIT | [source](https://github.com/bytemare/opaque) · [LICENSE](https://github.com/bytemare/opaque/blob/v0.18.0/LICENSE) |
| `github.com/bytemare/secp256k1` | `v0.3.0` | MIT | [source](https://github.com/bytemare/secp256k1) · [LICENSE](https://github.com/bytemare/secp256k1/blob/v0.3.0/LICENSE) |
| `github.com/coder/websocket` | `v1.8.15` | ISC | [source](https://github.com/coder/websocket) · [LICENSE](https://github.com/coder/websocket/blob/v1.8.15/LICENSE.txt) |
| `github.com/google/uuid` | `v1.6.0` | BSD 3-Clause | [source](https://github.com/google/uuid) · [LICENSE](https://github.com/google/uuid/blob/v1.6.0/LICENSE) |
| `github.com/gtank/ristretto255` | `v0.2.0` | BSD 3-Clause | [source](https://github.com/gtank/ristretto255) · [LICENSE](https://github.com/gtank/ristretto255/blob/v0.2.0/LICENSE) |
| `github.com/pion/dtls/v3` | `v3.1.8` | MIT | [source](https://github.com/pion/dtls) · [LICENSE](https://github.com/pion/dtls/tree/v3.1.8/LICENSE) |
| `github.com/pion/ice/v4` | `v4.4.2` | MIT | [source](https://github.com/pion/ice) · [LICENSE](https://github.com/pion/ice/tree/v4.4.2/LICENSE) |
| `github.com/pion/logging` | `v0.2.4` | MIT | [source](https://github.com/pion/logging) · [LICENSE](https://github.com/pion/logging/blob/v0.2.4/LICENSE) |
| `github.com/pion/mdns/v2` | `v2.2.0` | MIT | [source](https://github.com/pion/mdns) · [LICENSE](https://github.com/pion/mdns/tree/v2.2.0/LICENSE) |
| `github.com/pion/randutil` | `v0.1.0` | MIT | [source](https://github.com/pion/randutil) · [LICENSE](https://github.com/pion/randutil/blob/v0.1.0/LICENSE) |
| `github.com/pion/stun/v4` | `v4.0.0` | MIT | [source](https://github.com/pion/stun) · [LICENSE](https://github.com/pion/stun/tree/v4.0.0/LICENSE) |
| `github.com/pion/transport/v4` | `v4.1.0` | MIT | [source](https://github.com/pion/transport) · [LICENSE](https://github.com/pion/transport/tree/v4.1.0/LICENSE) |
| `github.com/pion/turn/v5` | `v5.1.0` | MIT | [source](https://github.com/pion/turn) · [LICENSE](https://github.com/pion/turn/tree/v5.1.0/LICENSE) |
| `github.com/wlynxg/anet` | `v0.0.5` | BSD 3-Clause | [source](https://github.com/wlynxg/anet) · [LICENSE](https://github.com/wlynxg/anet/blob/v0.0.5/LICENSE) |
| `golang.org/x/crypto` | `v0.54.0` | BSD 3-Clause | [source](https://go.googlesource.com/crypto) · [LICENSE](https://go.googlesource.com/crypto/+/v0.54.0/LICENSE) |
| `golang.org/x/net` | `v0.56.0` | BSD 3-Clause | [source](https://go.googlesource.com/net) · [LICENSE](https://go.googlesource.com/net/+/v0.56.0/LICENSE) |
| `golang.org/x/sys` | `v0.48.0` | BSD 3-Clause | [source](https://go.googlesource.com/sys) · [LICENSE](https://go.googlesource.com/sys/+/v0.48.0/LICENSE) |
| `golang.org/x/time` | `v0.15.0` | BSD 3-Clause | [source](https://go.googlesource.com/time) · [LICENSE](https://go.googlesource.com/time/+/v0.15.0/LICENSE) |
| `golang.org/x/term` | `v0.46.0` | BSD 3-Clause | [source](https://go.googlesource.com/term) · [LICENSE](https://go.googlesource.com/term/+/v0.46.0/LICENSE) |
| `golang.zx2c4.com/wintun` | `v0.0.0-20230126152724-0fa3db229ce2` | MIT | [source](https://git.zx2c4.com/wintun) · [LICENSE](https://git.zx2c4.com/wintun/tree/LICENSE) |
| `golang.zx2c4.com/wireguard` | `v0.0.0-20260522210424-ecfc5a8d5446` | MIT | [source](https://git.zx2c4.com/wireguard-go) · [LICENSE](https://git.zx2c4.com/wireguard-go/tree/LICENSE) |
| `tailscale.com` | `v1.102.4` | BSD 3-Clause | [source](https://github.com/tailscale/tailscale) · [LICENSE](https://github.com/tailscale/tailscale/blob/v1.102.4/LICENSE) |

The Go toolchain and standard library carry their own BSD-style notices. They
are not third-party modules in `go.mod`; see the [Go license
file](https://github.com/golang/go/blob/go1.26.6/LICENSE) for the toolchain used
by this revision.

## License text summaries

The MIT, BSD 3-Clause, and ISC notices below are reproduced to make the
redistribution terms visible alongside the module table. Copyright holders and
additional attribution remain as stated in each linked upstream file.

The principal copyright attributions in the runtime set are Daniel Bourdrez
(the `bytemare/*` modules), the Pion community (the `pion/*` modules), Coder
(`github.com/coder/websocket`), the Go Authors and Google contributors (the
`filippo.io/*`, `github.com/google/uuid`, `github.com/gtank/ristretto255`, and
`golang.org/x/*` modules), wlynxg (`github.com/wlynxg/anet`), WireGuard
contributors (`golang.zx2c4.com/wintun` and
`golang.zx2c4.com/wireguard`), and Tailscale Inc. and contributors
(`tailscale.com`). See each upstream license link for the complete attribution
and any additional copyright holders.

### MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

### BSD 3-Clause License

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

### ISC License

Copyright (c) 2025 Coder

Permission to use, copy, modify, and distribute this software for any purpose
with or without fee is hereby granted, provided that the above copyright notice
and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.

## Official Wintun runtime

Windows releases contain the x64 `wintun.dll` copied from the official archive
below. The build script verifies this exact SHA-256 before extraction and puts
the archive's license beside the DLL as `bin/WINTUN-LICENSE.txt`:

- URL: <https://www.wintun.net/builds/wintun-0.14.1.zip>
- SHA-256: `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`
- DLL path inside the archive: `wintun/bin/amd64/wintun.dll`
- License path inside the archive: `wintun/LICENSE.txt`

The Wintun prebuilt-binaries license is separate from the MIT license of the
Go bindings. It is redistributed verbatim in `bin/WINTUN-LICENSE.txt`; the
release does not modify the DLL. Optional Authenticode verification is
documented in [`deploy/README.md`](deploy/README.md) and is not asserted by
this source tree.
