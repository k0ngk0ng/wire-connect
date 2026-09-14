# wire-connect

两台内网机器，一条加密专线。

`wirectl connect` 使用短码配对，优先通过 ICE/STUN 建立 UDP 直连；无法直连时自动使用自建服务器上的 HTTPS/DERP 中继。两端通过 WireGuard 虚拟 IP 访问对方，应用无需接入专用 SDK。

```sh
# 机器 A
wirectl connect vpn.example.com

# 机器 B，输入 A 显示的短码
wirectl connect vpn.example.com 7k3m-f8q2-h6tw
```

这是同一个 `wirectl-connect` 可执行程序的插件入口。安装到 `wirectl` 同目录或 `PATH` 后即可使用；也可以直接执行 `wirectl-connect`，参数完全相同。

## 支持平台

| 平台 | 架构 | 客户端 | 公网服务端 |
|---|---|---|---|
| macOS | arm64（Apple Silicon） | 支持 | — |
| Linux | arm64、amd64 | 支持 | 支持 |
| Windows | amd64 | 支持 | — |

macOS Intel（amd64）和 Windows ARM 不在支持范围内。虚拟网络承载 IPv4 TCP/UDP；直连候选路径支持公网 IPv4、IPv6 和局域网地址。

## 安装

macOS（Apple Silicon）和 Linux（amd64/arm64），已有 Homebrew 时：

```sh
brew install k0ngk0ng/tap/wire-connect
```

Windows amd64，已有 Scoop 时，在普通 PowerShell 中执行：

```powershell
scoop bucket add k0ngk0ng https://github.com/k0ngk0ng/scoop-bucket
scoop install k0ngk0ng/wire-connect
```

两种方式均自动安装 `wirectl` 主程序。Linux 不使用 Homebrew 时，可按下面方式安装官方压缩包。升级由对应包管理器负责：

```sh
# Homebrew
brew update
brew upgrade k0ngk0ng/tap/wirectl k0ngk0ng/tap/wire-connect

# Scoop
scoop update
scoop update wirectl wire-connect
```

升级后，以平常使用的账号运行 `wirectl connect setup` 刷新 helper，再用 `wirectl connect resume` 刷新需要运行的连接；多个 profile 分别使用 `resume --name NAME`。此前手工安装过的用户，先检查 `type -a wirectl wirectl-connect`（Windows 用 `Get-Command wirectl,wirectl-connect -All`），避免 PATH 中旧版本遮住包管理器安装的版本。

[Homebrew Tap](https://github.com/k0ngk0ng/homebrew-tap) 和 [Scoop Bucket](https://github.com/k0ngk0ng/scoop-bucket) 的 Actions 每小时检查正式 Release，校验 GitHub SHA-256 和独立 `SHA256SUMS`，原生安装测试通过后才更新包定义。支持手动触发；GitHub 定时任务可能延迟。Brew 自动安装 Bash/Zsh 补全文件，仍需按 Homebrew 的说明启用 shell 补全系统。

### 手动安装

从 [GitHub Releases](https://github.com/k0ngk0ng/wire-connect/releases) 下载对应平台的压缩包，验证 `SHA256SUMS` 后解压。发布工作流还生成 GitHub 构建来源证明：

```sh
gh attestation verify <下载的压缩包> --repo k0ngk0ng/wire-connect
```

将 `bin/wirectl-connect` 放到 `PATH` 或 `wirectl` 同目录。Windows 使用 `bin/wirectl-connect.exe`，保留同目录的官方 `wintun.dll` 和许可证。不要从第三方 DLL 下载站获取驱动。

Windows 的 `wirectl` 需要支持 `.exe` 插件分发；如果旧版主程序无法识别 `connect`，直接运行 `wirectl-connect.exe`，参数相同。

安装后先以将要使用的账号执行一次：

```sh
wirectl connect setup
```

这一步会请求一次管理员授权，在 Linux/macOS 使用 `sudo`，在 Windows 显示 UAC。它只安装负责创建 TUN、地址和主机路由的特权 helper；配对凭据、WireGuard 私钥和连接进程仍归当前账号所有。以后普通的 `login`、`connect`、`resume`、`status` 和 `stop` 不需要 `sudo`。第一次直接执行 `connect` 时，如果终端是交互式的，程序也会在需要时引导执行 `setup`。

setup 绑定的是当前操作系统身份。更新客户端后，如果 helper 的协议或程序副本发生变化，`update` 会再次请求该身份的管理员授权以刷新 helper；这是预期的升级步骤。不要用一个账号 setup，再用另一个账号访问同一状态目录。

## Shell 补全

生成并在当前 shell 加载补全：

```sh
# zsh（尚未初始化补全系统时先执行 autoload -Uz compinit; compinit）
source <(wirectl connect completion zsh)

# bash
eval "$(wirectl connect completion bash)"
```

需要持久生效时，将对应的加载命令加入 `~/.zshrc` 或 `~/.bashrc`；macOS 的登录 bash 还需由 `~/.bash_profile` 加载 `~/.bashrc`。Bash 使用上面的 `eval`。如果也启用了 `wirectl download` 补全，先加载 download，再加载 connect；connect 补全同时支持 `wirectl connect` 和独立的 `wirectl-connect`，并支持子命令、选项以及文件和目录参数。

## 第一次使用

先在 Linux 公网服务器部署服务，并取得初始化时生成的服务器授权令牌。每台客户端、每个操作系统账号只需授权一次；令牌通过交互输入，不写在命令行中：

```sh
wirectl connect setup
wirectl connect login vpn.example.com
```

`setup` 的管理员授权与服务器 `login` 的授权是两件独立的事。若机器上已有可用的 helper，可以跳过 setup；若 helper 尚未安装，交互式 `connect` 会先引导安装。

然后机器 A 创建配对码：

```sh
wirectl connect vpn.example.com
```

机器 B 输入短码：

```sh
wirectl connect vpn.example.com 7k3m-f8q2-h6tw
```

`connect` 和 `resume` 默认把连接安装为当前账号的后台服务，成功建立连接后即可关闭终端。需要临时前台运行时显式加 `--foreground`；按 `Ctrl+C` 只结束这次前台连接并清理本次创建的 TUN 和路由：

```sh
wirectl connect vpn.example.com --foreground
wirectl connect resume --foreground
```

短码由 12 个易辨认字符组成，分三组显示，不区分大小写；前 4 位是公开的会合标识，后 8 位是配对秘密。有效期 10 分钟，房间只容纳这两台设备。支持 `--code <短码>` 手动创建，但会拒绝明显的弱码。

完成配对后显示双方虚拟 IP，例如：

```text
Paired · local 100.93.12.1 · peer 100.93.12.2
Connected in background · direct · 100.93.12.1 ↔ 100.93.12.2
```

应用直接使用对端地址：

```sh
ssh user@100.93.12.2
curl http://100.93.12.2:8080
```

应用本身必须监听可达地址，并允许来自对端虚拟 IP 的连接。程序不关闭系统防火墙，也不自动公开对端的整个局域网。

## 保存、恢复和后台运行

配对身份会保存在私有状态目录，重新连接无需旧短码：

```sh
wirectl connect resume
wirectl connect status
wirectl connect stop
```

`resume` 默认重新安装并启动后台服务；它使用已保存的配对身份，不会要求旧短码。需要当前终端托管进程时使用 `resume --foreground`。`Ctrl+C` 对前台进程有效，对后台服务没有影响。

`stop` 会停止当前账号的连接并禁用自动启动，但保留配对资料。再次执行默认后台的 `resume` 即可恢复：

```sh
wirectl connect stop
wirectl connect resume
```

后台服务由当前账号的原生服务管理器维护，连接服务本身以 `--foreground` 启动，因此不会递归安装服务：

- Linux 使用 systemd user service。`setup` 会为当前 UID 执行 `loginctl enable-linger`，使 user manager 在退出登录后仍能运行；不要因为停止一个连接就手动关闭 linger，它可能被该账号的其他服务共享。
- macOS 使用当前用户的 LaunchAgent，在登录时启动并由 launchd 保持运行。退出登录时由系统结束用户会话，重新登录后按配置恢复。
- Windows 使用当前用户 SID 对应的 Task Scheduler 任务，以登录触发、交互用户令牌和最低权限运行；任务会在登录时恢复，安装的副本同时携带官方 `wintun.dll`。

后台安装会把程序复制到受保护的包目录，并注册对应的用户服务；它不会迁移其他用户的私钥。`--uninstall` 会移除指定连接的服务注册和程序副本，但保留状态目录与配对凭据：

```sh
wirectl connect stop --uninstall
```

如果仍需忘记配对凭据，应在确认备份后显式删除对应的私有 `--state-dir` 内容；`stop --uninstall` 本身不会删除它。

多个配对使用不同名称：

```sh
wirectl connect vpn.example.com --name office
wirectl connect resume --name office
wirectl connect status --name office
wirectl connect stop --name office --uninstall
```

默认连接名已配对时，新配对需要指定其他名称或显式使用 `--replace`。

### root 和管理员账号

推荐让普通用户拥有自己的状态目录并只在 `setup` 时授权管理员操作。若已有部署必须由 root 运行，也可以继续使用 root：以 root 执行 `setup`、`login`、`connect`、`resume`、`status` 和 `stop`，这些命令会使用 root 自己的状态目录并安装系统级连接服务。不要把普通用户完成的 `login` 或配对状态与 root 的 `sudo` 环境混用。

```sh
sudo -H wirectl connect setup
sudo -H wirectl connect login vpn.example.com
sudo -H wirectl connect vpn.example.com
sudo -H wirectl connect resume
```

`sudo -H` 只适用于选择 root 工作流的场景；普通用户完成 setup 后，日常命令应直接使用当前账号。无论采用哪种方式，都要让同一个账号执行 `login`、配对、恢复和状态管理，否则会看到“未授权”或“连接未运行”。

## 查看路径和流量

`status` 默认列出当前账号状态目录中的所有已保存连接，顶部汇总连接数和 Direct / Relay / Other 数量，每条连接单独分块。使用 `--name office` 可只看指定连接：

```sh
wirectl connect status
```

需要持续观察时使用 `--watch`，程序每秒刷新一次；按 `Ctrl+C` 只退出状态查看，不会停止后台连接：

```sh
wirectl connect status --watch
```

终端中直连 `[DIRECT]` 显示绿色，中转 `[RELAY]` 显示黄色，无法读取状态 `[UNAVAILABLE]` 和已关闭 `[CLOSED]` 显示红色。`Other` 包括等待路径、已关闭或状态不可用的连接；不会根据旧流量推断当前路径。输出包含双方虚拟 IP、当前 UDP endpoint、本地时区时间和易读流量单位。直连/中转流量是进程启动以来的累计值，包含历史路径，不代表同时使用两条链路。未运行的已保存连接仍会列出。

`--watch` 在交互终端原地刷新，退出后恢复原屏幕；重定向时逐次追加快照。重定向输出、`TERM=dumb` 或设置 `NO_COLOR` 时不输出颜色。handshake 表示最近一次观察到的握手时间，不保证对端持续健康。

脚本或监控使用 `--json`，兼容原有行为：默认只查询 `default`（或 `--name` 指定的连接），单次输出一个原有格式的 JSON 对象。`--all --json` 输出所有已保存连接的数组，每项包含 `name`、可选 `server`、`status` 和状态读取失败时的 `error`；空目录输出 `[]`。`--all` 与 `--name` 不能同时使用。与 `--watch` 一起使用时每次快照输出一行 JSON：

```sh
wirectl connect status --json
wirectl connect status --watch --json
wirectl connect status --all --json

# 例如只保留路径、endpoint、计数和 handshake 证据
wirectl connect status --json | jq '{mode, direct_remote, direct_sent, direct_received, relay_sent, relay_received, mode_reason, last_handshake, updated}'
```

JSON 字段为 `running`、`mode`、`local_ip`、`peer_ip`、`sent`、`received`、`direct_sent`、`direct_received`、`relay_sent`、`relay_received`、可选的 `direct_remote`、`mode_since`、`mode_reason`、`last_handshake` 和 `updated`。字节计数是当前连接进程的累计值；服务重启后从零开始。`direct_remote` 是 ICE 选定的公网/局域网 UDP endpoint，不是 WireGuard 应用数据的明文目的地；WireGuard handshake 时间用于证明隧道端仍在工作。

例如，直连证据应表现为 `mode: "direct"`、有 `direct_remote` 和 `direct_sent`/`direct_received` 增长。当前直连传输期间 `relay_sent`/`relay_received` 应保持不变；如果此前经历过中继，两个 relay 计数可以已经非零：

```json
{"running":true,"mode":"direct","local_ip":"100.93.12.1","peer_ip":"100.93.12.2","direct_sent":4096,"direct_received":4096,"relay_sent":0,"relay_received":0,"direct_remote":"198.51.100.24:51820","mode_reason":"direct_selected","last_handshake":"2026-09-14T10:20:31Z","updated":"2026-09-14T10:20:32Z"}
```

中继证据应表现为 `mode: "relay"`、`relay_sent`/`relay_received` 增长；如果此前已经使用过直连，直连计数可以保留历史值，`mode_reason: "direct_lost"` 表示之后切换到了中继：

```json
{"running":true,"mode":"relay","local_ip":"100.93.12.1","peer_ip":"100.93.12.2","direct_sent":4096,"direct_received":4096,"relay_sent":8192,"relay_received":8192,"mode_reason":"direct_lost","last_handshake":"2026-09-14T10:21:04Z","updated":"2026-09-14T10:21:05Z"}
```

示例中的地址和时间只是字段形状示例；验收时应保存两端各自的 `status --json` 行，并同时确认虚拟 IP 之间的实际应用流量。

## 网络选项

```sh
# 与其他 VPN 网段冲突时指定私有虚拟地址池
wirectl connect vpn.example.com --network 10.203.0.0/16

# 限制为 HTTPS 中继
wirectl connect vpn.example.com --relay-only

# 降低 MTU，或使用非默认 STUN 端口
wirectl connect resume --mtu 1280 --stun stun:vpn.example.com:3478

# 前台输出 ICE 候选和路径诊断；Ctrl+C 只结束这次连接
wirectl connect resume --foreground --verbose

wirectl connect doctor vpn.example.com
```

默认地址池为 `100.64.0.0/10`。两端协商未占用地址，添加单个对端 `/32` 主机路由；默认网关与 DNS 保持不变。直连失败自动中继，不保证所有网络都能打洞，也不保证被网络策略禁止的 HTTPS/WebSocket 一定可达。中继增加服务器带宽消耗和延迟。

HTTPS 控制和中继连接遵循系统代理环境变量。只提供公网 IP 或使用私有 TLS 证书时，在首次登录预先配置通过可信渠道取得的证书指纹：

```sh
wirectl connect login https://203.0.113.10 --pin <证书的SHA256指纹>
```

指纹不匹配或证书过期时连接会失败；程序不提供跳过全部证书验证的开关。

`--verbose` 只向当前前台进程的标准错误输出连接诊断，例如 ICE 候选类型、地址和当前路径；后台服务不会继承该临时选项。不会输出配对码、ICE 凭据或私钥。诊断已安装的后台连接时使用 `wirectl connect resume --foreground --verbose`，它不会改变已保存的配对资料。

## 更新客户端

`update` 默认从本项目的 GitHub Release 获取当前平台的最新包，也可以指定 SemVer 版本：

```sh
wirectl connect update
wirectl connect update --version 1.2.0
```

Homebrew 和 Scoop 安装会在实际执行文件旁带有
`.wire-connect-package-manager` 标记，`update` 会提示分别执行
`brew upgrade k0ngk0ng/tap/wire-connect` 或 `scoop update wire-connect`，不会改写包管理器目录。手动安装的执行文件没有该标记，继续使用内置更新。

在线更新只接受官方 GitHub API 和 Release 下载地址。程序会下载目标 archive 和独立的 `SHA256SUMS` Release asset，分别校验 GitHub 提供的 SHA-256，再校验 `SHA256SUMS` 中对应的 archive 条目，确认无误后才原子替换当前 `wirectl-connect`。Linux/macOS 的执行文件必须由当前账号可写；安装在系统目录时请用拥有该安装目录的管理员工作流更新。Windows 会在执行文件占用时交给更新交接程序完成替换。

更新完成后，程序会刷新已经安装的 network helper 和仍启用的后台连接副本。因为 helper 运行在管理员身份，更新已安装 helper 时可能再次显示 sudo/UAC 授权；这是升级特权副本。已停止或已禁用的 profile 会保持停止状态，不会被 update 自动启动；下次执行 `resume` 时会复制当前最新版并启动。自定义状态目录需要显式传给 update：

```sh
wirectl connect update --state-dir /path/to/wire-connect
```

公网服务端如果由自定义 systemd unit 运行 `serve`，更新执行文件后还需要重启该 unit，再检查 HTTPS `/healthz` 和 UDP STUN；客户端的 `update` 不会自动重启任意自定义服务。

若仍在使用没有 `update` 子命令的 1.1.x，先手动下载并替换一次新版 `wirectl-connect`，再执行 `wirectl connect update` 管理后续升级。若刷新失败，先执行 `wirectl connect setup`，再执行 `wirectl connect resume`。

在隔离网络中可以使用离线包，但必须同时提供与目标平台和版本匹配的 archive 与 `SHA256SUMS`：

```sh
wirectl connect update \
  --archive ./wire-connect-1.2.0-linux-amd64.tar.gz \
  --checksums ./SHA256SUMS
```

离线包名必须是 `wire-connect-<version>-<goos>-<goarch>.tar.gz`；Windows 使用 `.zip`。离线模式只证明 archive 与你提供的 `SHA256SUMS` 匹配，不等同于 GitHub 发布者来源证明。若发布介质还配有独立取得、由运维渠道信任的 manifest，可额外传入：

```sh
wirectl connect update \
  --archive ./wire-connect-1.2.0-linux-amd64.tar.gz \
  --checksums ./SHA256SUMS \
  --manifest ./wire-connect-1.2.0.manifest.json
```

manifest 是描述同一 archive 和 `SHA256SUMS` 的第二份摘要，格式如下；摘要填写 64 位小写或大写十六进制 SHA-256：

```json
{
  "repository": "k0ngk0ng/wire-connect",
  "tag": "v1.2.0",
  "asset": "wire-connect-1.2.0-linux-amd64.tar.gz",
  "asset_sha256": "<archive SHA-256>",
  "checksums": "SHA256SUMS",
  "checksums_sha256": "<SHA256SUMS SHA-256>"
}
```

`--archive`、`--checksums` 和 `--manifest` 都是本地文件参数；程序拒绝符号链接、路径穿越、错误平台包、重复或缺失的 archive 条目，并且在全部验证完成前不会替换执行文件。不要把令牌、私钥或其他秘密放进更新参数、manifest 或 shell 历史。

## Linux 公网服务器

需要入站 **TCP 443** 和 **UDP 3478**，无需 TUN、系统 IP 转发、Redis 或外部数据库。域名应解析到服务器。

先初始化私有状态目录，并安全保存仅显示一次的授权令牌：

```sh
wirectl-connect serve --init --state-dir /var/lib/wire-connect
```

然后运行：

```sh
wirectl-connect serve --domain vpn.example.com --state-dir /var/lib/wire-connect
```

域名模式通过 ACME 自动获取并续期证书。已经管理证书时，可以传 `--cert <fullchain.pem> --key <privkey.pem>`。

已有 Nginx 占用 443 并管理证书时，后端使用本机 HTTP：

```sh
wirectl-connect serve --http --listen 127.0.0.1:8080 --state-dir /var/lib/wire-connect
```

Nginx 将该域名的 HTTPS 和 WebSocket 请求转发到 `http://127.0.0.1:8080`，客户端仍使用 `https://你的域名`。`--http` 只接受回环 IP 地址，不能绑定公网或内网网卡，也不能与证书或自动 TLS 参数混用。UDP 3478 仍直接对外开放。完整配置见 [Nginx 部署说明](deploy/README.md#nginx-tls-termination)。

服务默认限制中继连接数和每客户端带宽；设备需要先授权，再登记有时效的中继密钥，不能作为匿名开放中继使用。默认每客户端中继限速 10 MiB/s，可通过 `--relay-bytes-per-second` 调整。

生产部署使用 [systemd 模板与说明](deploy/README.md)，由低权限服务账号运行，仅保留绑定低端口的能力。服务启动输出结构化日志，`GET /healthz` 提供存活检查。备份整个私有状态目录，以保留设备授权、配对记录和证书。

一台服务器仍是单点。服务器不可用时，已经建立且路径仍有效的直连可以继续；新配对、中继和需要会合协助的路径恢复会受影响。

## 安全与协议

- WireGuard 负责隧道端到端加密和报文认证，中继无法解密应用数据。
- OPAQUE 负责短码认证。发起端在本地生成一次性注册记录，公网服务器只转发交换消息。
- 设备公钥通过完成密钥确认的加密控制通道交换；配对秘密与 WireGuard 预共享密钥采用用途分离的派生。
- 每次控制连接使用双方随机挑战派生新的方向性密钥，并校验序号，拒绝反射和重放。
- 本地私钥使用 Unix `0600`/私有目录或 Windows 受保护 ACL 保存。`status`/`stop` 使用 Unix socket 或有 ACL 的 Named Pipe，不开放管理 TCP 端口。
- 服务器可观察设备公网地址、连接时间和流量大小。获得客户端管理员权限的攻击者可以访问该客户端的密钥和数据。

密码组件来自上游实现；本项目的组合协议没有独立第三方审计。协议与测试边界见 [协议说明](docs/PROTOCOL.md) 和 [验证记录](docs/VALIDATION.md)。安全问题请使用 GitHub 私有漏洞报告，避免在公开 issue 中放入私钥或授权令牌。

## 构建与验证

需要 `go.mod` 指定的 Go 版本。仓库将构建缓存与临时文件放在 `.cache`：

```sh
mkdir -p .cache/go-build .cache/go-mod .cache/tmp
export GOCACHE="$PWD/.cache/go-build"
export GOMODCACHE="$PWD/.cache/go-mod"
export GOTMPDIR="$PWD/.cache/tmp"
export TMPDIR="$PWD/.cache/tmp"
go test -race ./...
go vet ./...
./scripts/build-release.sh --version snapshot
```

发布包同时包含依赖清单和第三方许可证说明。Actions 对 Linux、macOS、Windows 执行原生测试；版本标签的发布流程重新验证同一提交后才上传 Release，并附校验和和构建来源证明。Apple/Windows 应用代码签名证书未配置；官方 Wintun DLL 保留其上游签名。
