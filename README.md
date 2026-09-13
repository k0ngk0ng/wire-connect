# wire-connect

两台内网机器，一条加密专线。

`wirectl connect` 使用短码配对，优先通过 ICE/STUN 建立 UDP 直连；无法直连时自动使用自建服务器上的 HTTPS/DERP 中继。两端通过 WireGuard 虚拟 IP 访问对方，应用无需接入专用 SDK。

```sh
# 机器 A
sudo -H wirectl connect vpn.example.com

# 机器 B，输入 A 显示的短码
sudo -H wirectl connect vpn.example.com 7k3m-f8q2-h6tw
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

从 [GitHub Releases](https://github.com/k0ngk0ng/wire-connect/releases) 下载对应平台的压缩包，验证 `SHA256SUMS` 后解压。发布工作流还生成 GitHub 构建来源证明：

```sh
gh attestation verify <下载的压缩包> --repo k0ngk0ng/wire-connect
```

将 `bin/wirectl-connect` 放到 `PATH` 或 `wirectl` 同目录。Windows 使用 `bin/wirectl-connect.exe`，保留同目录的官方 `wintun.dll` 和许可证。不要从第三方 DLL 下载站获取驱动。

创建虚拟网卡和配置路由需要管理员权限。Linux/macOS 如果以管理员身份运行客户端，请在同一个管理员环境中运行登录、连接和恢复命令；使用 root 的默认状态目录时例如 `sudo -H wirectl connect ...`（直接运行插件则使用 `sudo -H wirectl-connect ...`）。root 创建的状态目录需要继续由 root 使用；也可以让同一个用户为每次命令显式指定同一个私有 `--state-dir`。Windows 使用管理员 PowerShell，下面命令中的 `sudo -H` 前缀应去掉后直接运行。

## 第一次使用

先在 Linux 公网服务器部署服务，取得初始化时生成的服务器授权令牌。每台客户端只需授权一次，令牌通过交互输入，不写在命令行中：

```sh
sudo -H wirectl connect login vpn.example.com
```

然后机器 A 创建配对码：

```sh
sudo -H wirectl connect vpn.example.com
```

机器 B 输入短码：

```sh
sudo -H wirectl connect vpn.example.com 7k3m-f8q2-h6tw
```

短码由 12 个易辨认字符组成，分三组显示，不区分大小写；前 4 位是公开的会合标识，后 8 位是配对秘密。有效期 10 分钟，房间只容纳这两台设备。支持 `--code <短码>` 手动创建，但会拒绝明显的弱码。

完成配对后显示双方虚拟 IP，例如：

```text
Paired · local 100.93.12.1 · peer 100.93.12.2
Connected · direct · 100.93.12.1 ↔ 100.93.12.2
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
sudo -H wirectl connect resume
sudo -H wirectl connect status
sudo -H wirectl connect stop
```

默认前台运行，`Ctrl+C` 会清理网卡和路由。需要开机恢复时：

```sh
sudo -H wirectl connect resume --background
```

后台安装需要管理员权限，并要求状态目录受管理员保护。安装器将程序复制到受保护的系统目录，再注册 systemd、launchd 或 Windows Service。它不会悄悄迁移其他用户的私钥。停止会禁用自动启动；重新使用 `resume --background` 启用。

多个配对使用不同名称：

```sh
sudo -H wirectl connect vpn.example.com --name office
sudo -H wirectl connect resume --name office
sudo -H wirectl connect status --name office
sudo -H wirectl connect stop --name office --uninstall
```

`--uninstall` 移除该连接的系统服务和受保护的程序副本，保留配对凭据。默认连接名已配对时，新配对需要指定其他名称或显式使用 `--replace`。

## 网络选项

```sh
# 与其他 VPN 网段冲突时指定私有虚拟地址池
sudo -H wirectl connect vpn.example.com --network 10.203.0.0/16

# 限制为 HTTPS 中继
sudo -H wirectl connect vpn.example.com --relay-only

# 降低 MTU，或使用非默认 STUN 端口
sudo -H wirectl connect resume --mtu 1280 --stun stun:vpn.example.com:3478

# 输出安全的 ICE 候选和路径诊断
sudo -H wirectl connect resume --verbose

sudo -H wirectl connect doctor vpn.example.com
```

默认地址池为 `100.64.0.0/10`。两端协商未占用地址，添加单个对端 `/32` 主机路由；默认网关与 DNS 保持不变。直连失败自动中继，不保证所有网络都能打洞，也不保证被网络策略禁止的 HTTPS/WebSocket 一定可达。中继增加服务器带宽消耗和延迟。

HTTPS 控制和中继连接遵循系统代理环境变量。只提供公网 IP 或使用私有 TLS 证书时，在首次登录预先配置通过可信渠道取得的证书指纹：

```sh
sudo -H wirectl connect login https://203.0.113.10 --pin <证书的SHA256指纹>
```

指纹不匹配或证书过期时连接会失败；程序不提供跳过全部证书验证的开关。

`--verbose` 只向标准错误输出连接诊断，例如 ICE 候选类型、地址和当前路径；不会输出配对码、ICE 凭据或私钥。

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
