# macOS 本地网络隔离

`world network exec` 已实现 macOS 进程出站访问限制，尚未实现每个 World 独立的网络栈。代码使用 Go 标准库与系统 `/usr/bin/sandbox-exec`；不修改系统 PF 规则、不需要 root、不调用 forkfs C ABI。策略由可信调用方提供，不接受任务自行扩权。它是本地运行时入口，尚未接入 World 的组织授权或 forkfs RPC。

## World 网络栈验收要求

任务已确认必须运行 macOS 原生程序。宿主原生机制的实测结果与当前限制见 [原生网络可行性核对](macos-native-network-feasibility.md)。以下独立 `localhost` 是此前采用的目标解释；若采用不同显式 IP，必须先确认接口语义调整，不能静默替换。

World/Workspace 是独立端口空间的边界。W1 和 W2 必须能够同时监听相同的地址、协议和端口，例如各自的 `127.0.0.1:8080`；应用无需改地址、改端口或增加代理配置。同一个 World 的不同进程和不同 `exec` 共享该网络栈，客户端访问 `localhost:8080` 只能连接本 World 的服务。

运行时身份须使用全局 Workspace Resource ID 和运行代际，不能只用 Store 内的 `W1` 简写或每次 Execution ID。Network 仍是授权与出站策略边界，不因两个 Workspace 属于同一个 Network 就合并它们的端口空间。

必须验证：

- W1 与 W2 同时监听相同 TCP 端口，分别返回不同标记；另一次 `exec` 在各自 World 内只能读到自己的标记。
- IPv4、IPv6、UDP 和通配地址监听均保持独立；子进程加入所属 World 的网络栈。
- 停止 W1 后，W2 的同端口服务继续工作；重建 W1 不串入旧运行代际的服务。
- 宿主或另一 World 不会因端口号相同而访问到该服务；对外发布端口必须显式配置并单独处理宿主端口冲突。
- 并发创建、进入与停止同一个 World 时，不得产生两个网络栈、连接到错误 World 或在停止后接受新任务。

当前 Seatbelt/代理测试验证的是出站访问限制和禁止监听，不能作为以上验收的通过证据。独立网络栈后端完成这些测试前，不能宣称该功能已经实现。

## 使用

需要 Go 1.24+ 和支持当前 Seatbelt profile 的 macOS。先构建：

```sh
go build -o bin/world ./cmd/world
workdir=$(mktemp -d)
```

断网执行：

```sh
./bin/world network exec \
  --policy examples/network-offline.json \
  --workdir "$workdir" -- /bin/sh -c 'echo offline; touch result'
```

显式放行 `example.com:443`：

```sh
./bin/world network exec \
  --policy examples/network-web.json \
  --workdir "$workdir" --timeout 30s -- \
  /usr/bin/curl --fail --show-error https://example.com/
```

策略格式：

```json
{
  "network_id": "development",
  "allow": [{"host": "example.com", "port": 443}]
}
```

`allow: []` 表示断网。每条规则授权一个 TCP 目标，支持域名或 IP 字面量；不支持通配符、CIDR、任意端口或 UDP 放行。域名在启动任务前由可信代理解析并固定地址，后续请求不重新解析。解析得到回环、私网或链路本地地址时拒绝启动；需要这些服务时必须明确授权 IP 字面量。HTTP 重定向产生的新目标仍需独立授权。

默认期限 5 分钟，最大 24 小时。返回任务退出码；信号退出返回 `128 + signal`，取消/超时返回 124，本地参数或运行基础设施错误返回 125。Seatbelt 或目标程序自身的启动失败保留其非零退出码，始终不退回无沙箱执行。

## 执行边界

| 路径 | 行为 |
| --- | --- |
| IPv4/IPv6 TCP、UDP、Unix socket 直接连接 | 内核拒绝，包括宿主回环服务 |
| 本地端口监听 | 内核拒绝 |
| HTTP 代理与 HTTPS CONNECT | 仅允许本次执行的代理端口，代理再次检查目标白名单与执行凭证 |
| 其他 Network 或其他执行的代理 | 端口被内核拒绝；不同执行的凭证也不可互换 |
| 子进程 | 继承相同 Seatbelt 限制，修改代理环境变量不能恢复直接连接 |
| 任务退出、超时或取消 | 关闭代理监听及所有已有隧道，停止任务进程组 |
| 非 macOS 或沙箱启动失败 | 拒绝执行，无降级路径 |

代理 listener 由内核原子分配并一直持有，没有“检查空闲端口后再绑定”的竞争窗口。由于 Seatbelt 的 `localhost` 规则覆盖 IPv4 和 IPv6，启动任务前必须同时持有 `127.0.0.1` 与 `::1` 的同一端口；任一绑定失败即拒绝启动，避免另一地址族的同端口被其他服务占用。每次执行保存独立、不可变的规则与随机凭证，没有可被另一任务覆写的全局代理策略。关闭过程同步且幂等，关闭期间新连接也被拒绝；上下文取消会撤销已有隧道。旧执行凭证不能使用之后复用相同端口的 World 代理。

启动器以参数数组传递命令和内存中的 profile，避免命令字符串拼接及临时策略文件被替换。一个固定的、单线程 shell 启动脚本先关闭标准输入输出之外的描述符，再用 `exec "$@"` 进入 Seatbelt；仅 `/dev/fd` 枚举得到并校验过的数字参与关闭操作，任务参数不插入脚本。这样也能关闭 Go `os/exec` 不会自动关闭的、由宿主传入的非 CLOEXEC socket。清理继承环境，设置私有 HOME/TMPDIR 与 HTTP(S) 代理，清空 NO_PROXY；不继承 DYLD 注入变量、宿主服务凭证。标准输出/错误通过管道转发；标准输入允许文件、管道和终端，拒绝 socket。

同时拒绝 Mach 服务查找/注册、跨进程信号与信息查询、POSIX/System V IPC，以及工作目录和本次临时目录之外的文件写入，减少借宿主服务代发请求的通道。允许查询进程自身信息，以兼容系统 curl。依赖 GUI、launchd 或其他 Mach 服务的命令可能失败；不能为兼容而直接开启全部 Mach 服务。

## 范围与限制

- 这是本机可信操作者启动开发任务的运行时原语，`network_id` 是策略标识，尚不是经过 World 身份认证的租户边界；调用方必须提供已授权策略和专用工作目录。不能把 CLI 的 `--policy` 直接暴露成不可信 Agent 的扩权入口。
- 没有实现完整文件读取隔离、组织权限、forkfs 生命周期/RPC、远程执行租约或配额，因此不宣称完整的多租户受管执行已经可用。父进程同一用户下的非受管宿主进程也不在隔离范围内。
- 放行的是 TCP 目标，不是 URL、HTTP 方法、TLS SNI 或仓库权限。CONNECT 不解密 TLS；显式授权转发代理或共享目标会授予该目标能提供的能力。不实现同 Network 任意端口互通或独立 IP 网络命名空间。
- 应用需支持 HTTP(S) 代理或 CONNECT；直接联网的 SDK、SSH 与 UDP/QUIC 不会自动适配。系统信任服务被限制时，一些 HTTPS 客户端可能需要显式 CA 文件或独立证书库。
- 进程组清理不等于完整的恶意守护进程回收。主动脱离进程组的后代仍继承沙箱，World 代理关闭后不能继续使用它；但 Seatbelt 的端口例外不会动态撤销，日后该端口被无认证的非 World 宿主服务复用仍有风险。需要对抗这类恶意任务的长期隔离应使用专用 VM/节点，不能将本入口标为该等级的运行环境。
- Seatbelt profile 是平台相关能力；`sandbox-exec` 的本机手册标注 deprecated。当前实现不静默放宽策略，应在目标 macOS 版本上通过内核测试后再部署。

## 验证

```sh
go test -race -timeout 2m ./...
go vet ./...
go build -o bin/world ./cmd/world
```

macOS 测试使用本机临时监听器，不依赖公网或需要 root 的配置。先验证宿主确实能连接，再断言沙箱返回 `EPERM/EACCES`，不把超时或拒绝连接冒充隔离。覆盖：

- TCP IPv4/IPv6、UDP、Unix socket、监听端口及 shell 子进程拒绝。
- HTTP 放行/403 拒绝、CONNECT 与真实 TLS 握手（显式测试 CA），放行目标的直连仍被拒绝。
- 其他 Network 代理端口拒绝、执行凭证不可互换、凭证不转发给目标服务；同时持有并保护两个地址族的代理端口。
- 多个 Network 并发运行、代理并发关闭、已有 CONNECT 隧道撤销、退出码与超时。
- 宿主写入和 launchd 访问拒绝，非法策略拒绝；实际传入的非 CLOEXEC socket 在启动前被关闭。

2026-09-23 在 macOS 27.0（26A428）、arm64、Go 1.27.1 上完成本机验证。仓库 CI 配置在 macOS 运行真实沙箱测试，在 Linux 运行代理测试和不支持平台时拒绝执行的测试。
