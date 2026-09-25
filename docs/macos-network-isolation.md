# macOS 网络运行时

World 使用 Rust。CLI 位于 `crates/world-cli`，运行时位于 `crates/world-runtime`，silo 的 socket 拦截库位于 `vendor/silo-bind`。forkfs RPC、控制面认证与计费未实现。

## 两种执行模式

| 模式 | 用途 | 本地监听 | 边界 |
| --- | --- | --- | --- |
| `world network exec` | 原有出站白名单模式的 Rust 迁移 | 禁止 | Seatbelt 拒绝直接 socket，独立认证 HTTP/CONNECT 代理放行目标 |
| `world exec <workspace>` | 多个 Workspace 同端口原生开发服务 | 支持 | 内部 silo 动态库在受支持程序内透明重写地址；没有内核 network namespace |

两种模式分别使用，当前不组合：Workspace localhost 模式需要直接访问其 loopback 地址和动态库注入，不能简单套入禁止监听的 Seatbelt profile。该模式也不自动继承出站白名单限制。

## 构建与安装

```sh
cargo build --workspace --locked
```

工具链由 `rust-toolchain.toml` 固定，依赖由 `Cargo.lock` 固定。`target/debug/world` 和 `target/debug/libworld_silo_bind.dylib` 必须放在同一目录。发布构建使用 `cargo build --workspace --release --locked`；仅 `cargo install` CLI 不会安装所需动态库。

## 同端口 localhost

```sh
mkdir -p ~/world-a ~/world-b
./target/debug/world workspace create A --workdir ~/world-a
./target/debug/world workspace create B --workdir ~/world-b
./target/debug/world workspace setup A
./target/debug/world workspace setup B
```

`create` 只登记 Workspace 与固定工作目录，输出 JSON 中的内部地址。`setup` 通过 `sudo /sbin/ifconfig lo0 alias ...` 添加该地址，需要管理员权限；不修改 sudoers、PF 或 `/etc/hosts`。执行前检查地址已经配置，缺失即拒绝启动，不回退到宿主 localhost。

在两个终端分别运行：

```sh
./target/debug/world exec A -- /opt/homebrew/bin/python3 -m http.server 8080 --bind 127.0.0.1
./target/debug/world exec B -- /opt/homebrew/bin/python3 -m http.server 8080 --bind 127.0.0.1
```

客户端也必须由对应 Workspace 启动，例如使用已安装的非 SIP 版本 curl：

```sh
./target/debug/world exec A -- /opt/homebrew/opt/curl/bin/curl http://localhost:8080/
./target/debug/world exec B -- /opt/homebrew/opt/curl/bin/curl http://localhost:8080/
```

应用继续使用 localhost 和原端口，不需要配置隔离 IP。每个 Workspace 的内部地址由 World 分配，内部 silo 动态库在 `bind/connect/sendto/sendmsg` 等调用处进行透明重写。同一 Workspace 的不同进程及多次 `exec` 使用同一映射；支持 IPv4、通配绑定、双栈 socket 的 `::1`/`::` 和 UDP。显式 IPv6-only socket 不支持，返回失败而非使用宿主地址。

默认状态目录为 `~/.local/share/world/workspaces`，`--state-dir` 可指定一个受信任的独立运行时注册表。必须让需要相互协调的 Workspace 使用同一注册表。跨进程文件锁串行分配地址，元信息以临时文件、fsync、原子替换提交；同 ID 重复创建幂等，换工作目录被拒绝。地址不会自动回收给另一个 Workspace，避免仍存活的旧进程进入新 Workspace。

## 临时目录

多数服务把锁文件和 Unix socket 放在 `/tmp`，例如 Postgres 的 `/tmp/.s.PGSQL.5432` 及其 `.lock`。只隔离端口时，两个 Workspace 仍会在这些路径上冲突，因此 `world exec` 同时把 `/tmp`、`/private/tmp`、`/var/tmp`、`/private/var/tmp` 重定向到该 Workspace 的私有目录 `~/.world/tmp/<内部地址>/{tmp,var/tmp}`（`~` 为创建该 Workspace 时的 `HOME`），并把 `TMPDIR` 设为其中的 `tmp/`。同一 Workspace 的多个进程和多次 `exec` 共享该目录，因此仍可用文件锁互斥；不同 Workspace 使用相同名字互不影响。宿主 `/tmp` 不可见，宿主上的非受管程序也看不到 Workspace 的 `/tmp`，需要通过 `world exec` 访问，与 localhost 一致。

私有目录在 `create` 时按当时的 `HOME` 确定并记录在注册表（`show` 的 `temp_root`）；之后不同 `HOME` 的执行仍使用同一目录。旧注册表条目在首次访问时按当前 `HOME` 补录。

重定向由同一动态库在 libSystem 路径调用处完成：打开、创建、stat、目录、改名、链接、权限、时间、xattr、`getattrlist`、`clonefile`、`chdir`、`exec`/`posix_spawn`（含 file actions）以及 `AF_UNIX` 的 `bind/connect/sendto/sendmsg`。`getcwd`、`realpath`、`readlink`、`getsockname/getpeername` 返回宿主名称（`/private/tmp/...`）；即使调用方缓冲区只够放下宿主名称、放不下更长的私有物理路径，也按宿主名称判断是否截断（`getcwd` 返回 `ERANGE`、`readlink` 截断长度），不会因为物理路径更长而误报。程序创建指向 `/tmp/...` 的符号链接时，链接内容写为 Workspace 内的位置。

限制：

- Workspace 工作目录不能位于上述临时目录下，否则拒绝执行；用于确定私有目录的 `HOME`（`create` 时，或补录旧注册表条目时）同样不能位于其中。私有目录本身必须在宿主临时目录之外，否则其自身路径会被再次重定向。`WORLD_TMP` 必须是规范路径（不含符号链接分量）；`world exec` 已确保这一点，手动设置时需自行规范化，否则视为无效。
- 记录的目录不可用（被删除、卸载）或属于其他用户时拒绝执行；共享注册表的不同用户不能共用同一 Workspace。
- Unix socket 路径上限 104 字节，重定向后路径会加上私有目录前缀（例如 `/Users/me/.world/tmp/127.77.0.1/tmp/`）。超长时 `bind/connect` 返回 `ENAMETOOLONG`。
- 已存在于 Workspace 之外、指向 `/tmp` 的符号链接由内核解析，不经过重定向；`fcntl(F_GETPATH)`、`accept/recvfrom` 返回的对端地址、原始系统调用和脚本 shebang 中位于 `/tmp` 的解释器不在覆盖范围内。
- 宿主前缀中的 `..` 只要其后仍有 `tmp` 分量，就由内核解析实际位置后再判断；含 `..` 的相对路径，以及首个有效分量为 `tmp`、`private` 或 `var` 的相对路径（如在 `/` 下的 `tmp/x`），先按物理工作目录或 dirfd 补全再判断。仍是限制的：相对符号链接目标、spawn file actions 中的路径、指向宿主临时目录且其后无 `tmp` 分量的符号链接、补全与实际调用之间其他线程 chdir 的竞争，以及工作目录或 dirfd 本身位于宿主临时目录内（仅可能来自 fd 传递或注入前打开的描述符，受管进程的 chdir/open 已被重定向）时的其他相对路径。
- 私有目录不会随 Workspace 自动清理，也不像宿主 `/tmp` 那样在重启时清空；需要时停止任务后手动删除。
- `~/.world`、`~/.world/tmp`、`<地址>`、`tmp`、`var`、`var/tmp` 必须是当前用户拥有的真实目录（非符号链接），前两级不可被组/其他用户写；否则拒绝执行且不修改任何权限。
- `world exec` 的入口程序（绝对/相对路径或经 PATH 查找）同样先按该 Workspace 的临时目录重定向，再做 SIP/setuid/脚本校验并启动；argv[0] 保持用户写法。
- 受管进程内 `posix_spawnp` 及 `env` 解释器按 PATH 查找时，相对 PATH 项先按进程实际（物理）工作目录补全再重定向；私有前缀不存在（ENOENT/ENOTDIR/EACCES）则跳过该项，其他错误直接返回，不回退宿主路径。

`world workspace show A` 查看配置。Workspace 本地 ID 是开发用稳定标识，尚未对接 forkfs 全局 Workspace Resource ID 或组织授权。`create` 成功只表示元信息登记，不表示已配置地址或通过隔离验收。重启后需要重新 `setup`。停止所有关联任务后可以按 show 返回的地址手工执行 `sudo ifconfig lo0 -alias IP` 清理别名；这不会删除工作目录或注册表。

## 内部实现：silo 补丁与兼容边界

上游为 [silo-rs/silo](https://github.com/silo-rs/silo)，固定提交 `8364a4298a0b85ffcecc281bfd5c6bb73963be8a`；来源、MIT 许可证和本地修改保存在 `vendor/silo-bind/`。

- localhost 始终重写，不保留上游“没有监听者就访问宿主”的回退，也不依赖存在竞争窗口的监听探测。
- 拦截到的其他 Workspace loopback 地址访问被拒绝；IPv4-mapped localhost 也必须映射到当前 Workspace。
- SIP 系统程序及带 setuid/setgid 位的程序直接拒绝；脚本需显式指定非 SIP 解释器。受拦截的子进程启动检查注入环境，不允许静默丢失；shebang 替代仅匹配同名解释器。`env -S` 支持普通空白分隔参数，含引号、转义或展开的形式明确拒绝，需显式调用解释器。带 chdir/fchdir spawn file actions 的相对目标或相对替代解释器也拒绝，以免目录切换改变实际执行目标。已有程序无需修改源码，但并不承诺所有 macOS 可执行文件都兼容。
- 共享临时目录按 Workspace 重定向（见[临时目录](#临时目录)）；启用时缺少或无效的 `WORLD_TMP` 终止任务，子进程必须继承逐字节相同的值。
- 动态库加载后写入本次执行确认文件；未确认会终止任务并报错。确认检查不能替代代码签名策略或证明每个 socket 调用都经过了拦截。
- 状态管理、代理和一般 CLI 使用安全 Rust；系统调用边界与继承描述符处理集中在运行时/动态库中。不得将语言的内存安全等同于无逻辑竞争。

**Workspace localhost 模式是可信开发任务的兼容层，不是恶意代码安全边界。** 原始系统调用、未被拦截的 API 或有意绕过注入的程序可能访问宿主网络。宿主非受管程序也能访问内部 alias；socket 返回的地址信息可能显示内部映射。它按 Workspace 隔离临时目录，但不提供跨 Workspace 文件保密、远程租约、配额、任意原生程序完整网络栈虚拟化。生产级受管节点不能仅据此标为完整隔离就绪。

## 出站白名单模式

```sh
./target/debug/world network exec --policy examples/network-offline.json --workdir ~/world-a -- /bin/echo offline
./target/debug/world network exec --policy examples/network-web.json --workdir ~/world-a --timeout 30s -- /usr/bin/curl -fsS https://example.com/
```

策略结构保持 `{ "network_id": "web", "allow": [{ "host": "example.com", "port": 443 }] }`。空 allow 为断网；支持明确的 TCP 域名/IP 和端口，拒绝未知字段、通配符和非法端口。域名启动时解析并固定地址，特殊用途地址（含共享地址、基准测试、文档和地址转换前缀）保守拒绝，需改为可信配置中的显式 IP 授权。

每次执行有独立不可变路由和随机代理凭证，同时占住 IPv4/IPv6 的代理端口。HTTP 请求与 CONNECT 都检查目标和凭证；代理凭证不转发至目标。HTTP 响应重定向不会绕过下一次目标校验。

Seatbelt 拒绝直接 TCP/UDP/Unix socket、监听、Mach 服务、跨进程信息与信号，以及工作目录和私有临时目录之外的写入。清理环境、通过管道转发输出、拒绝 socket 标准输入和可写的文件标准输入，并关闭额外继承描述符。失败不退回无沙箱执行。

两种模式都默认 5 分钟期限、最大 24 小时。传递任务退出码；信号退出为 `128 + signal`，取消/超时为 124，参数或基础设施错误为 125。退出/取消关闭出站代理已有隧道并停止任务进程组。主动脱离进程组的恶意后代不在完整回收保证内。

## 验证

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --workspace --locked
cargo build --workspace --examples --locked
python3 -m unittest discover -s tests -v
# 有 sudo 权限的专用 macOS 测试机：
WORLD_SILO_INTEGRATION=1 python3 -m unittest discover -s tests -v
```

原生测试使用没有 World 依赖的普通 Rust socket 程序。测试先确认宿主能连接，再验证 Seatbelt 权限拒绝，覆盖继承 fd、标准输入、子进程、HTTP/CONNECT/TLS、退出和超时。非特权测试也检查动态库实际注入及禁止宿主回退。

Workspace localhost 完整测试显式创建并清理两个真实 macOS loopback 别名；检查同端口监听、各自 localhost 连接、双栈/通配绑定、UDP、子进程继承、其他 Workspace 地址拒绝、没有监听者时不回退宿主，以及停止 A 后 B 的同端口服务仍正常。没有管理员能力时这些用例明确标为未运行，不能冒充验证通过。CI 的 macOS job 必须开启完整测试；Linux 后端的测试见 [Linux 网络运行时](linux-network-isolation.md)。
