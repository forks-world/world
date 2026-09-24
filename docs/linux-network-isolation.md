# Linux 网络运行时

Linux 与 macOS 使用同一个 CLI（`world network exec`、`world silo ...`），但后端是内核隔离：非特权 user namespace + network namespace。不需要 root，也不注入动态库。实现在 `crates/world-runtime/src/linux.rs`。

## 前提

- 允许非特权 user namespace。Fedora、Debian 等默认允许；Ubuntu 23.10+ 的 AppArmor 默认限制它，需要 `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`，或者为 `world` 配置 AppArmor profile。
- `network exec` 需要 Landlock ABI 3（Linux 6.2+，并且已在 LSM 列表中启用；更早的 ABI 不限制截断文件），以及 x86_64 或 aarch64 架构的 seccomp。缺少任何一项都拒绝执行，不会退回到无沙箱执行。
- 只构建 `target/debug/world` 即可，不需要 `libworld_silo_bind`。

## 出站白名单模式

```sh
./target/debug/world network exec --policy examples/network-offline.json --workdir /tmp/world-a -- /bin/echo offline
./target/debug/world network exec --policy examples/network-web.json --workdir /tmp/world-a --timeout 30s -- /usr/bin/curl -fsS https://example.com/
```

策略格式、代理凭证、目标校验、DNS 特殊地址规则、期限和退出码都与 macOS 相同，见 [macOS 网络运行时](macos-network-isolation.md#出站白名单模式)。

每次执行都会：

1. 在子进程中创建新的 user namespace、network namespace 和 IPC namespace（System V IPC 与 POSIX 消息队列都与宿主隔离），把当前 uid/gid 映射进去，并启用 `lo`。新 namespace 除 loopback 外没有任何接口，内核层面不存在去往宿主或外网的路由。
2. 有允许目标时，在该 namespace 的 `127.0.0.1`（以及可用时的 `::1`）上创建代理监听 socket，通过 `SCM_RIGHTS` 传回 World 进程。端口从 namespace 默认的临时端口范围（32768–60999）中随机选取；任务如果固定绑定同一端口，会得到 `EADDRINUSE`。代理在宿主侧接受连接并按策略转发。任务仍然通过 `http_proxy` 等变量使用代理。
3. 在私有 mount namespace 中把所有挂载递归设为只读和 `nodev`，只把工作目录和私有临时目录重新绑定为可写（仍为 `nodev`，其中的设备节点无法使用）。`/dev` 换成最小 tmpfs：只从宿主绑定 `null`、`zero`、`full`、`random`、`urandom`，另有 `fd`/`stdin`/`stdout`/`stderr` 符号链接和私有的 `/dev/shm`（64 MiB）。没有 `/dev/tty` 和 `/dev/pts`，任务无法打开宿主终端或其他设备节点并对其执行 ioctl。Landlock ABI 5+（Linux 6.10+）还会额外限制设备 ioctl。只读挂载会拒绝修改文件元数据（`chmod`、`chown`、时间戳、xattr），这些是 Landlock 管不到的。然后设置 `no_new_privs`，并清空能力（锁定 `SECBIT_NOROOT`、清除 ambient 能力、清空 bounding set），这样即使调用者是 root、在 namespace 内映射为 UID 0，任务也没有任何能力，无法重新挂载为可写；再用 Landlock 禁止工作目录、私有临时目录和 `/dev/null` 之外的写入，作为第二层限制。内核支持 Landlock ABI 6（Linux 6.12+）时，还禁止向沙箱外发送信号和连接沙箱外的抽象 Unix socket。
4. 用 seccomp 拒绝 `AF_INET`、`AF_INET6`、`AF_NETLINK` 之外的 `socket()`、数据报类型的 `socketpair()`、`io_uring_setup`，以及密钥管理调用（`keyctl`、`add_key`、`request_key`，因为调用者的 session keyring 会被继承）。network namespace 管不到文件系统 Unix socket（例如 Docker、D-Bus），这一步就是阻止借用它们出网。数据报 socket 对的一端可以被 `connect` 或 `sendto` 重新指向宿主 Unix socket，所以只允许 stream 和 seqpacket 类型的 `socketpair`，用于进程内部通信。
5. 在新的 PID namespace 中运行任务：由一个最小 init 担任 PID 1 并回收孤儿进程，任务是 PID 2，信号语义不变。任务退出、超时或被取消时，init 随之退出，内核会杀死该 namespace 中剩余的所有进程，包括用 `setsid`/`setpgid` 脱离进程组的后代。macOS 没有这项保证。
6. 清空环境变量；标准输入只接受匿名管道、`/dev/null` 或已关闭（见下文）；关闭 0/1/2 之外继承的描述符。

与 macOS 的差异：

- **本地监听**：macOS 的 Seatbelt 禁止监听；Linux 允许任务在自己的私有 loopback 上监听。其他执行和宿主都访问不到它。
- **错误码**：连接宿主监听端口时，得到的是 namespace 内的 `ECONNREFUSED`，而不是 `EPERM`；Unix socket 返回 `EACCES`。
- **进程信息**：所有支持的 Landlock ABI 都会阻止对沙箱外进程的 ptrace 及相关访问（`pidfd_getfd`、`process_vm_readv`、受保护的 `/proc/<pid>` 数据），因此任务无法借用宿主进程的 socket；但任务仍能列出宿主进程和它们的命令行。Linux 6.12 以前，同一 uid 的宿主进程也可能收到任务发出的信号。
- **路径**：私有 `/dev` 会遮住宿主 `/dev` 下的路径，因此不支持位于 `/dev` 下的工作目录（例如 `/dev/shm/...`）；`TMPDIR` 指向 `/dev` 下时，私有临时目录改建在 `/tmp`。
- **库调用者与 SIGCHLD**：在库中调用 `network exec` / `silo exec` 的进程不能忽略 `SIGCHLD`（`SIG_IGN` 或 `SA_NOCLDWAIT`，否则会直接报错），也不能在执行期间用 `waitpid(-1)` 回收未知子进程；否则任务的退出状态会丢失，`world` 会明确报错，而不会返回错误的状态。CLI 在启动时会重置 `SIGCHLD` 并解除对它的屏蔽。
- **进程回收**：Linux 的两种模式都在 PID namespace 中运行任务，脱离进程组的后代也会被回收；任务内看到的 PID 是 namespace 内的编号。
- **标准输入**：Linux 的 `network exec` 只接受匿名管道的读端、`/dev/null` 或已关闭的标准输入（管道写端会成为通向宿主的通道，也会被拒绝）。其他文件、目录、命名 FIFO、终端和设备都会被拒绝，因为即使是只读描述符，也能对其 inode 执行 `fchmod`、`fchown`、`futimens`、`fsetxattr` 或终端 ioctl。需要输入文件时改用管道，例如 `cat FILE | world network exec ...`。`/dev/null` 会在沙箱内从只读的私有 `/dev` 重新打开，因此任务不持有宿主的设备节点。
- **硬链接**：与 macOS 一样，写入边界基于路径。调用者事先放进工作目录、指向外部文件的硬链接会共享同一个 inode，任务可以通过它写入。任务自己无法创建这类别名：硬链接跨挂载会返回 `EXDEV`，经符号链接写入会落在只读视图上。forkfs Workspace 用 clonefile/reflink 创建独立 inode，不会产生这种别名；自行指定工作目录时，不要放入指向需保护文件的硬链接。
- **读取**：与 macOS 一样，不限制读取宿主文件。

## 同端口 localhost（silo）

```sh
mkdir -p /tmp/world-a /tmp/world-b
./target/debug/world silo create --world A --workdir /tmp/world-a
./target/debug/world silo create --world B --workdir /tmp/world-b
./target/debug/world silo setup --world A
./target/debug/world silo setup --world B
./target/debug/world silo exec --world A -- python3 -m http.server 8080 --bind 127.0.0.1
./target/debug/world silo exec --world B -- python3 -m http.server 8080 --bind 127.0.0.1
./target/debug/world silo exec --world A -- curl --noproxy '*' http://localhost:8080/
```

- 在 Linux 上，`setup` 不需要 sudo：它启动一个脱离终端的 holder 进程（进程名 `world-holder`，单线程，由 init 回收；不依赖 `world` 可执行文件，嵌入 `world_runtime` 的程序也能使用），由它持有该 World 的 user namespace 和 network namespace。holder 的 PID、启动时间和 namespace inode 记录在状态目录的 `holders.json` 中；重复 `setup` 是幂等的。
- `exec` 校验 holder 身份后，用 `setns` 加入这两个 namespace，再执行命令。同一个 World 的多次 `exec` 共享同一个内核网络栈。不同 World 的 localhost 完全独立，都可以绑定同一地址和端口，包括 `127.0.0.1`、`0.0.0.0`、`::1`、`::`、UDP，以及 1024 以下的端口。
- 程序形态不限：脚本、系统程序、静态链接程序和 setuid 程序都可以运行。其中 setuid 位在 namespace 中不会提升权限。注册表里的 `ip` 字段在 Linux 上只是标识，不参与网络。
- World 内只有 loopback：宿主访问不到 World 内的监听，World 内也没有外网，客户端必须同样通过 `world silo exec` 启动。继承的 `http_proxy` 等变量指向宿主代理时，World 内同样无法连接，访问 localhost 时应设置 `no_proxy` 或使用 `--noproxy`。与 macOS silo 一样，文件系统 Unix socket 不受限制。
- 在库中调用 `silo::setup` 的长期运行进程如果是 child subreaper，holder 会被它收养；Linux 5.4+ 上 teardown 会用 `waitid(P_PIDFD)` 精确回收，更早的内核上无法安全地按 PID 回收，需要调用者自行回收子进程。被外部杀死的 holder 会在下一次 `setup`/`teardown` 时，先用 pidfd 固定并核对启动时间，确认身份后再回收。如果 `pidfd_open` 被调用者自己的 seccomp 策略拒绝，`setup` 会失败，holder 在创建任何 namespace 之前就退出；这时同样需要调用者自行回收。
- `world silo teardown --world A` 停止 holder：先用 pidfd 固定进程再校验身份，避免 PID 复用误杀；Linux 5.3 以前没有 pidfd，会在校验后立即按 PID 发送信号。已经在运行的 World 进程会继续持有旧的 namespace，但之后的 `exec` 无法再加入它。holder 被杀死或机器重启后，需要重新 `setup`；新 namespace 不会与仍在运行的旧进程共享。

与 macOS 的 silo 不同，这里是内核 network namespace：原始系统调用、静态链接程序或绕过 libc 的程序，也无法访问其他 World 或宿主的 loopback。它仍然不是完整沙箱：不限制文件读写，同一 uid 的宿主进程可以加入 World 的 namespace，也不提供跨 World 文件保密、组织授权或远程租约。

## 验证

```sh
cargo test --workspace --locked
cargo build --workspace --locked && cargo build --workspace --examples --locked
python3 -m unittest discover -s tests -v < /dev/null
```

Linux 验收默认运行，不需要额外环境变量。CI 的 Ubuntu job 会先关闭 AppArmor 对非特权 user namespace 的限制。测试会显式把 `/dev/null` 作为 `world` 的标准输入，因此与运行测试的终端无关。
