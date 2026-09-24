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

1. 在子进程中创建新的 user namespace 和 network namespace，把当前 uid/gid 映射进去，并启用 `lo`。新 namespace 除 loopback 外没有任何接口，内核层面不存在去往宿主或外网的路由。
2. 有允许目标时，在该 namespace 的 `127.0.0.1`（以及可用时的 `::1`）上创建代理监听 socket，通过 `SCM_RIGHTS` 传回 World 进程。端口从 namespace 默认的临时端口范围（32768–60999）中随机选取；任务如果固定绑定同一端口，会得到 `EADDRINUSE`。代理在宿主侧接受连接并按策略转发。任务仍然通过 `http_proxy` 等变量使用代理。
3. 在私有 mount namespace 中把所有挂载递归设为只读，只把工作目录和私有临时目录重新绑定为可写。只读挂载会拒绝修改文件元数据（`chmod`、`chown`、时间戳、xattr），这些是 Landlock 管不到的。然后设置 `no_new_privs`，再用 Landlock 禁止工作目录、私有临时目录和 `/dev/null` 之外的写入，作为第二层限制。内核支持 Landlock ABI 6（Linux 6.12+）时，还禁止向沙箱外发送信号和连接沙箱外的抽象 Unix socket。
4. 用 seccomp 拒绝 `AF_INET`、`AF_INET6`、`AF_NETLINK` 之外的 `socket()`、数据报类型的 `socketpair()`，以及 `io_uring_setup`。network namespace 管不到文件系统 Unix socket（例如 Docker、D-Bus），这一步就是阻止借用它们出网。数据报 socket 对的一端可以被 `connect` 或 `sendto` 重新指向宿主 Unix socket，所以只允许 stream 和 seqpacket 类型的 `socketpair`，用于进程内部通信。
5. 在新的 PID namespace 中运行任务：由一个最小 init 担任 PID 1 并回收孤儿进程，任务是 PID 2，信号语义不变。任务退出、超时或被取消时，init 随之退出，内核会杀死该 namespace 中剩余的所有进程，包括用 `setsid`/`setpgid` 脱离进程组的后代。macOS 没有这项保证。
6. 清空环境变量；拒绝 socket 标准输入，以及以可写方式打开的普通文件或块设备标准输入（Landlock 不限制沙箱建立前已打开的描述符）；关闭 0/1/2 之外继承的描述符。

与 macOS 的差异：

- **本地监听**：macOS 的 Seatbelt 禁止监听；Linux 允许任务在自己的私有 loopback 上监听。其他执行和宿主都访问不到它。
- **错误码**：连接宿主监听端口时，得到的是 namespace 内的 `ECONNREFUSED`，而不是 `EPERM`；Unix socket 返回 `EACCES`。
- **进程信息**：所有支持的 Landlock ABI 都会阻止对沙箱外进程的 ptrace 及相关访问（`pidfd_getfd`、`process_vm_readv`、受保护的 `/proc/<pid>` 数据），因此任务无法借用宿主进程的 socket；但任务仍能列出宿主进程和它们的命令行。Linux 6.12 以前，同一 uid 的宿主进程也可能收到任务发出的信号。
- **进程回收**：Linux 的两种模式都在 PID namespace 中运行任务，脱离进程组的后代也会被回收；任务内看到的 PID 是 namespace 内的编号。
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

- 在 Linux 上，`setup` 不需要 sudo：它启动一个脱离终端的 holder 进程（`world silo hold`），由它持有该 World 的 user namespace 和 network namespace。holder 的 PID、启动时间和 namespace inode 记录在状态目录的 `holders.json` 中；重复 `setup` 是幂等的。
- `exec` 校验 holder 身份后，用 `setns` 加入这两个 namespace，再执行命令。同一个 World 的多次 `exec` 共享同一个内核网络栈。不同 World 的 localhost 完全独立，都可以绑定同一地址和端口，包括 `127.0.0.1`、`0.0.0.0`、`::1`、`::`、UDP，以及 1024 以下的端口。
- 程序形态不限：脚本、系统程序、静态链接程序和 setuid 程序都可以运行。其中 setuid 位在 namespace 中不会提升权限。注册表里的 `ip` 字段在 Linux 上只是标识，不参与网络。
- World 内只有 loopback：宿主访问不到 World 内的监听，World 内也没有外网，客户端必须同样通过 `world silo exec` 启动。继承的 `http_proxy` 等变量指向宿主代理时，World 内同样无法连接，访问 localhost 时应设置 `no_proxy` 或使用 `--noproxy`。与 macOS silo 一样，文件系统 Unix socket 不受限制。
- `world silo teardown --world A` 停止 holder。已经在运行的 World 进程会继续持有旧的 namespace，但之后的 `exec` 无法再加入它。holder 被杀死或机器重启后，需要重新 `setup`；新 namespace 不会与仍在运行的旧进程共享。

与 macOS 的 silo 不同，这里是内核 network namespace：原始系统调用、静态链接程序或绕过 libc 的程序，也无法访问其他 World 或宿主的 loopback。它仍然不是完整沙箱：不限制文件读写，同一 uid 的宿主进程可以加入 World 的 namespace，也不提供跨 World 文件保密、组织授权或远程租约。

## 验证

```sh
cargo test --workspace --locked
cargo build --workspace --locked && cargo build --workspace --examples --locked
python3 -m unittest discover -s tests -v < /dev/null
```

Linux 验收默认运行，不需要额外环境变量。CI 的 Ubuntu job 会先关闭 AppArmor 对非特权 user namespace 的限制。标准输入必须不是 socket（例如某些 Agent 终端），否则 `world` 会按设计拒绝执行。
