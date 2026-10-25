# World

World 为开发者和 Coding Agent 提供可分叉的工作环境，将文件系统、数据库、服务和外部副作用纳入同一个状态上下文。项目的目标是让多个 Agent 从共同基线独立工作，检查各自的变化，再选择合并、保留或丢弃成果。

核心工作流是 **fork → execute → diff → merge/discard**，并通过 checkpoint 保存可恢复的状态。这是产品目标；当前实现范围见下文。

## 项目目的与职责

| 核心能力 | 目标 |
| --- | --- |
| 可分叉文件系统（WorldFS / BranchFS） | 管理完整工作目录的快照、分支和差异，包括未跟踪文件、构建产物及依赖；通过正常文件系统接口供工具使用 |
| 数据库与服务分支 | 将数据库、对象存储等资源绑定到同一 World，让不同 Agent 使用各自的状态 |
| 网络虚拟化 | 为每个 World 提供独立的 localhost 与服务寻址，将相同地址和端口路由到对应分支 |
| 副作用管理 | 对接支持的服务，捕获、模拟或回放外部操作，展示待提交副作用，并在明确授权后提交 |
| 统一生命周期 | 协调 fork、执行、checkpoint、diff、合并与丢弃，报告各资源的能力、冲突和失败状态 |
| CLI、Skill 与 MCP | 为开发者和 Agent 提供同一套工作流程、结构化操作和恢复能力 |

安全执行由 Agent 宿主、容器或其他执行后端提供，World 负责声明所需能力并验证集成边界。World 的研发重点是状态分支、服务路由和副作用管理；已有出站白名单运行模式作为可选执行能力保留。

Codex、Claude Code、OpenCode 和 Pi 的接入需按版本与平台验证：Agent 的命令沙盒可能改变 World 的 localhost 视图，也不一定覆盖文件工具、插件与 MCP。Linux、macOS、Windows 原生与 WSL2 的实现矩阵、接入方式和待验证项见 [Agent sandbox 整合调研](docs/agent-sandbox-integration.md)。

Cursor、Copilot CLI / cloud agent、Gemini CLI、Cline、OpenHands、Devin、Cascade、Kiro、Aider 的逐项比较见 [其他 Coding Agent 调研](docs/coding-agent-survey.md)。执行适配还需覆盖自托管 worker、agent server 和一次性 runner 的生命周期。

macOS 宿主上的执行后端按 World 的执行 OS 选择：用户明确指定 Linux 时，实验性后端使用 Apple container，为每个 World 提供一个持久轻量 Linux VM；选择 macOS 或沿用未指定 OS 的原生工作流时，保留现有原生后端。已实现 create/setup/show/exec/teardown，并在本机验证非 root 执行、跨执行 localhost、cgroup 后代回收、超时取消与重启保留文件；NAT 出网尚不限制宿主或局域网访问。选择规则、CLI、生命周期与交付计划见 [Linux VM 后端设计](docs/linux-vm-backend.md)；原生方案的兼容边界见 [macOS 后端重新评估](docs/macos-backend-reassessment.md)。

WorldFS 是核心能力，forkfs 是计划通过 RPC 接入的首个文件系统后端。长期希望通过 FUSE/FSKit 等接口暴露分支文件系统，并由 CLI 管理挂载和进入环境的流程。macOS 初期接受不同的实际挂载路径，优先让少量（约 1～10 个）World 中的常用开发工具顺畅工作；Linux 利用内核 namespace 提供运行时视图。挂载前端、数据库分支与副作用管理均尚未实现。

组织、Network、认证、元信息和计费是支撑协作与托管部署的管理能力。Network 保留为组织内部的授权与资源归属范围；一个 Network 可以包含多个独立的 World/Workspace。当前 Workspace 是工作目录与运行时身份，后续将关联文件系统分支、数据库分支、服务映射和副作用记录。

完整设计见 [World 架构设计](docs/world-design.md)。forkfs RPC 服务是待实现的接入契约，World 不链接 forkfs 库，也不通过解析 CLI 输出控制它。

## 当前实现

World 现在使用 Rust workspace。macOS 和 Linux 已实现两种本地运行模式：

- `world network exec`：出站白名单。macOS 用 Seatbelt，禁止本地监听；Linux 为每次执行创建独立的 network namespace，只有 loopback，配合 Landlock 和 seccomp。
- `world exec`：在 Workspace 内执行，多个 Workspace 使用相同端口，同一 Workspace 的多次执行共享地址，应用无需修改源码或配置 World IP。macOS 内部使用固定版本的 silo 透明重写受支持原生程序的 localhost，`/tmp`、`/var/tmp` 也按 Workspace 隔离，同名锁文件和 Unix socket 互不冲突；Linux 让每个 Workspace 持有一个内核 network namespace 和 mount namespace，`/tmp`、`/var/tmp` 同样按 Workspace 隔离，通过 pasta 出网（宿主 localhost 仍不可达），宿主通过 Workspace 地址（如 `http://127.77.0.1:8080`）访问其中的服务，不需要 root，也不注入动态库。

```sh
cargo build --workspace
mkdir -p ~/world-a ~/world-b
./target/debug/world workspace create A --workdir ~/world-a
./target/debug/world workspace create B --workdir ~/world-b
./target/debug/world workspace setup A
./target/debug/world workspace setup B
# macOS 的 setup 需要管理员授权，只添加本 Workspace 的 loopback 别名；
# Linux 的 setup 不需要特权，只启动持有 Workspace namespace 的进程（world workspace teardown 停止它）。
./target/debug/world exec A -- /opt/homebrew/bin/python3 -m http.server 8080 --bind 127.0.0.1
# 另一终端可在 B 中运行相同命令、使用相同端口。
```

使用、验证和兼容边界见 [macOS 网络运行时](docs/macos-network-isolation.md) 和 [Linux 网络运行时](docs/linux-network-isolation.md)。macOS 的 Workspace localhost 模式是开发任务的 localhost 兼容层，不是对抗恶意代码的内核网络命名空间；Linux 是内核 namespace，但也不限制文件访问。两者都不能与出站白名单模式混为一谈。模型对拍、fuzz 与压力测试的运行方式见 [测试工具](docs/testing.md)。

### macOS 上运行 Linux World（实验性）

当前支持 Apple Silicon 与 Apple `container` 1.6.1；本机验证系统为 macOS 27.0.1。先安装该版本并显式启动服务，再运行：

```sh
container system start
cargo build --workspace
./target/debug/world workspace create linux-dev --os linux --memory 256M --cpus 1
./target/debug/world workspace setup linux-dev
# 可选：首次将宿主项目复制到空的 /workspace。
./target/debug/world workspace import linux-dev --source ./project
./target/debug/world exec linux-dev -- sh -lc 'uname -a; id; pwd'
./target/debug/world exec linux-dev -- sh -c 'echo hello > /workspace/example.txt'
./target/debug/world workspace teardown linux-dev
# 再次 setup 后 /workspace/example.txt 仍在。
```

VM 默认内存限额为 512 MiB，小型测试可指定 256 MiB；运行时与 guest 内核另有开销。首版保守限制同一用户经 World 启动的 VM：发现其他运行中的 container 时拒绝启动新 VM。允许同一个 World 的多个 exec 并发，每个命令具有独立 cgroup；正常结束也会清理其后台后代，因此开发服务应以前台 `world exec` 在独立终端中运行。teardown 遇到活跃执行会拒绝，先取消这些执行再停机。

工作目录固定为 guest `/workspace`，任务 UID 为 1000，不挂载宿主目录或导入宿主环境。首版使用固定 digest 的 Python/Alpine 镜像，已支持 `workspace import --source` 将宿主目录复制到空 `/workspace`；尚无 export、创建时的 `--import`、持久服务管理、PTY、宿主端口发布、WorldFS 或出口白名单。VM 提供独立内核边界，默认 NAT 并不阻止访问宿主、LAN 或其他 guest；不将此后端标为完整恶意任务沙盒。导入先生成宿主临时快照，再经 guest 暂存与校验发布，不覆盖已有内容。它包含隐藏文件与未跟踪文件，保留普通权限和符号链接，但不跟随链接读取外部目标；不保留 xattr/ACL/时间戳/硬链接关系，特殊文件和非 UTF-8 路径明确拒绝。导入时请暂停源目录写入；这不是原子文件系统快照。完整状态及限制见 [后端文档](docs/linux-vm-backend.md#当前实验实现)。

### Linux VM 生命周期

```sh
./target/debug/world workspace list
./target/debug/world workspace show linux-dev
./target/debug/world workspace teardown linux-dev
# 当前实验版可写层可能有项目文件：永久删除需要显式确认。
./target/debug/world workspace delete linux-dev --discard-runtime-data
```

`list` 保留所有本地注册记录；原生 Workspace 暂不探测运行状态，VM 返回 `created`、`ready`、`stopped`、`missing`、`unknown` 等状态及观测时间。provider 不可用时返回 `unknown` 与错误，不能当作实例不存在。删除仅支持已停机的 Linux VM，活跃执行会拒绝停机/删除；不会调用 forkfs 分支删除或停止全局 container 服务。无实例的登记可直接删除，已有实例还必须确认删除其可写层，并且不允许带挂载的实例直接删除。

生命周期阶段与启动 generation 落盘，删除中断可重复 `delete` 收尾。若已运行过的 VM 意外丢失，setup 会拒绝创建一个空环境来替代；检查数据恢复后，只有显式 `workspace setup <name> --recreate-missing` 才会重建空运行时。该选项不恢复旧文件。旧版本缺少生命周期记录的 VM 需 setup 重新验证；旧记录且实例缺失时同样要求显式重建。forkfs 挂载后 VM 仅承载运行时的工作另见 [Issue #28](https://github.com/forks-world/world/issues/28)。

当前 `workspace create --workdir` 绑定已有目录，不会自动创建文件系统分支。完整控制面、认证、计费、Skill/MCP、forkfs RPC 接入、FUSE/FSKit 前端、数据库分支、外部副作用捕获与跨资源 merge/discard 均仍为规划，不能将现有网络运行时视为完整 World 生命周期。
