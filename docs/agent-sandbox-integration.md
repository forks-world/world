# Agent sandbox 与 World 整合调研

核查日期：2026-10-07。范围为 Codex CLI、Claude Code、Anomaly 的 OpenCode，以及 Pi coding agent（当前上游 `earendil-works/pi`）。本次核对官方文档、公开源码和 World 本地实现；没有运行四种 Agent 的端到端集成测试。以下“可整合”是架构判断，不代表兼容性已经验收。

Cursor、Copilot CLI / cloud agent、Gemini CLI、Cline、OpenHands、Devin、Cascade、Kiro、Aider 的平台矩阵与逐项分析见 [扩展调研](coding-agent-survey.md)。其中的自托管执行端与 runner 路线补充本文的本地 CLI 和工具委派方案。

## 结论与职责边界

四者都存在接入路径，但不能假设每个 Agent 已经提供完整安全沙盒。World 应同时支持“使用 Agent 自带的命令沙盒”和“使用外部执行环境”两种组合，分别报告状态分支、网络视图与安全边界的能力。

| 层 | 职责 | World 接入方式 |
| --- | --- | --- |
| Agent harness | 模型连接、会话、工具调度、用户授权 | CLI 启动、MCP、插件或执行器适配 |
| 执行安全后端 | 文件访问、进程权限、网络出口限制 | 复用 Agent sandbox、独立 sandbox runtime、容器或 VM；验证实际覆盖范围 |
| World 环境 | 文件系统分支、Workspace localhost、服务与数据库分支、副作用记录 | 提供稳定 World 身份、资源绑定和生命周期 |

工具审批、MCP 和网络代理各有边界：审批不创建 OS 隔离；MCP 不自动重定向 Agent 的其他工具；域名代理也不自动具备数据库分支或外部操作回滚语义。

## 当前上游能力

| Agent | sandbox 现状 | 与 World 的接入点 | 主要限制 |
| --- | --- | --- | --- |
| Codex CLI | macOS Seatbelt；Linux bwrap + seccomp；Windows 原生分 elevated/unelevated；审批独立配置 | Workspace 中启动 CLI；MCP 暴露生命周期；另可研究 self-hosted executor | 命令网络策略、嵌套 namespace 和环境变量传递需要探测 |
| Claude Code | 命令工具使用 macOS Seatbelt / Linux、WSL2 bubblewrap 与代理；Windows 原生无内置 sandbox | Workspace 中启动；MCP；受控代理对接 | Linux 每次沙盒命令的 localhost 独立；Bash sandbox 不覆盖全部工具与辅助进程 |
| OpenCode | 官方明确没有 Agent sandbox；permission 是交互权限机制 | 整个进程进入 World 与外部安全环境；MCP、插件与自定义工具 | permission、hook 和环境变量都不能替代 OS 边界 |
| Pi | 官方明确没有内置安全沙盒；仓库提供可选 sandbox 扩展示例 | 整体启动；替换工具 operations；当前 main 的 MCP 支持 | 示例仅包装 bash 等指定路径，初始化失败会回到本地执行；不能直接作为严格模式 |

Codex 平台机制依据 [Sandbox](https://learn.chatgpt.com/docs/sandboxing) 与 [Agent approvals & security](https://learn.chatgpt.com/docs/agent-approvals-security)。Claude Code 的覆盖范围依据 [Sandboxed Bash tool](https://code.claude.com/docs/en/sandboxing)。OpenCode 依据 [SECURITY.md](https://github.com/anomalyco/opencode/blob/ecc4916b5a9608c30e6dd58a67f2137b594407ca/SECURITY.md)。Pi 依据 [安全说明](https://github.com/earendil-works/pi/blob/7fb59f995b0a1db552001a8577b234e4105d7179/SECURITY.md) 和 [sandbox 示例](https://github.com/earendil-works/pi/blob/7fb59f995b0a1db552001a8577b234e4105d7179/packages/coding-agent/examples/extensions/sandbox/index.ts)。

源码链接锁定此次读取的提交；OpenCode `dev`、Pi 与 sandbox-runtime `main` 的能力不等同于所有已发布版本。集成时仍需锁定安装版本并探测能力。本机 Codex npm 包为 `0.114.0`，不能用它代表当前官方文档对应的版本；本次版本命令未正常返回，版本号取自包元数据。

## 按操作系统划分的实现矩阵

必须同时记录 **宿主 OS、Agent 进程 OS、工具执行 OS**。Windows 桌面连接 WSL2 中的 Agent server，与 Windows 原生 Agent 只把 Bash 放进 WSL2，是不同组合；后者的直接文件工具仍可能在 Windows 运行。Git Bash 也不是 WSL2 或 Linux namespace。

下表描述上游机制，所有与 World 的组合仍待端到端验证。“可选示例”不表示默认启用，也不表示覆盖整个 Agent。

| Agent | Linux 原生 | macOS 原生 | Windows 原生 | Windows + WSL2 |
| --- | --- | --- | --- | --- |
| Codex | 当前默认 bwrap + seccomp；网络开关与代理策略分别配置 | Seatbelt；与 World 的 DYLD 注入链需组合验证 | `elevated` / `unelevated` 两种原生 sandbox，机制与保证不同 | Agent 在发行版内运行时使用 Linux sandbox；当前 bwrap 路线不支持 WSL1 |
| Claude Code | bubblewrap + 代理；每次 sandbox 命令私有 localhost | Seatbelt + 代理；本地监听与直连由平台策略控制 | 可以运行 Agent，但官方文档明确命令不受内置 sandbox 保护 | 使用 Linux bubblewrap 路线；另需检查 Windows 可执行文件互操作 |
| OpenCode | 无内置安全 sandbox | 无内置安全 sandbox | 支持原生运行，仍无内置安全 sandbox | 官方推荐的 Windows 使用方式；WSL 本身不增加 OpenCode 的工具权限隔离 |
| Pi | 无内置安全 sandbox；可选示例使用 sandbox-runtime | 无内置安全 sandbox；可选示例使用 sandbox-runtime | 支持 Git Bash 与可选 PowerShell；所核对 sandbox 示例排除 `win32` | Pi 进程在 WSL 内时走 Linux 路线；只把 shell 改为 WSL 不迁移全部工具 |

Codex 的 Unix 机制见前文；Windows 区别见 [官方 Windows sandbox 文档](https://learn.chatgpt.com/docs/windows/windows-sandbox)。Claude 平台支持见 [sandbox 文档](https://code.claude.com/docs/en/sandboxing)。OpenCode 运行方式见 [Windows / WSL](https://opencode.ai/docs/windows-wsl/)，安全边界仍以前述 SECURITY.md 为准。Pi 原生 shell 与 WSL 行为见 [Windows 指南](https://github.com/earendil-works/pi/blob/7fb59f995b0a1db552001a8577b234e4105d7179/packages/coding-agent/docs/windows.md)，扩展示例的平台判断见前述固定提交源码。

### Windows 原生不能套用 Unix 方案

Codex 的 `elevated` 模式使用专用低权限用户、文件权限和防火墙规则，初始化需要管理员批准；名称不意味着任务以管理员身份运行。`unelevated` 使用当前用户派生的受限 token 与 ACL，离线控制较弱。World 能力探测必须区分两者，验证实际执行身份对分支目录与服务的访问，不能把它们记为同一个安全等级。[Codex Windows sandbox](https://learn.chatgpt.com/docs/windows/windows-sandbox)

独立 **Anthropic sandbox-runtime 的 Windows alpha** 已使用专用 `srt-sandbox` 账号、按 SID 匹配的 WFP 出口规则和 NTFS ACE；安装需要系统级配置。它可作为 World 原生 Windows 执行后端的研究候选，但 Claude Code 内置 sandbox 仍明确不支持原生 Windows，Pi 示例也仍只接受 darwin/linux。必须分别核对 runtime 能力、Agent 是否采用、以及实际安装版本。[sandbox-runtime Windows alpha](https://github.com/anthropics/sandbox-runtime/blob/12a2be92c110cbc3c19584c4c8387e7e754c8179/README.md#windows-alpha)

上述 Windows 安全机制没有证明“每个 World 独立 localhost”。基于当前资料，World 原生 Windows 仍需另行设计服务地址空间、端口发布、分支文件视图与进程生命周期。共享 sandbox 账号也不能充当多个 World 的独立身份；专用账号、WFP 规则或 ACL 只是一部分机制，不能直接等同于 Linux 的 per-Workspace namespace。

### WSL2 是单独的部署目标

WSL2 可以作为复用 World Linux 后端的候选，但不是本次已经支持的平台。需探测其内核和发行版是否满足 World 所需的 namespace、Landlock、seccomp、pasta 与文件系统后端能力；Agent 使用 bwrap 不会消除 World 自身的这些前置条件。

Microsoft 文档区分 NAT 与 mirrored 网络；两种模式的 Windows/WSL localhost 可达性不同，还受到 Hyper-V 防火墙影响。因此 World 在 Linux 中发布的 `127.77.x.x` 地址不能直接当作 Windows 浏览器的可用入口，必须实测并设计显式桥接。镜像网络的宿主 localhost 互通也不能替代 World 自己的隔离边界。[WSL 网络文档](https://learn.microsoft.com/en-us/windows/wsl/networking)

优先把 Agent、World、工具链与工作目录放在同一 WSL2 发行版的 Linux 文件系统中进行验证。若使用 `/mnt/c`、UNC 路径、Windows 原生工具或 Windows UI，必须分别测试路径映射、大小写、权限、文件监听、Unix socket 与宿主互操作。文件系统分支后端需要独立检查 reflink/挂载能力，不能因“在 WSL2 中”就认定 forkfs 已可用。

### World 平台路线与能力契约

| 执行平台 | 当前 World 状态 | 下一步 |
| --- | --- | --- |
| Linux | 已有 Workspace network/mount namespace 和独立出站限制模式 | 验证四种 Agent 与内层 sandbox 的组合；保留共享 localhost 与明确安全边界 |
| macOS 原生 World | 已有 Silo localhost / 临时目录兼容层与 Seatbelt 出站限制模式 | 验证 SIP、系统 shell、签名程序与动态库加载 |
| Linux World / macOS 宿主 | 实验性 Apple 轻量 VM 后端与单 VM 执行回归通过，完整 Agent 接入待验收 | 用户显式选择 Linux；按 [VM 后端设计](linux-vm-backend.md) 验证每 World 独立 VM、guest Agent/文件视图与网络策略 |
| WSL2 | 尚未验收；可研究复用 Linux 后端 | 固定发行版、内核与 NAT/mirrored 模式，补 Windows 访问服务和互操作测试 |
| Windows 原生 | 尚无后端；当前源码含直接 Unix 依赖，不能声称已经原生可用 | 先确定原生工作负载需求；独立评估 Windows 安全执行、文件分支、网络虚拟化与终端适配 |

这是基于现有实现的路线建议，不预设 Windows 用户必须放弃原生工具。Windows 原生支持应单独交付；通过 WSL2 支持 Linux 工作负载不能标为原生 Windows 兼容。

执行适配器的能力记录至少增加以下维度，字段名称仍为拟议：

- `host_os`、`agent_os`、`execution_os`、CPU 架构、内核/Windows build、WSL 发行版与版本。
- Agent 与 runtime 的锁定版本、后端模式、实际执行用户/token 身份、启用及失败回退状态。
- 文件路径命名空间与映射、工作目录、工具链可见性、文件系统分支后端能力。
- localhost 是否跨执行共享、TCP/UDP/Unix socket/命名管道支持、代理位置与端口发布方式。
- 终端能力与进程树清理机制；Windows 原生需单独验证 ConPTY、Ctrl-C、Job Object 或其他后端清理策略，不能沿用 Unix 信号假设。
- 覆盖哪些工具和辅助进程、是否允许跨 OS 执行、所需安装权限以及策略不可用时的行为。

## Codex

优先把 CLI 的工作目录绑定到 World 的文件系统分支，保留所需的命令 sandbox，并通过 [MCP](https://learn.chatgpt.com/docs/extend/mcp) 提供 inspect、diff、checkpoint 等工具。MCP 是生命周期入口，不能让原有 shell 自动进入另一个 World。

当前官方文档将 Linux 后端描述为 bwrap + seccomp，并注明自 `0.115` 起转向 bwrap。因此，早期讨论中的“Linux 就是 Landlock + seccomp”不应继续作为集成前提。网络关闭时，World 服务也可能不可达；开启命令网络与启用域名代理是两个设置，必须检查有效配置。具体 namespace 行为随版本与网络策略验证，不套用 Claude 的结果。

还存在更明确的远程执行接入：官方 [Self-hosted sandboxes](https://developers.openai.com/api/docs/guides/agents-api/environments/self-hosted) 让用户在自己的环境运行 `codex exec-server`，由云端 harness 下发执行与文件操作。World 可研究承担环境创建、工作目录准备和 executor 生命周期管理。该文档示例使用 alpha CLI；它属于单独的 API 接入路线，不能视为本机普通 CLI 已有的通用 sandbox 插件接口。

## Claude Code 与 sandbox-runtime

Claude 的 Bash sandbox 不包含内置 Read/Edit/Write、WebFetch 等工具的 OS 限制；hooks、本地 MCP、LSP 等辅助进程也不因此自动进入 Bash sandbox。因此，只包装 Bash 不足以保证整个 Agent 都使用同一分支与副作用路径。[覆盖范围](https://code.claude.com/docs/en/sandboxing)

Linux 上，每次 sandbox 命令有自己的 localhost，不能直接访问外层进程监听的 localhost。macOS 的 `allowLocalBinding` 会扩大 localhost 的访问范围；它不提供 World 身份隔离。由此推断：简单套上 `world exec`，不能同时承诺保留全部原生 sandbox 行为与 World 共享 localhost 语义。[localhost 限制](https://code.claude.com/docs/en/sandboxing)

Claude 支持 `httpProxyPort` / `socksProxyPort` 指向自定义代理；配置生效后，该流量的过滤由自定义代理承担，不能假设原来的域名规则还会叠加生效。World 若选择此接入点，必须实现目标授权、Workspace 身份和撤销语义。[自定义代理](https://code.claude.com/docs/en/sandboxing#custom-proxy-configuration)

可复用的组件是独立的 [Anthropic sandbox-runtime](https://github.com/anthropics/sandbox-runtime/blob/12a2be92c110cbc3c19584c4c8387e7e754c8179/README.md)，它提供 CLI 和 `SandboxManager` API。World 可以评估作为可选执行适配器，不必嵌入整个 Claude Code。其 [Linux 源码](https://github.com/anthropics/sandbox-runtime/blob/12a2be92c110cbc3c19584c4c8387e7e754c8179/src/sandbox/linux-sandbox-utils.ts) 使用 `--unshare-net` 的网络隔离路径，仍需解决共享 World 服务视图；其 [macOS 源码](https://github.com/anthropics/sandbox-runtime/blob/12a2be92c110cbc3c19584c4c8387e7e754c8179/src/sandbox/macos-sandbox-utils.ts) 经 `/usr/bin/sandbox-exec` 启动，必须测试与 Silo 注入链的兼容性。

代理接入仅解决经过该代理的连接。数据库原生 TCP、UDP、Unix socket、监听端口和长期服务仍需单独设计；HTTP CONNECT 隧道本身也不能识别加密流量中的业务副作用。

## OpenCode

OpenCode 官方要求需要真正隔离的用户自行使用容器或 VM。因此，可以将整个 OpenCode 进程放入 World 对应的执行环境，但现有 `world exec` 本身仍不能补足文件保密等完整安全边界。

其 [插件接口](https://opencode.ai/docs/plugins/) 支持 `tool.execute.before/after`、`shell.env` 和自定义工具，也允许同名工具覆盖；这些接口适合绑定 World 身份、展示 diff 或接入执行器。仅设置 `WORLD_ID` 或改写 Bash 字符串不能约束所有文件操作、LSP、插件与 MCP。优先使用整体环境绑定，再通过 [MCP](https://opencode.ai/docs/mcp-servers/) 接入 World 生命周期。

## Pi

Pi 提供两种有价值的参考：将整个 Agent 放入隔离环境，或者保留宿主 harness、把工具操作委派给后端。[官方容器化指南](https://github.com/earendil-works/pi/blob/7fb59f995b0a1db552001a8577b234e4105d7179/packages/coding-agent/docs/containerization.md) 明确区分两者，也指出未委派的扩展仍在宿主执行。

[SSH 扩展示例](https://github.com/earendil-works/pi/blob/7fb59f995b0a1db552001a8577b234e4105d7179/packages/coding-agent/examples/extensions/ssh.ts) 通过 operations 接口替换 read/write/edit/bash，并处理 `user_bash`。World 可借鉴接口分层，建立 World 执行与文件操作适配器；需要另行枚举搜索、扩展工具等全部入口，不能直接复制示例就声称完整覆盖。

当前 main 已提供 [内置 MCP](https://github.com/earendil-works/pi/blob/7fb59f995b0a1db552001a8577b234e4105d7179/packages/coding-agent/docs/mcp.md)，支持 stdio / streamable HTTP；[扩展 API](https://github.com/earendil-works/pi/blob/7fb59f995b0a1db552001a8577b234e4105d7179/packages/coding-agent/docs/extensions.md) 也可动态注册 MCP server。应按实际安装版本探测，不能沿用“Pi 一律没有 MCP”的旧印象。

sandbox 示例使用 `@anthropic-ai/sandbox-runtime`，可参考包装方式；但它在初始化失败后将标志关闭，后续 bash 会执行本地工具。World 严格执行配置必须改为初始化失败就拒绝执行，且不能把该示例视为对全部 Pi 工具的保护。

## World 当前实现的具体缺口

本地检查基线为 World 提交 `b70c853` 及当前工作树。

| 代码位置 | 当前行为 | 集成工作 |
| --- | --- | --- |
| `crates/world-runtime/src/silo.rs` | macOS 使用 DYLD 注入；拒绝 SIP 路径与 shebang 脚本；检查启动注入确认 | 识别 npm 脚本入口与原生程序，验证 Agent → shell → sandbox helper → 子进程整条链；顶层确认不能证明所有子进程仍被注入 |
| `crates/world-runtime/src/linux.rs` | Workspace 持有 network/mount namespace，各次执行进入同一视图 | 检查 Agent 内层 bwrap 是否另建网络或临时目录视图，以及内层进程能否连接前一次执行启动的服务 |
| `crates/world-runtime/src/proxy.rs` | 带 Basic 凭证的 HTTP/CONNECT 白名单代理 | 不能直接等同于 Claude 的外部 HTTP/SOCKS 代理契约；需适配协议、认证与身份，不为兼容移除现有认证 |
| `crates/world-cli/src/main.rs`、`run.rs` | 执行默认期限 5 分钟，最长 24 小时；两种模式的输入约束不同 | 设计交互 Agent 的会话期限、终端与信号行为；不把默认命令执行直接当成长期 Agent 会话 |
| Workspace / forkfs 接入 | 当前绑定已有工作目录，文件系统分支 RPC 尚未落地 | Agent 的直接文件工具、shell 与语言服务必须最终看到同一分支 |

macOS 上经 SIP helper 或系统 shell 启动可能丢失 DYLD 注入，这是需要实测的兼容风险，不是本次已经证明所有 Agent 都失败。当前本机 `codex` 是 Node shebang 入口，已不满足 World 直接执行器的原生文件要求；最终原生二进制或显式解释器也还需验证后续子进程。

已有 `world network exec` 是按命令限制出口的模式，`world exec` 是 Workspace 网络视图模式。不能把两者简单嵌套后宣称所有能力自动相加：内层 namespace、环境清理、代理地址和监听限制都可能改变外层语义。

## 建议接入顺序

1. **能力探测与最小验证**：锁定 Agent 版本、可执行入口、OS 与有效策略，探测本地文件工具、连续两次命令的 localhost、临时目录、子进程继承及退出回收。先形成兼容矩阵，再发布支持声明。
2. **统一生命周期入口**：实现受限 World MCP / 应用服务，固定会话与 Workspace 的绑定。stdio MCP 与远程 MCP 的运行位置分别记录；远程工具若直接操作真实系统，必须经过对应 World 资源适配器才能纳入副作用语义。
3. **两条执行路线**：可信本地开发使用 World 视图并按已验证范围组合 Agent sandbox；需要完整安全隔离时，接入外部容器/VM 或经验证的 sandbox 后端，覆盖整个工作负载。只有外部边界确实满足要求且配置明确时，才考虑让 Agent 避免重复建立冲突的内层沙盒。
4. **工具委派原型**：以 Pi operations 和 OpenCode 自定义工具验证执行器接口；文件工具和执行工具一起路由。Codex/Claude 优先采用文档支持的环境、MCP 与代理入口，暂不假设有可替换全部本地执行的统一插件 API。
5. **服务与副作用扩展**：将网关身份绑定到 Workspace，分别处理允许的出口与分支服务。最后再接入具体业务操作的捕获、提交和恢复。

World 所需的执行契约应包含 `workspace_id`、运行代际、工作目录、文件访问根、环境变量、网络视图、服务映射、执行期限及能力证明；名称和类型仍待设计。安全配置缺失时拒绝严格模式，不能因 Agent 名称或 `WORLD_ID` 存在就认定隔离完成。

## 验收矩阵

以下均为待执行用例，不是本次测试结果。

| 验收项 | 判据 |
| --- | --- |
| 分支一致性 | read/edit/write、搜索、bash、LSP、MCP 所见目标与绑定一致；未纳入的入口明确列出 |
| 持续 localhost | 一次执行启动服务，另一次执行访问成功；两个 World 同端口返回各自数据 |
| 网络策略 | 允许目标可达、禁止目标拒绝；代理实际从正确 World 访问服务，不能误连宿主或其他 World |
| macOS 注入链 | 验证原生入口、Node/Bun、系统 shell、sandbox-exec 及子进程；注入丢失可识别 |
| Linux 嵌套 | 验证 bwrap/userns、私有 `/tmp`、代理 socket 与网络 namespace 的组合，不依赖关闭全局系统限制 |
| Windows 原生 | 分别验证 Codex elevated/unelevated；其他 Agent 明确外部后端；检查 ACL、实际用户、端口、命名管道、终端和进程树回收 |
| WSL2 | 分别验证 NAT/mirrored、Windows 到 Workspace 的服务入口、`/mnt/c`/Linux 路径与 `.exe` 互操作；发行版退出后正确报告失联 |
| 跨 OS 工具一致性 | Windows UI、WSL server、远程 MCP 与文件工具记录真实运行位置，不因 shell 成功就认定所有操作已进入 World |
| 工具覆盖 | Bash 以外的文件工具、hooks、插件、MCP、用户命令分别测试，安全声明限定到已验证范围 |
| 故障与生命周期 | sandbox 初始化失败、进程超时、取消、重连、后代进程清理和 Workspace teardown 有确定结果 |
| 凭证与副作用 | 模型连接和任务出口分开配置；未接入的远程工具不宣称被捕获；重试不重复提交已记录操作 |

只有相应矩阵通过后，才能将某个“Agent 版本 × 宿主/执行平台 × 后端版本 × 执行配置”标为支持。此次调研支持继续复用现有 World 运行时，并新增明确的执行适配层；不支持直接移除已有安全后端，也不支持把任意 Agent sandbox 当作完整 World 环境。
