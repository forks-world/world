# 其他 Coding Agent 与 World 整合调研

核查日期：2026-10-07。本文逐项调查 Cursor、Copilot CLI、Copilot cloud agent、Gemini CLI、Cline、OpenHands、Devin、Cascade、Kiro、Aider。Codex、Claude Code、OpenCode、Pi 见 [原调研](agent-sandbox-integration.md)。这是官方文档与公开工程说明的调查，没有安装或运行这些产品的集成测试，也不是市场份额排名。

以下区分官方已描述的能力、World 的接入建议，以及仍待验证的部分。动态文档可能先于实际安装版本；接入时必须固定版本、产品入口、后端和有效配置。“未找到内置 OS sandbox 的证据”不等于证明产品没有任何保护。

## 跨平台总览

表格描述任务执行环境，不能仅根据桌面客户端的 OS 判断。容器列指本文核对的 Linux 镜像；在 macOS/Windows 上启动这种容器，并不获得原生 Xcode/Windows 工作负载能力。来源与限制见各工具章节。

| 工具 / 入口 | Linux 执行 | macOS 执行 | Windows 原生执行 | WSL2 路线 | World 首选接入口 |
| --- | --- | --- | --- | --- | --- |
| Cursor 本地 Agent / CLI | 工程说明：Landlock + seccomp | Seatbelt | 所核对工程说明将沙盒放在 WSL2；未确认更新的原生后端 | Linux sandbox；需区分 IDE 文件工具位置 | CLI 环境绑定；另评估自托管 Cloud Agent worker |
| Copilot CLI | bubblewrap | Seatbelt | 近期 Windows 11：ProcessContainer 的 BaseContainer 层 | Linux 路线，依赖与内核需验收 | CLI + 现有 sandbox；单独适配代理 |
| Copilot cloud agent | Ubuntu x64 Actions runner | 官方不支持 macOS runner | 支持 Windows 64-bit runner | 不作为独立支持承诺 | 一次性自托管 runner |
| Gemini CLI | Docker/Podman；可选 runsc、实验性 LXC/LXD | Seatbelt 或 Linux 容器 | 文档列出原生 sandbox，但机制说明不完整 | Linux 后端，逐项探测 | 先验证容器；再验证原生工具沙盒 |
| Cline | 本地执行或 SSH helper | 本地执行；Mac 客户端可连 Mac helper | 本地入口；Desktop SSH 不支持 Windows 远端 | Linux helper 候选，未验收 | 远端 helper、SDK 执行器 / spoke |
| OpenHands SDK | Linux agent-server 容器 | Linux 容器 / 远端；未确认原生 Mac sandbox | Linux 容器 / 远端；未确认原生 Windows sandbox | Linux daemon/server，未验收 | World 管理 agent-server 与 workspace 生命周期 |
| Devin Cloud / Outposts | Linux VM；Linux worker | macOS VM；Apple Silicon worker | Windows VM 限量开放；Windows x64 worker | 非必要路线，未单独确认 | Outposts 自托管 worker |
| Cascade | 本地 IDE 工具；未核实 OS sandbox | 同左 | 同左；不能套用 Devin Cloud VM 能力 | 需确认实际执行端 | 分支目录 + MCP；完整工具环境绑定待验证 |
| Kiro IDE / CLI / Web | 本地权限策略；Web 为云端环境 | 本地权限策略；Web 为云端环境 | CLI 文档有原生 Windows 路径与 shell；OS sandbox 未核实 | Linux CLI 候选，未验收 | 本地 CLI 环境绑定；Web 单独接资源服务 |
| Aider | 本地 Python 进程或 Linux 容器 | 本地进程或 Linux 容器 | 本地进程或 Linux 容器后端 | Linux 本地/容器路线，未验收 | CLI / 脚本整体运行于 World 环境 |

## 1. Cursor Agent / CLI

**已核实。** 2026-02-18 的官方工程文章描述 macOS Seatbelt、Linux Landlock + seccomp，以及 Windows 通过 WSL2 运行 Linux sandbox。Linux 文件隐藏还涉及 overlay 视图。因此不能把 Cursor Linux 当成 Claude 的 bubblewrap 实现，也不能把文章中的 WSL2 路线写成原生 Windows sandbox。[工程说明](https://cursor.com/blog/agent-sandboxing)

当前运行模式文档区分执行审批与 sandbox 策略：Auto-review 下部分允许规则匹配的调用可在 sandbox 外执行，失败后的扩大权限路径也需考虑。配置了命令 sandbox 不证明 MCP、文件工具和所有辅助进程都在同一边界内。[运行模式](https://cursor.com/docs/agent/security/run-modes)

Cloud Agent 另有 Cursor 托管 Ubuntu VM 与自托管 Machines / Team Pools；自托管时工具调用在用户硬件执行，Agent loop 仍在云端。机器的隔离与生命周期由部署方负责。[运行位置选择](https://cursor.com/docs/cloud-agent/self-hosted/choose-runtime)

**World 建议。** 本地先验证 CLI 对分支目录、服务地址和子进程的继承；自托管路线则由 World 为任务准备 worker 环境。不能只在 World 中启动 IDE 客户端，就假定已有后台进程也迁入。

**首个验收。** 文件编辑与 shell 读到同一分支；两个会话同端口服务互不混淆；审批后扩大权限仍保持 World 状态绑定。Windows 单独记录 IDE、文件工具与 shell 各自的 OS。最新 Windows 原生后端是否已有变化仍需安装版本验证。

## 2. GitHub Copilot CLI

**已核实。** 当前本地 sandbox 属预览能力：macOS 使用 Seatbelt，Linux 使用 bubblewrap，近期 Windows 11 使用 ProcessContainer 的 BaseContainer 层，不采用 AppContainer 回退。CLI 遇到不支持的宿主可关闭当次 sandbox；企业强制策略下则拒绝执行。World 必须检查实际启用状态。[平台与失败行为](https://docs.github.com/en/copilot/concepts/security-governance-and-network-settings/about-cloud-and-local-sandboxes)

同一文档还明确代理差异：macOS 依赖程序遵守代理环境变量；Linux 在私有 network namespace 中强制经代理，代理 URL 不接受凭证；Windows CLI 暂不支持代理和 denied paths 配置。不能直接复用 World 带 Basic 认证的代理地址，也不能将三个平台视作同等出口保证。

CLI 的 `--cloud` 是另一条预览路线，在 Azure Container Apps Sandboxes 的临时 Linux 环境运行；它与下一节基于 Actions 的 cloud agent 是不同执行产品。[CLI 入口](https://docs.github.com/en/copilot/concepts/copilot-surfaces/copilot-cli)

**World 建议。** 优先本地 CLI，保留原生 sandbox 并验证嵌套网络。远程 MCP 可接生命周期，但不会迁移命令执行。严格配置下拒绝上游退回无 sandbox 的会话。

**首个验收。** Linux 连续命令访问同一 World 服务；macOS 忽略代理变量的程序也符合所声明策略；Windows 在准确 build 上检查有效限制。模型连接、任务出口和本地 MCP/LSP 的执行位置分别记录。

## 3. GitHub Copilot cloud agent

**已核实。** 执行环境由 GitHub Actions 提供，默认 Ubuntu，可选自托管 runner 和 Windows 64-bit runner；官方明确不支持 macOS runner。仓库的 `copilot-setup-steps.yml` 可配置准备步骤、runner 和服务。文档建议一次性 runner；准备步骤失败后 Agent 仍可能继续工作。[环境配置](https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/customize-cloud-agent/customize-the-agent-environment)

**World 建议。** 将一次性自托管 runner 作为执行适配目标：在任务领取前完成 World 准备，绑定 runner 工作目录、分支服务及出口策略，结束时收集 diff 并回收。仅在 setup step 中执行一次 `world exec` 不能改变后续 Agent 的进程环境。也不能把 setup 失败当作可靠的阻止执行机制。

**首个验收。** checkout、Agent 编辑、测试和提交都使用 World 分支目录；取消任务后 runner 与子进程全部退出；GitHub 上的 push/PR 操作按独立外部副作用处理。本地状态 discard 不会撤销已发送的 GitHub 操作。Windows 接入仍取决于 World 尚未实现的原生后端。

## 4. Gemini CLI

**已核实。** 官方列出 macOS Seatbelt、Docker/Podman、Windows Native Sandbox、Linux gVisor/runsc 与实验性 LXC/LXD。sandbox 需按开关与设置启用；还区分工具级隔离与完整 CLI 进程隔离。Windows 章节仅明确 `icacls` 的 Low Mandatory Level 及其持久化影响，对网络、token、进程回收的说明不足，不能补猜成完整实现。[Sandbox 文档](https://geminicli.com/docs/cli/sandbox/)

**World 建议。** 首先验证可配置镜像的容器路线，让代码挂载、服务网络与生命周期由 World 统一准备。原生路线分别验证 Seatbelt 与 Windows 文件权限副作用；Linux runsc/LXC 作为不同能力后端记录。切换工具级/进程级模式会改变凭证和辅助工具的所在位置，需要重新验收。

**首个验收。** 文件工具与 shell 使用相同分支；动态扩大权限不改变 World 身份；临时服务跨工具调用可达；Windows 丢弃分支后不在宿主原目录留下意外的完整性级别变更。文档与具体发布版是否一致仍待代码和运行测试。

## 5. Cline

**已核实。** 当前 SDK 分 hub、spoke、client：spoke 执行 Agent，hub 管理会话，CLI/IDE 可只是客户端；能力请求还可能委派回具备能力的客户端。`auto` 模式可在找不到兼容 hub 时回退到本地进程，普通进程分离不是 OS 安全沙盒。[架构](https://docs.cline.bot/sdk/architecture/hub-spoke)

Desktop SSH 将文件操作、命令、Git 和远端 MCP 放在远端 helper 中。文档支持 Linux x64/arm64，Mac 客户端可连接 macOS；不支持 Windows 远端。模型凭证会经隧道传给远端会话。[SSH 执行](https://docs.cline.bot/usage/cline-desktop-ssh)

SDK 生产指南建议自行实现受限工具执行，没有证明默认附带覆盖所有平台的 OS sandbox。其示例中的命令字符串过滤与占位执行函数也不能当作安全后端。[生产指南](https://docs.cline.bot/sdk/guides/going-to-production)

**World 建议。** 优先让远端 helper 或 SDK 执行进程进入 World 对应环境，明确 hub/spoke 的会话与目录绑定；同时约束可能返回客户端执行的能力。SSH 本身只提供连接与身份，不创建 World 隔离。

**首个验收。** 客户端退出、重新附着后仍是原 World；hub 自动发现不会连到另一个环境；严格模式禁止回退本地；远端 MCP 和客户端委派操作的真实位置可审计。

## 6. OpenHands

**已核实。** 当前 SDK 的 `DockerWorkspace` 创建 agent-server 容器、等待就绪并管理清理，远程会话通过 WebSocket 通信；示例镜像平台是 Linux amd64/arm64。因此 Mac/Windows 宿主上的 Linux 容器与原生执行应分开记录。[SDK Docker sandbox](https://docs.openhands.dev/sdk/guides/agent-server/docker-sandbox)

`APIRemoteWorkspace` 展示远端 API 管理环境的路线，但文档说明该 Runtime API 主要用于规模化评测，生产应用另指向 Cloud Workspace。不能把这个示例直接当作稳定的通用生产 provider 契约。[API sandbox](https://docs.openhands.dev/sdk/guides/agent-server/api-sandbox)

旧 GUI 文档还列出 Docker / Remote / Process，Process 不提供容器隔离；这些配置不应不加区分地沿用到 SDK。[旧入口的 sandbox 概览](https://docs.openhands.dev/openhands/usage/sandboxes/overview)

**World 建议。** 优先研究 SDK workspace / agent-server 接入：World 准备分支与服务，再启动 server，绑定会话、日志与销毁。避免仅包装外层 CLI，因为实际工具在容器内。Docker daemon 若在 World 外，创建的容器也不会自动继承调用者的 namespace。

**首个验收。** 两个 server 的挂载、内部服务、发布端口各自独立；重连不创建错误的新 World；server 退出后后台服务被清理。固定 SDK、镜像与协议版本，不依赖浮动 `latest` 验收。

## 7. Devin Cloud / Outposts

**已核实。** Cloud 默认 Linux，也提供 macOS VM；Windows VM 当前限量开放。blueprint 的 `runs-on` 选择平台，Windows 配置可使用 Git Bash 或 PowerShell。macOS 会话睡眠保留磁盘但不保留运行进程，因此快照不等于运行中服务恢复。[macOS](https://docs.devin.ai/onboard-devin/environment/macos-support)、[Windows](https://docs.devin.ai/onboard-devin/environment/windows-support)

Outposts 提供自托管 worker、任务领取/释放 API 和 `devin-remote serve` 启动契约，二进制覆盖 Linux x64/arm64、macOS arm64、Windows x64。官方要求每会话使用独立 state dir，避免默认共享位置造成状态混用。[Outposts reference](https://docs.devin.ai/cloud/outposts/reference)

**World 建议。** 这是明确的执行端接入口：World 编排器领取任务，创建环境，在其内部启动 remote，将 session ID 与 World ID、运行代际及目录绑定。该契约不证明 worker 自带完整 sandbox，外部隔离仍由部署负责。

**首个验收。** sleep、terminate、worker 重连与 claim 释放不会重复启动或串会话；凭证状态目录、仓库及浏览器服务均按会话隔离；Mac 服务恢复重新启动进程。Windows worker 的存在不代表 World 已支持它。

## 8. Cascade（原 Windsurf 文档入口）

**已核实。** 原 Windsurf Cascade 文档当前跳转至 Devin Desktop。文档将 Cascade 定义为本地 Agent，与 Devin Local 和 Devin Cloud 分开；提供文件/终端工具、MCP 与代码 checkpoint。[Cascade 概览](https://docs.devin.ai/desktop/cascade/cascade)

终端的 Disabled、Allowlist、Auto、Turbo 管理命令审批；deny list 在该文档中意味着需要审批，不等于 OS 拒绝执行。所核对页面没有描述可依赖的 Linux/macOS/Windows 内核级 sandbox。[终端权限](https://docs.devin.ai/desktop/terminal)

**World 建议。** 先让 IDE 打开 World 分支并通过 MCP 操作生命周期。完整整合需验证 IDE 后台文件工具、shell、语言服务及浏览器都进入正确执行环境；不能仅替换终端启动命令。也不能用 Devin Cloud VM 的能力填充 Cascade 本地平台矩阵。

**首个验收。** checkpoint/revert 与 World diff 的关系明确：代码恢复不会被展示成数据库或外部操作的回滚。跨平台原生隔离机制与可替换执行器接口仍待核实，暂不承诺安全整合。

## 9. Kiro IDE / CLI / Web

**已核实。** 当前权限文档为 IDE/CLI 提供 capability 的 allow/ask/deny 规则；Web 不使用同一套本地权限 YAML。权限中出现 sandbox/network 字段也不足以证明本地存在某种内核安全后端。[权限](https://kiro.dev/docs/permissions/)

Web 每个任务有隔离云端环境，仓库与浏览器在其中运行，文件状态随会话保留，删除会话会删除环境。本次未核实其底层内核/VM 机制或自定义环境 provider 接口。[Web sandbox](https://kiro.dev/docs/web/sandbox/)

CLI 配置文档已有原生 Windows 的日志路径和 PowerShell 排障说明，应把它与 WSL Linux 进程区分；这仍不能作为 Windows sandbox 的证据。[CLI setup](https://kiro.dev/docs/cli/setup/)

**World 建议。** 本地 CLI 采用整体环境绑定，再补生命周期工具；Web 优先接远端 World 资源服务，不假设能接管其环境创建。原生 Mac/Linux/Windows 分别验证 shell、文件工具与辅助进程，WSL 单列。

**首个验收。** 权限允许执行的操作仍被绑定到正确 World；本地与 Web 的会话切换不会复用错误的服务凭证；明确哪些远程操作不在 World 的副作用管理范围内。

## 10. Aider

**已核实。** Aider 提供本地安装及官方 Docker 镜像。Docker 示例将仓库挂入 `/app`，`/run` 命令在容器内执行。文档中的这种部署方式与普通本地进程不同，未核实本地进程自带 OS sandbox。[安装](https://aider.chat/docs/install.html)、[Docker](https://aider.chat/docs/install/docker.html)

官方提供 CLI 参数和 Python 脚本调用方式，适合 World 做自动化集成；本次不假设它有统一 MCP 或可替换执行器接口。[脚本接口](https://aider.chat/docs/scripting.html)

**World 建议。** 可作成本较低的初始端到端样例：在分支目录中启动整个进程或容器，完成编辑、测试、diff、discard。Git 提交与 World 的文件系统 checkpoint 分别处理；挂载真实宿主仓库仍会直接修改该仓库，Docker 不会自动创建状态分支。

**首个验收。** 自动提交、未跟踪文件、测试生成物都留在正确分支；容器退出后的 diff 完整。Mac/Windows 使用 Linux 镜像时，不能把通过的测试算作原生平台验收。

## 对 World 设计与实现的影响

本轮支持继续采用“World 管状态与服务，执行后端提供安全边界”的目的，但执行适配层至少需要三种接入口：

| 接入口 | 适合对象 | World 必须掌握的内容 |
| --- | --- | --- |
| 整体进程 / 工具委派 | Aider、Gemini、本地 CLI；Cline SDK | 实际执行进程、全部文件工具、子进程和工作目录 |
| 执行 server / worker | OpenHands、Cursor 自托管、Devin Outposts | 准备、就绪、连接、会话绑定、重连、终止与回收 |
| 一次性 runner | Copilot cloud agent | 任务领取前的环境准备、checkout 路径、runner 身份和外部提交 |

MCP 是这些路线共用的生命周期或资源接口，不能替代执行适配。ACP 连接客户端与 Agent，也不自动把所有工具放进 World。Git worktree、代码 checkpoint、VM 磁盘快照均不自动提供数据库一致性或外部副作用回滚。

建议按工程验证价值安排原型，不表示市场优先级：

1. **Aider + OpenHands SDK**：分别验证最简单的完整进程绑定与远端执行 server 契约；与原调研的 Pi/OpenCode 工具委派原型互补。
2. **Gemini + Copilot CLI + Cursor 本地**：验证已有 sandbox 的组合，重点覆盖工具级/进程级隔离、嵌套网络与失败回退。
3. **Cline helper、Cursor 自托管、Devin Outposts、Copilot runner**：验证持久会话、云端控制与本地执行的分离，以及任务领取和清理。
4. **Cascade、Kiro Web 等执行器不明确的入口**：先交付分支目录和受限资源接口，再扩大工具覆盖；Kiro 本地 CLI 可独立先行验证。

实现前应先明确能力记录：`host_os` / `execution_os`、Agent/runtime 版本、实际后端、工具覆盖、路径映射、网络视图、会话代际、启动失败行为和回收契约。World 当前 Linux/macOS 后端仍是起点；WSL2 未验收，Windows 原生后端尚不存在。已有 Silo 注入限制、Linux 嵌套 namespace、代理认证和 CLI 会话期限等缺口继续按 [原调研的验收矩阵](agent-sandbox-integration.md#验收矩阵) 处理。

本次只调整调研与设计文档，不据此关闭现有 sandbox、声称十四项工具已经兼容，或实现未经验证的后端切换。
