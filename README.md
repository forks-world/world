# World

World 是面向多个 Network 的管理控制面，负责 CLI、付费管理、元信息管理和 Network 隔离。

World 管理资源的归属、配置、访问权限与付费权益；具体资源的运行和网络规则执行交给 Network 对应的运行环境。

World 同时面向开发者和 Coding Agent：开发者通过 CLI 操作，Agent 通过 Skill 学习工作流程，并通过 MCP 调用结构化工具。两种入口共享 World API 的权限、付费和隔离规则。

forkfs 是 World 首批直接管理的资源：World 通过 forkfs RPC 服务管理 Snapshot 与 Workspace 的初始化、fork、checkpoint、diff、discard/restore 和 GC。forkfs 承载本地文件数据，World 管理归属、授权和执行；Network 网络隔离由 World 的运行环境层补充。

## 核心职责

| 职责 | 内容 |
| --- | --- |
| CLI | 登录、选择上下文、管理 Network、资源元信息及付费信息 |
| Skill + MCP | 为 Coding Agent 提供操作流程、结构化工具、异步操作跟踪与错误恢复 |
| 付费管理 | 套餐、订阅、权益、配额、用量与账单引用 |
| 元信息管理 | 资源标识、归属、类型、标签、配置版本与生命周期 |
| Network 隔离 | 权限、数据、凭证、任务和运行时访问边界 |
| forkfs 控制 | Snapshot / Workspace 生命周期、差异、回收及受管执行 |

组织是付费与成员管理单位；Network 是组织内部的资源隔离单位。资源属于唯一的 Network，跨 Network 访问必须显式授权。

完整设计见 [World 架构设计](docs/world-design.md)，包含职责边界、领域模型、CLI/API、Skill + MCP、隔离机制及分阶段实现计划。

forkfs RPC 服务是待实现的接入契约，World 不链接 forkfs 库，也不通过解析 CLI 输出控制它。

当前仓库处于设计阶段，文档中的命令与接口均为拟议规格，尚未实现。
