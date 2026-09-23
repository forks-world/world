# macOS 原生进程的同端口隔离

已确认的硬性要求：宿主 macOS 原生执行，每个 World 拥有独立的 `localhost`，不同 World 能使用相同地址和端口独立监听与连接，应用无需修改。

同一 World 的多个进程及多次 `exec` 必须共享其网络栈。用户已明确拒绝以不同显式 IP 和应用地址配置替代独立 `localhost`。VM、修改应用地址、端口重映射配置和代理配置均不能作为满足这些要求的交付物。

## 本机实测

2026-09-23，在 macOS 27.0（26A428）、arm64 上使用两个独立的 `/usr/bin/sandbox-exec` 进程测试。两份 profile 都允许网络访问，包含不同的 World 标记；测试没有修改宿主网络配置。

1. A 绑定 `127.0.0.1` 的一个临时 TCP 端口并持续监听；B 绑定相同地址、相同端口。B 返回 errno 48：`Address already in use`。
2. A 与 B 都启用 `SO_REUSEADDR`、`SO_REUSEPORT` 后绑定同一地址和端口，两个监听均成功。
3. 分别从 A profile 和 B profile 启动客户端，两个客户端在这次测试中均收到 B 的服务标记。复用选项没有根据 World 决定连接归属，不能当作 World 隔离。

这些结果证明现有 Seatbelt 方案没有提供所需端口命名空间；不能把一次测试扩大解释为已经排除所有定制内核或受限应用适配方案。

## 可用机制的边界

- **Seatbelt**：约束宿主网络操作的权限，不给每个 World 创建独立的套接字地址空间。macOS 本机 `bind(2)` 手册和 [Apple XNU 的绑定实现](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/in_pcb.c) 均体现地址冲突检查；上述实验验证了本机行为。
- **`SO_REUSEPORT`**：允许多个套接字重复绑定，不包含 World 身份路由与访问控制；不能用来满足独立服务语义。
- **Network Extension 透明代理**：公开接口处理连接的数据流，不提供独立的 `bind/listen` 命名空间。不能仅靠增加透明代理解决监听时已发生的地址冲突。依据：[Apple 流复制说明](https://developer.apple.com/documentation/networkextension/handling-flow-copying)及本机 SDK 的 `NETransparentProxyProvider.h`、`NEAppProxyTCPFlow.h`。
- **动态库注入/函数替换**：对可控应用可以研究地址重写，但不能承诺覆盖任意 macOS 程序。系统保护会限制受保护进程的动态链接器环境变量及注入行为；应用自身的代码签名策略也可能阻止加载。依据：[Apple 运行时保护说明](https://developer.apple.com/library/archive/documentation/Security/Conceptual/System_Integrity_Protection_Guide/RuntimeProtections/RuntimeProtections.html)。这类兼容层也不能直接冒充安全隔离边界。

基于目前核对的公开机制与本机实验，尚没有可交付的“宿主原生执行、任意程序无需修改、每个 World 独立 localhost”通用后端。

## 实现状态

当前实现被底层能力缺口阻塞，尚未完成独立网络栈后端。需求已经明确，不再将状态描述为等待用户选择操作系统或是否接受不同 IP。

继续实现需要先证明一个满足上述约束的原生机制，尤其是独立 `bind/listen` 语义、按 World 路由的 `connect`、子进程继承和不可跨 World 访问。受限程序的注入实验不能自动证明对未修改应用的通用兼容性或安全隔离。

PR 保持 draft，现有出站限制测试不能替代同端口隔离验收，也不能作为将该功能标为完成的依据。
