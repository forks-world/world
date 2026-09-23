# macOS 原生进程的同端口隔离

任务必须运行 macOS 原生程序。当前按宿主原生进程评估，不将 Linux VM 当作实现路径；也未获得采用 macOS VM 的范围确认。

目标是不同 World 使用相同端口、在各自 World 内监听和连接。还需区分两个接口要求：应用是否必须无需修改地使用 `localhost`，或允许每个 World 使用不同的显式 IP。此前设计将目标进一步解释为独立 `localhost`，这项解释需要与用户确认。

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

## 下一步的范围选择

如果允许显式配置地址，可以研究每个 World 分配独立 IP，应用绑定和连接该 IP 的相同端口。此时必须明确约束通配地址监听，并另外实现和验证跨 World 访问拒绝；仅分配不同 IP 不构成安全隔离，也不提供独立 `localhost`。该路径尚未实现、尚未验收。

如果必须保持独立 `localhost` 和任意程序零修改，则现有宿主原生方案不能宣称完成该目标。PR 保持 draft，不用现有出站限制测试替代同端口隔离验收。
