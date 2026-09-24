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

在确认必须使用原生 macOS 程序、独立 localhost 和应用无需改配置后，进一步找到并采用了 [silo 的动态库拦截机制](https://www.silo.rs/docs/how-it-works)。这为受支持程序提供了透明 localhost 兼容路径；前述“没有通用后端”的结论不应解读为所有透明模拟路径都不存在。

World 已迁移到 Rust，并接入固定版本的 silo-bind 源码；内部使用独立 loopback IP，但应用不需要自行配置这些 IP。World 修改了宿主回退和部分失败处理。使用方法、实际验收与兼容边界见 [macOS 网络运行时](macos-network-isolation.md)。

该实现仍不提供任意程序、任意系统调用和恶意代码的完整内核隔离。强隔离要求保留，不能仅以受支持开发程序的同端口测试通过就将完整受管执行标为完成。
