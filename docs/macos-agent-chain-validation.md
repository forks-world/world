# macOS Agent → Silo 链路实测

日期：2026-10-07。状态：已完成无需管理员权限的入口与子进程探测；完整双 Workspace 网络测试等待 loopback alias 配置。不能将本页结果标为完整链路通过。

## 环境与范围

- macOS 27.0.1，build 26A434，arm64。
- World 基线 `b70c853` 与当前工作树，重新构建 workspace 和 examples 成功。
- Claude Code 2.1.292，原生签名程序。
- OpenCode 1.18.35，原生程序。
- Node v26.10.0。
- Codex npm 入口存在，但引用的原生二进制缺失，`--version` 返回 `spawn ... ENOENT`；本次无法测试 Codex 执行链。
- PATH 中无 Pi，`/opt/homebrew/bin/bash`、`/opt/homebrew/bin/zsh` 不存在。

没有修改 Agent 安装、签名、用户配置或关闭 SIP，也没有发起模型请求。工作目录使用独立测试目录。

## 已执行结果

| 探测 | 结果 | 能证明什么 |
| --- | --- | --- |
| 普通启动 Claude / OpenCode | 均可打印版本 | 安装入口可运行 |
| 向 Claude 注入 Silo 后执行 `--version` | 退出 0，但 ACK 文件为空，无动态库加载日志 | 当前 Claude 程序的这条启动路径没有确认注入，不能当作支持 |
| 向 OpenCode 注入 Silo 后执行 `--version` | 退出 0，ACK 为 `world-silo-v1`，有加载日志 | 仅证明该入口加载动态库，不证明其工具链兼容 |
| 注入后的 Node 启动 `/bin/sh`、`/bin/bash`、`/bin/zsh` | 三者均返回 `EACCES` | 本机系统 shell 子进程链被 Silo 拒绝 |
| 注入后的 Node 启动 `/usr/bin/sandbox-exec` | 返回 `EACCES` | 这条直接调用系统 sandbox helper 的链路不可用 |
| 注入后的 Node 启动另一个同路径 Node | 子进程退出 0、输出标记，并记录子进程加载日志 | 受支持的原生子进程能够继承注入 |
| `world exec A ... claude --version` | 拒绝：workspace loopback alias 未配置 | 尚未进入 Agent 启动阶段；不能与直接注入结果混淆 |

直接注入探测采用本项目现有测试同样的动态库环境：`DYLD_INSERT_LIBRARIES`、`SILO_IP`、`SILO_CONNECT=1`、`WORLD_SILO_ACTIVE=1`、`WORLD_SILO_ACK`、`WORLD_TMP`、`TMPDIR`。使用未分配地址 `127.77.254.254`，因此只测加载及子进程，不据此验证服务可达性。每个顶层探测有独立空 ACK 文件；子进程另有加载日志。探测有超时与进程组清理。

Claude 的 codesign 检查显示 Hardened Runtime 已启用，包含 `disable-library-validation`，未包含 `allow-dyld-environment-variables`。这与未加载现象一致；尚未通过改变签名做因果对照，不将其写成唯一已证明原因。OpenCode 的签名包含上述 DYLD entitlement。Apple 分别说明了 [DYLD entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) 和 [SIP 对受保护进程的环境清理](https://developer.apple.com/library/archive/documentation/Security/Conceptual/System_Integrity_Protection_Guide/RuntimeProtections/RuntimeProtections.html)。

当前 World 在执行前要求 alias 可绑定，在执行后检查 ACK；ACK 缺失会报告 `localhost isolation was not confirmed; this executable is unsupported`。这一失败处理由代码核对，尚未在本机通过完整 `world exec` 路线重现 Claude 的 ACK 失败。

另外执行并通过三个已有回归用例：

```sh
python3 -m unittest \
  tests.test_runtime.CLI.test_shim_injection_and_no_host_fallback_without_alias \
  tests.test_runtime.CLI.test_child_script_cannot_drop_injection \
  tests.test_runtime.CLI.test_shebang_preserves_interpreter_and_arguments -v
```

它们验证无 alias 时不回退宿主、子脚本不能丢失注入、解释器与参数处理；不替代真实 Agent 工具调用测试。

## 待完成的完整链路

本机 `lo0` 只有默认地址，`sudo -n true` 返回需要密码。已创建独立注册表与 A/B 工作目录，地址为 `127.77.0.1`、`127.77.0.2`；尚未修改网络接口。管理员配置这两个 alias 后，可继续：

1. 通过真正的 `world exec` 重测 Claude/OpenCode 入口与 ACK。
2. 在 OpenCode server 的真实 session shell 接口执行无害命令，观察默认 shell 的选择与错误；该接口允许不经模型直接调用，[官方 Server API](https://opencode.ai/docs/server/)。Node 子进程探测不能冒充这一步。
3. 若默认 shell 可执行，则启动开发服务，再以第二次独立工具调用访问相同 localhost 端口。若失败，记录首个失败边界，再单独评估非 SIP 工具链；不更改用户现有安装。
4. A/B 同端口返回各自标记；停止 A 不影响 B；检查宿主回退、临时目录、子进程与超时清理。
5. 区分持续运行的 Agent 会话与单次 `world exec`：命令退出后的进程回收会影响后台服务生命周期，不能仅以后台 `&` 启动成功认定跨调用服务可用。

本机临时证据目录：`/Users/hurricane/Library/Caches/world-chain-jkqh330l`。其中保存注入结果、二进制路径及 SHA-256、入口失败结果和独立注册表；保留用于继续测试，不作为仓库长期依赖。

## 当前判断

Silo 可保留为受支持原生服务的轻量视图后端，但本机证据不支持把它设为任意 Coding Agent 的默认透明包装器。当前 Claude 的入口注入与系统 shell/helper 链均存在实际阻碍；OpenCode 只完成入口确认。完整 localhost、真实 Agent shell 与双 World 验收仍待上述条件满足后继续。

## 2026-10-08：Claude 注入失败原因复核

结论限定为本机 Claude Code 2.1.292：加载阶段没有采用 `DYLD_INSERT_LIBRARIES`。Hardened Runtime 已开启且缺少 DYLD entitlement，是与 Apple 文档及对照结果一致的主要解释；不是已经运行的 Silo socket 拦截逻辑失败，也不是 Claude Bash sandbox 才开始拒绝操作。

使用一个独立 C 动态库，只在 constructor 中向 stderr 写入 `WORLD_DYLD_PROBE_LOADED`，不包含 Silo、网络、ACK 或路径重定向。Python 直接启动目标程序并传入环境，未经过额外 shell。三种程序各执行三组 `--version`：

| 程序 | 不注入 | 注入最小 dylib | 指定不存在的 dylib |
| --- | --- | --- | --- |
| Claude Code 2.1.292 | 退出 0 | 退出 0，无 constructor 标记 | 退出 0，没有缺库报错 |
| OpenCode 1.18.35 | 退出 0 | 退出 0，有 constructor 标记 | dyld 缺库报错，SIGABRT |
| Node v26.10.0 | 退出 0 | 退出 0，有 constructor 标记 | dyld 缺库报错，SIGABRT |

这组实验把故障边界缩小到动态加载策略：即使移除全部 Silo 逻辑，Claude 仍不加载；指定无效库路径也没有触发加载错误。它不依赖 loopback alias 或管理员权限。临时源码与九组结果保存在 `/private/tmp/world-dyld-cause-gdep5ylo/`。

### 两项 entitlement 的区别

| 签名配置 | 控制内容 | 本机 Claude | 本机 OpenCode |
| --- | --- | --- | --- |
| `com.apple.security.cs.allow-dyld-environment-variables` | 允许 DYLD 环境变量影响加载行为 | 未声明 | true |
| `com.apple.security.cs.disable-library-validation` | 放宽被加载库的签名来源限制 | true | true |

允许加载第三方库，不等于允许通过启动环境强制注入第三方库。规则依据 Apple 的 [Allow DYLD Environment Variables](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) 与 [Disable Library Validation](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.disable-library-validation)。公开 [dyld 源码](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp) 也展示根据 AMFI 策略处理/清理环境的流程；该 main 源码用于解释机制，不等同于本机 dyld 版本的逐行验证。

签名检查使用 `codesign -d --entitlements -`；旧 `:-` 写法已被工具提示弃用。本轮 `codesign --verify --verbose=2` 另报告本机 Claude `invalid signature (code or signature have been modified)`，原因尚未查明，不能据此断言官方发布包损坏，也不能将本机样本推广到所有安装。Claude、OpenCode、Silo 的 SHA-256 均与 10 月 7 日保存值一致；本次未修改或重签名它们。该异常限制了“唯一签名原因”的确定性，但不改变上述加载对照的实测结果。

### 对接入方案的含义

- 切换 Claude 的 Bash sandbox 设置发生在应用启动之后，不能补上加载器阶段缺失的注入许可。
- 仅换成非 SIP shell、修改 PATH 或用启动脚本包一层，也不会改变 Claude 原生程序的签名权限；shell 兼容是后续独立问题。
- 在 Silo 动态库内增加 hook 无法修复“库根本未被加载”。World 可以增加启动前诊断，ACK 仍应作为运行时检查；本轮未改运行时。
- 若要继续透明注入，需要发行方提供允许该加载方式的构建，并重新验收工具链。本次未通过重签名、修改受保护安装或关闭系统安全机制来强行通过。
- 更实际的候选是 Claude 使用 World 分支目录，受支持的开发服务由 World/Silo 启动，并显式配置服务地址；或选择覆盖整个工作负载的独立执行环境。只把个别 Bash 调用送入 World 不代表 Read/Edit、MCP 等入口都被绑定。

以上只完成注入原因调查，未补全前述双 Workspace 网络验收。
