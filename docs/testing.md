# Fuzz / 压力测试

World 的 `world exec` silo 透明重写受支持程序对 `/tmp`、`/var/tmp` 的访问，把宿主临时目录替换成按 Workspace 隔离的私有目录。这一层改写面广、边界情况多，仅靠手写用例难以覆盖，因此在单元测试之外补充四层自动化测试。

## 概览

| 层 | 内容 | 位置 |
| --- | --- | --- |
| 1. 纯函数属性 / 模型对拍 | `world-tmp-path` 路径改写的 proptest 属性测试；`world-fsmodel` 内存文件系统模型与其自身不变量的对拍 | `crates/world-tmp-path/src/model_props.rs`、`crates/world-fsmodel/` |
| 2. shim 差分 fuzz | 随机文件系统操作序列，比较经 silo 的物理执行结果与 `world-fsmodel` 虚拟视图 | `crates/world-cli/examples/fuzz_driver/`、`tests/test_fuzz.py` |
| 3. 压力与并发 | 多 Workspace/多进程并发下的资源竞争、锁存活性、长时间 soak | `crates/world-cli/examples/stress_probe/`、`tests/test_stress.py` |
| 4. CI | PR 上跑小预算冒烟，夜间跑大预算 fuzz/stress 并保留失败现场 | `.github/workflows/test.yml`、`.github/workflows/fuzz.yml` |

## 核心判据

差分 fuzz 和压力测试共用同一个等价判据：

> 经 silo 重写后，对私有临时目录执行一系列文件系统操作得到的**物理结果**，必须等于把 `/tmp`（以及 `/var/tmp`）替换为该私有目录后、直接对同一目录树执行同一操作序列得到的**虚拟视图**（`world-fsmodel`）；且整个过程中**宿主真实 `/tmp` 不发生任何变化**。

任何一次不等价、或宿主 `/tmp` 被意外写入，都判定为失败并保留现场（种子、操作序列、双方文件树快照）。

## 如何本地运行

### Layer 1：属性测试与模型对拍

```sh
cargo test -p world-tmp-path
cargo test -p world-fsmodel --test conformance
```

环境变量：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PROPTEST_CASES` | proptest 默认（256） | `world-tmp-path` 每条属性生成的用例数；CI 夜间设为 `100000` |
| `WORLD_FSMODEL_CASES` | 未设置时用测试内置的小规模值 | `world-fsmodel` conformance 测试的随机用例数；CI 夜间设为 `2000` |
| `WORLD_FSMODEL_ESCAPING_LINKS` | 关闭 | 打开后生成器会构造指向私有根之外的符号链接，用于单独验证越界检测（默认关闭以避免掩盖其他失败） |

失败会在 `crates/world-tmp-path/proptest-regressions/` 下落一个回归用例文件；这个文件要提交进仓库，之后每次跑测试都会重放它。

### Layer 2：shim 差分 fuzz

```sh
python3 -m unittest tests.test_fuzz -v
```

环境变量：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `WORLD_FUZZ_BUDGET` | `10`（秒） | **每个 fuzz 测试类**各自的时间预算（不是整次运行的总预算）；夜间 CI 在 macOS 上 `ShimFuzz` 用 `1200`、`PrivilegedExecFuzz` 用 `900`，Linux 用 `1800` |
| `WORLD_FUZZ_SEED` | 随机 | 固定后可复现同一操作序列 |
| `WORLD_FUZZ_OPS` | `40` | 单个操作序列的步数 |
| `WORLD_FUZZ_ARTIFACTS` | `target/fuzz-artifacts` | 失败现场（种子、操作序列、双方快照）的落盘目录 |

三个测试类分别覆盖不同后端：`ShimFuzz`（macOS，无需特权）、`LinuxFuzz`（Linux，经 `world exec`）、`PrivilegedExecFuzz`（macOS，需要 `WORLD_SILO_INTEGRATION=1`，会真实添加/删除 loopback 别名）。默认只跑无需特权的部分。只跑特权那一类：

```sh
WORLD_SILO_INTEGRATION=1 python3 -m unittest tests.test_fuzz.PrivilegedExecFuzz -v
```

注意预算是按类计的：一个 job 里跑 N 个 fuzz 类，总耗时约为 N × `WORLD_FUZZ_BUDGET` 加上构建、语料重放、minimize 与清理（约 25 分钟）。所以 job 的 `timeout-minutes` 必须满足 `WORLD_FUZZ_BUDGET ≤ (timeout − 25 分钟) / N`；macOS `shim-diff`（75 分钟、2 个类）上限为 1500 秒。

### Layer 3：压力与并发

```sh
python3 -m unittest tests.test_stress -v
```

默认是冒烟档位（约 20 秒）。完整档位：

```sh
WORLD_STRESS=1 WORLD_STRESS_SCALE=4 python3 -m unittest tests.test_stress -v
```

`WORLD_STRESS_SCALE` 是并发数/迭代数的整数倍数。`stress_probe` 会在写任何东西之前先做 `verify_redirected`：`/tmp` 必须确实被重定向到私有根（macOS 用 `WORLD_TMP`，Linux 经 `world exec` 时由测试通过 `STRESS_PROBE_PHYSICAL_ROOT` 传入），否则以 `not running redirected` 退出 2（失败即拒绝，`StressProbeRefusesUnredirected` 覆盖）。所有工作线程都按总期限 join，超时或异常会被记录并使测试失败，而不是让线程悄悄退出。`test_network_soak` 额外需要 `WORLD_SILO_INTEGRATION=1` 且 `WORLD_STRESS=1` 才会运行。macOS 上超时会用 `sample` 抓取卡住进程的调用栈存进 `target/fuzz-artifacts`；Linux 有专门的持有者竞争（holder race）测试。

## 失败复现

1. 从失败输出或 CI 产物里取到种子（`WORLD_FUZZ_SEED`）和落盘的操作序列。
2. 用同一个种子重放：

   ```sh
   WORLD_FUZZ_SEED=<seed> python3 -m unittest tests.test_fuzz -v
   ```

   或者直接驱动 `fuzz_driver` 二进制做单步调试：

   ```sh
   cargo run -p world-cli --example fuzz_driver -- replay <artifact-file>
   cargo run -p world-cli --example fuzz_driver -- minimize <artifact-file>
   ```

   `replay` 精确重放一次失败的操作序列；`minimize` 在保持失败的前提下缩短操作序列，便于定位。
3. Layer 1 的 proptest 失败会在 `crates/world-tmp-path/proptest-regressions/` 生成回归文件，直接提交进仓库即可保证之后不再回归。
4. 长期有价值的 Layer 2 失败序列可以整理进 `tests/fuzz-corpus/`，作为固定回归语料，每次运行都会重放，不依赖随机种子命中。

## CI

- `test.yml`（PR + push main）：`WORLD_FUZZ_BUDGET=10`，只跑冒烟档位，目标是几分钟内给出信号；另有一步 `! grep -rn 'process::exit' crates/world-fsmodel/tests`，禁止在测试线程里直接 `process::exit`；失败时上传 `target/fuzz-artifacts` 和 `**/proptest-regressions`。
- `fuzz.yml`（每日 03:17 UTC 定时，也支持手动触发并指定 `seed`/`budget`，`budget` 的含义是每个 fuzz 类的秒数，留空使用各 job 的默认值）：大预算跑 Layer 1（`PROPTEST_CASES=100000`、`WORLD_FSMODEL_CASES=2000`，release 构建）、Layer 2（macOS `shim-diff` 75 分钟：`ShimFuzz` 1200 秒，再单独跑 `PrivilegedExecFuzz` 900 秒；Linux 60 分钟：1800 秒一个类）、Layer 3（`WORLD_STRESS=1`、`WORLD_STRESS_SCALE=4`，macOS 额外跑特权 soak）。每个 job 失败时上传产物，macOS job 结束时无论成败都会清理残留的 `127.77.*` loopback 别名和残留的 `wt-*` 私有临时目录。

## 已知限制

shim 是用户态的透明改写，以下情况文档化为已知缺口，不在判据覆盖范围内：

- 绕过 libc 直接发起的原始 syscall。
- `F_GETPATH`（以及等价的路径反解 API）可能拿到改写前后不一致的路径。
- 执行前就已存在、指向宿主临时目录的符号链接不会被回溯改写。
- 私有根内部的相对符号链接，如果逐级 `..` 能越出私有根，行为未定义（生成器不会主动构造这类链接，`WORLD_FSMODEL_ESCAPING_LINKS` 可单独打开验证）。
- APFS 大小写不敏感：用例生成器只使用小写 ASCII 文件名，不覆盖大小写折叠相关的路径冲突。
- 需要真实内核 namespace 或需要 root 的部分（Linux 持有者竞争、macOS 特权 loopback）本地未必能跑，只在 CI 里保证覆盖。
- 整条路径长度上限：模型按各 profile 的 `PATH_MAX`（mac 1024、Linux 4096，含结尾 NUL，即长度 `>=` 上限时 `ENAMETOOLONG`）判定；执行端会先对整条路径做同样的检查（因为它只把拆开后的父目录和末尾名字交给 syscall）。shim 自己的限制不建模：私有根前缀 + 子目录 + 剩余路径长度 `>= PATH_MAX` 时 shim 返回 `ENAMETOOLONG`，因此 `/tmp`、`/var/tmp` 下的绝对路径实际上限是 `PATH_MAX` 减去私有根前缀长度（`/private/...` 拼写再多几个字节），符号链接目标同理。macOS 的 `namei` 在跟随链接时还会在“链接内容长度 + 剩余路径长度 `>= MAXPATHLEN`”时返回 `ENAMETOOLONG`，Linux 没有这条规则，模型同样不建模。生成器的文件名 1-4 个字符、嵌套不超过约 8 层，生成的路径长度远小于 512 字节（debug 构建下有断言），所以这些缺口不会被生成器触发。
