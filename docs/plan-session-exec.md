# `session_exec` 工具实施计划

## 目标

新增 MCP 工具 `session_exec`：在**已存在的 PTY session** 中执行一次命令，默认等待 5 秒（可用 `wait_ms` 调整）并返回本次新增输出。等待窗口结束仍未完成时，返回 `timed_out=true`、不取消命令，并返回不透明 `token`；后续以 `session_exec_read(session_id, token)` 获取增量输出及最终退出码。命令运行结束后原 session 仍可继续交互，shell 状态（如当前目录、已导出的环境变量）保留。

该工具不建立新 SSH 连接，不等同于现有基于 SSH exec channel 的 `exec`，也不自动关闭 PTY session。

## 当前实现依据

- MCP 工具注册及 PTY 工具定义在 `src/mcp/mod.rs`。
- `PtyHandle::send_text()` 仅向 PTY 写入文本；`read_new()` 将当前文本缓冲一次性取走，尚无按命令边界收集输出的能力（`src/session/pty.rs`）。
- session 管理由 `src/session/mod.rs` 实现，应用层审计入口位于 `src/state.rs`。
- 现有 `ExecPayload` / `ExecResult` 可供输入类型和结果形状参考，但不能直接调用 `exec()`，因为那会使用独立 SSH exec channel，无法保证在指定 PTY/shell 中执行及保留 shell 状态。
- 工作树检查发现未跟踪项 `C:/`；实施前应先确认来源并保护，不要误纳入提交或清理。本计划不修改该项。

## 建议接口

MCP 工具名：`session_exec`

请求字段：

- `session_id: string`（必填）
- `argv: string[]` 或 `raw: string`（恰选其一；建议首版仅支持 `raw`，或复用现有 `argv`/`raw` 归一化校验）
- `wait_ms: integer`（可选；默认 5000ms，最大 300000ms。仅限定本次等待，不取消远端命令）
- `max_output_bytes: integer`（可选，设默认值和硬上限）

建议首版只接受单行命令，避免把多行脚本的 shell 语法/输入边界隐式扩大；若确需多行脚本，应作为显式字段并单独设计。

响应字段：

- `stdout: string`（PTY 无独立 stdout/stderr，建议统一返回 `output`，避免虚假区分）
- `exit_code: integer | null`
- `duration_ms: integer`
- `timed_out: boolean`
- `truncated: boolean`
- `session_id: string`
- `token: string | null`（仅命令仍运行时返回；用于 `session_exec_read`）
- 可选 `had_invalid_utf8: boolean`

新增读取工具 `session_exec_read(session_id, token, wait_ms?)`：返回自上次读取以来的增量输出；仍运行时维持 token，完成时 token 为 null 并返回退出码。token 为随机不可预测值，仅在该 PTY session 存活期间有效。

> PTY 的 stdout 与 stderr 合流。因此首选字段名为 `output`，不要承诺能区分 `stdout` 和 `stderr`。

## 实施阶段与验收门禁

### 阶段 0：基线与设计确认

1. 确认当前分支、工作树、最近提交及未跟踪 `C:/` 的性质；保留用户已有内容。
2. 复核 session 并发访问、idle TTL 刷新、MCP schema 导出和现有测试布局。
3. 定稿命令输入契约、输出字段、超时/最大输出限制、并发策略和审计字段。

**门禁：**不覆盖/清理既有未跟踪内容；接口能明确区分 PTY 合流输出和普通 SSH `exec` 结果。

### 阶段 1：PTY 命令输出边界与并发保护

1. 为 `PtyHandle` 增加专用的、受同步保护的命令执行/采集路径；避免简单地 `send_text()` 后反复 `read_new()`，因为它会消费其他调用者或 Web UI 的增量输出。
2. 使用每次执行唯一的随机/不可预测 token 作为 shell 起止标记，命令结束标记携带退出码；正确 shell-quote 用户命令，确保命令非零退出仍能输出结束标记并恢复 prompt。
3. 在一个 PTY session 上对 `session_exec` 调用串行化，防止两个命令的标记和输出交叉；明确它与 `session_send_text`、Web UI 键盘输入并发时的互斥/行为。推荐同一 session 的命令执行期间拒绝或排队冲突操作，并保证锁不会无限期持有。
4. 仅采集本次起止标记之间的内容；处理命令输出中偶然包含相同文本、ANSI/回车控制、无换行输出、locale/编码异常等情形。
5. 首次等待到期不发送 Ctrl-C、不取消命令；collector 继续在后台排空 PTY。返回 token，供 `session_exec_read` 长轮询。SSH session 断开或 collector 丢失输出时，返回明确的不确定状态且不伪造退出码。
6. 限制缓冲与返回长度；超过上限继续排空到结束标记但只保留限定输出，设置 `truncated=true`，避免内存持续增长。

**门禁：**单次命令能准确取得 exit code 和自己的输出；相邻命令输出不串线；并发调用、超时、截断时 session 不静默损坏或误报。

### 阶段 2：类型、会话层与状态/审计接线

1. 在 `src/types.rs`（或 MCP 专用请求类型所在位置）定义请求与结果类型及 JSON Schema。
2. 在 `src/session/pty.rs` 实现 PTY 层采集逻辑；在 `src/session/mod.rs` 通过 session ID 查找现有 handle 并提供 `session_exec` 方法。
3. 在 `src/state.rs` 增加业务入口及审计记录。审计仅记录 session/host、执行时长、退出码、超时/截断、字节数等元数据；**不得记录命令正文和输出**，除非未来提供明确脱敏策略。
4. 在 `src/mcp/mod.rs` 注册工具，进行 session 存在性校验、字段范围校验并把错误映射成 MCP 错误。
5. 工具说明明确：执行会改变远端状态；只在指定已打开 session 上运行；PTY 输出不区分 stdout/stderr；超时/退出码含义；首版限制。

**门禁：**工具 schema 可被 MCP 客户端发现；不存在 session、无效参数、会话断开均返回可理解错误；审计不泄漏命令和输出。

### 阶段 3：测试

单元/集成测试至少覆盖：

- `printf` 无换行输出、常规多行输出、输出含 ANSI/回车。
- 成功退出与非零退出（如 `false`），准确返回退出码。
- 连续调用两条命令，验证输出边界和 shell 状态保留（如 `cd` 后 `pwd`）。
- 命令输出中包含类似标记文本，不得提前结束/污染采集。
- 首次等待窗口到期后命令继续运行、返回 token；读取增量与最终退出码；执行中并发策略。
- 输出超限、非法 UTF-8、session 已关闭/不存在。
- 同一 session 并发 `session_exec`，以及和 `session_send_text`/Web UI 输入的竞争策略。
- 审计只含允许的元数据。

先运行格式化、静态检查和项目现有测试，再运行新增测试；必要时使用隔离的本地 SSH 测试端点，不对生产主机执行验证命令。

**门禁：**所有新增测试通过，现有回归无退化；并发/取消类用例稳定复现并通过。

### 阶段 4：构建与工具面验收

1. 执行 `cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings`（如项目现状允许）和 `cargo test`；记录真实退出状态。
2. 构建 release binary。
3. 在隔离实例启动 MCP 服务，调用 `tools/list` 验证出现 `session_exec`，核对 JSON Schema；通过测试 session 实际调用并读回结果。
4. 确认运行中的生产 `ssh-connector-mcp.service` 是否需要部署。构建成功不等于已部署；部署/重启需单独备份旧二进制、确认变更窗口和回滚方式，并在获准后执行。重启后再次通过 MCP `tools/list` 和真实测试 session 验收。

**门禁：**源码、测试、构建、MCP 暴露、实际调用按层分别有证据；未执行生产部署时明确标记“未部署”，不宣称线上工具可用。

### 阶段 5：文档与提交

1. 更新英文 `README.md` 和中文 `README.zh-CN.md`：功能说明、参数/结果、PTY 与 `exec` 差异、限制和安全注意事项。
2. 复核 diff，确保没有二进制、凭据、测试主机数据或 `C:/` 等未跟踪内容进入提交。
3. 按仓库约定提交；是否推送 fork/部署服务按 Nick 指示及既有授权执行，并验证远端 HEAD。

**门禁：**双语文档同步、diff 范围干净、提交/推送状态准确报告。

## 主要设计风险与决策点

- **PTY 协议没有真正的命令完成事件：**只能从 shell 注入标记并解析终端输出；对非 POSIX shell、被替换的 shell、命令执行 `exec`、交互式程序或改变终端状态等情况需要明确不支持或报告无法判定。
- **shell 执行策略：**命令须在当前 shell 执行以保留状态，但应通过可靠 quoting 注入；不要把用户原始字符串拼接进不受控的标记/控制语法。
- **并发与共享终端：**该 PTY 同时可能被 AI 与 Web UI 使用；需要实现 session 级命令锁与输入竞争策略，避免读缓冲被其他消费者取走。
- **读取 token 生命周期：**token 只在当前服务进程/session 存活期间有效；collector 异常、缓冲丢失或 session 断开时需报告明确错误，不伪造退出码。
- **结果语义：**PTY 输出是终端流而非两个独立管道，不可仿造单独 `stderr`；退出码只有观察到本次唯一结束标记时才可信。
- **背景任务：**命令若启动并脱离控制的后台进程，工具只能报告前台 shell 命令完成，不代表后台任务结束。

## 建议默认行为

- 每个 session 一次只运行一个 `session_exec`；冲突时快速返回 `session_busy`，或采用明确的有界排队，避免静默阻塞。
- 设置有限默认 `wait_ms` 及最大值，输出结果以 token 继续轮询；设置硬输出上限。
- 默认 shell 输入形式使用 `raw`，但起止协议由实现内部生成并安全引用；后续再视需求支持 `argv`。
- `wait_ms` 到期只报告待运行状态并返回 token，不发 Ctrl-C；后续使用 `session_exec_read` 获取输出与最终状态。
- 执行和结果均不写入审计正文，只写审计元数据。
