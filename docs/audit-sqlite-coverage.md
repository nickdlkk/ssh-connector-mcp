# SQLite 审计改造：阶段 0 覆盖矩阵与冻结决策

> 依据 `docs/plan-audit-sqlite.md` 阶段 0。此文件记录源码基线与实现约束，不表示实现或生产部署已完成。

## 基线证据（2026-09-30）

- 仓库：`main`，HEAD `94bde3a5f101b146c909d541706fa368cb7465bc`，与 `origin/main` 一致。
- tracked diff 为空。未跟踪内容：`C:/`、`docs/plan-audit-sqlite.md`、`docs/plan-session-exec.md`；实施不得整理、删除或改写这些用户内容。
- 源码包版本 `0.1.1`；正在运行的 systemd 服务 `/root/.hermes/profiles/ops/mcp/ssh-connector --version` 为 `0.1.0`。服务当前 active。源码和运行时不可混称。
- 旧审计目录有 27 个 JSONL 文件、6480 行，其中 6479 行可解析、1 行损坏；迁移必须保留源文件并累计报告损坏行。
- 已安装 `rusqlite 0.37`（bundled）；SQLite 可复用现有依赖。

## 冻结决策

1. 保留期：严格滚动 7×24 小时，以 RFC3339 UTC 时间戳判断；过期记录清理且查询时排除。
2. 旧日志：只导入当前保留窗口内的可解析记录；用 source file + line 定位确保重复启动幂等；标识 `source=migration`、`legacy=true`，不补造输入/输出。原 JSONL 永不由迁移删除或改写。
3. 输入策略：记录已进入 handler 的方法名、来源、标量/对象结构及安全元数据；禁止凭据明文、命令/脚本/PTY 正文、SFTP 内容/编码内容、密码/令牌、HTTP headers/cookies、环境变量值和路径值。Host 配置只留非秘密标识/类型/计数；命令及任意用户内容记录类型、长度/数量等元数据。
4. 输出策略：只允许函数完成时实际返回调用方的结果进入审计；递归敏感键脱敏，凭据 reveal 仅记录成功/失败与字段类型/长度，不记录秘密；命令/PTY/SFTP 文件正文等高风险自由文本只留类型/长度等元数据。输出记录设硬上限并记录原始序列化长度与截断标识。
5. 流式：WebSocket 只记升级/会话生命周期与错误元数据；不落逐帧输入/输出或终端中间态。
6. 时间：`ts_utc` 存 RFC3339 UTC（统一微秒）；默认排序 `ts_utc DESC, id DESC`。游标基于 `(ts_utc,id)`；排序字段严格白名单；最大 limit 500，默认 200；查询默认最近 7 天且最大跨度 7 天。
7. 错误策略：审计写入错误必须 `tracing::error!` 可观测。管理/变更调用在审计写入失败时按 fail-closed；只读调用可 fail-open，但必须错误日志；不允许静默丢审。
8. 访问控制：`/api/audit` 仍只在 loopback Web API，沿用现有部署访问边界；响应按输入/输出策略做敏感信息限制，不能直接把 credential reveal 或自由文本秘密返回给审计查询调用方。

## 外部调用覆盖矩阵（源码枚举）

`src/mcp/mod.rs` `#[tool_router]` 下全部 28 个 tools：

| 方法 | 输入要点 | 敏感/输出策略 |
|---|---|---|
| host_list | 无 | host summaries 返回值 |
| host_add | HostSpec | auth/jump auth/become_root/env 值只记录类型与元数据 |
| host_update | host_id + HostSpec | 同 host_add |
| host_remove | host_id | 记录标识与 ok/error |
| host_connect | host_id | 记录状态/error |
| host_disconnect | host_id | 记录状态/error |
| exec | host_id + argv/script/raw 三选一 | 命令正文和 stdout/stderr 不落库，只记长度/状态 |
| jumpserver_asset_list | 无 | 资产返回值，敏感键递归脱敏 |
| jumpserver_asset_accounts | asset_id | 账号返回值，敏感键递归脱敏 |
| jumpserver_session_open | asset_id/account_id/rows/cols | 返回 session metadata，不采集流 |
| session_open | host_id/rows/cols | 返回 session metadata |
| session_open_root | host_id/rows/cols | 不采集 root 密码/PTY 内容 |
| session_list | 无 | session metadata 返回值 |
| session_exec | session_id/raw/wait_ms/max_output_bytes | raw 和 output 正文只记长度/状态/token 不存 |
| session_exec_read | session_id/token/wait_ms | token 和 output 正文不存，仅状态/长度 |
| session_send_text | session_id/text | text 不存，只记字节数 |
| session_send_key | session_id/key | key 名可记录 |
| session_screen | session_id | screen 正文不存，只记结构/字节数 |
| session_read | session_id | terminal 文本不存，只记长度/状态 |
| session_resize | session_id/rows/cols | 记录元数据 |
| session_close | session_id | 记录 ok/error |
| sftp_list | host_id/path | 路径值按自由文本元数据处理；返回条目仅结构摘要 |
| sftp_get | host_id/path | 文件正文不存，只记 bytes/编码状态 |
| sftp_get_base64 | host_id/path | base64 正文不存，只记 bytes |
| sftp_put | host_id/path/content | content 不存，只记 bytes |
| sftp_put_base64 | host_id/path/content_base64 | 编码正文不存，只记 bytes |
| sftp_download_file | host_id/remote_path/local_path/选项 | path 按策略脱敏；返回 transfer metadata |
| sftp_upload_file | host_id/local_path/remote_path/选项 | path 按策略脱敏；返回 transfer metadata |

`src/web/mod.rs` 全部 17 个 handlers：

| 方法/路由 | 输入要点 | 敏感/输出策略 |
|---|---|---|
| status `/status` | 无 | 返回状态 |
| vault_init `/vault/init` | master_password | 仅元数据与结果，不记密码 |
| vault_unlock `/vault/unlock` | master_password | 仅元数据与结果，不记密码 |
| get_hosts `GET /hosts` | 无 | 脱敏 host detail 返回值 |
| add_host `POST /hosts` | HostSpec | 同 MCP host_add |
| get_jumpserver_assets | 无 | 脱敏业务返回值 |
| get_jumpserver_accounts | asset_id | 脱敏业务返回值 |
| update_host | id + HostSpec | 同 host_add |
| remove_host | id | 记录 ok/error |
| connect_host | id | 记录状态/error |
| disconnect_host | id | 记录状态/error |
| reveal_host | id + master_password | 高敏：永不存 auth/jump_hosts 返回正文 |
| get_sessions | 无 | session metadata 返回值 |
| close_session | id | 记录 ok/error |
| get_audit | 筛选/排序/分页 query | 不审计自查询结果正文以避免递归，仅元数据/结果数 |
| attach_session | id + WebSocket upgrade | 仅握手/生命周期结果，不记帧 |
| attach_socket | WebSocket stream | 只记关闭/错误元数据，不记帧或 PTY 输出 |

提取/JSON 反序列化失败（尚未进入 handler）不伪称为“函数输入审计”；应通过框架层错误/指标统计拒绝数，或明确标记 `entered=false` 的请求层事件。MCP schema 解码失败同理。

## 尚需阶段门禁

- 以上矩阵明确当前外部方法和敏感字段边界；代码实现后必须用自动化测试确认每个入口成功/失败恰好一条事件。
- 运行时备份、服务更新和生产 API/MCP验收属于阶段 5，需阶段 1–4 的代码/测试门禁通过后执行；此处不视作已授权删除旧日志。
