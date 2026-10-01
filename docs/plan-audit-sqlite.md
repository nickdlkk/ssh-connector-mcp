# 审计系统改造实施计划：SQLite、7 天保留、输入/返回值审计

## 目标与范围

将当前按日 JSONL 的本地审计改造为 SQLite 审计库，满足：

1. **按时间保留最近 7 天**：以 UTC 时间计算，自动清理超过 7×24 小时的记录；不是只限制文件数量或总容量。
2. **多维筛选与排序**：支持时间范围、动作/方法、host、session、调用来源/结果等条件筛选；支持白名单字段排序、升降序、分页。
3. **审计所有现有可调用方法的输入**：包括 MCP tools 以及 Web API 的业务方法；记录实际进入方法的已校验/规范化请求字段，并明确失败调用是否已进入函数边界。
4. **输出只取函数读取时的输出**：只审计被调用方法实际返回给调用方的结果（成功返回值或结构化错误），不采集 SSH/PTY 原始流、日志、终端屏幕中间态、网络包、后台消息或未被函数消费的输出。若某方法本身返回终端/命令输出，则该返回值属于函数读取输出，但仍须执行敏感信息脱敏和容量截断。
5. 不把审计变成凭据/敏感信息采集渠道；审计故障不能静默伪装成成功。

> “所有已有方法”在本计划中指现有 MCP tools 与 Web API 业务 handler。纯静态文件、WebSocket 每帧转发和内部 helper 不作为独立 RPC 方法；WebSocket 建立/关闭及错误可记录会话级元数据，逐帧输入/输出需按本计划的输入/函数返回原则另作约束，不落原始帧内容。

## 当前基线（源码检查）

- `src/audit.rs`：JSONL，`data_dir/audit/audit-YYYY-MM-DD.jsonl`；同步 `std::fs`；进程内 `Mutex`；清理最多 30 个文件/总计约 10 MiB；失败多处被忽略；`tail(limit)` 仅最新优先，无筛选/排序分页。
- `src/state.rs`：主机、exec、PTY、SFTP 等部分业务操作手工调用 `AuditLog::entry()`。普通 `exec` 的命令预览会写入审计；输出只记长度。PTY 输入正文不记，但 WebSocket 输入转发绕过逐次审计。部分读取方法目前没有审计返回值。
- `src/web/mod.rs`：vault init/unlock、credential reveal 有审计；许多其他 API handler 没有统一输入/输出审计。`/api/audit` 直接读取审计。
- 数据目录已有历史 JSONL；不应在迁移前覆盖或删除。当前工作树存在其他未提交改动及未跟踪 `C:/`，实施时需隔离并保护。

## 建议存储方案：SQLite

SQLite 比继续扩展 JSONL 更适合此需求：字段化索引和条件查询、排序/分页、原子写入、时间清理及并发读写都能由数据库直接支持。SQLite 仍是本机单文件审计，不自动提供不可篡改/远端留存保证；计划不把它描述为 WORM 审计系统。

建议文件：`data_dir/audit/audit.sqlite3`。连接配置建议 WAL、`busy_timeout`、外键（如有）、合理同步级别；对写入采用事务，明确迁移/备份和错误策略。

### 初始数据模型建议

`audit_events`：

- `id INTEGER PRIMARY KEY`（单调递增）
- `ts_utc TEXT NOT NULL`（RFC3339 UTC，精度统一）
- `method TEXT NOT NULL`（MCP tool/API route 的稳定名称）
- `source TEXT NOT NULL`（如 `mcp`、`web_api`、`websocket_lifecycle`、`internal`）
- `host_id TEXT NULL`
- `session_id TEXT NULL`
- `status TEXT NOT NULL`（`success` / `error`；可细分 validation/timeout 等）
- `duration_ms INTEGER NULL`
- `input_json TEXT NOT NULL`（脱敏后的结构化输入）
- `output_json TEXT NULL`（脱敏后的函数返回结果；错误返回按约定结构化）
- `input_bytes INTEGER NULL`、`output_bytes INTEGER NULL`、`truncated INTEGER NOT NULL DEFAULT 0`
- `error_code TEXT NULL`

索引至少包含 `(ts_utc)`、`(method, ts_utc)`、`(host_id, ts_utc)`、`(session_id, ts_utc)`、`(source, ts_utc)`、`(status, ts_utc)`。索引按真实查询和测试调整，避免过度索引。

### 输入/输出记录约束

- 以**函数边界**作为审计点：方法收到请求后，形成规范化、已脱敏输入快照；执行结束时，只记录该方法实际返回给调用者的值/错误。
- 对 MCP 在工具 handler 边界统一包裹；对 Web API 在 handler 边界统一包裹。避免每个业务方法重复遗漏，也避免双层重复记录。若底层 `AppState` 方法同时由 MCP/Web 调用，审计归属需固定一层并传入 `source`，每次外部调用恰好一条主事件。
- 原有 `exec_payload_audit_detail()` 的 preview 不再直接写明文；除非安全设计明确批准，不记录命令正文、脚本正文、argv 参数内容。仅记录参数名/类型、数量/字节数、是否存在、摘要（若安全审查批准）等元数据。不得把“截断 preview”当成脱敏。
- HostSpec / credential / vault master password / become_root password、private key、keyboard-interactive answers、token、headers/cookies 等必须递归脱敏；不存储秘密明文或可逆编码。路径、环境变量和值、命令参数也可能含秘密，采用 allowlist 字段策略，而非只按常见密码 key 名黑名单。
- 输出只记录方法返回值；但返回值也可能含凭据（例如显式 credential reveal）或命令输出中的密钥。实现统一输出脱敏、最大序列化字节数和截断标记。绝不可为满足“输出审计”而把秘密原样复制进数据库。
- 对大结果设全局硬上限及字段级策略；保存完整结果若超限则安全截断并标 `truncated=true`，保留返回类型/字节数。不得因审计把无限大输出全部落盘。
- 审计数据库错误必须可观测（日志/指标/健康状态），写入失败策略需按操作风险分级：管理/变更操作倾向 fail-closed 或明确返回“操作成功但审计失败”的可识别结果；读取类操作可采用 fail-open，但必须产生告警且不伪称已审计。具体默认在阶段 0 决策。

## 实施阶段与验收门禁

### 阶段 0：清点与设计冻结

1. 固化代码基线：分支、工作树 diff、当前二进制/服务版本；保护未提交内容和 `C:/`，不在其上做破坏性整理。
2. 从 `src/mcp/mod.rs` 和 `src/web/mod.rs` 枚举全部外部方法，生成覆盖清单，逐一标记输入 schema、可能敏感字段、返回类型、失败路径、输出策略及是否流式。
3. 决定输入/输出字段 allowlist、递归脱敏规则、特殊高敏方法（如 `credential_reveal`）策略、最大单条记录字节数、写入失败策略、保留边界（精确滚动 7×24 小时或 UTC 日历日；建议精确滚动 7×24 小时）。
4. 确定审计查询 API 参数、排序白名单、分页语义与访问控制；审计接口不能因输出记录而无限暴露敏感数据。

**门禁：**方法覆盖表完整；输入、输出、秘密脱敏、超限和失败策略已定；变更边界清晰。

### 阶段 1：SQLite store 与迁移

1. 新增/扩展 `AuditStore`（可替代 `AuditLog`），初始化 schema/version 表及所需索引。
2. 定义 SQLite schema、WAL/busy timeout、事务写入、参数化查询、原子清理及数据库权限/umask。
3. 启动时执行迁移：保留旧 JSONL 原件；可选将最近 7 天内有效 JSONL 事件导入 SQLite，标记 `source=migration` 并保留原 action/detail 语义；对过期数据按已批准保留策略不导入。记录导入、跳过、损坏行计数。迁移可重复运行且幂等。
4. 对旧事件按 schema 兼容方式填充字段，不捏造旧日志中未有的输入/输出；旧条目须标记为历史/字段不完整。
5. 提供恢复与回滚：迁移前 SQLite 一致性备份；出错不改写/删除 JSONL；能恢复旧二进制读取旧日志。定义回滚期间新审计如何暂存或双写，避免静默丢失。

**门禁：**空库初始化、并发读写、重启、重复迁移、损坏 JSONL 行、备份恢复、WAL checkpoint 均有测试；旧数据保留边界可验证。

### 阶段 2：7 天保留与可查询 API

1. 每次启动及周期任务执行清理，删除 `ts_utc < now_utc - 7 days` 的记录；清理过程事务化、可观测、幂等。周期频率可配置或固定为小时级，同时查询时不返回已过期记录。
2. 查询支持 `from`、`to`、`method`、`source`、`host_id`、`session_id`、`status`、`error_code` 等条件；允许组合筛选。
3. 支持 `sort_by` 白名单（默认 `ts_utc`）、`order=asc|desc`、`limit`、稳定分页（建议 cursor/keyset `(ts_utc,id)`，避免 offset 大页不稳定）；参数均范围校验、SQL 参数化。
4. 保持兼容性：旧 `/api/audit?limit=N` 映射到新查询默认值，逐步公布筛选/排序参数；若 MCP 也需查询工具，单独列入工具 schema/权限与测试。
5. 提供明确查询边界：默认时间窗口、最大页大小、最大筛选跨度，防止全库大扫描/响应过大。

**门禁：**组合筛选、全部可排序字段、双向顺序、边界时间、稳定翻页、空结果、超限输入、SQL 注入字符串都通过集成测试；旧 API 基本兼容。

### 阶段 3：全方法输入及返回值采集

1. 建立方法覆盖矩阵，覆盖清单中的每个 MCP tool 和 Web API handler，包括查询/只读方法、校验失败、业务错误、超时、部分失败。
2. 实现共享审计包装器/边界 helper，确保每次外部调用一个审计事件，计时覆盖实际函数调用；记录规范化输入与调用返回值/错误。
3. 对没有参数的方法记录 `{}`；对输出有敏感字段或体积过大的方法应用其专属 allowlist/redaction/truncation。
4. 统一记录 `session_read`、`session_screen`、`host_list`、`session_list`、SFTP 读取等函数返回值；不另行监听或持久化 SSH/PTY 原始流和中间输出。
5. PTY/WebSocket 流式通道只审计函数边界可定义的握手/生命周期结果和元数据；不逐帧存储原始内容。逐帧内容不是一次普通函数返回值，需明确不在输出正文范围内。
6. 更新原手工审计点，避免重复记录；移除命令 preview 等不安全字段；在审计中纳入稳定 method 名、来源、session/host 关联、状态及 error code。

**门禁：**覆盖矩阵每一方法具备成功与错误用例；每次调用恰好一条记录；记录的输出与函数实际返回一致（经批准的脱敏/截断除外）；无原始后台流落库；秘密扫描测试无泄漏。

### 阶段 4：安全、性能与回归验证

测试至少覆盖：

- master password、SSH password、private key、OTP、token、cookie、命令/脚本中的疑似秘密、HostSpec 敏感字段不会原文入库。
- 所有现有 MCP/Web 方法的输入/返回对象审计、错误审计、来源与关联 ID。
- 函数实际读取的命令/PTY/SFTP 返回值可被查询，但未被函数消费的后台/中间流不入库。
- 大输入/大输出截断标记、非法 UTF-8、空返回、序列化失败。
- 7 天边界过期/保留、时钟 UTC、清理并发与查询并发。
- 多维过滤、排序、分页稳定性、非法排序字段拒绝、注入防护、最大 limit。
- DB 锁、磁盘满、权限错误、损坏 DB 下的错误策略和告警；确认不会无声漏审。
- 查询/写入基准及索引计划；WAL/备份恢复与服务重启。

运行 `cargo fmt --check`、项目测试、`cargo clippy --all-targets --all-features -- -D warnings`（若项目基线支持）及新增集成测试，记录实测退出码和结果。

**门禁：**功能、保留、筛选、脱敏、审计完整性和性能测试通过；失败策略可观测，数据迁移可恢复。

### 阶段 5：文档、部署与运行验收

1. 更新英文/中文 README 与 API 文档：SQLite 位置、7 天滚动保留、查询筛选/排序/分页、输入/函数返回审计范围、敏感信息处理、流式方法限制、备份/恢复。
2. 隔离实例完成 schema 查询、API 筛选和真实 MCP/Web 调用验收。
3. 生产部署前备份当前二进制、审计 JSONL 与服务配置，确认磁盘、权限、停机窗口、回滚步骤；迁移不删除旧 JSONL。
4. 部署后读回服务状态、SQLite schema/保留任务、审计查询结果；制造一条无敏感的受控测试调用，确认输入/函数返回可查、秘密不入库、过期清理有效。
5. 逐层报告源码、测试、构建、迁移、运行服务、MCP/API、实际审计记录状态；未部署不得声称生产已生效。

**门禁：**部署及运行时验收有真实证据；回滚可执行；旧日志原件按保留/迁移决策保管。

## 主要风险与控制

- **输入审计可能记录秘密：**使用字段 allowlist/类型摘要和敏感字段策略；不原样存储 credential、命令正文等。输入审计的“完整”定义应是方法/参数结构与安全元数据完整，不是秘密明文完整。
- **输出审计可能复制敏感返回：**函数返回值也需脱敏/截断；`credential_reveal` 等高敏返回默认只记录字段名、类型、长度或访问结果，不落秘密正文。
- **PTY/HTTP 流式返回边界不明确：**审计定义为方法完成时实际交付给调用者的返回值；持续流只记录握手/生命周期元数据，不储存原始帧。若未来需要流内容审计需另行授权和设计。
- **审计写入影响业务可用性：**按操作类别明确 fail-closed/fail-open，所有失败可观测；避免“调用成功但未审计”无提示。
- **SQLite 不是不可篡改仓库：**root/服务账户可改库；若要求防篡改、跨主机留存或法律合规，还需远端 append-only 存储/签名链等独立方案，不在本次默认范围。
- **现有手工审计遗漏/重复：**通过外部方法清单和“一次调用一条主事件”测试闭环，不依赖人工 grep 认为覆盖完整。

## 当前状态

### 交付原则（务实版）

本计划追求可用、不会漏记明显秘密、能安全替换生产，不把本地运维审计做成合规取证项目。优先完成：

1. SQLite 单库、启动迁移保留旧 JSONL、UTC 滚动 7 天清理。
2. MCP/Web API 业务 handler 每次调用产生一条事件；记录方法、来源、状态、耗时、已过滤输入和安全结果摘要。避免对自由文本/凭据/命令正文做逐字存储。
3. `/api/audit` 基本筛选、排序、分页，limit 和响应字节数有上限。
4. 测试覆盖关键路径及最容易出事的安全点：迁移幂等、7 天清理、cursor 翻页、秘密不落库、大 body 被拒绝、MCP/Web 各一条真实调用写入一条事件。
5. 以上通过后，备份并替换生产二进制，读回服务/API/数据库确认生效；保留可恢复的旧二进制和原始 JSONL。

不把以下内容设为替换生产的前置门槛：每个工具/handler各写一套成功与失败 fixture、WebSocket 每个生命周期分支的完整模拟、硬盘满/全部 SQLite 故障模式注入、专门性能基准、法律级不可篡改验证。遇到明显数据丢失、重复事件或明文秘密风险仍必须修复；其余留作后续改进。

## 当前状态

### 执行记录（2026-09-30，最新续做）

- 生产服务仍 `active`，二进制/API版本 `0.1.0`。本轮未替换生产、未迁移或修改生产审计数据。候选版为 `0.1.1`。
- 已实现 SQLite/WAL、旧 JSONL 幂等导入并保留原件、UTC 七天清理、筛选/排序/cursor、MCP 共用调用边界、Web route middleware、输入输出脱敏/大小限制、写入错误结果传播；Web request body 上限为1MiB，超限拒绝并记录拒绝事件；审计 API 响应只存结果数和分页元数据以避免递归复制。
- 验证：`cargo test --locked` 56 passed；`cargo check --locked`、release build、`git diff --check` 均成功。`cargo fmt` / `cargo clippy` 子命令当前不可用。
- 隔离候选环境完成 MCP initialize/host_list、Web status/hosts、vault init 冒烟；主密码 sentinel未落库；SQLite 权限为0600。临时 systemd 实例已停止。隔离目录保留在 `/tmp/ssh-connector-audit-final-20260930` 和 `/tmp/ssh-connector-audit-webinit-20260930`。
- 遗留项按务实范围处理：不逐个为全部方法编写独立模拟 fixture；WebSocket帧正文不审计；不做专门性能基准/穷尽磁盘故障注入。仍需做一轮干净隔离库的单事件确认、最终候选构建与部署备份/回滚清单。

### 简化后的阶段状态

- 阶段 0：方法清点和秘密过滤策略已有，够支撑当前维护交付；不扩展成合规矩阵。
- 阶段 1：SQLite schema、WAL、幂等 JSONL迁移、保留原件、7天清理已实现；基本单测通过。
- 阶段 2：审计查询 API 初版已实现；基本查询、白名单、cursor测试通过。
- 阶段 3：MCP/Web 共用边界已接入；代表性 Web/MCP运行验收通过。部署前再用全新隔离目录确认各一条事件。
- 阶段 4：56项项目测试通过，包含关键安全/分页/保留/大请求拒绝；不再要求全面故障注入与基准。
- 阶段 5：候选冒烟已做，生产仍 0.1.0。接下来补干净隔离目录单事件复核、最终构建、生产备份与回滚预案，然后执行候选替换和运行验收。

### 允许延期（不阻塞第一版替换）

- WebSocket 建连/关闭/异常的生命周期细分事件（帧正文永不入库）。
- 所有 45 个入口分别编写成功/错误测试；以共用边界实现、路由/工具枚举、代表性端到端案例作为首版验收。
- 非常规 DB 磁盘满/硬件损坏/压力压测与查询基准。
- 额外合规级防篡改存储。SQLite 本地文件不宣称 WORM。

1. 新建全新随机隔离 data dir，MCP `host_list` 和 Web `/api/status` 各调用一次，SQL按方法统计确认各一条、敏感值不存在、响应可用。
2. 完成 release 构建；备份生产二进制、服务配置和审计 JSONL，写明回滚命令及验证点。
3. 用候选版替换并重启生产服务，读回 systemd状态、版本、API、SQLite表/最近审计记录与原JSONL保留状态；任一门禁失败立即回滚。

### 2026-09-30 生产替换完成记录

- Nick已明确“允许继续，可以替代生产”；并确认备份目录 `/root/.hermes/profiles/ops/.ssh-connector/rollback-0.1.0-2026-09-30/`。
- 替换前备份完成并核验：旧0.1.0二进制、systemd unit、`config.toml`、`jumpserver.env`、27个原始JSONL（合计2,113,524 bytes）均已复制；逐个读回比对27份JSONL内容完全一致。备份根/子目录权限0700，env文件0600。旧二进制哈希 `23c45054...97a176c5`；回滚命令为：`install -m 0755 /root/.hermes/profiles/ops/.ssh-connector/rollback-0.1.0-2026-09-30/ssh-connector-0.1.0 /root/.hermes/profiles/ops/mcp/ssh-connector && systemctl restart ssh-connector-mcp.service`。
- release候选0.1.1哈希 `ee232c48...de35ecf5`，安装后与构建产物/候选文件一致。
- 生产切换后 `ssh-connector-mcp.service=active`，运行二进制和 `/api/status` 均返回0.1.1；MCP initialize HTTP 200、tools/list HTTP 200并列出28个tools；Web状态API HTTP 200。
- 生产 SQLite 已创建 `audit.sqlite3`，权限0600，`PRAGMA integrity_check=ok`；迁移日志报告 imported=2390、expired=4089、malformed=1；库中event总数2393（迁入2390 + 部署后3条web_api status访问）；27份原JSONL仍在，未删除/改写。
- vault状态部署后为 initialized=true、unlocked=false，符合服务重启后需要重新解锁的既有行为；未触碰vault数据库内容。
- 生产调用级MCP `host_list` 的结果事件还有待 vault unlock 后由用户或后续受控解锁验证；本轮不伪称已完成业务MCP审计写入确认。


### 2026-09-30 续做追加

- 本轮将 Web request body 超限/读取失败从“用空 body 继续 handler”改为拒绝 HTTP 413；先记录 `{entered:false,body_rejected:true}` 及稳定路由，不把失败 body 误传给业务 handler。Response 读取超过 1MiB 则中止客户端响应并返回 500；待验证这一响应超限策略是否可在不缓冲全量 body 情况下实现。
- `/api/audit` 的审计输出已收窄为 `entry_count` 与 `has_next_cursor` 元数据，避免把已有审计行递归复制到新的审计记录；动态 ID 路由名称归一化。
- 新增测试：Web大请求拒绝且 vault 未初始化、MCP输入敏感字段过滤、credential reveal/MCP自由文本输出脱敏。SQLite 新增实际 7 天清理边界、SQL排序白名单正反序、DB写入失败传播、cursor有效性、记录上限与最终查询序列化截断测试。
- 最新 `cargo test --locked`：56 passed；`cargo check --locked`、release build、`git diff --check` 通过；格式和 clippy 检查仍因当前 cargo 子命令缺失未运行。
- 候选 1.1 用独立 systemd data dir/17600 port 完成 MCP host_list、Web status、hosts 查询、vault init 冒烟；master-password sentinel未入库；SQLite 权限0600；候选测试 unit停止。生产仍 active 0.1.0。
- 发现并修正最终查询记录自身需硬限制为 64KiB，防止 `/api/audit` 返回记录过大；输入及 MCP输出 JSON sanitize allowlist已增补事件字段及 JSON包装键。
- 当前明确遗留：原始 frame不存储及 WebSocket生命周期还无验收测试；response体超过1MiB当前 fail/拒绝方案需要慢响应/大响应测试；MCP每个工具尚无独立业务成功+失败样例，解析/schema拒绝尚无请求层 entered=false 统一事件；全量响应审计按硬限安全摘要处理，不保证任意自由文本原文可回读。

#### 下轮推进主线
1. 新建全新随机隔离目录和空库；重复 MCP host_list 两次，各验证准确事件数；Web status/vault init/invalid request 一次事件与错误策略。
2. 对 Web middleware 超限 body 明确拒绝/可观测策略；限制对 `/api/audit` 的递归事件内容泄露；对 response sanitizer逐 endpoint 加回归。
3. 持续补齐数据库恢复、锁/权限、保留秒边界、筛选/排序/cursor测试和秘密扫描，修复所有失败后再更新门禁。
4. 所有阶段门禁通过前，生产保持版本0.1.0且不得执行生产迁移/切换。


### 2026-09-30 范围收敛/最终隔离核验

Nick明确反馈无需过度缜密，并允许最终替代生产。本计划已新增“务实版”交付原则：关键安全、7天、迁移、基本筛选、一次调用一条事件、生产备份/回滚为首版门槛；完整故障注入、性能基准及每个方法独立模拟可后续安排。

- 最新全量测试：`cargo test --locked` **56 passed**；`cargo check --locked` exit 0；release build success；`git diff --check` success。
- 隔离最终验证使用全新 `/tmp/ssh-connector-clean-20260930`，candidate 0.1.1 运行：MCP `host_list` 调用两次各返回 HTTP 200；Web `GET /api/status` 返回200；SQL汇总为 `host_list,mcp,2` 及 `GET status,web_api,2`，即各调用每次一条事件，没有旧测试残留；数据库权限0600。验证后 transient unit 已停止。
- SQLite新增边界：最终查询事件本身经 64KiB sanitizer；cursor 排序绑定 timestamp/id并严格时间范围校验；`try_record_fields` 写库错误向入口传播。Web大请求现拒绝413并记录 entered=false，不会把空 body传入处理函数。审计查询路由只回记数量/cursor元数据。
- 当前生产仍 `ssh-connector-mcp.service=active`，版本及API `0.1.0`；candidate已放于 `/root/.hermes/profiles/ops/mcp/ssh-connector.candidate`（0.1.1）。生产数据目录现有27个旧 JSONL文件，部署尚未迁移。
- **当前切换阻断：**还没按切换前门禁备份生产二进制、systemd unit环境配置和27份源 JSONL，也没有演练可回滚的明确文件级操作/恢复读回。本轮未替换生产。下一步仅剩：执行备份并验证读回 -> 保存回滚命令 -> 原子替换候选并重启 -> 检查版本/API、SQLite迁移行数与源日志存在、受控安全调用及一条事件 -> 任一不通过立即回滚。


### 2026-09-30 v0.1.2生产替换

- Nick要求“执行生产替换”；按既有授权在同一目标上将0.1.2替代已运行的0.1.1。替换前新增备份目录 `/root/.hermes/profiles/ops/.ssh-connector/rollback-0.1.1-2026-09-30/`，包含0.1.1二进制、systemd unit、config.toml、jumpserver.env、live SQLite一致性备份、vault SQLite一致性备份及27份原JSONL逐文件拷贝。旧版本可用已记录的同路径 install+systemctl restart 回滚。
- Release二进制运行版本 `0.1.2`，SHA256 `43d0ed99a88462f1c4248ec1b407957ad133d4ecdb795111d4f64cf521bf4142`；安装后与 `target/release/ssh-connector` 哈希一致。
- 替换后 `ssh-connector-mcp.service` active；`/api/status` 返回0.1.2；启动日志报告旧日志迁移 imported=0（因近期行在0.1.1首轮迁移时已完成）、expired=4249、malformed=1，并从已有库清理过期160条。当前 SQLite `integrity_check=ok`、schema version 1、2240 events（migration 2230、web_api 10），mode 0600；27个源 JSONL原件仍保留。
- vault 状态 initialized=true/unlocked=false，服务重启后重新锁定为预期；已验 API 和MCP tools/list。未用存储主密码，因此未执行依赖解锁的生产业务MCP调用。部署后MCP工具返回主密码仅在用户解锁后可继续验证，不把未验证内容声称通过。


### 2026-09-30 审计前端表格视图

- Nick反馈原前端仍是审计卡片/列表且没有筛选，要求重构表格。现将 `static/index.html` 与 `static/app.js` 改为表格视图，展示 ID、时间、方法、来源、结果、Host/Session、耗时、脱敏输入/输出概要。
- 页面提供本地时间区间、method/source/host_id/session_id/status筛选、页长、白名单排序字段和升降序；使用 API cursor翻页，重置筛选并明确空/加载/错误态。表格行通过 `textContent` 创建，不将审计内容拼接为 HTML。
- `node --check static/app.js` 通过；`cargo test --locked web_audit_query_tests` 通过；后续全量 `cargo test --locked` 58 passed，后端筛选 API 已实际 GET 验证。
- 生产目录 `/root/.hermes/profiles/ops/.ssh-connector/static` 原来不是构建源码目录的实时镜像；本轮已备份旧 `index.html/app.js/style.css/favicon.svg` 到 `/root/.hermes/profiles/ops/.ssh-connector/rollback-ui-audit-table-2026-09-30/`，并只替换静态文件，不重启后端。
- 替换后用运行中生产服务读取 `/`、`app.js`、`style.css` 均返回HTTP200；读取文件SHA256与本地目标一致。生产服务仍 active，版本仍0.1.2。筛选API示例 `GET /api/audit?limit=5&source=web_api&order=desc&sort_by=ts_utc` 返回200且行来源满足筛选。
- 待人工浏览器观感复核；本机无 Playwright/Puppeteer/Jsdom 包，未做真实像素布局测试。后端生产已运行0.1.2，无需本次重启。


### 2026-09-30 生产审计前端替换确认

- Nick再次要求“替换生产”；复核发现前轮审计表格静态资源已从源码目录复制到实际生产 `data_dir/static`，因此本轮未重复覆盖文件、未重启后端。
- 生产 `ssh-connector-mcp.service` active、后端版本0.1.2；生产 `index.html`、`app.js`、`style.css`、`favicon.svg`分别通过HTTP200回读，并与生产磁盘文件SHA256/字节相同。HTML含筛选表格控件，实际app.js已含auditQuery/cursor pager实现。
- 生产审计筛选API `GET /api/audit?limit=3&source=web_api&sort_by=ts_utc&order=desc` 返回200且条目source符合筛选；前端脚本 `node --check`通过，过滤API集成测试通过。
- 当前生产静态资源相较旧版本备份在 `/root/.hermes/profiles/ops/.ssh-connector/rollback-ui-audit-table-2026-09-30/`。当前未提交的只是源码工作树静态文件更新；本轮再次比对生产目录，已与源码一致。
- 浏览器自动化包不可用，故没有真实 GUI 截图/视觉布局验收；响应文件和API均已读回确认。


### 2026-09-30 方法筛选 UX 调整

- 按 Nick反馈，将审计页“方法”从默认自由输入改为预设方法下拉列表，列出当前MCP工具与主要Web API事件名，并提供显式“自定义”开关；启用后使用精确method文本查询，避免默认输入框显得像必填、且降低拼错方法名的概率。
- 生产静态文件已备份至 `/root/.hermes/profiles/ops/.ssh-connector/rollback-ui-method-dropdown-2026-09-30/`，随后部署 `index.html/app.js/style.css/favicon.svg`。从生产HTTP逐个读回，状态200且字节与生产磁盘一致。后端未重启、版本保持0.1.2。
- `node --check static/app.js` 和 audit route integration test 通过。尚未用浏览器截图复核整体视觉表现。


### 方法自定义控件二次微调

- Nick反馈方法下拉下的自定义区域不协调。现将“自定义”复选开关移入方法字段标题右侧，默认方法下拉占用统一字段高度；打开自定义时原位切换为精确 method 输入框，不再在下拉下方另堆一行。
- 生产当前静态资源已用新文件替换并读回：`index.html` 23082B、`app.js` 50378B、`style.css` 25995B，各HTTP 200；后端服务未重启，仍0.1.2。替换前旧静态文件备份在 `/root/.hermes/profiles/ops/.ssh-connector/rollback-ui-method-toggle-2026-09-30/`。
- `node --check static/app.js`、审计 query 集成测试及 `git diff --check` 通过。未做截图级浏览器布局测试。


### 表头列排序交互更新（2026-09-30）

- 根据 Nick最新要求移除筛选面板里的独立排序字段/顺序下拉；改为在可排序表头（ID、时间、方法、来源、结果、主机/会话）点击切换排序列，重复点击切换升/降序，并显示方向箭头。耗时/输入/返回概要不提供排序入口。
- 排序仍调用后端白名单 `sort_by` 与 `order` 参数，cursor查询随排序变化重置到首屏。Node语法检查及 audit query 集成测试通过。
- 更新已部署 `/root/.hermes/profiles/ops/.ssh-connector/static/{index.html,app.js,style.css}`；部署前静态资源备份于 `rollback-ui-sort-header-2026-09-30/`。生产HTTP读回三文件均200且与磁盘完全相同；HTML含6个可排序表头，原独立排序select不存在。后端仍active、0.1.2，未重启。


### 方法多选查询（2026-09-30）

- Nick要求方法筛选支持多选。页面当前改成带搜索、全选/清空和已选数量的复选方法列表；自定义方法仍是并集项。浏览器会提交重复的 `methods=a&methods=b` 参数，Web Query 使用 `Option<Vec<String>>` 解析，SQLite 以参数化 `method IN (...)` 实施“任一选中方法”的并集筛选，最多32项。
- 新增 SQLite 集成单测验证多方法并集结果及超过32项拒绝。`cargo test --locked` 59 passed，`node --check static/app.js`、query集成测试、`git diff --check` 通过。
- 生产静态 `index.html/app.js/style.css` 已备份至 `/root/.hermes/profiles/ops/.ssh-connector/rollback-ui-method-multiselect-2026-09-30/` 后更新；HTTP三资源均200且与磁盘完全匹配；页面包含36个固定方法复选项和自定义方法开关。生产服务仍0.1.2、active，后端未重启。
- 用生产HTTP直接查询 `methods=host_list,exec` 返回200，说明后端解析路径可达；当前真实生产样本以GET audit/status为主，需有对应历史MCP事件时再验实际过滤结果集。


### 方法多选恢复下拉交互（2026-10-01）

- Nick反馈方法多选不应直接展开成常驻复选框列表，要求改回下拉多选。现增加“全部方法/已选 N 项”触发按钮；点击展开搜索、全选/清空和复选选项，点击外部或按 Escape 收起，支持 36 个预设项及既有自定义方法并集筛选。
- 验证：`node --check static/app.js`、HTML parser、ID唯一性检查、`git diff --check`通过；`cargo test --locked web_audit_query_tests` 1 passed。真实浏览器截图/像素验收未执行。
- 生产更新前备份 `index.html/app.js/style.css` 至 `/root/.hermes/profiles/ops/.ssh-connector/rollback-ui-method-dropdown-multiselect-2026-10-01/`；更新后生产HTTP三资源均200，响应字节与生产磁盘一致，页面返回包含下拉触发控件和36个方法项。服务仍active、版本0.1.2，未重启后端。


### 2026-10-01 生产验收复查与修复续办

- 复查发现之前将方法多选写成逗号分隔参数，与后端 `Option<Vec<String>>` 的重复 query 参数解析契约不一致；并且早先生产验证仅确认HTTP 200，没有核对返回条目是否严格属于所选方法，不能算功能验收通过。此项现在标记为**未验收/待修复**，不能以SQLite store 单测代替HTTP层验收。
- 已在生产真实调用 MCP `host_list` 两次，SQLite 对应 `source=mcp, method=host_list` 事件增量正好2，MCP tools/list 返回28项；服务仍active、版本0.1.2。
- 生产 SQLite `integrity_check=ok`、权限0600、27个源JSONL仍在；但直接SQL复核发现超过7天的旧行仍存在。源码目前在进程启动时清理且查询排除过期行，并无周期清理调度；阶段2原要求有启动及周期清理，需补上周期任务或明确调整计划，不能报告完全满足。
- 本轮修复门禁：用隔离及生产API验证单选/多选 `methods` 只返回选中集合、包含重复 query 参数与自定义项、错误参数/超32项拒绝；验证每次 audit 查询自身的审计事件不会污染被返回结果；完成后再部署并读回生产API结果与服务状态。
- 保留期门禁：为审计 store 增加定期清理（建议小时级）；提供可控测试证明任务运行后删除严格早于滚动7×24小时的记录、保留边界记录，并保证查询不返回过期数据；清理失败须可观测。验证生产旧过期行处理前先备份 SQLite/WAL 一致快照并记录删除计数。
- Rust `cargo fmt --check` 与 `cargo clippy --all-targets --all-features -- -D warnings` 在当前环境因 cargo 子命令未安装而不能运行；报告为未执行，不视作通过。真实浏览器视觉验收仍待做。


### 2026-10-01 多选过滤与周期清理修复完成

- 根因：Axum `Query` 不能将重复键 `methods=a&methods=b` 直接反序列化为 `Option<Vec<String>>`，报错为 `invalid type: string "alpha", expected a sequence`。原失败 handler 产生审计事件，导致未按 method 筛选时的响应中不断出现新的 `GET audit`，先前只看 HTTP 200 而没验证结果成员，造成误判。
- 修复：Web handler 用 `RawQuery` + `url::form_urlencoded` 逐项读取重复 `methods` 键；上限32项仍返回400；前端通过 `URLSearchParams.append` 按重复 query 参数提交所选方法。添加handler层集成测试验证并集只含所选项且不会带入 `GET audit` 事件，并测试超限拒绝。
- 保留清理：启动时已有清理；新增每小时运行的 async prune task，失败通过 `tracing::error` 显式记录。`SSH_CONNECTOR_AUDIT_PRUNE_INTERVAL_SECS` 可用于运维/测试覆盖周期，缺失、无效或0则默认为3600秒。加入查询层过期行排除回归测试。
- 隔离实际运行 candidate（17600端口，生产库一致快照的独立拷贝）：单选、多选MCP与Web筛选结果均只含选择方法；33项返回HTTP400。每秒清理的独立 systemd 隔离实例中，注入一条-8天事件后约1秒内日志 `expired audit rows deleted removed=1`，该行消失，数据库 integrity_check=ok；测试 unit 已停止。
- 生产修改前备份目录 `/root/.hermes/profiles/ops/.ssh-connector/rollback-audit-fix-2026-10-01/`：旧0.1.2二进制、unit、config、env、audit/vault一致性SQLite备份。此前清理操作另有完整快照 `/root/.hermes/profiles/ops/.ssh-connector/audit/rollback-audit-cleanup-2026-10-01.sqlite3`，覆盖删除前2324行及591过期行，integrity_check=ok、权限0600。
- 生产SQLite过期清理：备份后事务删除591条严格超过7天记录，剩余1733条，删除后 integrity_check=ok。期间服务未停止；候选0.1.2修复二进制部署并重启后，systemd为active，API状态0.1.2，SQLite integrity_check=ok、事件1743、过期行0。
- 生产HTTP实测：`source=mcp&methods=host_list` 返回2条且仅 `host_list`；MCP多选返回所选集合；`source=web_api&methods=GET+status` 返回27条且仅 `GET status`；Web多选返回37条且仅 `GET hosts` / `GET status`；33项返回400。二进制与候选SHA256一致：`f667e9c2e3f2978f6efa3fb5ab20ae59725592155b788c1aa847706f90959167`。
- 全量 `cargo test --offline` **62 passed**；release构建、`node --check static/app.js`、`git diff --check`通过。`cargo fmt`/clippy仍未安装。真实浏览器视觉验收仍未做。
