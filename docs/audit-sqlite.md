# Audit SQLite rollout notes / 审计 SQLite 实施说明

## English

The daemon stores new audit events in `data_dir/audit/audit.sqlite3` (SQLite WAL, local file). Startup retains and imports parseable legacy JSONL events from the rolling seven-day UTC window. Source JSONL files are never deleted by migration. Events older than exactly 7×24 hours are pruned at startup and hourly (override with `SSH_CONNECTOR_AUDIT_PRUNE_INTERVAL_SECS`); expired events are also excluded from queries. This database is not tamper-proof/WORM storage.

`GET /api/audit` remains compatible with `?limit=N` (default 200; maximum 500). Filters: `from`, `to` (RFC3339 timestamps), `method`, repeated `methods` parameters (OR/union semantics, maximum 32), `source`, `host_id`, `session_id`, `status`, `error_code`; sort allowlist: `ts_utc`, `id`, `method`, `source`, `host_id`, `session_id`, `status`, `error_code`; `order=asc|desc`; `cursor` for stable timestamp/id pagination (cursor paging requires `sort_by=ts_utc`). The default window is the most recent seven days and wider or expired ranges are rejected. A response includes `entries` and `next_cursor`.

Sensitive material must never be copied into audit records. Legacy event detail is filtered and bounded. Credential reveal and other arbitrary binary/text bodies must only be represented by safe metadata. Streaming WebSocket frame content is excluded; only lifecycle metadata belongs in audit.

## 中文

新事件写入 `data_dir/audit/audit.sqlite3`（SQLite WAL，本地单文件）。启动时仅迁入 UTC 滚动 7×24 小时内可解析的旧 JSONL 事件，迁移不会删除或改写 JSONL 原件。启动时及每小时清理超过 7×24 小时的记录（可用 `SSH_CONNECTOR_AUDIT_PRUNE_INTERVAL_SECS` 覆盖周期），查询也排除过期区间。SQLite 本身不是防篡改/WORM 审计仓库。

`GET /api/audit` 兼容旧 `?limit=N`（默认 200，最大 500）。可筛选 `from`、`to`（RFC3339）、`method`、重复的 `methods` 参数（OR/并集语义，最多32项）、`source`、`host_id`、`session_id`、`status`、`error_code`；排序白名单为 `ts_utc`、`id`、`method`、`source`、`host_id`、`session_id`、`status`、`error_code`；支持 `order=asc|desc` 和稳定时间/id 游标分页（游标分页要求 `sort_by=ts_utc`）。默认窗口是最近 7 天；超过保留期或跨度过大的查询会被拒绝。响应含 `entries` 与 `next_cursor`。

审计不得复制秘密明文。旧 detail 导入时会过滤并限制大小。凭据 reveal 和任意二进制/文本正文只能记安全元数据；WebSocket 流式帧正文不入库，仅记录生命周期元数据。

> 实现状态说明：本文描述目标接口与策略；逐一覆盖所有 MCP/Web handler、实际服务迁移和生产验收必须以自动化测试及运行证据为准。
