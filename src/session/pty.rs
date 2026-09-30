//! Persistent PTY sessions. Each session owns a russh channel with a PTY and a
//! background actor task that pumps remote bytes into a [`TerminalEmulator`] and
//! a raw byte ring (for Web-UI takeover), and forwards stdin to the remote.
//!
//! Sessions are addressed by id and survive across many AI tool calls; this is
//! what gives the AI a stateful interactive shell instead of one-shot execs.

use crate::error::{ConnectorError, ErrorCode, Result};
use crate::ssh::Connection;
use crate::term::{TerminalEmulator, key_to_bytes};
use crate::types::{KeyName, ReadResult, ScreenSnapshot, SessionExecResult};
use russh::ChannelMsg;
use russh::client;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Notify, broadcast};
use tokio::time::Instant;

/// Commands sent to the PTY actor.
enum PtyCmd {
    /// Raw bytes to write to the remote stdin.
    Input(Vec<u8>),
    /// Resize the remote PTY and local emulator.
    Resize { rows: u16, cols: u16 },
}

/// Shared, lock-protected view of the terminal state the actor maintains.
struct PtyState {
    emulator: TerminalEmulator,
    /// Plain UTF-8 text appended since the session started (for line reads),
    /// capped to a recent window.
    text_tail: String,
    last_activity: Instant,
    closed: bool,
    /// Byte offset (in seq terms) consumed by the last incremental read.
    last_read_seq: u64,
}

/// Handle to a live PTY session, cloneable across tasks.
#[derive(Clone)]
pub struct PtyHandle {
    pub session_id: String,
    pub host_id: String,
    pub created_at: String,
    rows: Arc<Mutex<(u16, u16)>>,
    state: Arc<Mutex<PtyState>>,
    cmd_tx: tokio::sync::mpsc::Sender<PtyCmd>,
    /// Raw byte stream for Web-UI takeover (xterm.js).
    raw_tx: broadcast::Sender<Vec<u8>>,
    operation_lock: Arc<Mutex<()>>,
    executions: Arc<Mutex<ExecutionState>>,
}

const TEXT_TAIL_CAP: usize = 256 * 1024;
const EXEC_JOB_CAP: usize = 1024 * 1024;

struct ExecJob {
    output: Vec<u8>,
    cursor: usize,
    complete: bool,
    exit_code: Option<i32>,
    timed_out: bool,
    truncated: bool,
    had_invalid_utf8: bool,
    output_cap: usize,
    started_at: std::time::Instant,
    notify: Arc<Notify>,
}

#[derive(Default)]
struct ExecutionState {
    active: Option<String>,
    jobs: std::collections::HashMap<String, ExecJob>,
}

pub struct PtySession;

impl PtySession {
    /// Open a PTY on the connection and spawn its actor. Returns a handle.
    pub async fn open(
        conn: &Connection,
        session_id: String,
        host_id: String,
        rows: u16,
        cols: u16,
    ) -> Result<PtyHandle> {
        let channel = conn.open_channel().await?;
        channel
            .request_pty(true, "xterm-256color", cols as u32, rows as u32, 0, 0, &[])
            .await
            .map_err(|e| ConnectorError::internal(format!("request_pty: {e}")))?;
        channel
            .request_shell(true)
            .await
            .map_err(|e| ConnectorError::internal(format!("request_shell: {e}")))?;

        let created_at = now_rfc3339();
        let state = Arc::new(Mutex::new(PtyState {
            emulator: TerminalEmulator::new(rows, cols),
            text_tail: String::new(),
            last_activity: Instant::now(),
            closed: false,
            last_read_seq: 0,
        }));
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel::<PtyCmd>(64);
        let (raw_tx, _) = broadcast::channel::<Vec<u8>>(256);

        let handle = PtyHandle {
            session_id: session_id.clone(),
            host_id,
            created_at,
            rows: Arc::new(Mutex::new((rows, cols))),
            state: state.clone(),
            cmd_tx,
            raw_tx: raw_tx.clone(),
            operation_lock: Arc::new(Mutex::new(())),
            executions: Arc::new(Mutex::new(ExecutionState::default())),
        };

        tokio::spawn(pty_actor(channel, state, cmd_rx, raw_tx));
        Ok(handle)
    }

    /// Map a semantic key to bytes and queue it as input.
    pub async fn send_key(handle: &PtyHandle, key: &KeyName) -> Result<()> {
        handle.input(key_to_bytes(key)).await
    }
}

impl PtyHandle {
    /// Queue raw input bytes to the remote.
    pub async fn input(&self, bytes: Vec<u8>) -> Result<()> {
        if self.executions.lock().await.active.is_some() {
            return Err(ConnectorError::new(ErrorCode::SessionBusy, "session_exec is still running; poll its token first"));
        }
        let _guard = self.operation_lock.try_lock().map_err(|_| ConnectorError::new(ErrorCode::SessionBusy, "session_exec is using this PTY"))?;
        self.input_unlocked(bytes).await
    }

    async fn input_unlocked(&self, bytes: Vec<u8>) -> Result<()> {
        self.cmd_tx.send(PtyCmd::Input(bytes)).await
            .map_err(|_| ConnectorError::new(ErrorCode::Disconnected, "pty actor gone"))
    }

    pub async fn execute(&self, command: &str, wait: Duration, max_output_bytes: usize) -> Result<SessionExecResult> {
        if command.trim().is_empty() || command.contains(['\n', '\r', '\0']) {
            return Err(ConnectorError::bad_request("raw must be a non-empty single-line command"));
        }
        if max_output_bytes == 0 || max_output_bytes > EXEC_JOB_CAP {
            return Err(ConnectorError::bad_request(format!("max_output_bytes must be between 1 and {EXEC_JOB_CAP}")));
        }
        let _guard = self.operation_lock.try_lock().map_err(|_| ConnectorError::new(ErrorCode::SessionBusy, "another PTY operation is in progress"))?;
        let mut executions = self.executions.lock().await;
        if executions.active.is_some() {
            return Err(ConnectorError::new(ErrorCode::SessionBusy, "a session_exec command is still running"));
        }
        let rx = self.raw_tx.subscribe();
        let token = execution_token()?;
        let start = format!("\n__SSH_CONNECTOR_BEGIN_{token}__\n");
        let end = format!("\n__SSH_CONNECTOR_END_{token}__:");
        let command_line = format!(
            "printf '\\n__SSH_CONNECTOR_BEGIN_%s__\\n' '{token}'; eval {}; __ssh_connector_rc=$?; printf '\\n__SSH_CONNECTOR_END_%s__:%s\\n' '{token}' \"$__ssh_connector_rc\"\n",
            shell_quote(command)
        );
        let notify = Arc::new(Notify::new());
        drop(_guard);
        let started_at = std::time::Instant::now();
        executions.active = Some(token.clone());
        executions.jobs.insert(token.clone(), ExecJob {
            output: Vec::new(), cursor: 0, complete: false, exit_code: None, timed_out: false,
            truncated: false, had_invalid_utf8: false, output_cap: max_output_bytes,
            started_at, notify: notify.clone(),
        });
        drop(executions);
        if let Err(error) = self.input_unlocked(format!("{command_line}\n").into_bytes()).await {
            let mut state = self.executions.lock().await;
            state.active = None;
            state.jobs.remove(&token);
            return Err(error);
        }
        tokio::spawn(collect_exec(
            rx, self.executions.clone(), token.clone(), start.into_bytes(), end.into_bytes(), max_output_bytes,
        ));
        wait_exec(&self.executions, &token, wait).await;
        read_exec_result(&self.executions, &self.session_id, &token, Duration::ZERO).await
    }

    pub async fn read_execution(&self, token: &str, wait: Duration) -> Result<SessionExecResult> {
        read_exec_result(&self.executions, &self.session_id, token, wait).await
    }

    /// Send text (UTF-8) as input.
    pub async fn send_text(&self, text: &str) -> Result<()> {
        self.input(text.as_bytes().to_vec()).await
    }

    /// Resize the PTY.
    pub async fn resize(&self, rows: u16, cols: u16) -> Result<()> {
        let _guard = self.operation_lock.try_lock().map_err(|_| ConnectorError::new(ErrorCode::SessionBusy, "another PTY operation is in progress"))?;
        *self.rows.lock().await = (rows, cols);
        self.cmd_tx
            .send(PtyCmd::Resize { rows, cols })
            .await
            .map_err(|_| ConnectorError::new(ErrorCode::Disconnected, "pty actor gone"))
    }

    /// Current structured screen snapshot.
    pub async fn snapshot(&self) -> ScreenSnapshot {
        self.state.lock().await.emulator.snapshot()
    }

    /// Incremental text read since the last call: returns newly appended text.
    pub async fn read_new(&self) -> ReadResult {
        let mut st = self.state.lock().await;
        let seq = st.emulator.seq();
        // We approximate "new" as the full text tail when the caller hasn't read
        // since the last append; callers wanting precise diffs use snapshot.seq.
        let data = std::mem::take(&mut st.text_tail);
        let likely_waiting = guess_waiting(&data);
        st.last_read_seq = seq;
        ReadResult {
            data,
            seq,
            likely_waiting_input: likely_waiting,
            had_invalid_utf8: false,
        }
    }

    pub async fn is_closed(&self) -> bool {
        self.state.lock().await.closed
    }

    pub async fn idle_secs(&self) -> u64 {
        self.state.lock().await.last_activity.elapsed().as_secs()
    }

    pub async fn dims(&self) -> (u16, u16) {
        *self.rows.lock().await
    }

    /// Subscribe to the raw byte stream (Web-UI takeover).
    pub fn subscribe_raw(&self) -> broadcast::Receiver<Vec<u8>> {
        self.raw_tx.subscribe()
    }
}

async fn wait_exec(state: &Arc<Mutex<ExecutionState>>, token: &str, wait: Duration) {
    let notify = {
        let state = state.lock().await;
        state.jobs.get(token).map(|job| job.notify.clone())
    };
    if let Some(notify) = notify {
        let _ = tokio::time::timeout(wait, async {
            loop {
                let notified = notify.notified();
                tokio::pin!(notified);
                let done = {
                    let state = state.lock().await;
                    state.jobs.get(token).map(|job| job.complete).unwrap_or(true)
                };
                if done { break; }
                notified.await;
            }
        }).await;
    }
}

async fn read_exec_result(state: &Arc<Mutex<ExecutionState>>, session_id: &str, token: &str, wait: Duration) -> Result<SessionExecResult> {
    wait_exec(state, token, wait).await;
    let mut state = state.lock().await;
    let job = state.jobs.get_mut(token).ok_or_else(|| ConnectorError::bad_request("execution token not found or expired"))?;
    let output = job.output[job.cursor..].to_vec();
    job.cursor = job.output.len();
    let (output, had_invalid_utf8) = match std::str::from_utf8(&output) {
        Ok(text) => (text.to_string(), false),
        Err(_) => (String::from_utf8_lossy(&output).into_owned(), true),
    };
    let complete = job.complete;
    let result = SessionExecResult {
        session_id: session_id.to_string(), token: if complete { None } else { Some(token.to_string()) },
        output, exit_code: if complete { job.exit_code } else { None },
        duration_ms: job.started_at.elapsed().as_millis() as u64,
        timed_out: !complete, truncated: job.truncated, had_invalid_utf8: job.had_invalid_utf8 || had_invalid_utf8,
    };
    if complete {
        state.jobs.remove(token);
    }
    Ok(result)
}

async fn collect_exec(
    mut rx: broadcast::Receiver<Vec<u8>>, state: Arc<Mutex<ExecutionState>>, token: String,
    start: Vec<u8>, end: Vec<u8>, cap: usize,
) {
    let mut pending = Vec::new();
    let mut started = false;
    loop {
        let chunk = match rx.recv().await {
            Ok(chunk) => chunk,
            Err(broadcast::error::RecvError::Lagged(_)) => {
                finish_exec(&state, &token, None, true).await;
                return;
            }
            Err(broadcast::error::RecvError::Closed) => {
                finish_exec(&state, &token, None, true).await;
                return;
            }
        };
        pending.extend_from_slice(&chunk);
        pending.retain(|byte| *byte != b'\r');
        if !started {
            if let Some(pos) = find_bytes(&pending, &start) {
                pending.drain(..pos + start.len());
                started = true;
            } else {
                let keep = start.len().saturating_sub(1);
                if pending.len() > keep {
                    let n = pending.len() - keep;
                    pending.drain(..n);
                }
                continue;
            }
        }
        if let Some(pos) = find_bytes(&pending, &end) {
            append_exec_output(&state, &token, &pending[..pos], cap).await;
            let status = String::from_utf8_lossy(&pending[pos + end.len()..]).trim().lines().next().unwrap_or("").parse::<i32>().ok();
            if status.is_none() {
                finish_exec(&state, &token, None, true).await;
            } else {
                finish_exec(&state, &token, status, false).await;
            }
            return;
        }
        let keep = end.len().saturating_sub(1);
        if pending.len() > keep {
            let n = pending.len() - keep;
            append_exec_output(&state, &token, &pending[..n], cap).await;
            pending.drain(..n);
        }
    }
}

async fn append_exec_output(state: &Arc<Mutex<ExecutionState>>, token: &str, data: &[u8], _cap: usize) {
    let mut state = state.lock().await;
    if let Some(job) = state.jobs.get_mut(token) {
        let take = job.output_cap.saturating_sub(job.output.len()).min(data.len());
        job.output.extend_from_slice(&data[..take]);
        job.truncated |= take < data.len();
        job.notify.notify_waiters();
    }
}

async fn finish_exec(state: &Arc<Mutex<ExecutionState>>, token: &str, exit_code: Option<i32>, timed_out: bool) {
    let mut state = state.lock().await;
    if let Some(job) = state.jobs.get_mut(token) {
        job.complete = timed_out || exit_code.is_some();
        job.exit_code = exit_code;
        job.timed_out = timed_out;

        job.notify.notify_waiters();
    }
    if state.active.as_deref() == Some(token) && (timed_out || exit_code.is_some()) { state.active = None; }
}

fn execution_token() -> Result<String> {
    let mut b=[0u8;16]; getrandom::fill(&mut b).map_err(|e| ConnectorError::internal(format!("marker RNG: {e}")))?;
    Ok(b.iter().map(|x|format!("{x:02x}")).collect())
}
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
fn find_bytes(data:&[u8], needle:&[u8])->Option<usize> { data.windows(needle.len()).position(|x|x==needle) }

/// Heuristic: output ends without a trailing newline and looks like a prompt.
fn guess_waiting(text: &str) -> bool {
    let t = text.trim_end_matches([' ', '\t']);
    let last = t.lines().last().unwrap_or("");
    last.ends_with("$ ")
        || last.ends_with("# ")
        || last.ends_with("> ")
        || last.ends_with('$')
        || last.ends_with('#')
        || last.to_lowercase().contains("password")
        || last.ends_with(": ")
}

async fn pty_actor(
    channel: russh::Channel<client::Msg>,
    state: Arc<Mutex<PtyState>>,
    mut cmd_rx: tokio::sync::mpsc::Receiver<PtyCmd>,
    raw_tx: broadcast::Sender<Vec<u8>>,
) {
    let mut channel = channel;
    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(PtyCmd::Input(bytes)) => {
                        let _ = channel.data_bytes(bytes).await;
                        state.lock().await.last_activity = Instant::now();
                    }
                    Some(PtyCmd::Resize { rows, cols }) => {
                        let _ = channel.window_change(cols as u32, rows as u32, 0, 0).await;
                        state.lock().await.emulator.resize(rows, cols);
                    }
                    None => {
                        // All handles dropped; tear down.
                        let _ = channel.close().await;
                        break;
                    }
                }
            }
            msg = channel.wait() => {
                let Some(msg) = msg else {
                    state.lock().await.closed = true;
                    break;
                };
                match msg {
                    ChannelMsg::Data { ref data } => {
                        feed(&state, &raw_tx, data).await;
                    }
                    ChannelMsg::ExtendedData { ref data, .. } => {
                        feed(&state, &raw_tx, data).await;
                    }
                    ChannelMsg::Eof | ChannelMsg::Close => {
                        state.lock().await.closed = true;
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn feed(state: &Arc<Mutex<PtyState>>, raw_tx: &broadcast::Sender<Vec<u8>>, data: &[u8]) {
    let mut st = state.lock().await;
    st.emulator.process(data);
    let (chunk, _) = match std::str::from_utf8(data) {
        Ok(s) => (s.to_string(), false),
        Err(_) => (String::from_utf8_lossy(data).into_owned(), true),
    };
    st.text_tail.push_str(&chunk);
    trim_text_tail(&mut st.text_tail);
    st.last_activity = Instant::now();
    // Best-effort broadcast to any Web-UI subscribers.
    let _ = raw_tx.send(data.to_vec());
}

fn trim_text_tail(text: &mut String) {
    if text.len() <= TEXT_TAIL_CAP {
        return;
    }
    let mut cut = text.len() - TEXT_TAIL_CAP;
    while !text.is_char_boundary(cut) {
        cut += 1;
    }
    text.drain(..cut);
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn execution_result_returns_token_then_incremental_output_and_exit() {
        let state = Arc::new(Mutex::new(ExecutionState::default()));
        let notify = Arc::new(Notify::new());
        state.lock().await.jobs.insert("opaque".into(), ExecJob {
            output: b"part".to_vec(), cursor: 0, complete: false, exit_code: None, timed_out: false,
            truncated: false, had_invalid_utf8: false, output_cap: EXEC_JOB_CAP, started_at: std::time::Instant::now(), notify,
        });
        let first = read_exec_result(&state, "s-test", "opaque", Duration::ZERO).await.unwrap();
        assert_eq!(first.output, "part");
        assert_eq!(first.token.as_deref(), Some("opaque"));
        assert!(first.timed_out);
        {
            let mut state = state.lock().await;
            let job = state.jobs.get_mut("opaque").unwrap();
            job.output.extend_from_slice(b"ial");
            job.complete = true;
            job.exit_code = Some(7);
        }
        let final_result = read_exec_result(&state, "s-test", "opaque", Duration::ZERO).await.unwrap();
        assert_eq!(final_result.output, "ial");
        assert_eq!(final_result.exit_code, Some(7));
        assert_eq!(final_result.token, None);
        assert!(!final_result.timed_out);
        assert!(state.lock().await.jobs.is_empty());
    }

    #[test]
    fn trims_multibyte_text_on_utf8_boundary() {
        let mut text = format!("prefix{}suffix", "中".repeat(TEXT_TAIL_CAP));
        trim_text_tail(&mut text);
        assert!(text.len() <= TEXT_TAIL_CAP);
        assert!(text.ends_with("suffix"));
        assert!(std::str::from_utf8(text.as_bytes()).is_ok());
    }
}
