//! Tailscale host checks and certificate access through tailscaled's LocalAPI.

use ferron_core::config::{ServerConfiguration, ServerConfigurationBlock};
use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::time::Instant;

const MAX_RESPONSE: usize = 1024 * 1024;
const STATUS_TIMEOUT: Duration = Duration::from_secs(30);
const CERT_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const DEFAULT_LOGIN_TIMEOUT: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Copy)]
enum LocalApiOperation {
    Status,
    Certificate,
}

impl LocalApiOperation {
    fn timeout(self) -> Duration {
        match self {
            Self::Status => STATUS_TIMEOUT,
            Self::Certificate => CERT_TIMEOUT,
        }
    }
}

fn localapi_io_error(error: std::io::Error, phase: &str, path: &str, timeout: Duration) -> String {
    if matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) {
        format!(
            "LocalAPI {phase} timed out for {path} after {}s",
            timeout.as_secs()
        )
    } else {
        format!("LocalAPI {phase} failed for {path}: {error}")
    }
}

pub fn parse_tailscale_host(host: &str) -> Option<(String, String)> {
    if host.len() > 253 {
        return None;
    }
    let lower = host.to_ascii_lowercase();
    let prefix = lower.strip_suffix(".ts.net")?;
    let (name, tailnet) = prefix.split_once('.')?;
    if name.is_empty()
        || tailnet.is_empty()
        || tailnet.contains('.')
        || ![name, tailnet].iter().all(|part| {
            part.len() <= 63
                && part
                    .bytes()
                    .next()
                    .is_some_and(|b| b.is_ascii_alphanumeric())
                && part
                    .bytes()
                    .last()
                    .is_some_and(|b| b.is_ascii_alphanumeric())
                && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return None;
    }
    Some((name.to_string(), tailnet.to_string()))
}

fn tls_block(block: &ServerConfigurationBlock) -> Option<&ServerConfigurationBlock> {
    let entries = block.directives.get("tls")?;
    if entries.len() != 1 {
        return None;
    }
    entries[0].children.as_ref()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeSocket {
    Managed,
    External(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    pub machine: String,
    pub tailnet: String,
    pub socket: NodeSocket,
}

pub fn managed_socket(machine: &str, tailnet: &str) -> PathBuf {
    let base = std::env::var("TS_SOCKET_DIR").unwrap_or_else(|_| "/var/run/tailscale".into());
    PathBuf::from(base).join(format!("{machine}-{tailnet}.sock"))
}

/// Inventory only: no daemon startup, filesystem changes, or certificate requests.
pub fn inventory(config: &ServerConfiguration) -> Result<BTreeMap<String, Node>, String> {
    let mut nodes: BTreeMap<String, Node> = BTreeMap::new();
    for ports in config.ports.values() {
        for port in ports {
            for (filter, block) in &port.hosts {
                let Some(host) = filter.host.as_deref() else {
                    continue;
                };
                if !host.to_ascii_lowercase().ends_with(".ts.net") {
                    continue;
                }
                let (machine, current) = parse_tailscale_host(host)
                    .ok_or_else(|| format!("invalid Tailscale hostname: {host}"))?;
                let selected = tls_block(block);
                if selected
                    .and_then(|tls| tls.get_value("provider"))
                    .and_then(|value| value.as_str())
                    != Some("tailscale")
                {
                    return Err(format!(
                        "{host}: ts.net hosts must select `tls {{ provider tailscale }}`"
                    ));
                }
                let socket = selected
                    .and_then(|tls| tls.get_value("socket"))
                    .map(|value| {
                        value
                            .as_string_with_interpolations(&HashMap::new())
                            .filter(|value| !value.trim().is_empty())
                            .map(|value| NodeSocket::External(value.trim().into()))
                            .ok_or_else(|| format!("{host}: invalid TLS socket"))
                    })
                    .transpose()?
                    .unwrap_or(NodeSocket::Managed);
                let key = format!("{machine}.{current}.ts.net");
                let node = Node {
                    machine,
                    tailnet: current,
                    socket,
                };
                match nodes.get(&key) {
                    Some(existing) if existing.socket != node.socket => {
                        // A socket supplied on any occurrence always takes precedence over inference.
                        match (&existing.socket, &node.socket) {
                            (NodeSocket::Managed, NodeSocket::External(_)) => {
                                nodes.insert(key, node);
                            }
                            (NodeSocket::External(_), NodeSocket::Managed) => {}
                            _ => return Err(format!("conflicting Tailscale sockets for {key}")),
                        }
                    }
                    None => {
                        nodes.insert(key, node);
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(nodes)
}

/// Resolves the auth key for a tailnet: `TS_AUTHKEY_<TAILNET>` (uppercased) wins over
/// the process-wide `TS_AUTHKEY`. Tailscale auth keys are scoped to a single tailnet,
/// so distinct tailnets each need their own key. Returns an empty string when unset.
fn authkey_for(tailnet: &str) -> String {
    let specific = format!("TS_AUTHKEY_{}", tailnet.to_ascii_uppercase());
    resolve_authkey(
        std::env::var(&specific).ok(),
        std::env::var("TS_AUTHKEY").ok(),
    )
}

fn resolve_authkey(specific: Option<String>, fallback: Option<String>) -> String {
    specific.or(fallback).unwrap_or_default()
}

/// Owns only the daemons it starts. Add-only on reload; dropping the final manager kills them.
pub struct OwnedChild(Mutex<Option<Child>>);

impl Default for OwnedChild {
    fn default() -> Self {
        Self(Mutex::new(None))
    }
}

impl OwnedChild {
    pub fn is_unstarted(&self) -> bool {
        self.0.lock().is_ok_and(|owned| owned.is_none())
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Ok(owned) = self.0.get_mut()
            && let Some(child) = owned.as_mut()
        {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[derive(Default)]
pub struct NodeManager {
    nodes: BTreeMap<String, (Node, Arc<OwnedChild>)>,
}

impl NodeManager {
    pub fn socket_for(&self, host: &str) -> Option<String> {
        let (machine, tailnet) = parse_tailscale_host(host)?;
        let node = self
            .nodes
            .get(&format!("{machine}.{tailnet}.ts.net"))?
            .0
            .clone();
        match node.socket {
            NodeSocket::External(socket) => Some(socket),
            NodeSocket::Managed => Some(
                managed_socket(&machine, &tailnet)
                    .to_string_lossy()
                    .into_owned(),
            ),
        }
    }

    pub fn reconcile(&mut self, requested: BTreeMap<String, Node>) -> Result<(), String> {
        for (name, node) in &requested {
            if let Some((previous, child)) = self.nodes.get_mut(name) {
                if previous != node {
                    return Err(format!(
                        "Tailscale node {name} changed on reload; restart required"
                    ));
                }
                match child.0.try_lock() {
                    Ok(mut owned) => {
                        if owned
                            .as_mut()
                            .is_some_and(|process| !matches!(process.try_wait(), Ok(None)))
                        {
                            return Err(format!(
                                "managed tailscaled for {name} exited or could not be checked; restart Ferron"
                            ));
                        }
                    }
                    Err(std::sync::TryLockError::WouldBlock) => {
                        // An active worker owns this child; registration never waits for it.
                    }
                    Err(std::sync::TryLockError::Poisoned(_)) => {
                        return Err(format!(
                            "managed tailscaled for {name} could not be checked; restart Ferron"
                        ));
                    }
                }
            }
        }
        for (name, node) in requested {
            if self.nodes.contains_key(&name) {
                continue;
            }
            self.nodes
                .insert(name, (node, Arc::new(OwnedChild::default())));
        }
        Ok(())
    }

    pub fn node(&self, host: &str) -> Option<(Node, Arc<OwnedChild>)> {
        self.nodes.get(host).cloned()
    }
}

/// Blocking worker-only operation; never called from registration or a TLS handshake.
pub fn provision(node: &Node, child: &OwnedChild) -> Result<(String, String), String> {
    let socket = match &node.socket {
        NodeSocket::External(path) => path.clone(),
        NodeSocket::Managed => {
            if std::env::var_os("TS_MANAGED_TAILSCALE").is_none() {
                return Err("managed tailscaled requires runtime-tailscale image".into());
            }
            let needs_start = {
                let mut owned = child.0.lock().map_err(|_| "managed child lock poisoned")?;
                match owned.as_mut() {
                    Some(existing) => {
                        if !matches!(existing.try_wait(), Ok(None)) {
                            return Err("managed tailscaled exited; restart Ferron".into());
                        }
                        false
                    }
                    None => true,
                }
            };
            if needs_start {
                let started = start_node(node)?;
                *child.0.lock().map_err(|_| "managed child lock poisoned")? = Some(started);
            }
            managed_socket(&node.machine, &node.tailnet)
                .to_string_lossy()
                .into_owned()
        }
    };
    let client = LocalApiClient::connect(&socket)?;
    client.fetch_cert(&format!("{}.{}.ts.net", node.machine, node.tailnet))
}

struct CommandResult {
    stdout: String,
    success: bool,
}

fn command_output(mut cmd: Command) -> Result<CommandResult, String> {
    cmd.stderr(Stdio::null()).stdout(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Tailscale command could not start: {e}"))?;
    // Drain concurrently so a large status response cannot block child termination.
    let mut stdout = child
        .stdout
        .take()
        .ok_or("missing Tailscale command stdout")?;
    let reader = thread::spawn(move || {
        let mut output = Vec::new();
        let mut chunk = [0_u8; 8192];
        loop {
            let count = stdout.read(&mut chunk).map_err(|e| e.to_string())?;
            if count == 0 {
                break;
            }
            if output.len() < MAX_RESPONSE {
                output.extend_from_slice(&chunk[..count.min(MAX_RESPONSE - output.len())]);
            }
        }
        String::from_utf8(output).map_err(|e| e.to_string())
    });
    let deadline = Instant::now() + Duration::from_secs(30);
    let result = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                break Ok(status.success());
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break Err("Tailscale command timed out or failed".into());
            }
        }
    };
    let output = reader
        .join()
        .map_err(|_| "Tailscale command reader failed")??;
    result.map(|success| CommandResult {
        stdout: output,
        success,
    })
}

fn require_success(result: CommandResult) -> Result<(), String> {
    if result.success {
        Ok(())
    } else {
        Err("Tailscale command failed".into())
    }
}

fn parse_status(result: CommandResult) -> Result<serde_json::Value, String> {
    serde_json::from_str(&result.stdout)
        .map_err(|_| "tailscale status did not return parseable JSON".into())
}

fn status(socket: &std::path::Path) -> Result<serde_json::Value, String> {
    let mut cmd = Command::new("tailscale");
    cmd.arg(format!("--socket={}", socket.display()))
        .args(["status", "--json"]);
    parse_status(command_output(cmd)?)
}

fn verify_cert_domains(status: &serde_json::Value, expected: &str) -> Result<(), String> {
    let available: Vec<&str> = status["CertDomains"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .collect();
    if status["BackendState"] == "Running"
        && available
            .iter()
            .any(|domain| domain.trim_end_matches('.').eq_ignore_ascii_case(expected))
    {
        return Ok(());
    }
    Err(format!(
        "tailscaled must be Running and authorize {expected} in CertDomains; BackendState: {}, available CertDomains: {}",
        status["BackendState"],
        serde_json::to_string(&available).unwrap_or_else(|_| "[]".into())
    ))
}

fn wait_for_cert_domains(
    node: &Node,
    socket: &std::path::Path,
    child: &mut Child,
) -> Result<(), String> {
    let expected = format!("{}.{}.ts.net", node.machine, node.tailnet);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if !matches!(child.try_wait(), Ok(None)) {
            return Err(format!(
                "tailscaled exited while waiting for CertDomains to authorize {expected}"
            ));
        }
        let result = status(socket).and_then(|current| verify_cert_domains(&current, &expected));
        if result.is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for {expected}: {}",
                result.unwrap_err()
            ));
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn up_args(node: &Node, socket: &std::path::Path, authkey: Option<&str>) -> Vec<String> {
    let mut args = vec![
        format!("--socket={}", socket.display()),
        "up".into(),
        format!("--hostname={}", node.machine),
        "--accept-dns=false".into(),
    ];
    if let Some(authkey) = authkey {
        args.push(format!("--authkey={authkey}"));
    }
    args
}

fn set_args(node: &Node, socket: &std::path::Path) -> Vec<String> {
    vec![
        format!("--socket={}", socket.display()),
        "set".into(),
        format!("--hostname={}", node.machine),
    ]
}

fn login_args(node: &Node, socket: &std::path::Path) -> Vec<String> {
    up_args(node, socket, None)
}

/// Extracts an interactive authentication or machine-approval URL from a
/// `tailscale up` output line.
fn parse_login_url(line: &str) -> Option<&str> {
    let start = line.find("https://login.tailscale.com/")?;
    let rest = &line[start..];
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    Some(&rest[..end])
}

fn login_timeout() -> Result<Duration, String> {
    let Some(raw) = std::env::var_os("TS_LOGIN_TIMEOUT") else {
        return Ok(DEFAULT_LOGIN_TIMEOUT);
    };
    let seconds: u64 = raw
        .to_string_lossy()
        .trim()
        .parse()
        .map_err(|_| "invalid TS_LOGIN_TIMEOUT (expected seconds)".to_string())?;
    if seconds == 0 {
        return Err("invalid TS_LOGIN_TIMEOUT".into());
    }
    Ok(Duration::from_secs(seconds))
}

/// Interactive registration: run `tailscale up` without an auth key, print the
/// authentication URL it emits to the operator log (stderr only; the URL is a
/// quasi-credential and never enters returned errors or TLS background
/// diagnostics), and wait for the browser login to complete. Remaining startup
/// (CertDomains and Serve) is handled by the caller like any other login.
fn login_interactive(
    node: &Node,
    socket: &std::path::Path,
    child: &mut Child,
) -> Result<(), String> {
    let expected = format!("{}.{}.ts.net", node.machine, node.tailnet);
    let timeout = login_timeout()?;
    let mut login = Command::new("tailscale")
        .args(login_args(node, socket))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not start tailscale login: {e}"))?;
    // Drain both pipes concurrently, printing each URL as soon as it appears,
    // so the login command can never block on a full pipe.
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let stdout = login.stdout.take();
    let stderr = login.stderr.take();
    let pipes: Vec<Box<dyn Read + Send>> = stdout
        .map(|pipe| Box::new(pipe) as Box<dyn Read + Send>)
        .into_iter()
        .chain(stderr.map(|pipe| Box::new(pipe) as Box<dyn Read + Send>))
        .collect();
    let mut readers = Vec::with_capacity(pipes.len());
    for pipe in pipes {
        let seen = Arc::clone(&seen);
        let expected = expected.clone();
        readers.push(thread::spawn(move || {
            for line in std::io::BufReader::new(pipe).lines() {
                let Ok(line) = line else { break };
                let Some(url) = parse_login_url(&line) else {
                    continue;
                };
                let mut seen = seen.lock().expect("login URL list lock");
                if !seen.iter().any(|seen| seen == url) {
                    seen.push(url.to_string());
                    drop(seen);
                    eprintln!("tailscale: {expected} awaiting authentication; visit {url}");
                }
            }
        }));
    }
    let deadline = Instant::now() + timeout;
    let result = loop {
        if !matches!(child.try_wait(), Ok(None)) {
            break Err("tailscaled exited while waiting for interactive login".into());
        }
        match login.try_wait() {
            Ok(Some(status)) if status.success() => {
                break Ok(());
            }
            Ok(Some(_)) => {
                break Err("interactive login failed; the login URL, if any, was printed to the Ferron log".into());
            }
            Ok(None) => {}
            Err(_) => {
                break Err("could not check interactive login status".into());
            }
        }
        if Instant::now() >= deadline {
            break Err(format!(
                "interactive login for {expected} did not complete within {}s; the login URL was printed to the Ferron log",
                timeout.as_secs()
            ));
        }
        thread::sleep(Duration::from_millis(250));
    };
    let _ = login.kill();
    let _ = login.wait();
    for reader in readers {
        let _ = reader.join();
    }
    result
}

fn daemon_args(state_dir: &std::path::Path, socket: &std::path::Path) -> [String; 4] {
    [
        format!("--state={}", state_dir.join("tailscaled.state").display()),
        format!("--statedir={}", state_dir.display()),
        format!("--socket={}", socket.display()),
        "--tun=userspace-networking".into(),
    ]
}

fn start_node(node: &Node) -> Result<Child, String> {
    let socket = managed_socket(&node.machine, &node.tailnet);
    let state_base = std::env::var("TS_STATE_DIR").unwrap_or_else(|_| "/var/lib/tailscale".into());
    let state_dir = PathBuf::from(state_base).join(format!("{}-{}", node.machine, node.tailnet));
    std::fs::create_dir_all(&state_dir).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(socket.parent().ok_or("invalid socket path")?)
        .map_err(|e| e.to_string())?;
    let mut child = Command::new("tailscaled")
        .args(daemon_args(&state_dir, &socket))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("could not start tailscaled: {e}"))?;
    let setup = (|| {
        let deadline = Instant::now() + Duration::from_secs(30);
        while std::os::unix::net::UnixStream::connect(&socket).is_err() {
            if child.try_wait().map_err(|e| e.to_string())?.is_some() || Instant::now() >= deadline
            {
                return Err("tailscaled socket did not become ready".into());
            }
            thread::sleep(Duration::from_millis(100));
        }
        let current = status(&socket)?;
        if current["BackendState"] != "Running" {
            // Never pass auth keys to a shell, logs, or returned command errors.
            if std::env::var_os("TS_EXTRA_ARGS").is_some() {
                return Err(
                    "TS_EXTRA_ARGS is unsupported; use a pre-authenticated state instead".into(),
                );
            }
            let authkey = authkey_for(&node.tailnet);
            if authkey.is_empty() {
                // Interactive registration: surface the login URL to the
                // operator log, then wait for the browser login to complete.
                // The URL is a quasi-credential: it goes to stderr only,
                // never into returned errors or TLS background diagnostics.
                login_interactive(node, &socket, &mut child)?;
            } else {
                let mut cmd = Command::new("tailscale");
                cmd.args(up_args(node, &socket, Some(&authkey)));
                require_success(command_output(cmd)?)?;
            }
        } else if verify_cert_domains(
            &current,
            &format!("{}.{}.ts.net", node.machine, node.tailnet),
        )
        .is_err()
        {
            // Persisted state may have a generated hostname; set renames it without reauthenticating.
            let mut cmd = Command::new("tailscale");
            cmd.args(set_args(node, &socket));
            require_success(command_output(cmd)?)?;
        }
        wait_for_cert_domains(node, &socket, &mut child)?;
        let port = std::env::var("TS_FERRON_HTTPS_PORT").unwrap_or_else(|_| "8443".into());
        let port: u16 = port
            .parse()
            .map_err(|_| "invalid TS_FERRON_HTTPS_PORT".to_string())?;
        if port == 0 {
            return Err("invalid TS_FERRON_HTTPS_PORT".into());
        }
        let mut cmd = Command::new("tailscale");
        cmd.arg(format!("--socket={}", socket.display())).args([
            "serve",
            "--bg",
            "--tcp=443",
            &format!("tcp://127.0.0.1:{port}"),
        ]);
        require_success(command_output(cmd)?)?;
        Ok(())
    })();
    if setup.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    setup.map(|()| child)
}

pub struct LocalApiClient {
    socket: String,
}

impl LocalApiClient {
    pub fn connect(socket: &str) -> Result<Self, String> {
        let socket = socket.trim();
        if socket.is_empty() {
            return Err("Tailscale socket is required".into());
        }
        let client = Self {
            socket: socket.to_string(),
        };
        let status = client.request("/localapi/v0/status", LocalApiOperation::Status)?;
        let json: serde_json::Value = serde_json::from_str(&status).map_err(|e| e.to_string())?;
        if json["BackendState"] != "Running" {
            return Err(format!(
                "tailscaled is not Running (BackendState: {})",
                json["BackendState"]
            ));
        }
        Ok(client)
    }

    pub fn fetch_cert(&self, host: &str) -> Result<(String, String), String> {
        let (machine, tailnet) = parse_tailscale_host(host)
            .ok_or_else(|| format!("invalid Tailscale hostname: {host}"))?;
        let expected = format!("{machine}.{tailnet}.ts.net");
        let status: serde_json::Value =
            serde_json::from_str(&self.request("/localapi/v0/status", LocalApiOperation::Status)?)
                .map_err(|e| format!("invalid LocalAPI status: {e}"))?;
        verify_cert_domains(&status, &expected)?;
        let path = format!("/localapi/v0/cert/{}?type=pair", expected);
        split_cert_pair(&self.request(&path, LocalApiOperation::Certificate)?)
    }

    fn request(&self, path: &str, operation: LocalApiOperation) -> Result<String, String> {
        let timeout = operation.timeout();
        let deadline = Instant::now() + timeout;
        let mut stream = std::os::unix::net::UnixStream::connect(&self.socket)
            .map_err(|e| localapi_io_error(e, "connect", path, timeout))?;
        stream
            .set_write_timeout(Some(remaining_timeout(deadline, path, "write", timeout)?))
            .map_err(|e| localapi_io_error(e, "set write timeout", path, timeout))?;
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: local-tailscaled.sock\r\nConnection: close\r\n\r\n"
        )
        .map_err(|e| localapi_io_error(e, "write", path, timeout))?;
        let mut bytes = Vec::new();
        loop {
            stream
                .set_read_timeout(Some(remaining_timeout(deadline, path, "read", timeout)?))
                .map_err(|e| localapi_io_error(e, "set read timeout", path, timeout))?;
            let mut chunk = [0_u8; 8192];
            let limit = chunk.len().min(MAX_RESPONSE + 1 - bytes.len());
            let read = stream
                .read(&mut chunk[..limit])
                .map_err(|e| localapi_io_error(e, "read", path, timeout))?;
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..read]);
            if bytes.len() > MAX_RESPONSE {
                return Err("LocalAPI response too large".into());
            }
        }
        parse_response(&bytes)
    }
}

fn remaining_timeout(
    deadline: Instant,
    path: &str,
    phase: &str,
    timeout: Duration,
) -> Result<Duration, String> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| {
            format!(
                "LocalAPI {phase} timed out for {path} after {}s",
                timeout.as_secs()
            )
        })
}

fn parse_response(bytes: &[u8]) -> Result<String, String> {
    let response = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .ok_or("malformed HTTP response")?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or("malformed HTTP status")?;
    let body = if headers.lines().any(|line| {
        line.to_ascii_lowercase()
            .starts_with("transfer-encoding: chunked")
    }) {
        decode_chunked(body)?
    } else {
        body.to_string()
    };
    if status != 200 {
        return Err(format!("LocalAPI HTTP {status}"));
    }
    Ok(body)
}

fn decode_chunked(mut body: &str) -> Result<String, String> {
    let mut result = String::new();
    loop {
        let (size, rest) = body.split_once("\r\n").ok_or("missing chunk size")?;
        let size = usize::from_str_radix(size.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|e| e.to_string())?;
        if size == 0 {
            return Ok(result);
        }
        let chunk = rest.get(..size).ok_or("truncated chunk")?;
        result.push_str(chunk);
        body = rest
            .get(size..)
            .and_then(|tail| tail.strip_prefix("\r\n"))
            .ok_or("invalid chunk terminator")?;
    }
}

fn split_cert_pair(body: &str) -> Result<(String, String), String> {
    let key_type = ["PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY"]
        .into_iter()
        .find(|kind| body.starts_with(&format!("-----BEGIN {kind}-----\n")))
        .ok_or("expected private key first")?;
    let end = format!("-----END {key_type}-----");
    let boundary = body.find(&end).ok_or("missing private key end")? + end.len();
    let (key, certs) = body.split_at(boundary);
    let certs = certs
        .strip_prefix('\n')
        .ok_or("missing certificate boundary")?;
    if !certs.starts_with("-----BEGIN CERTIFICATE-----\n") || certs.contains("PRIVATE KEY-----") {
        return Err("invalid certificate chain".into());
    }
    Ok((certs.to_string(), key.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferron_core::config::{
        ServerConfigurationDirectiveEntry, ServerConfigurationHostFilters, ServerConfigurationPort,
        ServerConfigurationValue,
    };
    use std::sync::Arc;

    fn tls_block(name: &str) -> ServerConfigurationBlock {
        let child = ServerConfigurationBlock {
            directives: Arc::new(
                [(
                    "provider".into(),
                    vec![ServerConfigurationDirectiveEntry {
                        args: vec![ServerConfigurationValue::String(name.into(), None)],
                        ..Default::default()
                    }],
                )]
                .into_iter()
                .collect(),
            ),
            ..Default::default()
        };
        ServerConfigurationBlock {
            directives: Arc::new(
                [(
                    "tls".into(),
                    vec![ServerConfigurationDirectiveEntry {
                        children: Some(child),
                        ..Default::default()
                    }],
                )]
                .into_iter()
                .collect(),
            ),
            ..Default::default()
        }
    }

    #[test]
    fn ts_net_hosts_require_tailscale_provider() {
        let mut config = ServerConfiguration::default();
        let host = |name: &str, block| {
            (
                ServerConfigurationHostFilters {
                    host: Some(name.into()),
                    ip: None,
                },
                block,
            )
        };
        config.ports.insert(
            "http".into(),
            vec![ServerConfigurationPort {
                port: Some(8443),
                hosts: vec![host(
                    "a.example.ts.net",
                    ServerConfigurationBlock::default(),
                )],
            }],
        );
        assert!(inventory(&config).unwrap_err().contains("must select"));
        config.global_config = Arc::new(tls_block("tailscale"));
        assert!(inventory(&config).unwrap_err().contains("must select"));
        config.ports.get_mut("http").unwrap()[0].hosts[0] =
            host("a.example.ts.net", tls_block("tailscale"));
        assert_eq!(inventory(&config).unwrap().len(), 1);
        config.ports.get_mut("http").unwrap()[0]
            .hosts
            .push(host("b.other.ts.net", tls_block("tailscale")));
        // Multiple tailnets are now supported; both nodes are inventoried.
        assert_eq!(inventory(&config).unwrap().len(), 2);
        config.ports.get_mut("http").unwrap()[0].hosts[1] =
            host("b.example.ts.net", tls_block("acme"));
        assert!(inventory(&config).unwrap_err().contains("must select"));
    }

    #[test]
    fn authkey_resolution_prefers_tailnet_specific_key() {
        assert_eq!(
            resolve_authkey(Some("dojo-key".into()), Some("shared-key".into())),
            "dojo-key"
        );
        assert_eq!(
            resolve_authkey(None, Some("shared-key".into())),
            "shared-key"
        );
        assert_eq!(resolve_authkey(None, None), "");
        assert_eq!(
            resolve_authkey(Some(String::new()), Some("shared-key".into())),
            ""
        );
    }
    #[test]
    fn key_first_with_chain() {
        let body = "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nissuer\n-----END CERTIFICATE-----\n";
        let (cert, key) = split_cert_pair(body).unwrap();
        assert_eq!(cert.matches("BEGIN CERTIFICATE").count(), 2);
        assert!(key.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(split_cert_pair("-----BEGIN CERTIFICATE-----\ncert").is_err());
    }
    #[test]
    fn http_errors_and_chunked_response() {
        assert!(
            parse_response(b"HTTP/1.1 403 Forbidden\r\n\r\npermission denied")
                .unwrap_err()
                .contains("403")
        );
        assert_eq!(
            parse_response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n0\r\n\r\n"
            )
            .unwrap(),
            "Wiki"
        );
    }

    #[test]
    fn localapi_timeouts_and_errors_are_contextual() {
        assert_eq!(LocalApiOperation::Status.timeout(), Duration::from_secs(30));
        assert_eq!(
            LocalApiOperation::Certificate.timeout(),
            Duration::from_secs(300)
        );
        let path = "/localapi/v0/cert/a.example.ts.net?type=pair";
        for kind in [std::io::ErrorKind::WouldBlock, std::io::ErrorKind::TimedOut] {
            let message = localapi_io_error(
                std::io::Error::from(kind),
                "read",
                path,
                LocalApiOperation::Certificate.timeout(),
            );
            assert!(message.contains("LocalAPI read timed out"));
            assert!(message.contains(path));
            assert!(message.contains("300s"));
            assert!(!message.contains("os error 11"));
        }
        let message = localapi_io_error(
            std::io::Error::from(std::io::ErrorKind::WouldBlock),
            "write",
            "/localapi/v0/status",
            LocalApiOperation::Status.timeout(),
        );
        assert!(message.contains("LocalAPI write timed out"));
        assert!(message.contains("/localapi/v0/status"));
        assert!(message.contains("30s"));
    }
    #[test]
    fn host_validation() {
        assert_eq!(
            parse_tailscale_host("A.Example.TS.NET"),
            Some(("a".into(), "example".into()))
        );
        assert!(parse_tailscale_host("a.b.c.ts.net").is_none());
        assert!(parse_tailscale_host("-a.example.ts.net").is_none());
        assert!(parse_tailscale_host("a-.example.ts.net").is_none());
        assert!(parse_tailscale_host(" a.example.ts.net").is_none());
        assert!(
            parse_tailscale_host(&format!("{}.{}.ts.net", "a".repeat(124), "b".repeat(124)))
                .is_none()
        );
    }

    fn host(
        name: &str,
        block: ServerConfigurationBlock,
    ) -> (ServerConfigurationHostFilters, ServerConfigurationBlock) {
        (
            ServerConfigurationHostFilters {
                host: Some(name.into()),
                ip: None,
            },
            block,
        )
    }

    fn with_socket(mut block: ServerConfigurationBlock, socket: &str) -> ServerConfigurationBlock {
        let tls = Arc::make_mut(&mut block.directives).get_mut("tls").unwrap();
        let child = tls[0].children.as_mut().unwrap();
        Arc::make_mut(&mut child.directives).insert(
            "socket".into(),
            vec![ServerConfigurationDirectiveEntry {
                args: vec![ServerConfigurationValue::String(socket.into(), None)],
                ..Default::default()
            }],
        );
        block
    }

    fn config_with_hosts(
        hosts: Vec<(ServerConfigurationHostFilters, ServerConfigurationBlock)>,
    ) -> ServerConfiguration {
        let mut config = ServerConfiguration::default();
        config.ports.insert(
            "https".into(),
            vec![ServerConfigurationPort {
                port: Some(8443),
                hosts,
            }],
        );
        config
    }

    #[test]
    fn inventory_is_canonical_and_deduplicates() {
        let config = config_with_hosts(vec![
            host("A.Example.ts.net", tls_block("tailscale")),
            host("a.example.ts.net", tls_block("tailscale")),
            host("public.example.com", tls_block("acme")),
        ]);
        let nodes = inventory(&config).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes["a.example.ts.net"].socket, NodeSocket::Managed);
        assert_eq!(
            managed_socket("a", "example"),
            PathBuf::from(
                std::env::var("TS_SOCKET_DIR").unwrap_or_else(|_| "/var/run/tailscale".into())
            )
            .join("a-example.sock")
        );
        for malformed in [
            "a.b.example.ts.net",
            "-a.example.ts.net",
            "a-.example.ts.net",
            ".ts.net",
        ] {
            assert!(
                inventory(&config_with_hosts(vec![host(
                    malformed,
                    tls_block("tailscale")
                )]))
                .is_err()
            );
        }
        // Multiple tailnets coexist; each is inventoried separately.
        let nodes = inventory(&config_with_hosts(vec![
            host("a.example.ts.net", tls_block("tailscale")),
            host("b.other.ts.net", tls_block("tailscale")),
        ]))
        .unwrap();
        assert_eq!(nodes.len(), 2);
        assert!(nodes.contains_key("a.example.ts.net"));
        assert!(nodes.contains_key("b.other.ts.net"));
        assert_eq!(nodes["a.example.ts.net"].tailnet, "example");
        assert_eq!(nodes["b.other.ts.net"].tailnet, "other");
    }

    #[test]
    fn explicit_socket_overrides_inference_and_conflicts_fail() {
        let managed = host("a.example.ts.net", tls_block("tailscale"));
        let external = host(
            "A.EXAMPLE.TS.NET",
            with_socket(tls_block("tailscale"), "/external/a.sock"),
        );
        let nodes = inventory(&config_with_hosts(vec![managed.clone(), external.clone()])).unwrap();
        assert_eq!(
            nodes["a.example.ts.net"].socket,
            NodeSocket::External("/external/a.sock".into())
        );
        assert_eq!(
            inventory(&config_with_hosts(vec![external.clone(), managed])).unwrap(),
            nodes
        );
        let conflict = host(
            "a.example.ts.net",
            with_socket(tls_block("tailscale"), "/other.sock"),
        );
        assert!(
            inventory(&config_with_hosts(vec![external, conflict]))
                .unwrap_err()
                .contains("conflicting")
        );
        let mut manager = NodeManager::default();
        manager.reconcile(nodes.clone()).unwrap();
        assert_eq!(
            manager.socket_for("A.example.ts.net"),
            Some("/external/a.sock".into())
        );
        manager.reconcile(BTreeMap::new()).unwrap(); // removal is deferred until restart
        assert_eq!(
            manager.socket_for("a.example.ts.net"),
            Some("/external/a.sock".into())
        );
        let mut changed = nodes;
        changed.get_mut("a.example.ts.net").unwrap().socket =
            NodeSocket::External("/other.sock".into());
        assert!(
            manager
                .reconcile(changed)
                .unwrap_err()
                .contains("restart required")
        );
    }

    #[test]
    fn command_arguments_and_cert_domain_authority() {
        let node = Node {
            machine: "a".into(),
            tailnet: "example".into(),
            socket: NodeSocket::Managed,
        };
        assert_eq!(
            up_args(&node, std::path::Path::new("/run/a.sock"), Some("secret")),
            [
                "--socket=/run/a.sock",
                "up",
                "--hostname=a",
                "--accept-dns=false",
                "--authkey=secret"
            ]
        );
        assert_eq!(
            up_args(&node, std::path::Path::new("/run/a.sock"), None),
            [
                "--socket=/run/a.sock",
                "up",
                "--hostname=a",
                "--accept-dns=false"
            ]
        );
        assert_eq!(
            set_args(&node, std::path::Path::new("/run/a.sock")),
            ["--socket=/run/a.sock", "set", "--hostname=a"]
        );
        assert_eq!(
            login_args(&node, std::path::Path::new("/run/a.sock")),
            [
                "--socket=/run/a.sock",
                "up",
                "--hostname=a",
                "--accept-dns=false"
            ]
        );
        let expected = "a.example.ts.net";
        let good = serde_json::json!({"BackendState":"Running", "Self":{"DNSName":"wrong.example.ts.net."}, "CertDomains":["A.Example.TS.NET."]});
        assert!(verify_cert_domains(&good, expected).is_ok());
        let wrong = serde_json::json!({"BackendState":"Running", "Self":{"DNSName":expected}, "CertDomains":["b.example.ts.net"]});
        let error = verify_cert_domains(&wrong, expected).unwrap_err();
        assert!(error.contains(expected));
        assert!(error.contains("b.example.ts.net"));
        assert!(
            verify_cert_domains(
                &serde_json::json!({"BackendState":"Running", "Self":{"DNSName":expected}}),
                expected
            )
            .is_err()
        );
        assert!(
            verify_cert_domains(
                &serde_json::json!({"BackendState":"Stopped", "CertDomains":[expected]}),
                expected
            )
            .is_err()
        );
    }

    #[test]
    fn login_url_parser_extracts_exact_url() {
        assert_eq!(parse_login_url("\tTo authenticate, visit:\n"), None);
        assert_eq!(
            parse_login_url("\tTo authenticate, visit: https://login.tailscale.com/a/123abc"),
            Some("https://login.tailscale.com/a/123abc")
        );
        assert_eq!(
            parse_login_url("\t\t\thttps://login.tailscale.com/a/xyz789?nodekey=deadbeef\n"),
            Some("https://login.tailscale.com/a/xyz789?nodekey=deadbeef")
        );
        assert_eq!(
            parse_login_url(
                "\tTo approve your machine, visit (as admin):\n\n\t\thttps://login.tailscale.com/a/admin-url"
            ),
            Some("https://login.tailscale.com/a/admin-url")
        );
        assert_eq!(parse_login_url("no url here"), None);
        assert_eq!(
            parse_login_url("noise https://login.tailscale.com/a/abc trailing words"),
            Some("https://login.tailscale.com/a/abc")
        );
        assert_eq!(
            parse_login_url("https://login.tailscale.com/a/only"),
            Some("https://login.tailscale.com/a/only")
        );
        // URLs are exact: embedded in other hosts must not match.
        assert_eq!(
            parse_login_url("https://example.com/login.tailscale.com/a/x"),
            None
        );
    }

    #[test]
    fn login_timeout_defaults_and_rejects_invalid() {
        // Without TS_LOGIN_TIMEOUT set, the 300s default applies. Env-var
        // branches are covered below under a shared lock because tests in
        // this crate share the process environment.
        let timeout = login_timeout().unwrap();
        assert_eq!(timeout, DEFAULT_LOGIN_TIMEOUT);
    }

    #[test]
    fn daemon_args_keep_state_and_cert_cache_per_node() {
        let a_state = std::path::Path::new("/var/lib/tailscale/a-sheep-dojo");
        let b_state = std::path::Path::new("/var/lib/tailscale/b-sheep-dojo");
        let a_socket = std::path::Path::new("/var/run/tailscale/a-sheep-dojo.sock");
        let b_socket = std::path::Path::new("/var/run/tailscale/b-sheep-dojo.sock");
        assert_eq!(
            daemon_args(a_state, a_socket),
            [
                "--state=/var/lib/tailscale/a-sheep-dojo/tailscaled.state",
                "--statedir=/var/lib/tailscale/a-sheep-dojo",
                "--socket=/var/run/tailscale/a-sheep-dojo.sock",
                "--tun=userspace-networking",
            ]
        );
        assert_eq!(
            daemon_args(b_state, b_socket),
            [
                "--state=/var/lib/tailscale/b-sheep-dojo/tailscaled.state",
                "--statedir=/var/lib/tailscale/b-sheep-dojo",
                "--socket=/var/run/tailscale/b-sheep-dojo.sock",
                "--tun=userspace-networking",
            ]
        );
        assert_ne!(
            daemon_args(a_state, a_socket),
            daemon_args(b_state, b_socket)
        );
    }

    #[test]
    fn nonzero_status_can_still_report_parseable_state() {
        let status = parse_status(CommandResult {
            stdout: r#"{"BackendState":"NeedsLogin"}"#.into(),
            success: false,
        })
        .unwrap();
        assert_eq!(status["BackendState"], "NeedsLogin");
        assert!(
            parse_status(CommandResult {
                stdout: "not JSON; secret must not appear in errors".into(),
                success: false,
            })
            .unwrap_err()
            .contains("did not return parseable JSON")
        );
        assert!(
            require_success(CommandResult {
                stdout: "secret".into(),
                success: false
            })
            .unwrap_err()
            .eq("Tailscale command failed")
        );
    }

    #[test]
    fn reconcile_rejects_exited_owned_daemon() {
        let node = Node {
            machine: "a".into(),
            tailnet: "example".into(),
            socket: NodeSocket::Managed,
        };
        let mut child = Command::new("sh").args(["-c", "exit 0"]).spawn().unwrap();
        child.wait().unwrap();
        let mut manager = NodeManager::default();
        manager.nodes.insert(
            "a.example.ts.net".into(),
            (node.clone(), Arc::new(OwnedChild(Mutex::new(Some(child))))),
        );
        let requested = BTreeMap::from([("a.example.ts.net".into(), node)]);
        assert!(
            manager
                .reconcile(requested)
                .unwrap_err()
                .contains("restart Ferron")
        );
    }
}
