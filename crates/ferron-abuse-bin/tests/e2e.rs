use abuse_core::initialize_database;
use rusqlite::Connection;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

// Each test reserves an ephemeral TCP port before Ferron binds it; serialize
// the live-server tests so parallel tests cannot claim the same released port.
static LIVE_SERVER_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn live_ipban_starts_without_definitions_and_keeps_serving_when_feed_is_unavailable() {
    let _server_guard = LIVE_SERVER_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let upstream = Upstream::start();
    let port = free_port();
    fs::write(
        temp.path().join("ferron.conf"),
        format!(
            "{{\n log \"{0}/access.log\"\n error_log \"{0}/error.log\"\n ipban_mode true\n ipban_log \"{0}/ipban.log\"\n ipban_url \"https://127.0.0.1:1/list\"\n ipban_interval \"1m\"\n}}\n*:{1} {{\n proxy http://{2}/\n}}\n",
            temp.path().display(),
            port,
            upstream.address,
        ),
    ).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ferron"))
        .current_dir(temp.path())
        .args(["run", "-c", "ferron.conf"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut process = FerronProcess {
        child: Some(child),
        temp,
        upstream: Some(upstream),
        listen_port: port,
        audit: PathBuf::new(),
    };
    process.wait_ready();
    assert_eq!(process.request("/normal").0, 200);
    assert!(process.temp.path().join("ipban.log").is_file());
    process.graceful_shutdown();
}

#[test]
fn live_wordpress_site_and_no_log_paths_preserve_bans_and_logs() {
    let _server_guard = LIVE_SERVER_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let upstream = Upstream::start();
    let db = temp.path().join("definitions.sqlite");
    initialize_database(&db).unwrap();
    Connection::open(&db).unwrap().execute_batch(
        "INSERT INTO attack_definitions
         (id,name,enabled,field,header_name,matcher,pattern,case_sensitive,attack_type,
          priority,description,version,created_at,updated_at) VALUES
         (1,'wp-ban-login',1,'path',NULL,'exact','/wp-login.php',1,'wp_ban',1,'',1,'now','now'),
         (2,'id-leak-wordpress-config',1,'path',NULL,'exact','/wp-config.php',1,'id_leak',2,'',1,'now','now'),
         (3,'no-log-favicon',1,'path',NULL,'exact','/favicon.ico',1,'no_log',0,'',1,'now','now');",
    ).unwrap();
    let port = free_port();
    let config = format!(
        "{{\n log \"{0}/access.log\"\n error_log \"{0}/error.log\"\n ban_mode true\n honeypot_mode false\n ban_duration \"30s\"\n ban_extensions \"php\"\n definitions_db \"{1}\"\n audit_log \"{0}/audit.ndjson\"\n matched_log \"{0}/matched.log\"\n}}\n*:{2} {{\n proxy http://{3}/\n}}\nwp.localhost:{2} {{\n wordpress_site true\n share_bans false\n proxy http://{3}/\n}}\n",
        temp.path().display(),
        db.display(),
        port,
        upstream.address,
    );
    fs::write(temp.path().join("ferron.conf"), config).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ferron"))
        .current_dir(temp.path())
        .args(["run", "-c", "ferron.conf"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut process = FerronProcess {
        child: Some(child),
        temp,
        upstream: Some(upstream),
        listen_port: port,
        audit: PathBuf::new(),
    };
    process.wait_ready();
    assert_eq!(process.request("/favicon.ico").0, 200);
    assert_eq!(process.request("/wp-login.php").0, 403);
    assert_eq!(process.request("/favicon.ico").0, 403);
    assert_eq!(process.request("/ordinary").0, 403);
    assert_eq!(process.request_host("wp.localhost", "/wp-login.php").0, 200);
    assert_eq!(process.request_host("wp.localhost", "/index.php").0, 200);
    assert_eq!(
        process.request_host("wp.localhost", "/wp-config.php").0,
        403
    );
    assert_eq!(process.request_host("wp.localhost", "/favicon.ico").0, 403);
    process.graceful_shutdown();
    let matched = fs::read_to_string(process.temp.path().join("matched.log")).unwrap();
    assert!(matched.contains("\"wp-ban\""), "{matched}");
    assert!(
        matched.contains("\"wp.localhost\" \"id-leak-wordpress-config\""),
        "{matched}"
    );
    assert!(
        matched.contains("\"id-leak-wordpress-config\""),
        "{matched}"
    );
    assert!(!matched.contains("/favicon.ico"), "{matched}");
    let audit = fs::read_to_string(process.temp.path().join("audit.ndjson")).unwrap();
    assert!(audit.contains("/ordinary"), "{audit}");
    assert!(!audit.contains("/favicon.ico"), "{audit}");
}

#[test]
fn live_global_policy_catches_unconfigured_ip_host_requests() {
    let _server_guard = LIVE_SERVER_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let upstream = Upstream::start();
    let db = temp.path().join("definitions.sqlite");
    initialize_database(&db).unwrap();
    insert_test_definitions(&Connection::open(&db).unwrap());
    let port = free_port();
    let templates = temp.path().join("templates");
    default_templates(&templates);
    let config = format!(
        "{{\n log \"{0}/access.log\"\n error_log \"{0}/error.log\"\n ban_mode true\n honeypot_mode true\n ban_duration \"30s\"\n definitions_db \"{1}\"\n honeypot_templates_dir \"{2}\"\n audit_log \"{0}/audit.ndjson\"\n matched_log \"{0}/matched.log\"\n}}\nprotected.example:{3} {{\n ban_mode false\n proxy http://{4}/\n}}\n",
        temp.path().display(),
        db.display(),
        templates.display(),
        port,
        upstream.address,
    );
    fs::write(temp.path().join("ferron.conf"), config).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ferron"))
        .current_dir(temp.path())
        .args(["run", "-c", "ferron.conf"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let audit = temp.path().join("audit.ndjson");
    let mut process = FerronProcess {
        child: Some(child),
        temp,
        upstream: Some(upstream),
        listen_port: port,
        audit,
    };
    process.wait_ready();

    // The explicitly configured named host retains its local ban-mode override.
    assert_eq!(process.request_host("protected.example", "/known").0, 200);
    assert_eq!(process.upstream_count(), 1);
    let (status, body) = process.request_host("127.0.0.1", DECOY_PATH);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    // Existing ID-leak bans deliberately return Not Found for unrelated paths.
    assert_eq!(process.request_host("127.0.0.1", "/ordinary").0, 404);
    assert_eq!(process.request_host("127.0.0.1", "/known").0, 403);
    assert_eq!(process.upstream_count(), 1);

    process.graceful_shutdown();
    let matched = fs::read_to_string(process.temp.path().join("matched.log")).unwrap();
    assert!(matched.contains(&format!("\"{DECOY_NAME}\"")), "{matched}");
    let audit = fs::read_to_string(&process.audit).unwrap();
    assert!(audit.contains("/ordinary"), "{audit}");
}

const DECOY_NAME: &str = "operator-google-decoy";
const DECOY_PATH: &str = "/operator-credentials";

fn insert_test_definitions(connection: &Connection) {
    connection
        .execute_batch(
            "INSERT INTO attack_definitions
         (id,name,enabled,field,header_name,matcher,pattern,case_sensitive,attack_type,
          priority,description,version,created_at,updated_at) VALUES
         (100,'test-known',1,'path',NULL,'exact','/known',1,'scanner',1,'',1,'now','now'),
         (101,'operator-google-decoy',1,'path',NULL,'exact','/operator-credentials',1,
          'id_leak',2,'',1,'now','now');",
        )
        .unwrap();
}

fn default_templates(directory: &Path) {
    fs::create_dir(directory).unwrap();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../definitions/honeypot-responses/id-leak-google-credentials.yaml");
    let yaml = fs::read_to_string(source).unwrap().replace(
        "name: id-leak-google-credentials",
        &format!("name: {DECOY_NAME}"),
    );
    fs::write(directory.join(format!("{DECOY_NAME}.yaml")), yaml).unwrap();
}

struct Upstream {
    address: String,
    requests: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Upstream {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let requests = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_requests = Arc::clone(&requests);
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_millis(200)))
                            .ok();
                        let mut request = [0u8; 4096];
                        let read = stream.read(&mut request).unwrap_or(0);
                        if read == 0 || !request[..read].starts_with(b"GET ") {
                            continue;
                        }
                        thread_requests.fetch_add(1, Ordering::Relaxed);
                        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nupstream";
                        let _ = stream.write_all(response);
                        let _ = stream.flush();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            address,
            requests,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(&self.address);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct FerronProcess {
    child: Option<Child>,
    temp: TempDir,
    upstream: Option<Upstream>,
    listen_port: u16,
    audit: PathBuf,
}

impl FerronProcess {
    fn start(ban_mode: bool, honeypot_mode: bool, allowlist: bool) -> Self {
        Self::start_with_templates(ban_mode, honeypot_mode, allowlist, None)
    }

    fn start_with_templates(
        ban_mode: bool,
        honeypot_mode: bool,
        allowlist: bool,
        templates_override: Option<&Path>,
    ) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let upstream = Upstream::start();
        let db = temp.path().join("definitions.sqlite");
        initialize_database(&db).unwrap();
        let connection = Connection::open(&db).unwrap();
        insert_test_definitions(&connection);
        if allowlist {
            connection
                .execute(
                    "INSERT INTO ip_allowlist (id,cidr,enabled,created_at,updated_at)
                     VALUES (100,'127.0.0.1/32',1,'now','now')",
                    [],
                )
                .unwrap();
        }
        drop(connection);
        let audit = temp.path().join("audit.ndjson");
        let port = free_port();
        let templates = temp.path().join("templates");
        if honeypot_mode && templates_override.is_none() {
            default_templates(&templates);
        }
        let templates_directive = if honeypot_mode {
            format!(
                "    honeypot_templates_dir \"{}\"\n",
                templates_override.unwrap_or(&templates).display()
            )
        } else {
            String::new()
        };
        let config = format!(
            "{{\n    log \"{}/access.log\"\n    error_log \"{}/error.log\"\n    ban_mode {}\n    honeypot_mode {}\n    ban_duration \"1s\"\n    definitions_db \"{}\"\n{}    audit_log \"{}\"\n}}\n\n*:{} {{\n    proxy http://{}/\n}}\n",
            temp.path().display(),
            temp.path().display(),
            ban_mode,
            honeypot_mode,
            db.display(),
            templates_directive,
            audit.display(),
            port,
            upstream.address,
        );
        fs::write(temp.path().join("ferron.conf"), config).unwrap();
        let binary = env!("CARGO_BIN_EXE_ferron");
        let child = Command::new(binary)
            .current_dir(temp.path())
            .args(["run", "-c", "ferron.conf"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut process = Self {
            child: Some(child),
            temp,
            upstream: Some(upstream),
            listen_port: port,
            audit,
        };
        process.wait_ready();
        process
    }

    fn wait_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(8);
        while Instant::now() < deadline {
            if let Some(child) = &mut self.child
                && child.try_wait().unwrap().is_some()
            {
                panic!("ferron exited before readiness");
            }
            if TcpStream::connect(("127.0.0.1", self.listen_port)).is_ok() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("ferron readiness timeout");
    }

    fn request(&self, target: &str) -> (u16, Vec<u8>) {
        self.request_host("localhost", target)
    }

    fn request_host(&self, host: &str, target: &str) -> (u16, Vec<u8>) {
        let mut stream = TcpStream::connect(("127.0.0.1", self.listen_port)).unwrap();
        stream
            .write_all(
                format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        let status = String::from_utf8_lossy(&bytes)
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        (status, bytes)
    }

    fn wait_for_audit_lines(&self, count: usize) -> Vec<serde_json::Value> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Ok(text) = fs::read_to_string(&self.audit) {
                let values = text
                    .lines()
                    .filter_map(|line| serde_json::from_str(line).ok())
                    .collect::<Vec<_>>();
                if values.len() >= count {
                    return values;
                }
            }
            thread::sleep(Duration::from_millis(25));
        }
        Vec::new()
    }

    fn graceful_shutdown(&mut self) {
        if let Some(mut child) = self.child.take() {
            #[cfg(unix)]
            unsafe {
                libc::kill(child.id() as i32, libc::SIGTERM);
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if child.try_wait().unwrap().is_some() {
                    return;
                }
                thread::sleep(Duration::from_millis(25));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    fn upstream_count(&self) -> usize {
        self.upstream
            .as_ref()
            .map(|upstream| upstream.requests.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
}

#[test]
fn live_site_overrides_share_bans_by_default_and_route_logs_per_site() {
    let _server_guard = LIVE_SERVER_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let upstream = Upstream::start();
    let db = temp.path().join("definitions.sqlite");
    initialize_database(&db).unwrap();
    insert_test_definitions(&Connection::open(&db).unwrap());
    let port = free_port();
    let config = format!(
        "{{\n log \"{0}/access.log\"\n error_log \"{0}/error.log\"\n ban_mode false\n honeypot_mode false\n ban_duration \"30s\"\n definitions_db \"{1}\"\n audit_log \"{0}/global.ndjson\"\n}}\n*:{2} {{\n proxy http://{3}/\n}}\na.localhost:{2} {{\n ban_mode true\n ban_extensions \"php\"\n matched_log \"{0}/a.log\"\n proxy http://{3}/\n}}\nb.localhost:{2} {{\n ban_mode true\n audit_log \"{0}/b.ndjson\"\n proxy http://{3}/\n}}\nc.localhost:{2} {{\n ban_mode true\n share_bans false\n proxy http://{3}/\n}}\nd.localhost:{2} {{\n proxy http://{3}/\n}}\n",
        temp.path().display(),
        db.display(),
        port,
        upstream.address
    );
    fs::write(temp.path().join("ferron.conf"), config).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ferron"))
        .current_dir(temp.path())
        .args(["run", "-c", "ferron.conf"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut process = FerronProcess {
        child: Some(child),
        temp,
        upstream: Some(upstream),
        listen_port: port,
        audit: PathBuf::new(),
    };
    process.wait_ready();
    assert_eq!(process.request_host("c.localhost", "/clean").0, 200);
    assert_eq!(process.request_host("a.localhost", "/probe.php").0, 403);
    assert_eq!(process.request_host("b.localhost", "/clean").0, 403);
    assert_eq!(process.request_host("c.localhost", "/clean").0, 200);
    assert_eq!(process.request_host("d.localhost", "/clean").0, 200);
    assert_eq!(process.request_host("c.localhost", "/known").0, 403);
    assert_eq!(process.request_host("c.localhost", "/clean").0, 403);
    let audit_path = process.temp.path().join("b.ndjson");
    let matched_path = process.temp.path().join("a.log");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if fs::read_to_string(&audit_path).is_ok_and(|text| text.contains("/clean"))
            && fs::read_to_string(&matched_path).is_ok_and(|text| text.contains("extban"))
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "site-specific logs were not written"
        );
        thread::sleep(Duration::from_millis(25));
    }
    process.graceful_shutdown();
}

#[test]
fn live_site_can_disable_global_bans_and_enable_global_honeypot_catalog() {
    let _server_guard = LIVE_SERVER_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let upstream = Upstream::start();
    let db = temp.path().join("definitions.sqlite");
    initialize_database(&db).unwrap();
    insert_test_definitions(&Connection::open(&db).unwrap());
    let templates = temp.path().join("templates");
    default_templates(&templates);
    let port = free_port();
    let config = format!(
        "{{\n log \"{0}/access.log\"\n error_log \"{0}/error.log\"\n ban_mode true\n honeypot_mode false\n ban_duration \"30s\"\n definitions_db \"{1}\"\n honeypot_templates_dir \"{2}\"\n audit_log \"{0}/global.ndjson\"\n}}\na.localhost:{3} {{\n honeypot_mode true\n proxy http://{4}/\n}}\nb.localhost:{3} {{\n ban_mode false\n proxy http://{4}/\n}}\n",
        temp.path().display(),
        db.display(),
        templates.display(),
        port,
        upstream.address
    );
    fs::write(temp.path().join("ferron.conf"), config).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ferron"))
        .current_dir(temp.path())
        .args(["run", "-c", "ferron.conf"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut process = FerronProcess {
        child: Some(child),
        temp,
        upstream: Some(upstream),
        listen_port: port,
        audit: PathBuf::new(),
    };
    process.wait_ready();
    assert_eq!(process.request_host("a.localhost", DECOY_PATH).0, 200);
    assert_eq!(process.request_host("a.localhost", "/unmatched").0, 404);
    assert_eq!(process.request_host("b.localhost", "/known").0, 200);
    assert_eq!(process.request_host("b.localhost", "/unmatched").0, 200);
    process.graceful_shutdown();
}

#[test]
fn live_catalog_controls_response_content_type_and_stops_upstream() {
    let _server_guard = LIVE_SERVER_LOCK.lock().unwrap();
    let templates = tempfile::tempdir().unwrap();
    fs::write(
        templates.path().join(format!("{DECOY_NAME}.yaml")),
        format!("version: 1\nname: {DECOY_NAME}\nrestype: normal\ncontent_type: application/yaml; charset=utf-8\ntemplate: |\n  catalog-owned-marker: true\n"),
    ).unwrap();
    let process = FerronProcess::start_with_templates(true, true, false, Some(templates.path()));
    let (status, bytes) = process.request(DECOY_PATH);
    assert_eq!(status, 200);
    let response = String::from_utf8_lossy(&bytes);
    assert!(
        response
            .to_ascii_lowercase()
            .contains("content-type: application/yaml; charset=utf-8")
    );
    assert!(response.contains("catalog-owned-marker: true"));
    assert!(!response.contains("upstream"));
    assert_eq!(process.upstream_count(), 0);
    assert_eq!(process.request("/google-credentials.json").0, 404);
}

#[test]
fn live_startup_rejects_missing_or_incomplete_catalog() {
    let _server_guard = LIVE_SERVER_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("definitions.sqlite");
    initialize_database(&db).unwrap();
    insert_test_definitions(&Connection::open(&db).unwrap());
    let empty = temp.path().join("empty-templates");
    fs::create_dir(&empty).unwrap();
    for templates in [temp.path().join("absent-templates"), empty] {
        let port = free_port();
        let config = format!(
            "{{\n    log \"{0}/access.log\"\n    error_log \"{0}/error.log\"\n    ban_mode true\n    honeypot_mode true\n    ban_duration \"1s\"\n    definitions_db \"{1}\"\n    honeypot_templates_dir \"{2}\"\n    audit_log \"{0}/audit.ndjson\"\n}}\n\n*:{3} {{ root . }}\n",
            temp.path().display(),
            db.display(),
            templates.display(),
            port
        );
        fs::write(temp.path().join("ferron.conf"), config).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_ferron"))
            .current_dir(temp.path())
            .args(["run", "-c", "ferron.conf"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(
                    !status.success(),
                    "invalid catalog unexpectedly started: {}",
                    templates.display()
                );
                break;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                let _ = child.wait();
                panic!(
                    "invalid catalog startup did not fail: {}",
                    templates.display()
                );
            }
            thread::sleep(Duration::from_millis(25));
        }
    }
}

impl Drop for FerronProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.upstream.take();
        let _ = self.temp.path();
    }
}

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn live_matching_honeypot_known_exclusion_unmatched_audit_and_expiry() {
    let _server_guard = LIVE_SERVER_LOCK.lock().unwrap();
    let process = FerronProcess::start(true, true, false);
    let (status, body) = process.request(DECOY_PATH);
    assert_eq!(status, 200);
    assert!(String::from_utf8_lossy(&body).contains("service_account"));
    assert_eq!(process.upstream_count(), 0);
    assert_eq!(process.wait_for_audit_lines(0).len(), 0);
    assert_eq!(process.request(DECOY_PATH).0, 200);
    let (unmatched_status, unmatched_body) = process.request("/unmatched");
    assert_eq!(unmatched_status, 404);
    assert!(!String::from_utf8_lossy(&unmatched_body).contains("api_secret"));
    let audit = process.wait_for_audit_lines(1);
    assert_eq!(audit.len(), 1);
    assert!(audit[0].get("matched_definition_ids").is_none());
    assert!(
        audit[0]["triggering_definition_ids"]
            .as_array()
            .is_some_and(|ids| !ids.is_empty())
    );
    assert!(
        audit[0]["triggering_attack_types"]
            .as_array()
            .is_some_and(|types| !types.is_empty())
    );
    assert_eq!(audit[0]["response_mode"], "not_found");
    assert_eq!(process.upstream_count(), 0);
    thread::sleep(Duration::from_millis(1200));
    assert_eq!(process.request("/unmatched").0, 200);
    assert_eq!(process.upstream_count(), 1);
}

#[test]
fn live_modes_and_allowlist_are_independent() {
    let _server_guard = LIVE_SERVER_LOCK.lock().unwrap();
    let fail2ban = FerronProcess::start(true, false, false);
    assert_eq!(fail2ban.request("/known").0, 403);
    assert_eq!(fail2ban.upstream_count(), 0);

    let honey_only = FerronProcess::start(false, true, false);
    assert_eq!(honey_only.request(DECOY_PATH).0, 200);
    assert_eq!(honey_only.request("/unmatched").0, 200);
    assert_eq!(honey_only.upstream_count(), 1);

    let disabled = FerronProcess::start(false, false, false);
    assert_eq!(disabled.request("/known").0, 200);
    assert_eq!(disabled.upstream_count(), 1);

    let allowlisted = FerronProcess::start(true, true, true);
    assert_eq!(allowlisted.request(DECOY_PATH).0, 200);
    assert_eq!(allowlisted.request("/unmatched").0, 200);
    assert_eq!(allowlisted.upstream_count(), 2);
}

#[test]
fn live_shutdown_drains_queued_audit_record() {
    let _server_guard = LIVE_SERVER_LOCK.lock().unwrap();
    let mut process = FerronProcess::start(true, true, false);
    assert_eq!(process.request(DECOY_PATH).0, 200);
    let _ = process.request("/shutdown-unmatched");
    process.graceful_shutdown();
    let audit = process.wait_for_audit_lines(1);
    assert_eq!(audit.len(), 1);
    assert!(audit[0].get("matched_definition_ids").is_none());
    assert!(
        audit[0]["triggering_definition_ids"]
            .as_array()
            .is_some_and(|ids| !ids.is_empty())
    );
}

#[test]
fn live_startup_fails_when_both_definition_sources_are_invalid() {
    let _server_guard = LIVE_SERVER_LOCK.lock().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let port = free_port();
    let config = format!(
        "{{\n    log \"{}/access.log\"\n    error_log \"{}/error.log\"\n    ban_mode true\n    honeypot_mode false\n    ban_duration \"1s\"\n    definitions_db \"{}/missing.sqlite\"\n    definitions_url \"https://127.0.0.1:1/missing.sqlite\"\n    audit_log \"{}/audit.ndjson\"\n}}\n\n*:{} {{ root . }}\n",
        temp.path().display(),
        temp.path().display(),
        temp.path().display(),
        temp.path().display(),
        port,
    );
    fs::write(temp.path().join("ferron.conf"), config).unwrap();
    let binary = env!("CARGO_BIN_EXE_ferron");
    let mut child = Command::new(binary)
        .current_dir(temp.path())
        .args(["run", "-c", "ferron.conf"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "invalid-source startup did not fail"
        );
        thread::sleep(Duration::from_millis(25));
    };
    assert!(!status.success());
}
