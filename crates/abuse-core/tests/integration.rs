use abuse_core::*;
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::Value;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime};
use tempfile::tempdir;

fn limits() -> Limits {
    Limits::default()
}

fn input(target: &str) -> RequestInput {
    RequestInput {
        client_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        proxy_ip: None,
        method: "GET".to_owned(),
        host: "example.invalid".to_owned(),
        target: target.to_owned(),
        user_agent: "abuse-core-test".to_owned(),
        headers: vec![
            ("User-Agent".to_owned(), "abuse-core-test".to_owned()),
            ("X-Trace".to_owned(), "safe-value".to_owned()),
        ],
        request_bytes: 12,
        body_sha256: None,
    }
}

fn config(db: &Path) -> ProtectionConfig {
    ProtectionConfig {
        ban_mode: true,
        honeypot_mode: true,
        wordpress_site: false,
        ban_extensions: Vec::new(),
        ban_duration: Duration::from_secs(60),
        definitions_db: db.to_owned(),
        definitions_url: None,
        audit_log: db.with_extension("ndjson"),
        limits: limits(),
        fail2ban: Fail2banPolicy::default(),
    }
}

fn catalog(snapshot: &DefinitionSnapshot) -> Arc<TemplateCatalog> {
    let directory = tempdir().unwrap();
    let sources = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../definitions/honeypot-responses"
    ));
    for entry in snapshot.definitions() {
        if entry.definition().attack_type == AttackType::IdLeak {
            let filename = format!("{}.yaml", entry.name());
            std::fs::copy(sources.join(&filename), directory.path().join(filename)).unwrap();
        }
    }
    Arc::new(TemplateCatalog::load(directory.path(), snapshot).unwrap())
}

// A deliberately small test-only fixture. Production initialization never
// inserts these rows; tests opt into exactly the definitions they need.
fn insert_test_definitions(connection: &Connection) {
    connection.execute_batch(
        "INSERT INTO attack_definitions
         (id,name,enabled,field,header_name,matcher,pattern,case_sensitive,attack_type,
          priority,description,version,created_at,updated_at) VALUES
         (101,'id-leak-dotenv',1,'path',NULL,'regex','(?:^|/)\\.env(?:\\.production)?$',1,'id_leak',1,'',1,'now','now'),
         (102,'id-leak-google-credentials',1,'path',NULL,'exact','/google-credentials.json',1,'id_leak',2,'',1,'now','now'),
         (103,'id-leak-aws-credentials',1,'path',NULL,'exact','/.aws/credentials',1,'id_leak',3,'',1,'now','now'),
         (104,'id-leak-netrc',1,'path',NULL,'exact','/.netrc',1,'id_leak',4,'',1,'now','now'),
         (105,'id-leak-docker-config',1,'path',NULL,'exact','/.docker/config.json',1,'id_leak',5,'',1,'now','now'),
         (106,'id-leak-htpasswd',1,'path',NULL,'exact','/.htpasswd',1,'id_leak',6,'',1,'now','now');",
    ).unwrap();
}

#[test]
fn snapshot_cases_from_yaml() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cases_dir = root.join("../../definitions/tests/cases");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&cases_dir)
        .unwrap_or_else(|error| panic!("{}: {error}", cases_dir.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "yml"))
        .collect();
    paths.sort();
    assert!(
        !paths.is_empty(),
        "{}: no .yml fixtures",
        cases_dir.display()
    );
    for path in paths {
        let fixture: SnapshotFixture = serde_yaml::from_str(
            &std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display())),
        )
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let directory = tempdir().unwrap();
        let db = directory.path().join("definitions.sqlite");
        let connection = Connection::open(&db).unwrap();
        for migration in &fixture.migrations {
            let source = path.parent().unwrap().join(migration);
            let sql = std::fs::read_to_string(&source).unwrap_or_else(|error| {
                panic!("{}: migration {migration}: {error}", path.display())
            });
            connection.execute_batch(&sql).unwrap_or_else(|error| {
                panic!("{}: migration {migration}: {error}", path.display())
            });
        }
        drop(connection);
        let snapshot = DefinitionSnapshot::load(&db, limits())
            .unwrap_or_else(|error| panic!("{}: snapshot: {error}", path.display()));
        assert_eq!(
            snapshot.snapshot_version(),
            fixture.snapshot_version,
            "{}",
            path.display()
        );
        let catalog = catalog(&snapshot);
        for (index, case) in fixture.cases.into_iter().enumerate() {
            let context = format!(
                "{}: case {} ({})",
                path.display(),
                index + 1,
                case.request.target
            );
            assert!(
                case.selected.len() <= 1,
                "{context}: selected must have at most one item"
            );
            let mut request = input(&case.request.target);
            if let Some(method) = case.request.method {
                request.method = method;
            }
            if let Some(host) = case.request.host {
                request.host = host;
            }
            if let Some(user_agent) = case.request.user_agent {
                request.user_agent = user_agent;
            }
            if let Some(headers) = case.request.headers {
                request.headers = headers;
            }
            if let Some(request_bytes) = case.request.request_bytes {
                request.request_bytes = request_bytes;
            }
            if let Some(body_sha256) = case.request.body_sha256 {
                request.body_sha256 = Some(body_sha256);
            }
            let normalized = normalize_request(request, &limits())
                .unwrap_or_else(|error| panic!("{context}: normalization: {error}"));
            let matched = snapshot.match_request(&normalized);
            let names: Vec<_> = snapshot
                .definitions()
                .iter()
                .filter(|definition| matched.matched_definition_ids.contains(&definition.id()))
                .map(|definition| definition.name())
                .collect();
            for required in &case.matched {
                assert!(
                    names.contains(&required.as_str()),
                    "{context}: missing {required:?} in {names:?}"
                );
            }
            assert_eq!(
                matched.selected_id_leak_name.as_deref(),
                case.selected.first().map(String::as_str),
                "{context}: selected definition"
            );
            if case.no_match {
                assert!(
                    !matched.is_match(),
                    "{context}: unexpected match: {matched:?}"
                );
            }
            if let Some(name) = matched.selected_id_leak_name.as_deref() {
                catalog
                    .render(name)
                    .unwrap_or_else(|error| panic!("{context}: rendering {name}: {error}"));
            }
        }
    }
}

#[derive(Deserialize)]
struct SnapshotFixture {
    migrations: Vec<String>,
    snapshot_version: u64,
    cases: Vec<SnapshotCase>,
}

#[derive(Deserialize)]
struct SnapshotCase {
    request: FixtureRequest,
    #[serde(default)]
    matched: Vec<String>,
    selected: Vec<String>,
    #[serde(default)]
    no_match: bool,
}

#[derive(Deserialize)]
struct FixtureRequest {
    target: String,
    method: Option<String>,
    host: Option<String>,
    user_agent: Option<String>,
    headers: Option<Vec<(String, String)>>,
    request_bytes: Option<u64>,
    body_sha256: Option<String>,
}

struct DelayedClock {
    reading: Mutex<ClockReading>,
    calls: AtomicUsize,
    second_called: mpsc::Sender<()>,
    second_release: Arc<(Mutex<bool>, Condvar)>,
}

impl Clock for DelayedClock {
    fn now(&self) -> ClockReading {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let reading = *self.reading.lock().unwrap();
        if call == 1 {
            self.second_called.send(()).unwrap();
            let (released, wake) = &*self.second_release;
            let mut released = released.lock().unwrap();
            while !*released {
                released = wake.wait(released).unwrap();
            }
        }
        reading
    }
}

impl DelayedClock {
    fn advance(&self, duration: Duration) {
        let mut reading = self.reading.lock().unwrap();
        reading.wall_time = reading.wall_time.checked_add(duration).unwrap();
        reading.monotonic = reading.monotonic.checked_add(duration).unwrap();
    }

    fn release_second(&self) {
        let (released, wake) = &*self.second_release;
        *released.lock().unwrap() = true;
        wake.notify_all();
    }
}

struct BlockingIncidentIds {
    called: mpsc::Sender<()>,
    release: Arc<(Mutex<bool>, Condvar)>,
}

impl IncidentIdGenerator for BlockingIncidentIds {
    fn next_id(&self) -> String {
        self.called.send(()).unwrap();
        let (released, wake) = &*self.release;
        let mut released = released.lock().unwrap();
        while !*released {
            released = wake.wait(released).unwrap();
        }
        "delayed-incident".to_owned()
    }
}

fn release_pair(pair: &Arc<(Mutex<bool>, Condvar)>) {
    let (released, wake) = &**pair;
    *released.lock().unwrap() = true;
    wake.notify_all();
}

#[test]
fn schema_init_does_not_seed_and_is_idempotent() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("definitions.sqlite");
    initialize_database(&path).unwrap();
    initialize_database(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    assert!(list_definitions(&connection).unwrap().is_empty());
    insert_test_definitions(&connection);
    initialize_database(&path).unwrap();
    assert_eq!(list_definitions(&connection).unwrap().len(), 6);
    let snapshot = SnapshotLoader::new(limits()).unwrap().load(&path).unwrap();
    assert_eq!(
        snapshot
            .match_request(
                &normalize_request(input("/google-credentials.json"), &limits()).unwrap()
            )
            .selected_id_leak_name
            .as_deref(),
        Some("id-leak-google-credentials")
    );
}

#[test]
fn listing_reads_current_db_rows_and_arbitrary_definition_matches() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("definitions.sqlite");
    initialize_database(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    connection.execute_batch("INSERT INTO attack_definitions (id,name,enabled,field,header_name,matcher,pattern,case_sensitive,attack_type,priority,description,version,created_at,updated_at) VALUES (9841,'operator-scanner',1,'path',NULL,'exact','/operator-only',1,'scanner',2,'',1,'now','now'), (9842,'disabled-leak',0,'path',NULL,'regex','^/disabled$',1,'id_leak',3,'',1,'now','now');").unwrap();
    let entries = list_definitions(&connection).unwrap();
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        vec!["operator-scanner", "disabled-leak"]
    );
    assert_eq!(entries[0].attack_type, "scanner");
    assert_eq!(entries[0].pattern, "/operator-only");
    assert!(!entries[1].enabled);
    let snapshot = SnapshotLoader::new(limits()).unwrap().load(&path).unwrap();
    assert_eq!(
        snapshot
            .match_request(&normalize_request(input("/operator-only"), &limits()).unwrap())
            .matched_definition_ids,
        vec![9841]
    );
    assert!(
        !snapshot
            .match_request(&normalize_request(input("/disabled"), &limits()).unwrap())
            .is_match()
    );
}

#[test]
fn db_added_id_leak_uses_external_template_without_compiled_catalog() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("definitions.sqlite");
    initialize_database(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "INSERT INTO attack_definitions
         (id,name,enabled,field,header_name,matcher,pattern,case_sensitive,attack_type,
          priority,description,version,created_at,updated_at)
         VALUES (9911,'operator-decoy',1,'path',NULL,'exact','/operator-secret',1,
                 'id_leak',1,'',1,'now','now');",
        )
        .unwrap();
    let templates = directory.path().join("templates");
    std::fs::create_dir(&templates).unwrap();
    std::fs::write(
        templates.join("operator-decoy.yaml"),
        "version: 1\nname: operator-decoy\nrestype: normal\ntemplate: operator response\n",
    )
    .unwrap();

    let snapshot = SnapshotLoader::new(limits()).unwrap().load(&path).unwrap();
    let match_result =
        snapshot.match_request(&normalize_request(input("/operator-secret"), &limits()).unwrap());
    assert_eq!(
        match_result.selected_id_leak_name.as_deref(),
        Some("operator-decoy")
    );
    let catalog = TemplateCatalog::load(&templates, &snapshot).unwrap();
    assert_eq!(
        catalog.render("operator-decoy").unwrap().body,
        "operator response"
    );
}

#[test]
fn migrated_templates_preserve_structural_credential_shapes() {
    use base64::Engine;
    let directory = tempdir().unwrap();
    let db = directory.path().join("definitions.sqlite");
    initialize_database(&db).unwrap();
    let connection = Connection::open(&db).unwrap();
    insert_test_definitions(&connection);
    let snapshot = SnapshotLoader::new(limits()).unwrap().load(&db).unwrap();
    let responses = catalog(&snapshot);

    let google: Value =
        serde_json::from_str(&responses.render("id-leak-google-credentials").unwrap().body)
            .unwrap();
    let email = google["client_email"].as_str().unwrap();
    assert!(email.ends_with(&format!(
        "@{}.iam.gserviceaccount.com",
        google["project_id"].as_str().unwrap()
    )));
    assert!(
        google["client_x509_cert_url"]
            .as_str()
            .unwrap()
            .ends_with(&email.replace('@', "%40"))
    );
    let pem = google["private_key"].as_str().unwrap();
    assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
    assert!(pem.ends_with("-----END PRIVATE KEY-----\n"));
    let der = base64::engine::general_purpose::STANDARD
        .decode(
            pem.lines()
                .filter(|line| !line.starts_with("-----"))
                .collect::<String>(),
        )
        .unwrap();
    assert_eq!(der[0], 0x30);
    assert!(der.windows(11).any(|window| window
        == [
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01
        ]));

    let docker: Value =
        serde_json::from_str(&responses.render("id-leak-docker-config").unwrap().body).unwrap();
    let auth = docker["auths"]["https://index.docker.io/v1/"]["auth"]
        .as_str()
        .unwrap();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(auth)
        .unwrap();
    let decoded = String::from_utf8(decoded).unwrap();
    let (user, password) = decoded.split_once(':').unwrap();
    assert_eq!(user.len(), 10);
    assert_eq!(password.len(), 32);

    let htpasswd = responses.render("id-leak-htpasswd").unwrap();
    assert!(
        regex::Regex::new(r"^deploy_[a-z0-9]{6}:\$2y\$10\$[./A-Za-z0-9]{53}\n$")
            .unwrap()
            .is_match(&htpasswd.body)
    );
    let dotenv = responses.render("id-leak-dotenv").unwrap().body;
    let name = dotenv
        .lines()
        .find_map(|line| line.strip_prefix("APP_NAME="))
        .unwrap();
    let domain = format!("{}.local", name.replace('-', ""));
    assert!(dotenv.contains(&format!("APP_URL=https://app.{domain}\n")));
    assert!(dotenv.contains(&format!("DB_HOST=db.{domain}\n")));
    assert!(dotenv.contains(&format!("MAIL_HOST=smtp.{domain}\n")));
}

#[test]
fn db_definitions_cover_test_credential_paths() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("definitions.sqlite");
    initialize_database(&path).unwrap();
    insert_test_definitions(&Connection::open(&path).unwrap());
    let snapshot = SnapshotLoader::new(limits()).unwrap().load(&path).unwrap();
    for target in [
        "/.env",
        "/.env.production",
        "/google-credentials.json",
        "/.aws/credentials",
        "/.netrc",
    ] {
        assert!(
            snapshot
                .match_request(&normalize_request(input(target), &limits()).unwrap())
                .has_id_leak()
        );
    }
}

#[test]
fn db_credential_rule_honeypots_on_first_request_without_known_match_audit() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("new-credentials.sqlite");
    initialize_database(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    insert_test_definitions(&connection);
    drop(connection);
    let snapshot = SnapshotLoader::new(limits()).unwrap().load(&path).unwrap();
    let engine =
        PolicyEngine::with_catalog(config(&path), snapshot.clone(), catalog(&snapshot)).unwrap();

    let decision = engine.evaluate_input(input("/%2enetrc"), SystemTime::now());
    assert!(decision.matches.has_id_leak());
    assert!(decision.ban.is_some());
    assert!(decision.audit.is_none());
    match decision.action {
        PolicyAction::Honeypot(response) => {
            assert_eq!(response.content_type, "text/plain; charset=utf-8");
            assert!(response.body.starts_with("machine git."));
        }
        other => panic!("expected honeypot on first request, got {other:?}"),
    }
    assert!(engine.audit_queue().try_dequeue().is_none());
}

#[test]
fn ban_extensions_precede_definitions_honeypots_and_active_bans() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("definitions.sqlite");
    initialize_database(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    insert_test_definitions(&connection);
    // A matching id_leak rule would normally select a honeypot response.
    connection
        .execute_batch(
            "INSERT INTO attack_definitions
        (id,name,enabled,field,header_name,matcher,pattern,case_sensitive,attack_type,
         priority,description,version,created_at,updated_at) VALUES
        (200,'id-leak-php',1,'path',NULL,'exact','/secret.PHP',1,'id_leak',1,'',1,'now','now');",
        )
        .unwrap();
    let templates = directory.path().join("templates");
    std::fs::create_dir(&templates).unwrap();
    for entry in [
        "id-leak-dotenv",
        "id-leak-google-credentials",
        "id-leak-aws-credentials",
        "id-leak-netrc",
        "id-leak-docker-config",
        "id-leak-htpasswd",
        "id-leak-php",
    ] {
        std::fs::write(
            templates.join(format!("{entry}.yaml")),
            format!("version: 1\nname: {entry}\nrestype: normal\ntemplate: 'decoy'\n"),
        )
        .unwrap();
    }
    let snapshot = SnapshotLoader::new(limits()).unwrap().load(&path).unwrap();
    let responses = Arc::new(TemplateCatalog::load(&templates, &snapshot).unwrap());
    let mut protection = config(&path);
    protection.ban_extensions = vec!["php".into()];
    protection.fail2ban.status_code = 429;
    let engine = PolicyEngine::with_catalog(protection, snapshot, responses).unwrap();
    let now = SystemTime::now();
    let first = engine.evaluate_input(input("/secret.PHP?x=.asp"), now);
    assert_eq!(
        first.action,
        PolicyAction::Fail2ban {
            status_code: 429,
            retry_after_seconds: 60,
            capacity_exhausted: false,
            normalization_error: false
        }
    );
    assert!(!first.matches.is_match());
    let ban = first.ban.unwrap();
    assert_eq!(ban.triggering_definition_ids, vec![-1]);
    assert_eq!(ban.triggering_attack_types, vec![AttackType::Scanner]);
    assert_eq!(ban.expires_at, now + Duration::from_secs(60));
    assert_eq!(engine.metrics().snapshot().known_rule_matches, 0);
    assert_eq!(engine.metrics().snapshot().honeypot_responses, 0);
    let again = engine.evaluate_input(input("/a/../secret.php"), now);
    assert_eq!(again.action, first.action);
    assert_eq!(again.ban.unwrap().incident_id, ban.incident_id);
    let later = engine.evaluate_input(input("/ordinary"), now);
    assert_eq!(later.action, first.action);
    assert_eq!(later.ban.unwrap().incident_id, ban.incident_id);
    assert_eq!(later.audit, Some(AuditEnqueueResult::Normal));
    let mut id_leak_request = input("/.netrc");
    id_leak_request.client_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 19));
    assert!(matches!(
        engine.evaluate_input(id_leak_request, now).action,
        PolicyAction::Honeypot(_)
    ));
    let mut extension_request = input("/unmatched.php");
    extension_request.client_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 19));
    let extension = engine.evaluate_input(extension_request, now);
    assert_eq!(extension.action, first.action);
    assert_eq!(
        extension.ban.unwrap().triggering_attack_types,
        vec![AttackType::IdLeak]
    );
}

#[test]
fn ban_extensions_match_only_the_complete_final_normalized_path_segment() {
    let directory = tempdir().unwrap();
    let db = directory.path().join("definitions.sqlite");
    initialize_database(&db).unwrap();
    let snapshot = SnapshotLoader::new(limits()).unwrap().load(&db).unwrap();
    let mut protection = config(&db);
    protection.honeypot_mode = false;
    protection.ban_extensions = vec!["php".into(), "asp".into()];
    let engine = PolicyEngine::new(protection.clone(), snapshot.clone()).unwrap();
    for (index, target) in ["/a/b.PHP?x=.asp", "/a/x%2eAsP", "/a/../index.pHp"]
        .iter()
        .enumerate()
    {
        let mut request = input(target);
        request.client_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, index as u8 + 1));
        assert!(
            matches!(
                engine.evaluate_input(request, SystemTime::now()).action,
                PolicyAction::Fail2ban { .. }
            ),
            "{target}"
        );
    }
    for (index, target) in [
        "/a.php/other",
        "/a.php/",
        "/a?file=x.php",
        "/a.php.txt",
        "/php",
        "/.php",
        "/a.php%252f",
        "/a.php/../safe",
    ]
    .iter()
    .enumerate()
    {
        let mut request = input(target);
        request.client_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, index as u8 + 1));
        assert_eq!(
            engine.evaluate_input(request, SystemTime::now()).action,
            PolicyAction::Continue,
            "{target}"
        );
    }
    protection.ban_mode = false;
    let disabled = PolicyEngine::new(protection, snapshot).unwrap();
    assert_eq!(
        disabled
            .evaluate_input(input("/x.php"), SystemTime::now())
            .action,
        PolicyAction::Continue
    );
    assert_eq!(
        disabled
            .evaluate_input(input("/%FF.php"), SystemTime::now())
            .action,
        PolicyAction::Continue
    );
    assert_eq!(disabled.registry().len(), 0);
}

#[test]
fn ban_extensions_respect_allowlist_and_registry_capacity() {
    let directory = tempdir().unwrap();
    let db = directory.path().join("definitions.sqlite");
    initialize_database(&db).unwrap();
    let connection = Connection::open(&db).unwrap();
    connection.execute_batch("INSERT INTO ip_allowlist (id,cidr,enabled,created_at,updated_at) VALUES (1,'192.0.2.0/24',1,'now','now');").unwrap();
    let mut bounded = limits();
    bounded.max_bans = 1;
    let snapshot = SnapshotLoader::new(bounded.clone())
        .unwrap()
        .load(&db)
        .unwrap();
    let mut protection = config(&db);
    protection.honeypot_mode = false;
    protection.limits = bounded;
    protection.ban_extensions = vec!["php".into()];
    let engine = PolicyEngine::new(protection, snapshot).unwrap();
    assert_eq!(
        engine
            .evaluate_input(input("/bad.php"), SystemTime::now())
            .action,
        PolicyAction::Continue
    );
    assert_eq!(engine.registry().len(), 0);
    for (octet, exhausted) in [(1, false), (2, true)] {
        let mut request = input("/bad.php");
        request.client_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, octet));
        let decision = engine.evaluate_input(request, SystemTime::now());
        assert!(
            matches!(decision.action, PolicyAction::Fail2ban { capacity_exhausted, .. } if capacity_exhausted == exhausted)
        );
        assert_eq!(decision.ban.is_none(), exhausted);
    }
    assert_eq!(engine.metrics().snapshot().bans_created, 1);
    assert_eq!(engine.metrics().snapshot().bans_capacity_exhausted, 1);
}

#[test]
fn direct_core_extension_config_requires_canonical_unique_values() {
    let directory = tempdir().unwrap();
    let db = directory.path().join("definitions.sqlite");
    for value in [".php", "PHP", "a/b", " ", "a.b"] {
        let mut protection = config(&db);
        protection.ban_extensions = vec![value.into()];
        assert!(protection.validate().is_err(), "{value}");
    }
    let mut protection = config(&db);
    protection.ban_extensions = vec!["php".into(), "php".into()];
    assert!(protection.validate().is_err());
}

#[test]
fn paths_not_in_db_do_not_match() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("definitions.sqlite");
    initialize_database(&path).unwrap();
    insert_test_definitions(&Connection::open(&path).unwrap());
    let snapshot = SnapshotLoader::new(limits()).unwrap().load(&path).unwrap();
    for target in ["/.env.example", "/key.json", "/.git/config", "/wp-admin/"] {
        assert!(
            !snapshot
                .match_request(&normalize_request(input(target), &limits()).unwrap())
                .is_match()
        );
    }
}

#[test]
fn custom_admin_console_rule_is_scanner_not_id_leak() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("definitions.sqlite");
    initialize_database(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    connection.execute_batch("INSERT INTO attack_definitions (id,name,enabled,field,header_name,matcher,pattern,case_sensitive,attack_type,priority,description,version,created_at,updated_at) VALUES (9999,'custom-admin-console',1,'path',NULL,'prefix','/admin-console',1,'scanner',1,'',1,'now','now');").unwrap();
    let snapshot = SnapshotLoader::new(limits()).unwrap().load(&path).unwrap();
    let result = snapshot
        .match_request(&normalize_request(input("/admin-console/users"), &limits()).unwrap());
    assert_eq!(result.matched_attack_types, vec![AttackType::Scanner]);
    assert!(!result.has_id_leak());
}

#[test]
fn initialize_schema_migrates_away_legacy_honeypot_metadata() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("legacy.sqlite");
    initialize_database(&path).unwrap();
    {
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE honeypot_metadata (
                     definition_id INTEGER PRIMARY KEY,
                     provider TEXT NOT NULL
                 );
                 INSERT INTO honeypot_metadata (definition_id, provider)
                 VALUES (1, 'generic');",
            )
            .unwrap();
    }
    // The read-only loader ignores the obsolete table, so a legacy v1 database
    // stays loadable without re-initialization.
    let snapshot = SnapshotLoader::new(limits()).unwrap().load(&path).unwrap();
    assert_eq!(snapshot.summary().definition_count, 0);

    // Re-running the offline installer step drops the obsolete table in place.
    initialize_database(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    let exists: i64 = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master
                           WHERE type = 'table' AND name = 'honeypot_metadata')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(exists, 0);
}

#[test]
fn initialization_preserves_every_definition_row_and_snapshot_version() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("definitions.sqlite");
    initialize_database(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    connection.execute_batch(
        "INSERT INTO attack_definitions
         (id,name,enabled,field,header_name,matcher,pattern,case_sensitive,attack_type,
          priority,description,version,created_at,updated_at) VALUES
         (7,'id-leak-awsrc-root',1,'path',NULL,'exact','/awsrc',1,'id_leak',70,'',1,'now','now'),
         (3,'id-leak-generic-key-json',1,'path',NULL,'exact','/key.json',1,'id_leak',30,'',1,'now','now'),
         (1,'id-leak-dotenv',1,'path',NULL,'regex','^/custom-env$',1,'id_leak',10,'edited',3,'yesterday','today'),
         (2,'administrator-owned',0,'path',NULL,'exact','/safe',1,'unknown',1,'',1,'now','now');",
    ).unwrap();
    let rows = || -> Vec<(i64, String, String, i64, String, String, i64)> {
        connection.prepare("SELECT id, name, pattern, version, created_at, updated_at, enabled FROM attack_definitions ORDER BY id")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    };
    let before = rows();
    initialize_database(&path).unwrap();
    initialize_database(&path).unwrap();
    assert_eq!(rows(), before);
    assert_eq!(
        connection
            .query_row(
                "SELECT value FROM schema_meta WHERE key = 'snapshot_version'",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        "1"
    );
}

#[test]
fn normalization_decodes_once_and_dotenv_is_precise() {
    let normalized =
        normalize_target("/%2eenv%2elocal?token=secret&safe=value", &limits()).unwrap();
    assert_eq!(normalized.path.value, "/.env.local");
    assert_eq!(normalized.query_for_match.value, "token=secret&safe=value");
    assert_eq!(
        normalized.query_for_audit.value,
        "token=<redacted>&safe=value"
    );
    let query_secrets = normalize_target(
        "/x?x-api-key=one&private_key=two&credential=three&key=four",
        &limits(),
    )
    .unwrap();
    assert_eq!(
        query_secrets.query_for_audit.value,
        "x-api-key=<redacted>&private_key=<redacted>&credential=<redacted>&key=<redacted>"
    );

    let directory = tempdir().unwrap();
    let path = directory.path().join("definitions.sqlite");
    initialize_database(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    insert_test_definitions(&connection);
    let snapshot = SnapshotLoader::new(limits()).unwrap().load(&path).unwrap();

    let dotenv = normalize_request(input("/%2eenv.production"), &limits()).unwrap();
    assert!(snapshot.match_request(&dotenv).has_id_leak());
    let ordinary = normalize_request(input("/app/environment/status"), &limits()).unwrap();
    assert!(!snapshot.match_request(&ordinary).is_match());
}

#[test]
fn normalization_rejects_malformed_input_and_normalizes_path_once() {
    assert_eq!(
        normalize_target("//a///b/%2F/../c", &limits())
            .unwrap()
            .path
            .value,
        "/a/c"
    );
    assert_eq!(
        normalize_target("/a/%2e%2e//b", &limits())
            .unwrap()
            .path
            .value,
        "/b"
    );
    assert_eq!(
        normalize_target("/%252f", &limits()).unwrap().path.value,
        "/%2f"
    );
    assert!(normalize_target("/bad%2", &limits()).is_err());
    assert!(normalize_target("/%FF", &limits()).is_err());
    assert!(IpCidr::parse("192.0.2.1/24").is_err());
}

#[test]
fn optional_allowlist_table_can_be_absent() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("definitions.sqlite");
    initialize_database(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    connection.execute("DROP TABLE ip_allowlist", []).unwrap();
    let snapshot = SnapshotLoader::new(limits()).unwrap().load(&path).unwrap();
    assert_eq!(snapshot.summary().allowlist_count, 0);
}

#[test]
fn loader_rejects_non_sqlite_files_and_header_limits_are_fail_closed() {
    let directory = tempdir().unwrap();
    let invalid_path = directory.path().join("not.sqlite");
    std::fs::write(&invalid_path, b"not a sqlite database").unwrap();
    assert!(
        SnapshotLoader::new(limits())
            .unwrap()
            .load(&invalid_path)
            .is_err()
    );

    let mut limited = limits();
    limited.max_request_headers = 1;
    assert!(normalize_request(input("/ordinary"), &limited).is_err());
    limited.max_request_headers = 64;
    limited.max_header_name_length = 3;
    assert!(normalize_request(input("/ordinary"), &limited).is_err());
}

#[test]
fn exact_prefix_regex_headers_and_multiple_matches_are_evaluated() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("definitions.sqlite");
    initialize_database(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "INSERT INTO attack_definitions
             (id,name,enabled,field,header_name,matcher,pattern,case_sensitive,attack_type,
              priority,description,version,created_at,updated_at)
             VALUES (10,'exact-path',1,'path',NULL,'exact','/probe',1,'scanner',1,'',1,'now','now'),
                    (11,'prefix-agent',1,'user_agent',NULL,'prefix','scanner',0,'scanner',2,'',1,'now','now'),
                    (12,'regex-query',1,'query',NULL,'regex','(?:admin|root)=',1,'credential_attack',3,'',1,'now','now'),
                    (13,'header-match',1,'header','x-forwarded-for','exact','203.0.113.9',1,'unknown',4,'',1,'now','now')",
            [],
        )
        .unwrap();
    let snapshot = SnapshotLoader::new(limits()).unwrap().load(&path).unwrap();
    let mut request = input("/probe?admin=1");
    request.user_agent = "ScAnNeR/1".to_owned();
    request
        .headers
        .push(("X-Forwarded-For".to_owned(), "203.0.113.9".to_owned()));
    let normalized = normalize_request(request, &limits()).unwrap();
    let result = snapshot.match_request(&normalized);
    assert_eq!(result.matched_definition_ids, vec![10, 11, 12, 13]);
    assert!(!result.truncated);
}

#[test]
fn duplicate_headers_are_preserved_and_incomplete_values_only_prefix_match() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("definitions.sqlite");
    initialize_database(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "INSERT INTO attack_definitions
             (id,name,enabled,field,header_name,matcher,pattern,case_sensitive,attack_type,
              priority,description,version,created_at,updated_at)
             VALUES (14,'exact-header',1,'header','x-duplicate','exact','secret',1,'scanner',1,'',1,'now','now'),
                    (15,'prefix-header',1,'header','x-duplicate','prefix','sec',1,'scanner',2,'',1,'now','now'),
                    (16,'regex-header',1,'header','x-duplicate','regex','^sec',1,'scanner',3,'',1,'now','now')",
            [],
        )
        .unwrap();
    let snapshot = SnapshotLoader::new(limits()).unwrap().load(&path).unwrap();
    let mut request = input("/ordinary");
    request.headers = vec![
        ("X-Duplicate".to_owned(), "secret".to_owned()),
        ("X-Duplicate".to_owned(), "second".to_owned()),
    ];
    let normalized = normalize_request(request, &limits()).unwrap();
    assert_eq!(normalized.headers["x-duplicate"].len(), 2);
    assert_eq!(
        snapshot.match_request(&normalized).matched_definition_ids,
        vec![14, 15, 16]
    );

    let mut short_limits = limits();
    short_limits.max_header_value_length = 3;
    let mut request = input("/ordinary");
    request.headers = vec![("X-Duplicate".to_owned(), "secret".to_owned())];
    let normalized = normalize_request(request, &short_limits).unwrap();
    assert!(!normalized.headers["x-duplicate"][0].complete);
    let short_snapshot = SnapshotLoader::new(short_limits.clone())
        .unwrap()
        .load(&path)
        .unwrap();
    let result = short_snapshot.match_request(&normalized);
    assert_eq!(result.matched_definition_ids, vec![15]);
    assert!(normalized.has_truncated_input());
    let ban = BanEntry {
        incident_id: "test-audit".to_owned(),
        ip: normalized.client_ip,
        created_at: SystemTime::UNIX_EPOCH,
        expires_at: SystemTime::UNIX_EPOCH + Duration::from_secs(60),
        triggering_definition_ids: vec![15],
        triggering_attack_types: vec![AttackType::Scanner],
        original_request_summary: "GET /ordinary".to_owned(),
    };
    let audit = AuditRecord::unmatched(
        SystemTime::now(),
        &ban,
        1,
        &normalized,
        ResponseMode::Fail2ban,
        &short_limits,
    );
    assert!(audit.degraded());
}

#[test]
fn matcher_evaluates_all_rules_but_caps_retained_ids() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("definitions.sqlite");
    initialize_database(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "INSERT INTO attack_definitions
             (id,name,enabled,field,header_name,matcher,pattern,case_sensitive,attack_type,
              priority,description,version,created_at,updated_at)
             VALUES (40,'one',1,'path',NULL,'prefix','/all',1,'scanner',1,'',1,'now','now'),
                    (41,'two',1,'path',NULL,'prefix','/all',1,'id_leak',2,'',1,'now','now'),
                    (42,'three',1,'path',NULL,'prefix','/all',1,'credential_attack',3,'',1,'now','now')",
            [],
        )
        .unwrap();
    let mut bounded_limits = limits();
    bounded_limits.max_matches = 1;
    let snapshot = SnapshotLoader::new(bounded_limits.clone())
        .unwrap()
        .load(&path)
        .unwrap();
    let request = normalize_request(input("/all/three"), &bounded_limits).unwrap();
    let result = snapshot.match_request(&request);
    assert_eq!(result.matched_definition_ids, vec![40]);
    assert!(result.truncated);
    assert!(result.has_id_leak());
    assert_eq!(result.selected_id_leak_name.as_deref(), Some("two"));
    assert!(
        result
            .matched_attack_types
            .contains(&AttackType::CredentialAttack)
    );
}

#[test]
fn overlap_priority_and_edited_path_select_definition_template() {
    let directory = tempdir().unwrap();
    let db = directory.path().join("rules.sqlite");
    initialize_database(&db).unwrap();
    let connection = Connection::open(&db).unwrap();
    connection
        .execute_batch(
            "INSERT INTO attack_definitions
        (id,name,enabled,field,header_name,matcher,pattern,case_sensitive,attack_type,
         priority,description,version,created_at,updated_at) VALUES
        (11,'first',1,'path',NULL,'exact','/edited',1,'id_leak',5,'',1,'now','now'),
        (12,'second',1,'path',NULL,'exact','/edited',1,'id_leak',6,'',1,'now','now');",
        )
        .unwrap();
    let limits = Limits {
        max_matches: 1,
        ..Limits::default()
    };
    let snapshot = SnapshotLoader::new(limits.clone())
        .unwrap()
        .load(&db)
        .unwrap();
    let templates = directory.path().join("templates");
    std::fs::create_dir(&templates).unwrap();
    for name in ["first", "second"] {
        std::fs::write(
            templates.join(format!("{name}.yaml")),
            format!("version: 1\nname: {name}\nrestype: normal\ntemplate: '{name}'\n"),
        )
        .unwrap();
    }
    let catalog = Arc::new(TemplateCatalog::load(templates, &snapshot).unwrap());
    let request = normalize_request(input("/edited"), &limits).unwrap();
    let matches = snapshot.match_request(&request);
    assert_eq!(matches.matched_definition_ids, vec![11]);
    assert!(matches.truncated);
    assert_eq!(matches.selected_id_leak_name.as_deref(), Some("first"));
    let mut protection = config(&db);
    protection.limits = limits;
    protection.ban_mode = false;
    let policy = PolicyEngine::with_catalog(protection, snapshot, catalog).unwrap();
    match policy.evaluate(&request, SystemTime::now()).action {
        PolicyAction::Honeypot(response) => assert_eq!(response.body, "first"),
        other => panic!("expected selected template: {other:?}"),
    }
}

#[test]
fn cumulative_regex_budget_rejects_many_short_patterns() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("definitions.sqlite");
    initialize_database(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "INSERT INTO attack_definitions
             (id,name,enabled,field,header_name,matcher,pattern,case_sensitive,attack_type,
              priority,description,version,created_at,updated_at)
             VALUES (50,'short-one',1,'path',NULL,'regex','a',1,'scanner',1,'',1,'now','now'),
                    (51,'short-two',1,'path',NULL,'regex','b',1,'scanner',2,'',1,'now','now')",
            [],
        )
        .unwrap();
    let mut bounded = limits();
    bounded.max_regex_program_bytes = 1_024;
    bounded.max_regex_dfa_bytes = 1_024;
    bounded.max_compiled_regex_bytes_total = 2_048;
    assert!(SnapshotLoader::new(bounded).unwrap().load(&path).is_err());
}

#[test]
fn disabled_rows_are_validated_and_invalid_regex_is_rejected() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("definitions.sqlite");
    initialize_database(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "INSERT INTO attack_definitions
             (id,name,enabled,field,header_name,matcher,pattern,case_sensitive,attack_type,
              priority,description,version,created_at,updated_at)
             VALUES (20,'bad-regex',0,'path',NULL,'regex','(?<=secret)',1,'scanner',1,'',1,'now','now')",
            [],
        )
        .unwrap();
    let error = SnapshotLoader::new(limits())
        .unwrap()
        .load(&path)
        .unwrap_err();
    assert!(error.to_string().contains("regular expression"));
}

#[test]
fn allowlist_bypasses_matching_and_honeypot() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("definitions.sqlite");
    initialize_database(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "INSERT INTO attack_definitions
             (id,name,enabled,field,header_name,matcher,pattern,case_sensitive,attack_type,
              priority,description,version,created_at,updated_at)
             VALUES (30,'allowlisted-leak',1,'path',NULL,'exact','/key.json',1,'id_leak',1,'',1,'now','now')",
            [],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO ip_allowlist (id,cidr,enabled,created_at,updated_at)
             VALUES (1,'192.0.2.0/24',1,'now','now')",
            [],
        )
        .unwrap();
    let snapshot = SnapshotLoader::new(limits()).unwrap().load(&path).unwrap();
    let mut protection = config(&path);
    protection.honeypot_mode = false;
    let engine = PolicyEngine::new(protection, snapshot).unwrap();
    let request = normalize_request(input("/key.json"), &limits()).unwrap();
    let decision = engine.evaluate(&request, SystemTime::UNIX_EPOCH + Duration::from_secs(10));
    assert_eq!(decision.action, PolicyAction::Continue);
    assert!(decision.matches.matched_definition_ids.is_empty());
    assert_eq!(engine.registry().len(), 0);
}

#[test]
fn policy_bans_immediately_honeypots_and_does_not_extend_expiry() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("definitions.sqlite");
    initialize_database(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    insert_test_definitions(&connection);
    drop(connection);
    let snapshot = SnapshotLoader::new(limits()).unwrap().load(&path).unwrap();
    let engine =
        PolicyEngine::with_catalog(config(&path), snapshot.clone(), catalog(&snapshot)).unwrap();
    let request = normalize_request(input("/google-credentials.json"), &limits()).unwrap();
    let first_time = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    let base = engine.registry().clock_reading();
    let first_reading = ClockReading {
        wall_time: first_time,
        monotonic: base.monotonic,
    };
    let first = engine.evaluate_at(&request, first_reading);
    assert!(matches!(first.action, PolicyAction::Honeypot(_)));
    let expiry = first.ban.as_ref().unwrap().expires_at;
    let second = engine.evaluate_at(
        &request,
        ClockReading {
            wall_time: first_time + Duration::from_secs(10),
            monotonic: base.monotonic + Duration::from_secs(10),
        },
    );
    assert_eq!(second.ban.unwrap().expires_at, expiry);
    assert_eq!(engine.registry().len_at(first_reading), 1);
    let after_expiry = normalize_request(input("/ordinary"), &limits()).unwrap();
    assert_eq!(
        engine
            .evaluate_at(
                &after_expiry,
                ClockReading {
                    wall_time: expiry,
                    monotonic: base.monotonic + Duration::from_secs(60),
                },
            )
            .action,
        PolicyAction::Continue
    );
    assert_eq!(
        engine.registry().len_at(ClockReading {
            wall_time: expiry,
            monotonic: base.monotonic + Duration::from_secs(60),
        }),
        0
    );
    assert_eq!(engine.metrics().snapshot().bans_expired, 1);
}

#[test]
fn unmatched_banned_requests_are_queued_only_once_and_redacted() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("definitions.sqlite");
    initialize_database(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    insert_test_definitions(&connection);
    drop(connection);
    let snapshot = SnapshotLoader::new(limits()).unwrap().load(&path).unwrap();
    let engine =
        PolicyEngine::with_catalog(config(&path), snapshot.clone(), catalog(&snapshot)).unwrap();
    let trigger = normalize_request(input("/.aws/credentials"), &limits()).unwrap();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    let _ = engine.evaluate(&trigger, now);
    let mut unmatched_input = input("/ordinary");
    unmatched_input.proxy_ip = Some("172.69.223.81".parse().unwrap());
    unmatched_input.headers.extend([
        (
            "Authorization".to_owned(),
            "Bearer real-looking-secret".to_owned(),
        ),
        ("Cookie".to_owned(), "session=private".to_owned()),
        ("X-API-Key".to_owned(), "api-private".to_owned()),
        ("private_key".to_owned(), "pem-private".to_owned()),
    ]);
    let unmatched = normalize_request(unmatched_input, &limits()).unwrap();
    let decision = engine.evaluate(&unmatched, now + Duration::from_secs(1));
    assert_eq!(decision.action, PolicyAction::NotFound);
    assert_eq!(decision.audit, Some(AuditEnqueueResult::Normal));
    assert!(decision.matches.matched_definition_ids.is_empty());
    let record = engine.audit_queue().try_dequeue().unwrap();
    assert_eq!(record.headers()["authorization"], vec![REDACTED_VALUE]);
    assert_eq!(record.headers()["cookie"], vec![REDACTED_VALUE]);
    assert_eq!(record.headers()["x-api-key"], vec![REDACTED_VALUE]);
    assert_eq!(record.headers()["private_key"], vec![REDACTED_VALUE]);
    let json: Value =
        serde_json::from_str(&record.to_json_line(limits().max_audit_line_bytes).unwrap()).unwrap();
    assert!(json.get("matched_definition_ids").is_none());
    assert!(json.get("attack_type").is_none());
    assert!(json.get("body_sha256").is_none());
    assert!(json.get("request_bytes").is_none());
    assert_eq!(json["content_length_bytes"], 12);
    assert_eq!(json["triggering_definition_ids"], serde_json::json!([103]));
    assert_eq!(
        json["triggering_attack_types"],
        serde_json::json!(["id_leak"])
    );
    assert_eq!(json["response_mode"], "not_found");
    assert_eq!(json["proxy_ip"], "172.69.223.81");
    assert_eq!(json["ip"], "192.0.2.10");
}

#[test]
fn proxy_ip_is_logged_but_the_visitor_ip_is_banned() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("definitions.sqlite");
    initialize_database(&path).unwrap();
    Connection::open(&path)
        .unwrap()
        .execute_batch(
            "INSERT INTO attack_definitions
         (id,name,enabled,field,header_name,matcher,pattern,case_sensitive,attack_type,
          priority,description,version,created_at,updated_at) VALUES
         (1,'probe',1,'path',NULL,'exact','/probe',1,'scanner',1,'',1,'now','now');",
        )
        .unwrap();
    let snapshot = DefinitionSnapshot::load(&path, limits()).unwrap();
    let mut settings = config(&path);
    settings.honeypot_mode = false;
    let engine = PolicyEngine::new(settings, snapshot).unwrap();
    let client_ip: IpAddr = "2a0f:ca80:b00b:6b07::5".parse().unwrap();
    let proxy_ip: IpAddr = "172.69.223.81".parse().unwrap();
    let now = SystemTime::now();
    let mut trigger = input("/probe");
    trigger.client_ip = client_ip;
    trigger.proxy_ip = Some(proxy_ip);
    engine.evaluate_input(trigger, now);
    assert!(engine.registry().get(client_ip).is_some());
    assert!(engine.registry().get(proxy_ip).is_none());
    let mut followup = input("/ordinary");
    followup.client_ip = client_ip;
    followup.proxy_ip = Some(proxy_ip);
    engine.evaluate_input(followup, now);
    let audit = engine.audit_queue().try_dequeue().unwrap();
    let json: Value =
        serde_json::from_str(&audit.to_json_line(limits().max_audit_line_bytes).unwrap()).unwrap();
    assert_eq!(json["ip"], client_ip.to_string());
    assert_eq!(json["proxy_ip"], proxy_ip.to_string());
}

#[test]
fn id_leak_still_honeypots_when_registry_capacity_is_exhausted() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("definitions.sqlite");
    initialize_database(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    insert_test_definitions(&connection);
    drop(connection);
    let mut bounded_limits = limits();
    bounded_limits.max_bans = 1;
    let snapshot = SnapshotLoader::new(bounded_limits.clone())
        .unwrap()
        .load(&path)
        .unwrap();
    let mut protection = config(&path);
    protection.limits = bounded_limits;
    let engine =
        PolicyEngine::with_catalog(protection, snapshot.clone(), catalog(&snapshot)).unwrap();

    let mut filling = input("/.aws/credentials");
    filling.client_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
    let _ = engine.evaluate_input(filling, SystemTime::now());
    let current = engine.evaluate_input(input("/.aws/credentials"), SystemTime::now());
    assert!(matches!(current.action, PolicyAction::Honeypot(_)));
    assert!(current.ban.is_none());
    assert_eq!(engine.metrics().snapshot().bans_capacity_exhausted, 1);
}

#[test]
fn coordination_serializes_new_ban_and_concurrent_unmatched_audit() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("definitions.sqlite");
    initialize_database(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    insert_test_definitions(&connection);
    drop(connection);
    let snapshot = SnapshotLoader::new(limits()).unwrap().load(&path).unwrap();
    let engine = Arc::new(
        PolicyEngine::with_catalog(config(&path), snapshot.clone(), catalog(&snapshot)).unwrap(),
    );
    let (created_tx, created_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let trigger_engine = Arc::clone(&engine);
    let trigger = thread::spawn(move || {
        let decision = trigger_engine.evaluate_input(input("/.aws/credentials"), SystemTime::now());
        created_tx.send(()).unwrap();
        release_rx.recv().unwrap();
        decision
    });
    created_rx.recv().unwrap();
    let unmatched_engine = Arc::clone(&engine);
    let unmatched = thread::spawn(move || {
        unmatched_engine.evaluate_input(input("/ordinary"), SystemTime::now())
    });
    let decision = unmatched.join().unwrap();
    release_tx.send(()).unwrap();
    trigger.join().unwrap();
    assert_eq!(decision.audit, Some(AuditEnqueueResult::Normal));
    assert_eq!(decision.action, PolicyAction::NotFound);
}

#[test]
fn decision_clock_is_captured_after_a_delayed_per_ip_lock() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("definitions.sqlite");
    initialize_database(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    insert_test_definitions(&connection);
    drop(connection);
    let snapshot = SnapshotLoader::new(limits()).unwrap().load(&path).unwrap();

    let (clock_tx, clock_rx) = mpsc::channel();
    let second_release = Arc::new((Mutex::new(false), Condvar::new()));
    let clock = Arc::new(DelayedClock {
        reading: Mutex::new(ClockReading {
            wall_time: SystemTime::UNIX_EPOCH + Duration::from_secs(100),
            monotonic: Instant::now(),
        }),
        calls: AtomicUsize::new(0),
        second_called: clock_tx,
        second_release: Arc::clone(&second_release),
    });
    let (id_tx, id_rx) = mpsc::channel();
    let id_release = Arc::new((Mutex::new(false), Condvar::new()));
    let registry = BanRegistry::with_components(
        limits().max_bans,
        clock.clone(),
        Arc::new(BlockingIncidentIds {
            called: id_tx,
            release: Arc::clone(&id_release),
        }),
    )
    .unwrap();
    let queue = Arc::new(AuditQueue::new(limits().max_audit_queue).unwrap());
    let engine = Arc::new(
        PolicyEngine::with_metric_sink_and_catalog(
            config(&path),
            snapshot.clone(),
            registry,
            queue,
            Arc::new(Metrics::default()),
            None,
            Some(catalog(&snapshot)),
        )
        .unwrap(),
    );

    let trigger_engine = Arc::clone(&engine);
    let trigger = thread::spawn(move || {
        trigger_engine.evaluate_input(input("/.aws/credentials"), SystemTime::now())
    });
    id_rx.recv().unwrap();

    let (started_tx, started_rx) = mpsc::channel();
    let unmatched_engine = Arc::clone(&engine);
    let unmatched = thread::spawn(move || {
        started_tx.send(()).unwrap();
        unmatched_engine.evaluate_input(input("/ordinary"), SystemTime::now())
    });
    started_rx.recv().unwrap();

    // An old implementation sampled the clock before waiting on the lock;
    // that path signals here with the stale reading. The fixed path remains
    // blocked until the trigger releases the per-IP lock.
    assert!(clock_rx.recv_timeout(Duration::from_millis(100)).is_err());
    clock.advance(Duration::from_secs(61));
    release_pair(&id_release);
    clock.release_second();
    trigger.join().unwrap();
    let decision = unmatched.join().unwrap();
    assert_eq!(decision.action, PolicyAction::Continue);
    assert!(decision.audit.is_none());
}

#[test]
fn audit_queue_has_reserved_nonblocking_lane_and_valid_minimal_schema() {
    let queue = AuditQueue::new(2).unwrap();
    let ban = BanEntry {
        incident_id: "queue-test".to_owned(),
        ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        created_at: SystemTime::UNIX_EPOCH,
        expires_at: SystemTime::UNIX_EPOCH + Duration::from_secs(10),
        triggering_definition_ids: vec![1],
        triggering_attack_types: vec![AttackType::Scanner],
        original_request_summary: "GET /".to_owned(),
    };
    let request = normalize_request(input("/normal"), &limits()).unwrap();
    let record = AuditRecord::unmatched(
        SystemTime::UNIX_EPOCH,
        &ban,
        1,
        &request,
        ResponseMode::Fail2ban,
        &limits(),
    );
    assert_eq!(
        queue.try_enqueue(record.clone()),
        AuditEnqueueResult::Normal
    );
    assert_eq!(
        queue.try_enqueue(record.clone()),
        AuditEnqueueResult::MinimalFallback
    );
    assert_eq!(queue.try_enqueue(record), AuditEnqueueResult::FullDrop);
    let first = queue.try_dequeue().unwrap();
    let json: Value =
        serde_json::from_str(&first.to_json_line(limits().max_audit_line_bytes).unwrap()).unwrap();
    assert_eq!(json["triggering_definition_ids"], serde_json::json!([1]));
    assert_eq!(
        json["triggering_attack_types"],
        serde_json::json!(["scanner"])
    );
    assert_eq!(json["content_length_bytes"], 12);
    assert!(json.get("matched_definition_ids").is_none());
    assert!(json.get("attack_type").is_none());
    assert!(json.get("body_sha256").is_none());
    let degraded = first.minimal();
    assert!(degraded.degraded());
    let degraded_json: Value = serde_json::from_str(
        &degraded
            .to_json_line(limits().max_audit_line_bytes)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(degraded_json["degraded"], true);
    assert_eq!(queue.dropped_count(), 1);
}

#[test]
fn audit_writer_waits_without_polling_and_shutdown_unblocks_it() {
    let queue = Arc::new(AuditQueue::new(2).unwrap());
    let writer = AuditWriter::spawn(Arc::clone(&queue), |_record| {}).unwrap();
    thread::sleep(Duration::from_millis(10));
    writer.shutdown_and_join().unwrap();
    assert!(queue.is_shutdown());
}

#[test]
fn writer_failure_marks_queue_failed_and_closes_submissions() {
    let queue = Arc::new(AuditQueue::new(2).unwrap());
    let ban = BanEntry {
        incident_id: "writer-failure".to_owned(),
        ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        created_at: SystemTime::UNIX_EPOCH,
        expires_at: SystemTime::UNIX_EPOCH + Duration::from_secs(60),
        triggering_definition_ids: vec![1],
        triggering_attack_types: vec![AttackType::Scanner],
        original_request_summary: "GET /".to_owned(),
    };
    let request = normalize_request(input("/writer"), &limits()).unwrap();
    let record = AuditRecord::unmatched(
        SystemTime::UNIX_EPOCH,
        &ban,
        1,
        &request,
        ResponseMode::Fail2ban,
        &limits(),
    );
    let writer = AuditWriter::spawn_until(Arc::clone(&queue), |_record| false).unwrap();
    assert_eq!(
        queue.try_enqueue(record.clone()),
        AuditEnqueueResult::Normal
    );
    for _ in 0..100 {
        if queue.is_failed() {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(queue.is_failed());
    assert_eq!(queue.try_enqueue(record), AuditEnqueueResult::FullDrop);
    writer.shutdown_and_join().unwrap();
}

#[test]
fn dropping_writer_requests_shutdown_without_self_join_deadlock() {
    let queue = Arc::new(AuditQueue::new(2).unwrap());
    let writer = AuditWriter::spawn_until(Arc::clone(&queue), |_record| true).unwrap();
    drop(writer);
    assert!(queue.is_shutdown());
}

#[test]
fn normalization_errors_fail_closed_and_honeypot_size_is_startup_validated() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("definitions.sqlite");
    initialize_database(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    insert_test_definitions(&connection);
    drop(connection);
    let snapshot = SnapshotLoader::new(limits()).unwrap().load(&path).unwrap();
    let google = catalog(&snapshot)
        .render("id-leak-google-credentials")
        .unwrap();
    let google_json: Value = serde_json::from_str(&google.body).unwrap();
    assert!(
        google_json["private_key"]
            .as_str()
            .unwrap()
            .contains("BEGIN PRIVATE KEY")
    );
    let mut protection = config(&path);
    protection.limits.max_honeypot_body_bytes = 128;
    assert!(PolicyEngine::new(protection, snapshot).is_err());

    let snapshot = SnapshotLoader::new(limits()).unwrap().load(&path).unwrap();
    let engine =
        PolicyEngine::with_catalog(config(&path), snapshot.clone(), catalog(&snapshot)).unwrap();
    let mut malformed = input("/%FF");
    malformed.body_sha256 = None;
    let decision = engine.evaluate_input(malformed, SystemTime::now());
    assert!(matches!(
        decision.action,
        PolicyAction::Fail2ban {
            normalization_error: true,
            ..
        }
    ));
    assert_eq!(engine.metrics().snapshot().normalization_errors, 1);
}

#[test]
fn malformed_policy_ordering_respects_modes_allowlist_and_active_bans() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("definitions.sqlite");
    initialize_database(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    insert_test_definitions(&connection);
    connection
        .execute(
            "INSERT INTO ip_allowlist (id,cidr,enabled,created_at,updated_at)
             VALUES (1,'192.0.2.0/24',1,'now','now')",
            [],
        )
        .unwrap();
    drop(connection);
    let snapshot = SnapshotLoader::new(limits()).unwrap().load(&path).unwrap();

    let mut disabled = config(&path);
    disabled.ban_mode = false;
    disabled.honeypot_mode = false;
    let disabled_engine = PolicyEngine::new(disabled, snapshot.clone()).unwrap();
    assert_eq!(
        disabled_engine
            .evaluate_input(input("/%FF"), SystemTime::now())
            .action,
        PolicyAction::Continue
    );

    let mut honey_only = config(&path);
    honey_only.ban_mode = false;
    let honey_only_engine =
        PolicyEngine::with_catalog(honey_only, snapshot.clone(), catalog(&snapshot)).unwrap();
    assert_eq!(
        honey_only_engine
            .evaluate_input(input("/%FF"), SystemTime::now())
            .action,
        PolicyAction::Continue
    );

    let allowlisted_engine =
        PolicyEngine::with_catalog(config(&path), snapshot.clone(), catalog(&snapshot)).unwrap();
    assert_eq!(
        allowlisted_engine
            .evaluate_input(input("/%FF"), SystemTime::now())
            .action,
        PolicyAction::Continue
    );

    let mut unlisted = input("/.aws/credentials");
    unlisted.client_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
    let banned_engine =
        PolicyEngine::with_catalog(config(&path), snapshot.clone(), catalog(&snapshot)).unwrap();
    let _ = banned_engine.evaluate_input(unlisted, SystemTime::now());
    let mut malformed = input("/%FF?%78%2d%61%70%69%2d%6b%65%79=secret");
    malformed.client_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
    let decision = banned_engine.evaluate_input(malformed, SystemTime::now());
    assert_eq!(decision.action, PolicyAction::NotFound);
    assert_eq!(decision.audit, Some(AuditEnqueueResult::Normal));
    let audit = banned_engine.audit_queue().try_dequeue().unwrap();
    assert!(audit.degraded());
    let line = audit.to_json_line(limits().max_audit_line_bytes).unwrap();
    assert!(!line.contains("secret"));
    assert!(line.contains("<redacted>=<redacted>"));
}

#[test]
fn metrics_expose_required_events() {
    let metrics = Metrics::default();
    for event in [
        MetricEvent::BanCreated,
        MetricEvent::BanExpired,
        MetricEvent::BanCapacityExhausted,
        MetricEvent::HoneypotResponse,
        MetricEvent::KnownRuleMatch,
        MetricEvent::UnmatchedBannedRequest,
        MetricEvent::AuditMinimalFallback,
        MetricEvent::DroppedAuditRecord,
        MetricEvent::InvalidDefinition,
        MetricEvent::InvalidDefinitionSource,
        MetricEvent::NormalizationError,
    ] {
        metrics.record(event);
    }
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.bans_created, 1);
    assert_eq!(snapshot.bans_capacity_exhausted, 1);
    assert_eq!(snapshot.invalid_definition_sources, 1);
    assert_eq!(snapshot.normalization_errors, 1);
}

#[test]
fn metric_sink_is_bounded_and_nonblocking() {
    let (sender, receiver) = MetricEventSender::channel(1).unwrap();
    assert!(sender.try_record(MetricEvent::KnownRuleMatch));
    assert!(!sender.try_record(MetricEvent::BanCreated));
    assert_eq!(sender.dropped_count(), 1);
    assert_eq!(receiver.try_recv(), Some(MetricEvent::KnownRuleMatch));
}

#[test]
fn policy_rejects_metric_queue_capacity_mismatch() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("definitions.sqlite");
    initialize_database(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    insert_test_definitions(&connection);
    drop(connection);
    let snapshot = SnapshotLoader::new(limits()).unwrap().load(&path).unwrap();
    let (sender, _receiver) = MetricEventSender::channel(1).unwrap();
    let registry = BanRegistry::new(limits().max_bans).unwrap();
    let queue = Arc::new(AuditQueue::new(limits().max_audit_queue).unwrap());
    assert!(
        PolicyEngine::with_metric_sink(
            config(&path),
            snapshot,
            registry,
            queue,
            Arc::new(Metrics::default()),
            Some(sender),
        )
        .is_err()
    );
}

#[test]
fn configurable_limits_cannot_exceed_hard_ceilings() {
    let mut bounded = limits();
    bounded.max_definitions = HARD_MAX_DEFINITIONS + 1;
    assert!(bounded.validate().is_err());
    let mut bounded = limits();
    bounded.max_metric_queue = HARD_MAX_METRIC_QUEUE + 1;
    assert!(bounded.validate().is_err());
    let mut bounded = limits();
    bounded.max_ban_duration = HARD_MAX_BAN_DURATION + Duration::from_secs(1);
    assert!(bounded.validate().is_err());
}
