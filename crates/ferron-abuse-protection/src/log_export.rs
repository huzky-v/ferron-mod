//! Fixed, authenticated single-day log export and in-place truncation.
use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, NaiveDate, Utc};
use ferron_core::config::ServerConfigurationBlock;
use ferron_core::pipeline::{PipelineError, Stage};
use ferron_core::registry::StageConstraint;
use ferron_http::{HttpContext, HttpResponse};
use ferron_observability::ObservabilityConfigExtractor;
use flate2::{Compression, write::GzEncoder};
use futures_channel::oneshot;
use http::{Method, header};
use http_body_util::{BodyExt, Full};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, mpsc};

pub struct LogExportStage;

const WORK_QUEUE_SIZE: usize = 8;
type WorkResult = io::Result<Option<Vec<u8>>>;
type WorkerSender = mpsc::SyncSender<LogWork>;

struct LogWork {
    path: PathBuf,
    kind: String,
    date: Option<NaiveDate>,
    gzip: bool,
    reply: oneshot::Sender<WorkResult>,
}

fn worker() -> Option<&'static WorkerSender> {
    static WORKER: OnceLock<Option<WorkerSender>> = OnceLock::new();
    WORKER
        .get_or_init(|| {
            let (sender, receiver) = mpsc::sync_channel::<LogWork>(WORK_QUEUE_SIZE);
            std::thread::Builder::new()
                .name("ferron-log-export".to_owned())
                .spawn(move || {
                    for work in receiver {
                        let result = if let Some(date) = work.date {
                            export(&work.path, &work.kind, date, work.gzip).map(Some)
                        } else {
                            truncate(&work.path).map(|()| None)
                        };
                        let _ = work.reply.send(result);
                    }
                })
                .ok()
                .map(|_| sender)
        })
        .as_ref()
}

async fn run_work(path: PathBuf, kind: String, date: Option<NaiveDate>, gzip: bool) -> WorkResult {
    let (reply, receiver) = oneshot::channel();
    let worker = worker().ok_or_else(|| io::Error::other("log export worker unavailable"))?;
    worker
        .try_send(LogWork {
            path,
            kind,
            date,
            gzip,
            reply,
        })
        .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "log export worker busy"))?;
    receiver
        .await
        .map_err(|_| io::Error::other("log export worker stopped"))?
}

#[async_trait(?Send)]
impl Stage<HttpContext> for LogExportStage {
    fn name(&self) -> &str {
        "abuse_log_export"
    }

    fn constraints(&self) -> Vec<StageConstraint> {
        vec![
            // Match ACME's early interception point so proxy and redirect
            // handlers never receive the reserved log namespace.
            StageConstraint::Before("https_redirect".to_owned()),
            StageConstraint::Before("client_ip_from_header".to_owned()),
            StageConstraint::Before("ferron_abuse_protection".to_owned()),
            StageConstraint::Before("abuse_protection".to_owned()),
            StageConstraint::Before("http_response".to_owned()),
            StageConstraint::Before("cache".to_owned()),
            StageConstraint::Before("basicauth".to_owned()),
            StageConstraint::Before("forward_proxy".to_owned()),
            StageConstraint::Before("reverse_proxy".to_owned()),
            StageConstraint::Before("static_file".to_owned()),
        ]
    }

    async fn run(&self, context: &mut HttpContext) -> Result<bool, PipelineError> {
        let Some(uri) = context
            .original_uri
            .as_ref()
            .or_else(|| context.req.as_ref().map(|request| request.uri()))
        else {
            return Ok(true);
        };
        let Some(kind) = uri.path().strip_prefix("/.ferron-logs/") else {
            return Ok(true);
        };
        let Some(directive) = directive(kind) else {
            // Reserve the entire internal namespace rather than forwarding unknown paths.
            context.res = Some(HttpResponse::BuiltinError(404, None));
            return Ok(false);
        };
        let Some(request) = context.req.as_ref() else {
            return Ok(true);
        };
        let key = std::env::var("FERRON_LOG_EXPORT_BEARER_KEY").unwrap_or_default();
        let auth_status = authorization_status(&key, request.headers().get(header::AUTHORIZATION));
        if let Some(status) = auth_status {
            context.res = Some(HttpResponse::BuiltinError(status, None));
            return Ok(false);
        }
        let method = request.method().clone();
        if method != Method::GET && method != Method::DELETE {
            context.res = Some(HttpResponse::BuiltinError(405, None));
            return Ok(false);
        }
        let enabled = |block: &ServerConfigurationBlock, name: &str| {
            block.get_value(name).and_then(|v| v.as_boolean()) == Some(true)
        };
        let layers = &context.configuration.layers;
        let global = layers.first().map(AsRef::as_ref);
        let protection = |name| {
            layers
                .iter()
                .rev()
                .find_map(|block| block.get_value(name).and_then(|v| v.as_boolean()))
                == Some(true)
        };
        let active = match kind {
            "ipban" => global.is_some_and(|block| enabled(block, "ipban_mode")),
            "matched" | "unmatched" => protection("ban_mode") || protection("honeypot_mode"),
            "geo" => {
                layers
                    .iter()
                    .rev()
                    .find_map(|block| block.get_value("geo_mode").and_then(|v| v.as_boolean()))
                    == Some(true)
            }
            "access" => true,
            _ => false,
        };
        let path = if kind == "access" {
            access_log_path(layers)
        } else if kind == "ipban" {
            global
                .and_then(|block| block.get_value(directive))
                .and_then(|value| value.as_str())
                .filter(|path| !path.is_empty())
                .map(PathBuf::from)
        } else {
            layers.iter().rev().find_map(|block| {
                block
                    .get_value(directive)
                    .and_then(|value| value.as_str())
                    .filter(|path| !path.is_empty())
                    .map(PathBuf::from)
            })
        };
        if !active || path.is_none() {
            context.res = Some(HttpResponse::BuiltinError(404, None));
            return Ok(false);
        }
        let path = path.unwrap();
        let kind = kind.to_owned();
        let gzip = accepts_gzip(request.headers().get(header::ACCEPT_ENCODING));
        let date = if method == Method::GET {
            match requested_date(uri.query(), Utc::now().date_naive()) {
                Some(date) => Some(date),
                None => {
                    context.res = Some(HttpResponse::BuiltinError(400, None));
                    return Ok(false);
                }
            }
        } else {
            None
        };
        let result = run_work(path, kind, date, gzip).await;
        match result {
            Ok(Some(bytes)) => {
                let body = Full::new(Bytes::from(bytes))
                    .map_err(|never| match never {})
                    .boxed_unsync();
                let mut response = http::Response::builder()
                    .status(200)
                    .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                    .header(header::VARY, "Accept-Encoding")
                    .header(header::CACHE_CONTROL, "no-store");
                if gzip {
                    response = response.header(header::CONTENT_ENCODING, "gzip");
                }
                context.res = Some(HttpResponse::Custom(
                    response
                        .body(body)
                        .map_err(|error| PipelineError::custom(error.to_string()))?,
                ));
            }
            Ok(None) => {
                let body = Full::new(Bytes::new())
                    .map_err(|never| match never {})
                    .boxed_unsync();
                context.res = Some(HttpResponse::Custom(
                    http::Response::builder()
                        .status(204)
                        .header(header::CACHE_CONTROL, "no-store")
                        .body(body)
                        .map_err(|error| PipelineError::custom(error.to_string()))?,
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                context.res = Some(HttpResponse::BuiltinError(404, None))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                context.res = Some(HttpResponse::BuiltinError(503, None))
            }
            other => {
                ferron_core::log_error!("log export failed: {:?}", other);
                context.res = Some(HttpResponse::BuiltinError(500, None));
            }
        }
        Ok(false)
    }
}

/// Resolve Ferron's `log <path>` alias and explicit `observability { provider file;
/// access_log <path> }` blocks through the same extractor used by its sinks.
fn access_log_path(layers: &[std::sync::Arc<ServerConfigurationBlock>]) -> Option<PathBuf> {
    for layer in layers.iter().rev() {
        let blocks = ObservabilityConfigExtractor::new(layer)
            .extract_observability_blocks()
            .ok()?;
        for block in blocks.iter().rev() {
            if block.get_value("provider").and_then(|value| value.as_str()) != Some("file") {
                continue;
            }
            if let Some(path) = block
                .get_value("access_log")
                .and_then(|value| value.as_str())
                .filter(|path| !path.is_empty())
            {
                return Some(PathBuf::from(path));
            }
        }
    }
    None
}

fn requested_date(query: Option<&str>, today: NaiveDate) -> Option<NaiveDate> {
    let Some(query) = query else {
        return Some(today);
    };
    let date = query.strip_prefix("date=")?;
    if date.len() != 10 || date.contains('&') {
        return None;
    }
    NaiveDate::parse_from_str(date, "%Y-%m-%d").ok()
}

fn authorization_status(key: &str, authorization: Option<&http::HeaderValue>) -> Option<u16> {
    if key.is_empty() {
        return Some(404);
    }
    if authorization
        .is_some_and(|value| value.as_bytes().strip_prefix(b"Bearer ") == Some(key.as_bytes()))
    {
        None
    } else {
        Some(401)
    }
}

fn accepts_gzip(value: Option<&http::HeaderValue>) -> bool {
    value
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|encoding| {
                let mut parts = encoding.trim().split(';');
                parts
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case("gzip"))
                    && parts.all(|parameter| {
                        let parameter = parameter.trim();
                        !parameter.starts_with("q=")
                            || parameter
                                .strip_prefix("q=")
                                .and_then(|quality| quality.parse::<f32>().ok())
                                .is_some_and(|quality| quality > 0.0 && quality <= 1.0)
                    })
            })
        })
}

fn directive(kind: &str) -> Option<&'static str> {
    match kind {
        "ipban" => Some("ipban_log"),
        "matched" => Some("matched_log"),
        "unmatched" => Some("audit_log"),
        "access" => Some("access_log"),
        "geo" => Some("geo_log"),
        _ => None,
    }
}

fn open_existing(path: &Path, write: bool) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(write)
            .custom_flags(libc::O_NOFOLLOW);
        let file = options.open(path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "log is not a regular file",
            ));
        }
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let file = OpenOptions::new().read(true).write(write).open(path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "log is not a regular file",
            ));
        }
        Ok(file)
    }
}

fn truncate(path: &Path) -> io::Result<()> {
    open_existing(path, true)?.set_len(0)
}

fn export(path: &Path, kind: &str, date: NaiveDate, gzip: bool) -> io::Result<Vec<u8>> {
    let file = open_existing(path, false)?;
    if gzip {
        let mut output = GzEncoder::new(Vec::new(), Compression::default());
        write_day(file, kind, date, &mut output)?;
        output.finish()
    } else {
        let mut output = Vec::new();
        write_day(file, kind, date, &mut output)?;
        Ok(output)
    }
}

fn write_day(file: File, kind: &str, date: NaiveDate, output: &mut impl Write) -> io::Result<()> {
    for line in BufReader::new(file).split(b'\n') {
        let line = line?;
        if line_date(&line, kind) == Some(date) {
            output.write_all(&line)?;
            output.write_all(b"\n")?;
        }
    }
    Ok(())
}

fn line_date(line: &[u8], kind: &str) -> Option<NaiveDate> {
    let line = std::str::from_utf8(line).ok()?;
    if kind == "unmatched" || (kind == "access" && line.starts_with('{')) {
        let value: serde_json::Value = serde_json::from_str(line).ok()?;
        return DateTime::parse_from_rfc3339(value.get("timestamp")?.as_str()?)
            .ok()
            .map(|time| time.with_timezone(&Utc).date_naive());
    }
    let timestamp = line.split_once('[')?.1.split_once(']')?.0;
    DateTime::parse_from_str(timestamp, "%d/%b/%Y:%H:%M:%S %z")
        .ok()
        .map(|time| time.with_timezone(&Utc).date_naive())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferron_core::config::{ServerConfigurationDirectiveEntry, ServerConfigurationValue};
    use ferron_http::HttpRequest;
    use flate2::read::GzDecoder;
    use http::HeaderValue;
    use http::Request;
    use http_body_util::Empty;
    use std::io::Read;
    use std::sync::Arc;

    #[test]
    fn access_path_follows_ferron_log_alias_and_scoped_file_sink() {
        fn entry(
            args: Vec<ServerConfigurationValue>,
            children: Option<ServerConfigurationBlock>,
        ) -> ServerConfigurationDirectiveEntry {
            ServerConfigurationDirectiveEntry {
                args,
                children,
                span: None,
            }
        }
        fn string(value: &str) -> ServerConfigurationValue {
            ServerConfigurationValue::String(value.to_owned(), None)
        }
        let mut global = ServerConfigurationBlock::default();
        Arc::make_mut(&mut global.directives).insert(
            "log".into(),
            vec![entry(vec![string("/var/log/ferron/access.log")], None)],
        );
        assert_eq!(
            access_log_path(&[Arc::new(global.clone())]),
            Some(PathBuf::from("/var/log/ferron/access.log"))
        );

        let mut sink = ServerConfigurationBlock::default();
        let directives = Arc::make_mut(&mut sink.directives);
        directives.insert("provider".into(), vec![entry(vec![string("file")], None)]);
        directives.insert(
            "access_log".into(),
            vec![entry(vec![string("/var/log/ferron/site.log")], None)],
        );
        let mut site = ServerConfigurationBlock::default();
        Arc::make_mut(&mut site.directives)
            .insert("observability".into(), vec![entry(vec![], Some(sink))]);
        assert_eq!(
            access_log_path(&[Arc::new(global), Arc::new(site)]),
            Some(PathBuf::from("/var/log/ferron/site.log"))
        );
    }

    #[test]
    fn disabled_and_non_file_access_sinks_remain_unavailable() {
        let mut block = ServerConfigurationBlock::default();
        Arc::make_mut(&mut block.directives).insert(
            "log".into(),
            vec![ServerConfigurationDirectiveEntry {
                args: vec![ServerConfigurationValue::Boolean(false, None)],
                children: None,
                span: None,
            }],
        );
        assert_eq!(access_log_path(&[Arc::new(block)]), None);
    }

    #[test]
    fn export_and_delete_work_without_a_tokio_runtime() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("access.log");
        std::fs::write(&path, b"a [29/Oct/2026:12:04:16 +0000] first\n").unwrap();
        let date = NaiveDate::from_ymd_opt(2026, 10, 29).unwrap();
        let contents = futures_executor::block_on(run_work(
            path.clone(),
            "access".to_owned(),
            Some(date),
            false,
        ))
        .unwrap()
        .unwrap();
        assert_eq!(contents, b"a [29/Oct/2026:12:04:16 +0000] first\n");
        futures_executor::block_on(run_work(path.clone(), "access".to_owned(), None, false))
            .unwrap();
        assert_eq!(std::fs::metadata(path).unwrap().len(), 0);
    }

    #[test]
    fn missing_date_defaults_to_today_but_invalid_dates_are_rejected() {
        let today = NaiveDate::from_ymd_opt(2026, 10, 29).unwrap();
        assert_eq!(requested_date(None, today), Some(today));
        assert_eq!(
            requested_date(Some("date=2026-10-28"), today),
            NaiveDate::from_ymd_opt(2026, 10, 28)
        );
        for query in [
            "",
            "date=",
            "date=2026-02-30",
            "date=2026-10-29&other=1",
            "other=1",
        ] {
            assert_eq!(requested_date(Some(query), today), None, "query: {query}");
        }
    }

    #[tokio::test]
    async fn reserves_only_new_namespace_before_other_handlers() {
        let stage = LogExportStage;
        let mut context = HttpContext::default();
        context.original_uri = Some("/.ferron-logs/unknown".parse().unwrap());
        assert!(!stage.run(&mut context).await.unwrap());
        assert!(matches!(
            context.res,
            Some(HttpResponse::BuiltinError(404, _))
        ));

        context.res = None;
        context.original_uri = Some("/.internals/unknown".parse().unwrap());
        assert!(stage.run(&mut context).await.unwrap());
        assert!(context.res.is_none());

        context.original_uri = None;
        let request: HttpRequest = Request::builder()
            .uri("/.ferron-logs/unknown")
            .body(
                Empty::<Bytes>::new()
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .unwrap();
        context.req = Some(request);
        assert!(!stage.run(&mut context).await.unwrap());
        assert!(matches!(
            context.res,
            Some(HttpResponse::BuiltinError(404, _))
        ));
    }

    #[test]
    fn intercepts_before_redirect_proxy_and_request_filtering() {
        let constraints = LogExportStage.constraints();
        for stage in [
            "https_redirect",
            "client_ip_from_header",
            "ferron_abuse_protection",
            "forward_proxy",
            "reverse_proxy",
        ] {
            assert!(
                constraints.iter().any(|constraint| matches!(constraint, StageConstraint::Before(name) if name == stage)),
                "log endpoint must precede {stage}"
            );
        }
    }

    #[test]
    fn missing_key_hides_route_and_wrong_token_is_unauthorized() {
        let valid = HeaderValue::from_static("Bearer secret");
        let wrong = HeaderValue::from_static("Bearer wrong");
        assert_eq!(authorization_status("", Some(&valid)), Some(404));
        assert_eq!(authorization_status("secret", None), Some(401));
        assert_eq!(authorization_status("secret", Some(&wrong)), Some(401));
        assert_eq!(authorization_status("secret", Some(&valid)), None);
    }

    #[test]
    fn gzip_is_negotiated_not_a_download_format() {
        assert!(!accepts_gzip(None));
        assert!(accepts_gzip(Some(&HeaderValue::from_static("br, gzip"))));
        assert!(accepts_gzip(Some(&HeaderValue::from_static("gzip;q=0.5"))));
        assert!(!accepts_gzip(Some(&HeaderValue::from_static("gzip;q=0"))));
        assert!(!accepts_gzip(Some(&HeaderValue::from_static("xgzip"))));
    }

    #[test]
    fn exports_only_selected_utc_day_across_offsets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("matched.log");
        std::fs::write(
            &path,
            "a [01/Jan/2025:00:00:00 +0000] first\n\
             b [01/Jan/2025:23:59:59 +0000] last\n\
             c [02/Jan/2025:00:00:00 +0000] next\n\
             d [02/Jan/2025:01:00:00 +0200] offset\n\
             invalid line\n",
        )
        .unwrap();
        let day = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
        let compressed = export(&path, "matched", day, true).unwrap();
        let mut text = String::new();
        GzDecoder::new(compressed.as_slice())
            .read_to_string(&mut text)
            .unwrap();
        assert!(text.contains("first"));
        assert!(text.contains("last"));
        assert!(text.contains("offset"));
        assert!(!text.contains("next"));
        assert!(!text.contains("invalid"));
        assert_eq!(
            export(&path, "matched", day, false).unwrap(),
            text.as_bytes()
        );
        truncate(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        std::fs::write(&path, "still writable\n").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"still writable\n");
    }

    #[test]
    fn unmatched_ndjson_uses_timestamp_and_never_exports_other_dates() {
        let day = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
        assert_eq!(
            line_date(br#"{"timestamp":"2025-01-02T00:30:00+01:00"}"#, "unmatched"),
            Some(day)
        );
        assert_eq!(line_date(b"not json", "unmatched"), None);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_and_does_not_create_missing_files() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        std::fs::write(&target, b"safe").unwrap();
        symlink(&target, &link).unwrap();
        assert!(truncate(&link).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"safe");
        assert_eq!(
            truncate(&dir.path().join("missing")).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }
}
