use crate::matched_log;
use crate::module::{SharedState, SiteState};
use crate::request_source::{malformed_input, request_input};
use abuse_core::{AuditEnqueueResult, PolicyAction, PolicyDecision};
use async_trait::async_trait;
use bytes::Bytes;
use ferron_core::pipeline::{PipelineError, Stage};
use ferron_core::registry::StageConstraint;
use ferron_http::{HttpContext, HttpResponse};
use ferron_observability::{
    Event, MetricAttributeValue, MetricEvent as FerronMetricEvent, MetricType, MetricValue,
};
use http::header::{CONTENT_TYPE, HeaderName, HeaderValue, RETRY_AFTER};
use http_body_util::{BodyExt, Full};
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;
use typemap_rev::TypeMapKey;

#[derive(Debug, Clone)]
pub struct AbuseRequestState {
    pub action: &'static str,
    pub audit: Option<AuditEnqueueResult>,
    pub pending_match: Option<(SystemTime, String, Option<Arc<SiteState>>)>,
}

pub struct AbuseRequestStateKey;

impl TypeMapKey for AbuseRequestStateKey {
    type Value = AbuseRequestState;
}

pub struct AbuseProtectionStage {
    state: Arc<OnceLock<Arc<SharedState>>>,
}

impl AbuseProtectionStage {
    pub fn new(state: Arc<OnceLock<Arc<SharedState>>>) -> Self {
        Self { state }
    }
}

#[async_trait(?Send)]
impl Stage<HttpContext> for AbuseProtectionStage {
    fn name(&self) -> &str {
        "ferron_abuse_protection"
    }

    fn constraints(&self) -> Vec<StageConstraint> {
        vec![
            StageConstraint::After("client_ip_from_header".to_owned()),
            StageConstraint::Before("abuse_protection".to_owned()),
            StageConstraint::Before("http_response".to_owned()),
            StageConstraint::Before("cache".to_owned()),
            StageConstraint::Before("basicauth".to_owned()),
            StageConstraint::Before("forward_proxy".to_owned()),
            StageConstraint::Before("reverse_proxy".to_owned()),
            StageConstraint::Before("static_file".to_owned()),
        ]
    }

    fn is_applicable(
        &self,
        config: Option<&ferron_core::config::ServerConfigurationBlock>,
    ) -> bool {
        config.is_some_and(|block| {
            block.has_directive("ban_mode")
                || block.has_directive("honeypot_mode")
                || block.has_directive("wordpress_site")
                || block.has_directive("definitions_db")
                || block.has_directive("definitions_bundle")
                || block.has_directive("honeypot_templates_dir")
                || block.has_directive("ipban_mode")
                || block.has_directive("geo_mode")
        })
    }

    async fn run(&self, context: &mut HttpContext) -> Result<bool, PipelineError> {
        let Some(state) = self.state.get() else {
            return Ok(true);
        };
        let site = if state.standalone_ipban {
            None
        } else {
            context
                .configuration
                .layers
                .get(1)
                .map(|_| state.site_for(&context.configuration.layers, context.hostname.as_deref()))
                .transpose()
                .map_err(PipelineError::custom)?
        };
        let policy = match &site {
            Some(site) => site.policy.as_ref(),
            None => state.policy.as_ref(),
        };
        if let Some(geo) = &state.geo
            && let Some(ip) = context.remote_address.map(|a| a.ip().to_canonical())
            && !state
                .snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.is_allowlisted(ip))
        {
            let rules =
                crate::geo::rules(&context.configuration.layers).map_err(PipelineError::custom)?;
            if let Some(reason) = geo.matches(ip, &rules) {
                if let Some(path) = &rules.log {
                    let mut logs = geo.logs.lock().unwrap();
                    if !logs.contains_key(path) {
                        match crate::module::open_audit_file(path)
                            .and_then(matched_log::MatchedLog::spawn)
                        {
                            Ok(writer) => {
                                logs.insert(path.clone(), writer);
                            }
                            Err(error) => ferron_core::log_warn!("geo log open failed: {}", error),
                        }
                    }
                    if let Some(writer) = logs.get(path) {
                        writer.record(matched_log::format_line(
                            context,
                            SystemTime::now(),
                            403,
                            &reason,
                        ));
                    }
                }
                fail2ban_response(
                    context,
                    403,
                    abuse_core::Fail2banPolicy::default().retry_after.as_secs(),
                )
                .map_err(|e| PipelineError::custom(e.to_string()))?;
                return Ok(false);
            }
        }
        if let Some(ipban) = &state.ipban
            && let Some(ip) = context
                .remote_address
                .map(|address| address.ip().to_canonical())
            && !state
                .snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.is_allowlisted(ip))
            && ipban.contains(ip)
        {
            let now = SystemTime::now();
            if let Some(writer) = ipban.log.lock().unwrap().as_ref() {
                writer.record(matched_log::format_line(context, now, 403, "ipban"));
            }
            fail2ban_response(
                context,
                403,
                abuse_core::Fail2banPolicy::default().retry_after.as_secs(),
            )
            .map_err(|error| PipelineError::custom(error.to_string()))?;
            context.insert::<AbuseRequestStateKey>(AbuseRequestState {
                action: "ipban",
                audit: None,
                pending_match: None,
            });
            drain_metrics(context, state);
            return Ok(false);
        }
        let Some(policy) = policy else {
            return Ok(true);
        };
        let now = SystemTime::now();
        let decision = match request_input(context, &state.limits) {
            Ok(input) => policy.evaluate_input(input, now),
            Err(_) => {
                let Some(ip) = context
                    .remote_address
                    .map(|address| address.ip().to_canonical())
                else {
                    return Ok(true);
                };
                let mut input = malformed_input(ip);
                input.proxy_ip = crate::cloudflare::proxy_ip(context);
                policy.evaluate_malformed_input(input, now)
            }
        };
        let action = apply_decision(context, &decision)
            .map_err(|error| PipelineError::custom(error.to_string()))?;
        let mut pending_match = None;
        let matched = site
            .as_ref()
            .map_or(&state.matched_log, |site| &site.matched_log);
        if let Some(rule) = matched_log::rule_names(&decision, policy)
            && matched.lock().unwrap().is_some()
        {
            if let Some(status) = matched_log::status(&decision.action) {
                record_match(matched, context, now, status, &rule);
            } else {
                pending_match = Some((now, rule, site.clone()));
            }
        }
        drain_metrics(context, state);
        context.insert::<AbuseRequestStateKey>(AbuseRequestState {
            action,
            audit: decision.audit,
            pending_match,
        });
        Ok(matches!(decision.action, PolicyAction::Continue))
    }

    async fn run_inverse(&self, context: &mut HttpContext) -> Result<(), PipelineError> {
        if let Some(request_state) = context.remove::<AbuseRequestStateKey>()
            && let Some((now, rule, site)) = request_state.pending_match
            && let Some(state) = self.state.get()
        {
            let status = match context.res.as_ref() {
                Some(HttpResponse::BuiltinError(code, _)) => *code,
                Some(HttpResponse::Custom(response)) => response.status().as_u16(),
                _ => 200,
            };
            record_match(
                site.as_ref()
                    .map_or(&state.matched_log, |site| &site.matched_log),
                context,
                now,
                status,
                &rule,
            );
        }
        Ok(())
    }
}

fn record_match(
    matched_log: &std::sync::Mutex<Option<crate::matched_log::MatchedLog>>,
    context: &HttpContext,
    now: SystemTime,
    status: u16,
    rule: &str,
) {
    if let Some(writer) = matched_log.lock().unwrap().as_ref() {
        writer.record(matched_log::format_line(context, now, status, rule));
    }
}

fn drain_metrics(context: &mut HttpContext, state: &SharedState) {
    let mut counts = [0u64; 13];
    if let Some(receiver) = state.metric_receiver.lock().unwrap().as_ref() {
        for _ in 0..1024 {
            let Some(event) = receiver.try_recv() else {
                break;
            };
            counts[metric_index(event)] = counts[metric_index(event)].saturating_add(1);
        }
    }
    let dropped = state.metric_sender.dropped_count();
    let previous = state
        .metric_dropped_seen
        .swap(dropped, std::sync::atomic::Ordering::Relaxed);
    counts[12] = counts[12].saturating_add(dropped.saturating_sub(previous));
    for (index, value) in counts.into_iter().enumerate() {
        if value == 0 {
            continue;
        }
        context.events.emit(Event::Metric(FerronMetricEvent {
            name: metric_name(index),
            attributes: Vec::<(&'static str, MetricAttributeValue)>::new(),
            ty: MetricType::Counter,
            value: MetricValue::U64(value),
            unit: Some("{event}"),
            description: Some("Ferron abuse protection core event."),
            trace_context: None,
        }));
    }
}

fn metric_index(event: abuse_core::MetricEvent) -> usize {
    match event {
        abuse_core::MetricEvent::BanCreated => 0,
        abuse_core::MetricEvent::BanExpired => 1,
        abuse_core::MetricEvent::BanCapacityExhausted => 2,
        abuse_core::MetricEvent::HoneypotResponse => 3,
        abuse_core::MetricEvent::KnownRuleMatch => 4,
        abuse_core::MetricEvent::UnmatchedBannedRequest => 5,
        abuse_core::MetricEvent::AuditMinimalFallback => 6,
        abuse_core::MetricEvent::DroppedAuditRecord => 7,
        abuse_core::MetricEvent::AuditWriterError => 8,
        abuse_core::MetricEvent::InvalidDefinition => 9,
        abuse_core::MetricEvent::InvalidDefinitionSource => 10,
        abuse_core::MetricEvent::NormalizationError => 11,
    }
}

fn metric_name(index: usize) -> &'static str {
    match index {
        0 => "ferron_abuse.bans_created",
        1 => "ferron_abuse.bans_expired",
        2 => "ferron_abuse.ban_capacity_exhausted",
        3 => "ferron_abuse.honeypot_responses",
        4 => "ferron_abuse.known_rule_matches",
        5 => "ferron_abuse.unmatched_banned_requests",
        6 => "ferron_abuse.audit_minimal_fallbacks",
        7 => "ferron_abuse.dropped_audit_records",
        8 => "ferron_abuse.audit_writer_errors",
        9 => "ferron_abuse.invalid_definitions",
        10 => "ferron_abuse.invalid_definition_sources",
        11 => "ferron_abuse.normalization_errors",
        _ => "ferron_abuse.metric_channel_drops",
    }
}

fn apply_decision(
    context: &mut HttpContext,
    decision: &PolicyDecision,
) -> Result<&'static str, Box<dyn std::error::Error>> {
    match &decision.action {
        PolicyAction::Continue => Ok("continue"),
        PolicyAction::NotFound => {
            context.res = Some(HttpResponse::BuiltinError(404, None));
            Ok("not_found")
        }
        PolicyAction::Fail2ban {
            status_code,
            retry_after_seconds,
            ..
        } => {
            fail2ban_response(context, *status_code, *retry_after_seconds)?;
            Ok("fail2ban")
        }
        PolicyAction::Honeypot(response) => {
            let correlation = decision
                .ban
                .as_ref()
                .map(|ban| ban.incident_id.as_str())
                .unwrap_or("capacity");
            let body = Full::new(Bytes::from(response.body.as_bytes().to_vec()))
                .map_err(|never| match never {})
                .boxed_unsync();
            let response = http::Response::builder()
                .status(response.status_code)
                .header(CONTENT_TYPE, response.content_type)
                .header(
                    HeaderName::from_static("x-ferron-abuse-correlation"),
                    correlation,
                )
                .body(body)?;
            context.res = Some(HttpResponse::Custom(response));
            Ok("honeypot")
        }
    }
}

fn fail2ban_response(
    context: &mut HttpContext,
    status: u16,
    retry_after: u64,
) -> Result<(), http::header::InvalidHeaderValue> {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        RETRY_AFTER,
        HeaderValue::from_str(&retry_after.to_string())?,
    );
    context.res = Some(HttpResponse::BuiltinError(status, Some(headers)));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use abuse_core::{AuditQueue, Limits, MetricSink};
    use ferron_observability::{EventSink, MetricValue};
    use std::sync::Mutex;
    use std::sync::atomic::AtomicU64;

    #[tokio::test]
    async fn standalone_ipban_blocks_and_logs_but_preserves_allowlist() {
        let directory = tempfile::tempdir().unwrap();
        let db = directory.path().join("definitions.sqlite");
        abuse_core::initialize_database(&db).unwrap();
        rusqlite::Connection::open(&db).unwrap().execute_batch(
            "INSERT INTO ip_allowlist (id, cidr, created_at, updated_at) VALUES (1, '198.51.100.7/32', 'now', 'now');"
        ).unwrap();
        let snapshot = abuse_core::DefinitionSnapshot::load(&db, Limits::default()).unwrap();
        let path = directory.path().join("ipban.log");
        let ipban = Arc::new(crate::ipban::IpBanState::new(
            crate::config::IpBanConfig {
                url: "https://example.invalid/list".into(),
                interval: std::time::Duration::from_secs(3600),
                log: path.clone(),
            },
            std::fs::File::create(&path).unwrap(),
        ));
        *ipban.list.write().unwrap() = Arc::new(
            abuse_core::IpBanSet::parse("198.51.100.7\n198.51.100.8\n".as_bytes()).unwrap(),
        );
        *ipban.log.lock().unwrap() = Some(
            crate::matched_log::MatchedLog::spawn(ipban.file.lock().unwrap().take().unwrap())
                .unwrap(),
        );
        let (metric_sender, metric_receiver) =
            abuse_core::MetricEventSender::from_limits(&Limits::default()).unwrap();
        let state = Arc::new(SharedState {
            policy: None,
            disabled_audit_queue: None,
            audit_file: Mutex::new(None),
            matched_file: Mutex::new(None),
            matched_log: Mutex::new(None),
            writer: Mutex::new(None),
            max_audit_line_bytes: Limits::default().max_audit_line_bytes,
            limits: Limits::default(),
            metric_sender,
            metric_receiver: Mutex::new(Some(metric_receiver)),
            metric_dropped_seen: AtomicU64::new(0),
            global_config: Arc::new(Default::default()),
            snapshot: Some(snapshot),
            catalog: None,
            shared_registry: abuse_core::BanRegistry::new(Limits::default().max_bans).unwrap(),
            sites: Mutex::new(Default::default()),
            named_hosts: Default::default(),
            cloudflare_ranges: None,
            ipban: Some(Arc::clone(&ipban)),
            standalone_ipban: true,
            geo: None,
        });
        let stage_state = Arc::new(OnceLock::new());
        stage_state.set(state).ok().unwrap();
        let stage = AbuseProtectionStage::new(stage_state);
        let mut allowed = HttpContext::default();
        allowed.remote_address = Some("198.51.100.7:80".parse().unwrap());
        assert!(stage.run(&mut allowed).await.unwrap());
        let mut blocked = HttpContext::default();
        blocked.remote_address = Some("198.51.100.8:80".parse().unwrap());
        assert!(!stage.run(&mut blocked).await.unwrap());
        assert_eq!(
            blocked.get::<AbuseRequestStateKey>().unwrap().action,
            "ipban"
        );
        match blocked.res.as_ref().unwrap() {
            HttpResponse::BuiltinError(403, Some(headers)) => {
                assert_eq!(headers[RETRY_AFTER], "60");
            }
            _ => panic!("expected fail2ban-style 403"),
        }
        let log = ipban.log.lock().unwrap().take().unwrap();
        log.shutdown_and_join().unwrap();
        let lines = std::fs::read_to_string(&path).unwrap();
        assert!(lines.contains("198.51.100.8 - - ["));
        assert!(lines.ends_with("\"ipban\"\n"));
        assert!(!lines.contains("198.51.100.7"));
    }

    #[test]
    fn metric_mapping_uses_fixed_names_without_request_labels() {
        assert_eq!(
            metric_name(metric_index(abuse_core::MetricEvent::BanCreated)),
            "ferron_abuse.bans_created"
        );
        assert_eq!(
            metric_name(metric_index(abuse_core::MetricEvent::DroppedAuditRecord)),
            "ferron_abuse.dropped_audit_records"
        );
        assert_eq!(metric_name(12), "ferron_abuse.metric_channel_drops");
    }

    struct Capture(std::sync::Arc<Mutex<Vec<(String, u64)>>>);

    impl EventSink for Capture {
        fn emit(&self, event: Event) {
            if let Event::Metric(metric) = event
                && let MetricValue::U64(value) = metric.value
            {
                self.0.lock().unwrap().push((metric.name.to_owned(), value));
            }
        }
    }

    #[test]
    fn drain_maps_channel_overflow_to_metric_channel_drops() {
        let (sender, receiver) = abuse_core::MetricEventSender::channel(1).unwrap();
        assert!(sender.try_record(abuse_core::MetricEvent::BanCreated));
        assert!(!sender.try_record(abuse_core::MetricEvent::NormalizationError));
        let state = SharedState {
            policy: None,
            disabled_audit_queue: Some(std::sync::Arc::new(AuditQueue::new(2).unwrap())),
            audit_file: Mutex::new(None),
            matched_file: Mutex::new(None),
            matched_log: Mutex::new(None),
            writer: Mutex::new(None),
            max_audit_line_bytes: Limits::default().max_audit_line_bytes,
            limits: Limits::default(),
            metric_sender: sender,
            metric_receiver: Mutex::new(Some(receiver)),
            metric_dropped_seen: AtomicU64::new(0),
            global_config: Arc::new(Default::default()),
            snapshot: None,
            catalog: None,
            shared_registry: abuse_core::BanRegistry::new(Limits::default().max_bans).unwrap(),
            sites: Mutex::new(Default::default()),
            named_hosts: Default::default(),
            cloudflare_ranges: None,
            ipban: None,
            standalone_ipban: false,
            geo: None,
        };
        let captured = std::sync::Arc::new(Mutex::new(Vec::new()));
        let mut context = HttpContext::default();
        context.events = ferron_observability::CompositeEventSink::new(vec![std::sync::Arc::new(
            Capture(std::sync::Arc::clone(&captured)),
        )]);
        drain_metrics(&mut context, &state);
        let events = captured.lock().unwrap();
        assert!(events.contains(&("ferron_abuse.bans_created".to_owned(), 1)));
        assert!(events.contains(&("ferron_abuse.metric_channel_drops".to_owned(), 1)));
        assert!(
            !events
                .iter()
                .any(|(name, _)| name == "ferron_abuse.normalization_errors")
        );
    }
}
