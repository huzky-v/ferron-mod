use crate::cloudflare::{CloudflareIpStage, load_ranges};
use crate::config::{
    DIRECTIVES, SITE_DIRECTIVES, extract_config, extract_ipban_config, extract_site_config,
    ipban_only, proxied_by, validate_ipban_only,
};
use crate::definition_source::resolve_snapshot_startup;
use crate::ipban::IpBanState;
use crate::matched_log::MatchedLog;
use crate::stage::AbuseProtectionStage;
use abuse_core::{
    AuditQueue, AuditWriter, BanRegistry, DefinitionSnapshot, Limits, MetricEvent,
    MetricEventReceiver, MetricEventSender, MetricSink, Metrics, PolicyEngine, TemplateCatalog,
};
use ferron_core::config::ServerConfigurationBlock;
use ferron_core::loader::ModuleLoader;
use ferron_core::registry::RegistryBuilder;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, OnceLock};

pub struct SiteState {
    pub policy: Option<Arc<PolicyEngine>>,
    pub matched_log: Mutex<Option<MatchedLog>>,
    writer: Mutex<Option<AuditWriter>>,
}

impl std::fmt::Debug for SiteState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SiteState")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

#[derive(Hash, Eq, PartialEq)]
pub struct SiteKey {
    base_layer: usize,
    named_host: Option<String>,
}

impl SiteState {
    fn shutdown(&self) -> (Option<AuditWriter>, Option<MatchedLog>) {
        (
            self.writer.lock().unwrap().take(),
            self.matched_log.lock().unwrap().take(),
        )
    }
}

pub struct SharedState {
    pub policy: Option<Arc<PolicyEngine>>,
    pub disabled_audit_queue: Option<Arc<AuditQueue>>,
    pub audit_file: Mutex<Option<File>>,
    pub matched_file: Mutex<Option<File>>,
    pub matched_log: Mutex<Option<MatchedLog>>,
    pub writer: Mutex<Option<AuditWriter>>,
    pub max_audit_line_bytes: usize,
    pub limits: Limits,
    pub metric_sender: Arc<MetricEventSender>,
    pub metric_receiver: Mutex<Option<MetricEventReceiver>>,
    pub metric_dropped_seen: AtomicU64,
    pub global_config: Arc<ServerConfigurationBlock>,
    pub snapshot: Option<DefinitionSnapshot>,
    pub catalog: Option<Arc<TemplateCatalog>>,
    pub shared_registry: BanRegistry,
    pub sites: Mutex<HashMap<SiteKey, Arc<SiteState>>>,
    pub named_hosts: HashSet<String>,
    pub cloudflare_ranges: Option<Vec<abuse_core::IpCidr>>,
    pub ipban: Option<Arc<IpBanState>>,
    pub standalone_ipban: bool,
    pub geo: Option<Arc<crate::geo::GeoState>>,
}

impl SharedState {
    pub fn audit_queue(&self) -> Option<Arc<AuditQueue>> {
        self.policy
            .as_ref()
            .map(|policy| Arc::clone(policy.audit_queue()))
            .or_else(|| self.disabled_audit_queue.clone())
    }

    pub fn site_for(
        &self,
        layers: &[Arc<ServerConfigurationBlock>],
        hostname: Option<&str>,
    ) -> Result<Arc<SiteState>, String> {
        let base = layers.get(1).ok_or("missing site configuration layer")?;
        // Ferron can layer a default host before a named host. Include only
        // configured names so arbitrary Host headers cannot create site states.
        let named = hostname
            .map(str::to_ascii_lowercase)
            .filter(|host| self.named_hosts.contains(host));
        let key = SiteKey {
            base_layer: Arc::as_ptr(base) as usize,
            named_host: named,
        };
        let mut sites = self.sites.lock().unwrap();
        if let Some(site) = sites.get(&key) {
            return Ok(Arc::clone(site));
        }
        let mut site_block = ServerConfigurationBlock::default();
        for block in layers.iter().skip(1) {
            let directives = Arc::make_mut(&mut site_block.directives);
            for name in SITE_DIRECTIVES {
                if let Some(entries) = block.directives.get(*name) {
                    directives.insert((*name).to_owned(), entries.clone());
                }
            }
        }
        let adapter = extract_site_config(&self.global_config, &site_block)?;
        let enabled = adapter.core.ban_mode || adapter.core.honeypot_mode;
        let policy = if enabled {
            let registry = if adapter.share_bans {
                self.shared_registry.clone()
            } else {
                BanRegistry::new(self.limits.max_bans).map_err(str::to_owned)?
            };
            Some(Arc::new(
                PolicyEngine::with_metric_sink_and_catalog(
                    adapter.core.clone(),
                    self.snapshot
                        .clone()
                        .ok_or("definitions were not loaded for an enabled site")?,
                    registry,
                    Arc::new(
                        AuditQueue::new(self.limits.max_audit_queue).map_err(|e| e.to_string())?,
                    ),
                    Arc::new(Metrics::default()),
                    Some(Arc::clone(&self.metric_sender)),
                    self.catalog.clone(),
                )
                .map_err(|e| e.to_string())?,
            ))
        } else {
            None
        };
        let writer = if let Some(policy) = &policy {
            let file = open_audit_file(&adapter.core.audit_log).map_err(|e| e.to_string())?;
            Some(
                spawn_audit_writer(
                    file,
                    Arc::clone(policy.audit_queue()),
                    self.max_audit_line_bytes,
                    Arc::clone(&self.metric_sender),
                )
                .map_err(|e| e.to_string())?,
            )
        } else {
            None
        };
        let matched_log = if enabled {
            adapter
                .matched_log
                .as_deref()
                .map(|path| MatchedLog::spawn(open_audit_file(path)?))
                .transpose()
                .map_err(|e| e.to_string())?
        } else {
            None
        };
        let site = Arc::new(SiteState {
            policy,
            matched_log: Mutex::new(matched_log),
            writer: Mutex::new(writer),
        });
        sites.insert(key, Arc::clone(&site));
        Ok(site)
    }
}

fn reject_nested_abuse_settings(block: &ServerConfigurationBlock) -> Result<(), String> {
    for entries in block.directives.values() {
        for entry in entries {
            if let Some(children) = &entry.children {
                if let Some(name) = children
                    .directives
                    .keys()
                    .find(|name| DIRECTIVES.contains(&name.as_str()))
                {
                    return Err(format!(
                        "`{name}` can only be set in the global or site block"
                    ));
                }
                reject_nested_abuse_settings(children)?;
            }
        }
    }
    Ok(())
}

#[derive(Default)]
pub struct FerronAbuseProtectionModuleLoader {
    state: Arc<OnceLock<Arc<SharedState>>>,
}

impl ModuleLoader for FerronAbuseProtectionModuleLoader {
    fn register_configuration_adapters(
        &mut self,
        registry: &mut std::collections::HashMap<
            &'static str,
            Box<dyn ferron_core::config::adapter::ConfigurationAdapter>,
        >,
    ) {
        for (name, adapter) in std::mem::take(registry) {
            registry.insert(
                name,
                Box::new(AbuseCatchAllConfigurationAdapter { inner: adapter }),
            );
        }
    }

    fn register_global_configuration_validators(
        &mut self,
        registry: &mut Vec<Box<dyn ferron_core::config::validator::ConfigurationValidator>>,
    ) {
        registry.push(Box::new(
            crate::config::AbuseProtectionConfigurationValidator,
        ));
    }

    fn register_per_protocol_configuration_validators(
        &mut self,
        registry: &mut std::collections::HashMap<
            &'static str,
            Vec<Box<dyn ferron_core::config::validator::ConfigurationValidator>>,
        >,
    ) {
        registry.entry("http").or_default().push(Box::new(
            crate::config::AbuseProtectionConfigurationValidator,
        ));
    }

    fn register_directives(&mut self, registry: &mut ferron_core::directives::DirectiveRegistry) {
        use ferron_core::directives::{Directive, DirectiveSubblock};
        for (name, usage, description) in [
            ("ban_mode", "ban_mode <bool>", "Enable IP banning."),
            (
                "honeypot_mode",
                "honeypot_mode <bool>",
                "Enable randomized id_leak honeypot responses.",
            ),
            (
                "wordpress_site",
                "wordpress_site <bool>",
                "Allow normal WordPress paths and PHP extensions on this site (default false).",
            ),
            (
                "ban_duration",
                "ban_duration <duration>",
                "Fixed ban duration (site-overridable).",
            ),
            (
                "ban_extensions",
                "ban_extensions <extension> [extension ...]",
                "Optional file extensions that immediately trigger a normal IP ban.",
            ),
            (
                "definitions_db",
                "definitions_db <path>",
                "Read-only local attack definition SQLite database.",
            ),
            (
                "definitions_url",
                "definitions_url <https-url>",
                "Optional HTTPS definition source fetched once at startup.",
            ),
            (
                "definitions_bundle",
                "definitions_bundle <default|path|https-url>",
                "Optional ZIP bundle containing definitions and honeypot responses.",
            ),
            (
                "honeypot_templates_dir",
                "honeypot_templates_dir <path>",
                "Startup-only YAML response catalog; required with honeypot_mode.",
            ),
            (
                "audit_log",
                "audit_log <path>",
                "Append-only unmatched banned-request NDJSON path.",
            ),
            (
                "matched_log",
                "matched_log <path>",
                "Optional Apache combined-format log of matched rules with rule name as the final field.",
            ),
            (
                "share_bans",
                "share_bans <bool>",
                "Share IP bans across sites (default true).",
            ),
            (
                "proxied_by",
                "proxied_by <none|cloudflare>",
                "Resolve Cloudflare visitor IP from CF-Connecting-IP when the peer belongs to Cloudflare (default none).",
            ),
            (
                "ipban_mode",
                "ipban_mode <bool>",
                "Enable the periodically downloaded IP blocklist (default false).",
            ),
            (
                "ipban_url",
                "ipban_url <https-url>",
                "HTTPS IP blocklist source (defaults to the AbuseIPDB s100-14d IPv4 list).",
            ),
            (
                "ipban_interval",
                "ipban_interval <duration>",
                "Successful IP blocklist refresh interval (default 24h).",
            ),
            (
                "ipban_log",
                "ipban_log <path>",
                "Dedicated Apache-format blocked-request log; required when ipban_mode is true.",
            ),
            (
                "geo_mode",
                "geo_mode <bool>",
                "Enable ASN and country filtering.",
            ),
            (
                "geo_database",
                "geo_database <path>",
                "Global GeoLite2 country database path.",
            ),
            (
                "geo_asn_database",
                "geo_asn_database <path>",
                "Global GeoLite2 ASN database path.",
            ),
            (
                "geo_url",
                "geo_url <https-url>",
                "Country database download URL.",
            ),
            (
                "geo_asn_url",
                "geo_asn_url <https-url>",
                "ASN database download URL.",
            ),
            (
                "geo_interval",
                "geo_interval <duration>",
                "Database refresh interval (default 7d).",
            ),
            (
                "geo_block_asn",
                "geo_block_asn <asn> [asn ...]",
                "Blocked ASN numbers.",
            ),
            (
                "geo_block_country",
                "geo_block_country <code> [code ...]",
                "Blocked country codes.",
            ),
            (
                "geo_block_continent",
                "geo_block_continent <code> [code ...]",
                "Blocked continent codes.",
            ),
            ("geo_log", "geo_log <path>", "Geo filtering log."),
        ] {
            registry.register(
                Directive {
                    name,
                    usage,
                    description,
                    applicable_protocols: Some(&["http"]),
                    global_only: !crate::config::SITE_DIRECTIVES.contains(&name),
                    subblock_link: Some(DirectiveSubblock::custom("abuse_protection")),
                },
                DirectiveSubblock::default(),
            );
        }
    }

    fn register_stages(&mut self, registry: RegistryBuilder) -> RegistryBuilder {
        let registry = registry.with_stage::<ferron_http::HttpContext, _>(move || {
            Arc::new(crate::log_export::LogExportStage)
        });
        let state = Arc::clone(&self.state);
        let registry = registry.with_stage::<ferron_http::HttpContext, _>(move || {
            Arc::new(CloudflareIpStage::new(Arc::clone(&state)))
        });
        let state = Arc::clone(&self.state);
        registry.with_stage::<ferron_http::HttpContext, _>(move || {
            Arc::new(AbuseProtectionStage::new(Arc::clone(&state)))
        })
    }

    fn register_modules(
        &mut self,
        _registry: Arc<ferron_core::registry::Registry>,
        modules: &mut Vec<Arc<dyn ferron_core::Module>>,
        config: Arc<ferron_core::config::ServerConfiguration>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if ipban_only(&config.global_config) {
            return self.register_standalone_ipban(modules, &config);
        }
        let adapter = extract_config(&config.global_config)?;
        if adapter.cloudflare && config.global_config.has_directive("client_ip_from_header") {
            return Err(
                "`proxied_by cloudflare` cannot be combined with `client_ip_from_header`".into(),
            );
        }
        let cloudflare_ranges =
            if adapter.cloudflare {
                Some(load_ranges().map_err(|error| {
                    format!("failed to load Cloudflare proxy IP ranges: {error}")
                })?)
            } else {
                None
            };
        let ipban = adapter
            .ipban
            .as_ref()
            .map(|settings| {
                open_audit_file(&settings.log)
                    .map(|file| Arc::new(IpBanState::new(settings.clone(), file)))
            })
            .transpose()?;
        let definitions_bundle = adapter.definitions_bundle.clone();
        let matched_log = adapter.matched_log.clone();
        let honeypot_templates_dir = adapter.honeypot_templates_dir.clone();
        let core_config = adapter.core.clone();
        let mut enabled = core_config.ban_mode || core_config.honeypot_mode;
        let mut honeypot_enabled = core_config.honeypot_mode;
        let mut site_logs: Vec<(PathBuf, Option<PathBuf>)> = Vec::new();
        let mut named_hosts = HashSet::new();
        for port in config.ports.get("http").into_iter().flatten() {
            for (filters, block) in &port.hosts {
                if let Some(host) = &filters.host {
                    named_hosts.insert(host.to_ascii_lowercase());
                }
                reject_nested_abuse_settings(block)?;
                if block.get_value("geo_mode").and_then(|v| v.as_boolean()) == Some(true)
                    && !config.global_config.has_directive("geo_database")
                {
                    return Err("geo_mode requires global geo_database and geo_asn_database".into());
                }
                if adapter.cloudflare && block.has_directive("client_ip_from_header") {
                    return Err(
                        "`proxied_by cloudflare` cannot be combined with `client_ip_from_header`"
                            .into(),
                    );
                }
                let site = extract_site_config(&config.global_config, block)?;
                if site.core.ban_mode || site.core.honeypot_mode {
                    enabled = true;
                    honeypot_enabled |= site.core.honeypot_mode;
                    site_logs.push((site.core.audit_log, site.matched_log));
                }
            }
        }
        let (metric_sender, metric_receiver) = MetricEventSender::from_limits(&core_config.limits)?;
        let audit_file = match open_audit_file(&core_config.audit_log) {
            Ok(file) => file,
            Err(error) => {
                let _ = metric_sender.try_record(MetricEvent::AuditWriterError);
                let _ = metric_sender.try_record(MetricEvent::DroppedAuditRecord);
                ferron_core::log_error!("ferron abuse audit_log startup open failed: {}", error);
                return Err(error.into());
            }
        };
        let matched_file = matched_log.as_deref().map(open_audit_file).transpose()?;
        // Fail at startup for invalid log destinations even when a site has not received traffic.
        for (audit, matched) in &site_logs {
            open_audit_file(audit)?;
            if let Some(path) = matched {
                open_audit_file(path)?;
            }
        }
        let (policy, disabled_audit_queue, snapshot, catalog, shared_registry) = if enabled {
            let bundle = if let Some(source) = definitions_bundle.as_deref() {
                Some(
                    crate::bundle_source::load(source, &core_config.limits, honeypot_enabled)
                        .map_err(|error| {
                            let _ = metric_sender.try_record(MetricEvent::InvalidDefinitionSource);
                            ferron_core::log_error!(
                                "ferron abuse definitions_bundle startup load failed: {}",
                                error
                            );
                            error
                        })?,
                )
            } else {
                None
            };
            let snapshot = if let Some((snapshot, _)) = &bundle {
                snapshot.clone()
            } else {
                resolve_snapshot_startup(&core_config, &metric_sender).map_err(|error| {
                    let _ = metric_sender.try_record(MetricEvent::InvalidDefinitionSource);
                    ferron_core::log_error!(
                        "ferron abuse definitions_db startup load failed: {}",
                        error
                    );
                    format!(
                        "failed to load definitions_db {:?}: {error}",
                        core_config.definitions_db
                    )
                })?
            };
            let catalog = if let Some((_, catalog)) = bundle {
                catalog
            } else if honeypot_enabled {
                let directory = honeypot_templates_dir
                    .as_ref()
                    .ok_or("honeypot_templates_dir is required when honeypot_mode is enabled")?;
                Some(Arc::new(
                    TemplateCatalog::load(directory, &snapshot).map_err(|error| {
                        ferron_core::log_error!(
                            "ferron abuse honeypot_templates_dir startup load failed: {}",
                            error
                        );
                        format!(
                            "failed to load honeypot_templates_dir {:?}: {error}",
                            directory
                        )
                    })?,
                ))
            } else {
                None
            };
            let registry = BanRegistry::new(core_config.limits.max_bans)?;
            let audit_queue = Arc::new(AuditQueue::new(core_config.limits.max_audit_queue)?);
            let metrics = Arc::new(Metrics::default());
            let policy = if core_config.ban_mode || core_config.honeypot_mode {
                Some(Arc::new(PolicyEngine::with_metric_sink_and_catalog(
                    core_config.clone(),
                    snapshot.clone(),
                    registry.clone(),
                    audit_queue,
                    metrics,
                    Some(Arc::clone(&metric_sender)),
                    catalog.clone(),
                )?))
            } else {
                None
            };
            (policy, None, Some(snapshot), catalog, registry)
        } else {
            let queue = Arc::new(AuditQueue::new(core_config.limits.max_audit_queue)?);
            (
                None,
                Some(queue),
                None,
                None,
                BanRegistry::new(core_config.limits.max_bans)?,
            )
        };
        let state = Arc::new(SharedState {
            policy,
            disabled_audit_queue,
            audit_file: Mutex::new(Some(audit_file)),
            matched_file: Mutex::new(matched_file),
            matched_log: Mutex::new(None),
            writer: Mutex::new(None),
            max_audit_line_bytes: core_config.limits.max_audit_line_bytes,
            limits: core_config.limits.clone(),
            metric_sender,
            metric_receiver: Mutex::new(Some(metric_receiver)),
            metric_dropped_seen: AtomicU64::new(0),
            global_config: Arc::clone(&config.global_config),
            snapshot,
            catalog,
            shared_registry,
            sites: Mutex::new(HashMap::new()),
            named_hosts,
            cloudflare_ranges,
            ipban,
            standalone_ipban: false,
            geo: crate::geo::GeoState::new(&config.global_config)?.map(Arc::new),
        });
        self.state
            .set(state)
            .map_err(|_| "abuse protection state initialized more than once")?;
        modules.push(Arc::new(AbuseProtectionModule {
            state: Arc::clone(&self.state),
        }));
        Ok(())
    }
}

struct AbuseCatchAllConfigurationAdapter {
    inner: Box<dyn ferron_core::config::adapter::ConfigurationAdapter>,
}

impl ferron_core::config::adapter::ConfigurationAdapter for AbuseCatchAllConfigurationAdapter {
    fn adapt(
        &self,
        params: &std::collections::HashMap<String, String>,
    ) -> ferron_core::config::adapter::AdaptResult {
        let (mut config, watcher, metadata) = self.inner.adapt(params)?;
        crate::config_adapter::add_abuse_catch_all(&mut config);
        Ok((config, watcher, metadata))
    }

    fn file_extension(&self) -> Vec<&'static str> {
        self.inner.file_extension()
    }
}

impl FerronAbuseProtectionModuleLoader {
    fn register_standalone_ipban(
        &self,
        modules: &mut Vec<Arc<dyn ferron_core::Module>>,
        config: &Arc<ferron_core::config::ServerConfiguration>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let global = &config.global_config;
        validate_ipban_only(global)?;
        let ipban = extract_ipban_config(global)?;
        let cloudflare = proxied_by(global)?;
        if cloudflare && global.has_directive("client_ip_from_header") {
            return Err(
                "`proxied_by cloudflare` cannot be combined with `client_ip_from_header`".into(),
            );
        }
        let mut named_hosts = HashSet::new();
        for port in config.ports.get("http").into_iter().flatten() {
            for (filters, block) in &port.hosts {
                if let Some(host) = &filters.host {
                    named_hosts.insert(host.to_ascii_lowercase());
                }
                reject_nested_abuse_settings(block)?;
                if block.get_value("geo_mode").and_then(|v| v.as_boolean()) == Some(true)
                    && !global.has_directive("geo_database")
                {
                    return Err("geo_mode requires global geo_database and geo_asn_database".into());
                }
                if let Some(name) = block.directives.keys().find(|name| {
                    DIRECTIVES.contains(&name.as_str())
                        && ![
                            "geo_mode",
                            "geo_block_asn",
                            "geo_block_country",
                            "geo_block_continent",
                            "geo_log",
                        ]
                        .contains(&name.as_str())
                }) {
                    return Err(format!(
                        "`{name}` requires the existing protection configuration or is global-only"
                    )
                    .into());
                }
                if cloudflare && block.has_directive("client_ip_from_header") {
                    return Err(
                        "`proxied_by cloudflare` cannot be combined with `client_ip_from_header`"
                            .into(),
                    );
                }
            }
        }
        let cloudflare_ranges = if cloudflare {
            Some(load_ranges()?)
        } else {
            None
        };
        let limits = Limits::default();
        let (metric_sender, metric_receiver) = MetricEventSender::from_limits(&limits)?;
        let state = Arc::new(SharedState {
            policy: None,
            disabled_audit_queue: None,
            audit_file: Mutex::new(None),
            matched_file: Mutex::new(None),
            matched_log: Mutex::new(None),
            writer: Mutex::new(None),
            max_audit_line_bytes: limits.max_audit_line_bytes,
            limits: limits.clone(),
            metric_sender,
            metric_receiver: Mutex::new(Some(metric_receiver)),
            metric_dropped_seen: AtomicU64::new(0),
            global_config: Arc::clone(global),
            snapshot: None,
            catalog: None,
            shared_registry: BanRegistry::new(limits.max_bans)?,
            sites: Mutex::new(HashMap::new()),
            named_hosts,
            cloudflare_ranges,
            ipban: ipban
                .as_ref()
                .map(|settings| {
                    open_audit_file(&settings.log)
                        .map(|file| Arc::new(IpBanState::new(settings.clone(), file)))
                })
                .transpose()?,
            standalone_ipban: true,
            geo: crate::geo::GeoState::new(global)?.map(Arc::new),
        });
        self.state
            .set(state)
            .map_err(|_| "abuse protection state initialized more than once")?;
        modules.push(Arc::new(AbuseProtectionModule {
            state: Arc::clone(&self.state),
        }));
        Ok(())
    }
}

pub struct AbuseProtectionModule {
    state: Arc<OnceLock<Arc<SharedState>>>,
}

impl ferron_core::Module for AbuseProtectionModule {
    fn name(&self) -> &str {
        "ferron-abuse-protection"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn start(
        &self,
        runtime: &mut ferron_core::runtime::Runtime,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Some(state) = self.state.get().cloned() else {
            return Err("abuse protection state was not initialized".into());
        };
        if state.policy.is_some() {
            let queue = state.audit_queue().ok_or("audit queue not initialized")?;
            let max_line = state.max_audit_line_bytes;
            let Some(file) = state.audit_file.lock().unwrap().take() else {
                return Err("audit writer file was already consumed".into());
            };
            let writer =
                spawn_audit_writer(file, queue, max_line, Arc::clone(&state.metric_sender))?;
            *state.writer.lock().unwrap() = Some(writer);
            if let Some(file) = state.matched_file.lock().unwrap().take() {
                *state.matched_log.lock().unwrap() = Some(MatchedLog::spawn(file)?);
            }
        }
        if let Some(ipban) = &state.ipban {
            let file = ipban
                .file
                .lock()
                .unwrap()
                .take()
                .ok_or("ipban log file was already consumed")?;
            *ipban.log.lock().unwrap() = Some(MatchedLog::spawn(file)?);
            let refresh = Arc::clone(ipban);
            let shutdown = ferron_core::shutdown::SHUTDOWN_TOKEN.load_full();
            runtime.spawn_secondary_task(async move {
                loop {
                    let worker = Arc::clone(&refresh);
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        result = tokio::task::spawn_blocking(move || worker.fetch()) => {
                            match result {
                                Ok(Ok(count)) => {
                                    ferron_core::log_info!("ferron ipban refreshed: {} addresses", count);
                                    tokio::select! {
                                        _ = shutdown.cancelled() => break,
                                        _ = tokio::time::sleep(refresh.config.interval) => {}
                                    }
                                }
                                error => {
                                    ferron_core::log_warn!("ferron ipban refresh failed: {:?}", error);
                                    tokio::select! {
                                        _ = shutdown.cancelled() => break,
                                        _ = tokio::time::sleep(std::cmp::min(refresh.config.interval, std::time::Duration::from_secs(300))) => {}
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }
        if let Some(geo) = &state.geo {
            let refresh = Arc::clone(geo);
            let shutdown = ferron_core::shutdown::SHUTDOWN_TOKEN.load_full();
            runtime.spawn_secondary_task(async move {
                loop {
                    let worker = Arc::clone(&refresh);
                    let result = tokio::select! { _ = shutdown.cancelled() => break, result = tokio::task::spawn_blocking(move || worker.fetch()) => result };
                    let delay = match result {
                        Ok(Ok(())) => refresh.interval,
                        error => { ferron_core::log_warn!("ferron geo refresh failed: {:?}", error); std::cmp::min(refresh.interval, std::time::Duration::from_secs(300)) }
                    };
                    tokio::select! { _ = shutdown.cancelled() => break, _ = tokio::time::sleep(delay) => {} }
                }
            });
        }
        let writer_state = Arc::clone(&state);
        let shutdown = ferron_core::shutdown::SHUTDOWN_TOKEN.load_full();
        runtime.spawn_secondary_task(async move {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    if let Some(geo) = &writer_state.geo {
                        let logs = std::mem::take(&mut *geo.logs.lock().unwrap());
                        for (_, writer) in logs { let _ = tokio::task::spawn_blocking(move || writer.shutdown_and_join()).await; }
                    }
                    if let Some(ipban) = &writer_state.ipban {
                        let writer = ipban.log.lock().unwrap().take();
                        if let Some(writer) = writer {
                            let _ = tokio::task::spawn_blocking(move || writer.shutdown_and_join()).await;
                        }
                    }
                    let writer = {
                        let mut guard = writer_state.writer.lock().unwrap();
                        guard.take()
                    };
                    if let Some(writer) = writer {
                        let _ = tokio::task::spawn_blocking(move || writer.shutdown_and_join()).await;
                    }
                    let matched = writer_state.matched_log.lock().unwrap().take();
                    if let Some(matched) = matched {
                        let _ = tokio::task::spawn_blocking(move || matched.shutdown_and_join()).await;
                    }
                    let sites: Vec<_> = writer_state.sites.lock().unwrap().values().cloned().collect();
                    for site in sites {
                        let (writer, matched) = site.shutdown();
                        if let Some(writer) = writer {
                            let _ = tokio::task::spawn_blocking(move || writer.shutdown_and_join()).await;
                        }
                        if let Some(matched) = matched {
                            let _ = tokio::task::spawn_blocking(move || matched.shutdown_and_join()).await;
                        }
                    }
                }
            }
        });
        Ok(())
    }
}

fn spawn_audit_writer(
    mut file: File,
    queue: Arc<AuditQueue>,
    max_line: usize,
    metric_sender: Arc<MetricEventSender>,
) -> Result<AuditWriter, Box<dyn std::error::Error>> {
    Ok(AuditWriter::spawn_until(queue, move |record| {
        let line = record
            .to_json_line(max_line)
            .or_else(|_| record.minimal_json_line(max_line));
        let Ok(line) = line else {
            let _ = metric_sender.try_record(MetricEvent::DroppedAuditRecord);
            let _ = metric_sender.try_record(MetricEvent::AuditWriterError);
            ferron_core::log_error!("ferron abuse audit serialization failed");
            return false;
        };
        if file.write_all(line.as_bytes()).is_err() || file.flush().is_err() {
            let _ = metric_sender.try_record(MetricEvent::DroppedAuditRecord);
            let _ = metric_sender.try_record(MetricEvent::AuditWriterError);
            ferron_core::log_error!("ferron abuse audit write or flush failed");
            return false;
        }
        true
    })?)
}

pub(crate) fn open_audit_file(path: &std::path::Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                if !metadata.file_type().is_file() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "audit_log must be a regular non-symlink file",
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "audit_log target is not a regular file",
            ));
        }
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "audit_log target is not a regular file",
            ));
        }
        Ok(file)
    }
}

#[cfg(test)]
mod tests {
    use super::open_audit_file;
    use std::fs::File;
    use tempfile::tempdir;

    #[test]
    fn audit_open_rejects_directory() {
        let directory = tempdir().unwrap();
        assert!(open_audit_file(directory.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn audit_open_rejects_symlink() {
        use std::os::unix::fs::symlink;
        let directory = tempdir().unwrap();
        let target = directory.path().join("target.ndjson");
        File::create(&target).unwrap();
        let link = directory.path().join("link.ndjson");
        symlink(&target, &link).unwrap();
        assert!(open_audit_file(&link).is_err());
    }
}
