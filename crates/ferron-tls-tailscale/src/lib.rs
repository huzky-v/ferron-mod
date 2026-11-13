//! TLS provider for authorized Tailscale MagicDNS hostnames.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak, mpsc};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ferron_core::config::ServerConfigurationBlock;
use ferron_core::config::validator::{
    ConfigurationValidationError, ConfigurationValidator, ConfigurationValidatorContext,
    ConfigurationValidatorScopedKey,
};
use ferron_core::config_validator_scoped_key;
use ferron_core::loader::ModuleLoader;
use ferron_core::providers::Provider;
use ferron_core::registry::RegistryBuilder;
use ferron_core::runtime::Runtime;
use ferron_tls::builder::build_server_config_builder;
use ferron_tls::config::{TlsCryptoConfig, TlsServerConfig};
use ferron_tls::{TlsContext, TlsResolver, validate_tls_common};
use rustls::ServerConfig;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

pub struct TlsTailscaleResolver {
    config: Arc<ServerConfig>,
    state: Arc<HostState>,
}

#[async_trait(?Send)]
impl TlsResolver for TlsTailscaleResolver {
    fn get_tls_config(&self) -> Arc<ServerConfig> {
        self.config.clone()
    }

    fn get_tls_background_error(&self) -> Option<String> {
        let state = self.state.inner.read().ok()?;
        match &state.phase {
            Phase::Pending | Phase::Provisioning => {
                Some("Tailscale certificate provisioning pending".into())
            }
            Phase::Failed(error) => Some(format!(
                "Tailscale certificate provisioning failed: {error}"
            )),
            Phase::Ready => None,
        }
    }
}

#[derive(Debug)]
enum Phase {
    Pending,
    Provisioning,
    Ready,
    Failed(String),
}

#[derive(Debug)]
struct HostStatus {
    phase: Phase,
    changed: Instant,
    key: Option<Arc<CertifiedKey>>,
}

#[derive(Debug)]
struct HostState {
    inner: RwLock<HostStatus>,
    crypto: Arc<rustls::crypto::CryptoProvider>,
    crypto_config: TlsCryptoConfig,
}

impl HostState {
    fn new(crypto: Arc<rustls::crypto::CryptoProvider>, crypto_config: TlsCryptoConfig) -> Self {
        Self {
            inner: RwLock::new(HostStatus {
                phase: Phase::Pending,
                changed: Instant::now(),
                key: None,
            }),
            crypto,
            crypto_config,
        }
    }

    fn matches_crypto(&self, config: &TlsCryptoConfig) -> bool {
        self.crypto_config.cipher_suites == config.cipher_suites
            && self.crypto_config.kx_groups == config.kx_groups
            && self.crypto_config.min_version == config.min_version
            && self.crypto_config.max_version == config.max_version
    }

    fn publish(&self, result: Result<Arc<CertifiedKey>, String>) {
        if let Ok(mut state) = self.inner.write() {
            state.changed = Instant::now();
            match result {
                Ok(key) => {
                    state.key = Some(key);
                    state.phase = Phase::Ready;
                }
                Err(error) => {
                    state.phase = Phase::Failed(error);
                } // retain last-good cert
            }
        }
    }
}

#[derive(Debug)]
struct DynamicResolver(Arc<HostState>);

impl ResolvesServerCert for DynamicResolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current_key()
    }
}

impl DynamicResolver {
    fn current_key(&self) -> Option<Arc<CertifiedKey>> {
        self.0.inner.read().ok()?.key.clone()
    }
}

struct Work {
    node: ferron_tailscale::Node,
    child: Arc<ferron_tailscale::OwnedChild>,
    state: Arc<HostState>,
}

struct Shared {
    nodes: Mutex<ferron_tailscale::NodeManager>,
    states: Mutex<BTreeMap<String, Arc<HostState>>>,
    active: Mutex<BTreeMap<String, ()>>,
    started: AtomicBool,
    shutting_down: Arc<AtomicBool>,
    tx: Mutex<Option<mpsc::SyncSender<Work>>>,
}

impl Drop for Shared {
    fn drop(&mut self) {
        // Workers hold only Weak<Shared>; closing the sender wakes idle workers.
        // In-flight bounded CLI/LocalAPI work finishes without delaying teardown.
        self.shutting_down.store(true, Ordering::Release);
        if let Ok(mut tx) = self.tx.lock() {
            tx.take();
        }
    }
}

impl Default for Shared {
    fn default() -> Self {
        Self {
            nodes: Mutex::new(ferron_tailscale::NodeManager::default()),
            states: Mutex::new(BTreeMap::new()),
            active: Mutex::new(BTreeMap::new()),
            started: AtomicBool::new(false),
            shutting_down: Arc::new(AtomicBool::new(false)),
            tx: Mutex::new(None),
        }
    }
}

impl Shared {
    fn state(
        &self,
        host: &str,
        crypto: Arc<rustls::crypto::CryptoProvider>,
        crypto_config: &TlsCryptoConfig,
    ) -> Result<Arc<HostState>, String> {
        let (machine, tailnet) =
            ferron_tailscale::parse_tailscale_host(host).ok_or("invalid Tailscale hostname")?;
        let host = format!("{machine}.{tailnet}.ts.net");
        if self
            .nodes
            .lock()
            .map_err(|_| "node lock poisoned")?
            .node(&host)
            .is_none()
        {
            return Err(format!("Tailscale host {host} not in node inventory"));
        }
        let state = self
            .states
            .lock()
            .map_err(|_| "state lock poisoned")?
            .entry(host)
            .or_insert_with(|| Arc::new(HostState::new(crypto, crypto_config.clone())))
            .clone();
        if !state.matches_crypto(crypto_config) {
            return Err(
                "Tailscale TLS crypto settings changed for this host; restart Ferron".into(),
            );
        }
        Ok(state)
    }

    fn queue_ready(&self) {
        let Some(tx) = self.tx.lock().ok().and_then(|tx| tx.clone()) else {
            return;
        };
        let Ok(states) = self.states.lock() else {
            return;
        };
        let hosts: Vec<_> = states
            .iter()
            .map(|(name, state)| (name.clone(), state.clone()))
            .collect();
        drop(states);
        let Ok(mut active) = self.active.lock() else {
            return;
        };
        for (name, state) in hosts {
            if active.contains_key(&name) {
                continue;
            }
            let Some((node, child)) = self.nodes.lock().ok().and_then(|nodes| nodes.node(&name))
            else {
                continue;
            };
            let Ok(mut status) = state.inner.write() else {
                continue;
            };
            let retry = matches!(status.phase, Phase::Pending)
                || matches!(status.phase, Phase::Failed(_))
                    && status.changed.elapsed() >= Duration::from_secs(30);
            if !retry {
                continue;
            }
            match tx.try_send(Work {
                node,
                child,
                state: state.clone(),
            }) {
                Ok(()) => {
                    status.phase = Phase::Provisioning;
                    status.changed = Instant::now();
                    active.insert(name, ());
                }
                Err(mpsc::TrySendError::Full(_)) => break,
                Err(mpsc::TrySendError::Disconnected(_)) => break,
            }
        }
    }

    fn start(self: &Arc<Self>, runtime: &mut Runtime) {
        if self.started.swap(true, Ordering::AcqRel) {
            return;
        }
        let (tx, rx) = mpsc::sync_channel::<Work>(2);
        *self.tx.lock().expect("worker queue lock") = Some(tx);
        let rx = Arc::new(Mutex::new(rx));
        let weak_workers = Arc::downgrade(self);
        for _ in 0..2 {
            let rx = rx.clone();
            let weak_workers = weak_workers.clone();
            let shutting_down = self.shutting_down.clone();
            std::thread::spawn(move || {
                loop {
                    let job = { rx.lock().expect("worker receive lock").recv() };
                    let Ok(job) = job else {
                        break;
                    };
                    if shutting_down.load(Ordering::Acquire) {
                        break;
                    }
                    let result = ferron_tailscale::provision(&job.node, &job.child).and_then(
                        |(cert_pem, key_pem)| {
                            let certs: Vec<CertificateDer<'static>> =
                                CertificateDer::pem_reader_iter(&mut cert_pem.as_bytes())
                                    .collect::<Result<_, _>>()
                                    .map_err(|_| "invalid Tailscale certificate PEM")?;
                            if certs.is_empty() {
                                return Err("tailscaled returned no certificates".into());
                            }
                            let key = PrivateKeyDer::from_pem_reader(&mut key_pem.as_bytes())
                                .map_err(|_| "invalid Tailscale private key PEM")?;
                            let key = job
                                .state
                                .crypto
                                .key_provider
                                .load_private_key(key)
                                .map_err(|_| "invalid Tailscale private key")?;
                            let certified = CertifiedKey::new(certs, key);
                            certified
                                .keys_match()
                                .map_err(|_| "Tailscale certificate and key do not match")?;
                            Ok(Arc::new(certified))
                        },
                    );
                    let host = format!("{}.{}.ts.net", job.node.machine, job.node.tailnet);
                    if result.is_ok() {
                        // Read before publish(): an existing key means this run renewed
                        // the last-good certificate instead of acquiring the first one.
                        let renewed = job
                            .state
                            .inner
                            .read()
                            .ok()
                            .is_some_and(|status| status.key.is_some());
                        eprintln!(
                            "tailscale: {host} certificate {}",
                            if renewed { "renewed" } else { "acquired" }
                        );
                    }
                    job.state.publish(result);
                    if let Some(shared) = weak_workers.upgrade()
                        && let Ok(mut active) = shared.active.lock()
                    {
                        active.remove(&host);
                    }
                }
            });
        }
        let weak: Weak<Self> = Arc::downgrade(self);
        runtime.spawn_secondary_task(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                let Some(shared) = weak.upgrade() else {
                    break;
                };
                shared.queue_ready();
            }
        });
    }
}

pub struct TlsTailscaleProvider {
    manager: Arc<Shared>,
}

impl Provider<TlsContext<'_>> for TlsTailscaleProvider {
    fn name(&self) -> &str {
        "tailscale"
    }

    fn execute(&self, ctx: &mut TlsContext<'_>) -> Result<(), Box<dyn std::error::Error>> {
        let host = ctx
            .domain
            .host
            .as_deref()
            .ok_or("Tailscale TLS requires a hostname")?;
        let tls_config = TlsServerConfig::from_config(ctx.config)?;
        let builder = build_server_config_builder(&tls_config.crypto, &tls_config.client_auth)?;
        let state = self
            .manager
            .state(host, builder.crypto_provider().clone(), &tls_config.crypto)
            .map_err(std::io::Error::other)?;
        let mut config = builder.with_cert_resolver(Arc::new(DynamicResolver(state.clone())));
        if let Some(ticketer) = ferron_tls::builder::build_ticketer(ctx.config) {
            config.ticketer = ticketer;
        }
        if let Some(alpn) = &ctx.alpn {
            config.alpn_protocols = alpn.clone();
        }
        ctx.resolver = Some(Arc::new(TlsTailscaleResolver {
            config: Arc::new(config),
            state,
        }));
        Ok(())
    }
}

pub struct TlsTailscaleConfigurationValidator;

impl ConfigurationValidator for TlsTailscaleConfigurationValidator {
    fn validate_block(
        &self,
        config: &ServerConfigurationBlock,
        ctx: &mut ConfigurationValidatorContext,
    ) -> Result<(), ConfigurationValidationError> {
        validate_tls_common!(config, ctx);
        ctx.used_directives.insert("socket".to_string());
        if let Some(entries) = config.directives.get("socket")
            && (entries.len() != 1
                || entries[0].args.len() != 1
                || !entries[0].args[0]
                    .as_string_with_interpolations(&HashMap::new())
                    .is_some_and(|socket| !socket.trim().is_empty()))
        {
            return Err("`socket` must be a single non-empty string".into());
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct TlsTailscaleModuleLoader {
    manager: Arc<Shared>,
    module: Arc<TlsTailscaleModule>,
}

impl Default for TlsTailscaleModuleLoader {
    fn default() -> Self {
        let manager = Arc::new(Shared::default());
        let module = Arc::new(TlsTailscaleModule {
            manager: manager.clone(),
        });
        Self { manager, module }
    }
}

struct TlsTailscaleModule {
    manager: Arc<Shared>,
}

impl ferron_core::Module for TlsTailscaleModule {
    fn name(&self) -> &str {
        "tls-tailscale"
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn start(&self, runtime: &mut Runtime) -> Result<(), Box<dyn std::error::Error>> {
        self.manager.start(runtime);
        Ok(())
    }
}

impl ModuleLoader for TlsTailscaleModuleLoader {
    fn register_providers(&mut self, registry: RegistryBuilder) -> RegistryBuilder {
        let manager = self.manager.clone();
        registry.with_provider::<TlsContext, _>(move || {
            Arc::new(TlsTailscaleProvider {
                manager: manager.clone(),
            })
        })
    }

    fn register_scoped_configuration_validators(
        &mut self,
        registry: &mut HashMap<ConfigurationValidatorScopedKey, Box<dyn ConfigurationValidator>>,
    ) {
        registry.insert(
            config_validator_scoped_key!("tls", "tailscale"),
            Box::new(TlsTailscaleConfigurationValidator),
        );
    }

    fn register_modules(
        &mut self,
        _registry: Arc<ferron_core::registry::Registry>,
        modules: &mut Vec<Arc<dyn ferron_core::Module>>,
        config: Arc<ferron_core::config::ServerConfiguration>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let nodes = ferron_tailscale::inventory(&config).map_err(std::io::Error::other)?;
        self.manager
            .nodes
            .lock()
            .map_err(|e| std::io::Error::other(e.to_string()))?
            .reconcile(nodes)
            .map_err(std::io::Error::other)?;
        modules.push(self.module.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferron_core::config::{ServerConfigurationBlock, ServerConfigurationHostFilters};
    use rustls_pki_types::{PrivatePkcs8KeyDer, ServerName};

    fn test_key() -> Arc<CertifiedKey> {
        let generated =
            rcgen::generate_simple_self_signed(vec!["a.example.ts.net".into()]).unwrap();
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            generated.signing_key.serialize_der(),
        ));
        Arc::new(CertifiedKey::new(
            vec![generated.cert.der().clone()],
            provider.key_provider.load_private_key(private_key).unwrap(),
        ))
    }

    fn test_server_builder() -> rustls::ConfigBuilder<ServerConfig, rustls::WantsVerifier> {
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
    }

    #[test]
    fn pending_failure_and_published_cert_are_host_scoped() {
        let state = Arc::new(HostState::new(
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            TlsCryptoConfig::default(),
        ));
        let other = Arc::new(HostState::new(
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            TlsCryptoConfig::default(),
        ));
        let resolver = TlsTailscaleResolver {
            config: Arc::new(
                test_server_builder()
                    .with_no_client_auth()
                    .with_cert_resolver(Arc::new(DynamicResolver(state.clone()))),
            ),
            state: state.clone(),
        };
        let dynamic = DynamicResolver(state.clone());
        // rustls uses the same ServerConfig resolver for TCP and QUIC.
        assert!(dynamic.current_key().is_none());
        assert!(
            resolver
                .get_tls_background_error()
                .unwrap()
                .contains("pending")
        );
        state.publish(Err("socket unavailable".into()));
        assert!(
            resolver
                .get_tls_background_error()
                .unwrap()
                .contains("socket unavailable")
        );
        let key = test_key();
        state.publish(Ok(key.clone()));
        assert!(Arc::ptr_eq(&dynamic.current_key().unwrap(), &key));
        assert!(resolver.get_tls_background_error().is_none());
        assert!(other.inner.read().unwrap().key.is_none());
        state.publish(Err("refresh failed".into()));
        assert!(dynamic.current_key().is_some());
    }

    #[test]
    fn rustls_handshake_resolves_none_then_published_cert() {
        let state = Arc::new(HostState::new(
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            TlsCryptoConfig::default(),
        ));
        let server_config = Arc::new(
            test_server_builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(DynamicResolver(state.clone()))),
        );
        let key = test_key();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(key.cert[0].clone()).unwrap();
        let client_config = Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
        );
        let try_hello = || {
            let mut client = rustls::ClientConnection::new(
                client_config.clone(),
                ServerName::try_from("a.example.ts.net").unwrap(),
            )
            .unwrap();
            let mut bytes = Vec::new();
            client.write_tls(&mut bytes).unwrap();
            let mut server = rustls::ServerConnection::new(server_config.clone()).unwrap();
            server.read_tls(&mut bytes.as_slice()).unwrap();
            server.process_new_packets()
        };
        assert!(try_hello().is_err());
        state.publish(Ok(key));
        assert!(try_hello().is_ok());
    }

    #[test]
    fn registration_only_inventories_and_reuses_state() {
        let shared = Shared::default();
        let host = "a.example.ts.net";
        shared
            .nodes
            .lock()
            .unwrap()
            .reconcile(BTreeMap::from([(
                host.into(),
                ferron_tailscale::Node {
                    machine: "a".into(),
                    tailnet: "example".into(),
                    socket: ferron_tailscale::NodeSocket::Managed,
                },
            )]))
            .unwrap();
        assert!(!shared.started.load(Ordering::Relaxed));
        assert!(shared.tx.lock().unwrap().is_none());
        assert!(
            shared
                .nodes
                .lock()
                .unwrap()
                .node(host)
                .unwrap()
                .1
                .is_unstarted()
        );
        let crypto = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let first = shared
            .state(host, crypto.clone(), &TlsCryptoConfig::default())
            .unwrap();
        let second = shared
            .state("A.EXAMPLE.TS.NET", crypto, &TlsCryptoConfig::default())
            .unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        first.publish(Ok(test_key()));
        assert!(second.inner.read().unwrap().key.is_some());
        let changed_crypto = TlsCryptoConfig {
            min_version: Some(ferron_tls::config::TlsVersion::Tls13),
            ..Default::default()
        };
        assert!(
            shared
                .state(
                    host,
                    Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
                    &changed_crypto
                )
                .unwrap_err()
                .contains("restart Ferron")
        );
    }

    #[test]
    fn provider_execute_never_contacts_pending_socket() {
        let manager = Arc::new(Shared::default());
        manager
            .nodes
            .lock()
            .unwrap()
            .reconcile(BTreeMap::from([(
                "a.example.ts.net".into(),
                ferron_tailscale::Node {
                    machine: "a".into(),
                    tailnet: "example".into(),
                    socket: ferron_tailscale::NodeSocket::External(
                        "/does/not/exist/tailscaled.sock".into(),
                    ),
                },
            )]))
            .unwrap();
        let config = ServerConfigurationBlock::default();
        let mut ctx = TlsContext {
            config: &config,
            alpn: None,
            domain: ServerConfigurationHostFilters {
                host: Some("a.example.ts.net".into()),
                ip: None,
            },
            port: 8443,
            resolver: None,
        };
        TlsTailscaleProvider {
            manager: manager.clone(),
        }
        .execute(&mut ctx)
        .unwrap();
        assert!(
            ctx.resolver
                .as_ref()
                .unwrap()
                .get_tls_background_error()
                .unwrap()
                .contains("pending")
        );
        assert!(
            manager.states.lock().unwrap()["a.example.ts.net"]
                .inner
                .read()
                .unwrap()
                .key
                .is_none()
        );
        assert!(manager.tx.lock().unwrap().is_none());
    }

    #[test]
    fn bounded_queue_enforces_single_flight_and_backpressure() {
        let shared = Shared::default();
        let mut nodes = BTreeMap::new();
        for machine in ["a", "b", "c"] {
            nodes.insert(
                format!("{machine}.example.ts.net"),
                ferron_tailscale::Node {
                    machine: machine.into(),
                    tailnet: "example".into(),
                    socket: ferron_tailscale::NodeSocket::External("/not-used".into()),
                },
            );
        }
        shared.nodes.lock().unwrap().reconcile(nodes).unwrap();
        let crypto = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        for machine in ["a", "b", "c"] {
            shared
                .state(
                    &format!("{machine}.example.ts.net"),
                    crypto.clone(),
                    &TlsCryptoConfig::default(),
                )
                .unwrap();
        }
        let (tx, rx) = mpsc::sync_channel(2);
        *shared.tx.lock().unwrap() = Some(tx);
        shared.queue_ready();
        assert_eq!(shared.active.lock().unwrap().len(), 2);
        shared.queue_ready();
        assert_eq!(shared.active.lock().unwrap().len(), 2);
        assert!(matches!(rx.try_recv(), Ok(Work { .. })));
        shared.queue_ready();
        assert_eq!(shared.active.lock().unwrap().len(), 3);
        assert!(matches!(rx.try_recv(), Ok(Work { .. })));
        assert!(matches!(rx.try_recv(), Ok(Work { .. })));
        assert!(rx.try_recv().is_err());
    }
}
