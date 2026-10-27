use abuse_core::IpCidr;
use ferron_core::config::ServerConfigurationBlock;
use ferron_core::pipeline::{PipelineError, Stage};
use ferron_core::registry::StageConstraint;
use ferron_http::{HttpContext, HttpResponse};
use reqwest::blocking::Client;
use std::io::Read;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use typemap_rev::TypeMapKey;

use crate::module::SharedState;

const URLS: [&str; 2] = [
    "https://www.cloudflare.com/ips-v4",
    "https://www.cloudflare.com/ips-v6",
];
const MAX_LIST_BYTES: usize = 16 * 1024;

pub struct ProxyIpKey;

impl TypeMapKey for ProxyIpKey {
    type Value = IpAddr;
}

pub fn proxy_ip(context: &HttpContext) -> Option<IpAddr> {
    context.get::<ProxyIpKey>().copied()
}

pub fn load_ranges() -> Result<Vec<IpCidr>, Box<dyn std::error::Error>> {
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 3 || attempt.url().scheme() != "https" {
                attempt.error("Cloudflare IP list redirect must stay on HTTPS")
            } else {
                attempt.follow()
            }
        }))
        .build()?;
    let mut ranges = Vec::new();
    for (index, url) in URLS.iter().enumerate() {
        let response = client.get(*url).send()?.error_for_status()?;
        if response
            .content_length()
            .is_some_and(|size| size > MAX_LIST_BYTES as u64)
        {
            return Err(format!("Cloudflare IP list {url} is too large").into());
        }
        let mut bytes = Vec::new();
        response
            .take((MAX_LIST_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_LIST_BYTES {
            return Err(format!("Cloudflare IP list {url} is too large").into());
        }
        ranges.extend(parse_ranges(std::str::from_utf8(&bytes)?, index == 0)?);
    }
    Ok(ranges)
}

fn parse_ranges(text: &str, ipv4: bool) -> Result<Vec<IpCidr>, String> {
    let ranges: Vec<IpCidr> = text
        .lines()
        .map(|line| {
            let range = IpCidr::parse(line.trim()).map_err(|error| error.to_string())?;
            if range.address().is_ipv4() != ipv4 {
                return Err("Cloudflare IP list contains an address of the wrong family".to_owned());
            }
            Ok(range)
        })
        .collect::<Result<_, _>>()?;
    if ranges.is_empty() || ranges.len() > 256 {
        return Err("Cloudflare IP list has an invalid number of ranges".to_owned());
    }
    Ok(ranges)
}

fn resolve_client_ip(peer: IpAddr, header: Option<&str>, ranges: &[IpCidr]) -> Option<IpAddr> {
    if !ranges
        .iter()
        .any(|range| range.contains(peer.to_canonical()))
    {
        return None;
    }
    header?.parse::<IpAddr>().ok().map(|ip| ip.to_canonical())
}

pub struct CloudflareIpStage {
    state: Arc<OnceLock<Arc<SharedState>>>,
}

impl CloudflareIpStage {
    pub fn new(state: Arc<OnceLock<Arc<SharedState>>>) -> Self {
        Self { state }
    }
}

#[async_trait::async_trait(?Send)]
impl Stage<HttpContext> for CloudflareIpStage {
    fn name(&self) -> &str {
        "ferron_cloudflare_ip"
    }

    fn constraints(&self) -> Vec<StageConstraint> {
        vec![
            StageConstraint::Before("client_ip_from_header".to_owned()),
            StageConstraint::Before("ferron_abuse_protection".to_owned()),
        ]
    }

    fn is_applicable(&self, config: Option<&ServerConfigurationBlock>) -> bool {
        config.is_some_and(|block| block.has_directive("proxied_by"))
    }

    async fn run(&self, context: &mut HttpContext) -> Result<bool, PipelineError> {
        let Some(ranges) = self
            .state
            .get()
            .and_then(|state| state.cloudflare_ranges.as_ref())
        else {
            return Ok(true);
        };
        let Some(peer) = context.remote_address else {
            return Ok(true);
        };
        if !ranges
            .iter()
            .any(|range| range.contains(peer.ip().to_canonical()))
        {
            return Ok(true);
        }
        let header = context
            .req
            .as_ref()
            .and_then(|request| request.headers().get("cf-connecting-ip"))
            .and_then(|value| value.to_str().ok());
        let Some(client_ip) = resolve_client_ip(peer.ip(), header, ranges) else {
            // Never ban the shared Cloudflare peer because its visitor header is absent or invalid.
            context.res = Some(HttpResponse::BuiltinError(400, None));
            return Ok(false);
        };
        context.insert::<ProxyIpKey>(peer.ip().to_canonical());
        context.remote_address = Some(std::net::SocketAddr::new(
            client_ip.to_canonical(),
            peer.port(),
        ));
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abuse_core::{AuditQueue, Limits, MetricEventSender};
    use bytes::Bytes;
    use ferron_http::HttpRequest;
    use http::Request;
    use http_body_util::{BodyExt, Empty};
    use std::sync::Mutex;
    use std::sync::atomic::AtomicU64;

    #[test]
    fn lists_must_be_valid_nonempty_and_match_the_family() {
        assert!(parse_ranges("172.64.0.0/13\n", true).is_ok());
        assert!(parse_ranges("2a06:98c0::/29\n", false).is_ok());
        assert!(parse_ranges("", true).is_err());
        assert!(parse_ranges("172.64.0.0/13\ninvalid\n", true).is_err());
        assert!(parse_ranges("2a06:98c0::/29\n", true).is_err());
    }

    #[test]
    fn only_trusted_peers_with_single_valid_client_ip_are_rewritten() {
        let ranges = parse_ranges("172.64.0.0/13\n", true).unwrap();
        let cloudflare: IpAddr = "172.69.223.81".parse().unwrap();
        let visitor: IpAddr = "2a0f:ca80:b00b:6b07::5".parse().unwrap();
        assert_eq!(
            resolve_client_ip(cloudflare, Some("2a0f:ca80:b00b:6b07::5"), &ranges),
            Some(visitor)
        );
        assert_eq!(
            resolve_client_ip(
                "192.0.2.1".parse().unwrap(),
                Some("2a0f:ca80:b00b:6b07::5"),
                &ranges
            ),
            None
        );
        assert_eq!(
            resolve_client_ip(cloudflare, Some("1.2.3.4, 5.6.7.8"), &ranges),
            None
        );
        assert_eq!(resolve_client_ip(cloudflare, None, &ranges), None);
    }

    #[tokio::test]
    async fn trusted_peer_rewrites_request_input_and_malformed_header_never_bans_peer() {
        let (metric_sender, metric_receiver) = MetricEventSender::channel(2).unwrap();
        let state = Arc::new(OnceLock::new());
        state
            .set(Arc::new(SharedState {
                policy: None,
                disabled_audit_queue: Some(Arc::new(AuditQueue::new(2).unwrap())),
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
                snapshot: None,
                catalog: None,
                shared_registry: abuse_core::BanRegistry::new(2).unwrap(),
                sites: Mutex::new(Default::default()),
                named_hosts: Default::default(),
                cloudflare_ranges: Some(parse_ranges("172.64.0.0/13\n", true).unwrap()),
                ipban: None,
                standalone_ipban: false,
                geo: None,
            }))
            .ok()
            .unwrap();
        let stage = CloudflareIpStage::new(state);
        let mut context = HttpContext::default();
        context.remote_address = Some("172.69.223.81:443".parse().unwrap());
        context.original_uri = Some("/probe".parse().unwrap());
        let request: HttpRequest = Request::builder()
            .uri("/probe")
            .header("cf-connecting-ip", "2a0f:ca80:b00b:6b07::5")
            .header("x-forwarded-for", "192.0.2.99, 2a0f:ca80:b00b:6b07::5")
            .body(
                Empty::<Bytes>::new()
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .unwrap();
        context.req = Some(request);
        assert!(stage.run(&mut context).await.unwrap());
        let input = crate::request_source::request_input(&context, &Limits::default()).unwrap();
        assert_eq!(input.client_ip.to_string(), "2a0f:ca80:b00b:6b07::5");
        assert_eq!(input.proxy_ip.unwrap().to_string(), "172.69.223.81");

        context.remote_address = Some("172.69.223.81:443".parse().unwrap());
        context.remove::<ProxyIpKey>();
        context
            .req
            .as_mut()
            .unwrap()
            .headers_mut()
            .remove("cf-connecting-ip");
        assert!(!stage.run(&mut context).await.unwrap());
        assert!(matches!(
            context.res,
            Some(HttpResponse::BuiltinError(400, _))
        ));
        assert_eq!(
            context.remote_address.unwrap().ip().to_string(),
            "172.69.223.81"
        );
        assert!(proxy_ip(&context).is_none());
    }
}
