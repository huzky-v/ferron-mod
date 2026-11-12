//! acme-dns DNS-01 provider. Credentials are registered once and reused on renewal.

use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use ferron_core::{
    config::{
        ServerConfigurationBlock,
        validator::{
            ConfigurationValidationError, ConfigurationValidator, ConfigurationValidatorContext,
            ConfigurationValidatorScopedKey,
        },
    },
    config_validator_scoped_key,
    loader::ModuleLoader,
    providers::Provider,
    registry::RegistryBuilder,
};
use ferron_dns::{DnsClient, DnsContext, DnsProviderError, DnsRecord, DnsRecordType};
use serde::Serialize;
use url::Url;

pub struct AcmeDnsModuleLoader;

impl ModuleLoader for AcmeDnsModuleLoader {
    fn register_providers(&mut self, registry: RegistryBuilder) -> RegistryBuilder {
        registry.with_provider::<DnsContext<'static>, _>(|| Arc::new(AcmeDnsProvider))
    }

    fn register_scoped_configuration_validators(
        &mut self,
        registry: &mut HashMap<ConfigurationValidatorScopedKey, Box<dyn ConfigurationValidator>>,
    ) {
        registry.insert(
            config_validator_scoped_key!("dns", "acme-dns"),
            Box::new(AcmeDnsValidator),
        );
    }
}

fn setting(config: &ServerConfigurationBlock, key: &str) -> Result<String, String> {
    config
        .get_value(key)
        .and_then(|v| v.as_string_with_interpolations(&HashMap::new()))
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| format!("acme-dns requires nonempty `{key}`"))
}

fn endpoint_url(endpoint: &str, allow_http: bool) -> Result<Url, String> {
    let url = Url::parse(endpoint).map_err(|e| format!("invalid acme-dns endpoint: {e}"))?;
    if url.scheme() != "https"
        && !(url.scheme() == "http"
            && (allow_http || matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"))))
    {
        return Err(
            "acme-dns endpoint must use HTTPS (HTTP requires `allow_http true` outside loopback)"
                .into(),
        );
    }
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(
            "acme-dns endpoint must be a root URL without credentials, query or fragment".into(),
        );
    }
    Ok(url)
}

fn client_from_config(config: &ServerConfigurationBlock) -> Result<AcmeDnsClient, String> {
    let allow_http = config
        .get_value("allow_http")
        .map(|value| {
            value
                .as_boolean()
                .ok_or_else(|| "acme-dns `allow_http` must be a boolean".to_string())
        })
        .transpose()?
        .unwrap_or(false);
    let endpoint = endpoint_url(&setting(config, "endpoint")?, allow_http)?;
    let username = setting(config, "username")?;
    let password = setting(config, "password")?;
    let subdomain = setting(config, "subdomain")?;
    if subdomain.contains('.')
        || subdomain.contains('/')
        || subdomain.chars().any(char::is_whitespace)
    {
        return Err("acme-dns `subdomain` must be the registration's single DNS label".into());
    }
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;
    Ok(AcmeDnsClient {
        endpoint,
        username,
        password,
        subdomain,
        http,
    })
}

struct AcmeDnsProvider;
impl Provider<DnsContext<'static>> for AcmeDnsProvider {
    fn name(&self) -> &str {
        "acme-dns"
    }

    fn execute(&self, ctx: &mut DnsContext) -> Result<(), Box<dyn std::error::Error>> {
        let client = client_from_config(ctx.config).map_err(DnsProviderError::new)?;
        ctx.client = Some(Arc::new(client));
        Ok(())
    }
}

struct AcmeDnsValidator;
impl ConfigurationValidator for AcmeDnsValidator {
    fn validate_block(
        &self,
        config: &ServerConfigurationBlock,
        ctx: &mut ConfigurationValidatorContext,
    ) -> Result<(), ConfigurationValidationError> {
        for key in [
            "endpoint",
            "username",
            "password",
            "subdomain",
            "allow_http",
        ] {
            ctx.used_directives.insert(key.to_string());
        }
        client_from_config(config)
            .map(|_| ())
            .map_err(ConfigurationValidationError::from)
    }
}

struct AcmeDnsClient {
    endpoint: Url,
    username: String,
    password: String,
    subdomain: String,
    http: reqwest::Client,
}

#[derive(Serialize)]
struct Update<'a> {
    subdomain: &'a str,
    txt: &'a str,
}

#[async_trait]
impl DnsClient for AcmeDnsClient {
    fn minimum_ttl(&self) -> u32 {
        60
    }

    async fn update_record(&self, record: &DnsRecord) -> Result<(), DnsProviderError> {
        if record.record_type != DnsRecordType::TXT
            || !record.name.starts_with("_acme-challenge.")
            || record.value.is_empty()
        {
            return Err(DnsProviderError::new(
                "acme-dns only supports nonempty ACME TXT challenges",
            ));
        }
        let url = self
            .endpoint
            .join("update")
            .map_err(|e| DnsProviderError::new(e.to_string()))?;
        let response = self
            .http
            .post(url)
            .header("X-Api-User", &self.username)
            .header("X-Api-Key", &self.password)
            .json(&Update {
                subdomain: &self.subdomain,
                txt: &record.value,
            })
            .send()
            .await
            .map_err(|e| DnsProviderError::new(format!("acme-dns update failed: {e}")))?;
        if !response.status().is_success() {
            return Err(DnsProviderError::new(format!(
                "acme-dns update returned HTTP {}",
                response.status()
            )));
        }
        Ok(())
    }

    async fn delete_record(
        &self,
        _name: &str,
        _record_type: DnsRecordType,
    ) -> Result<(), DnsProviderError> {
        // acme-dns has no delete endpoint. It rolls two TXT values to support
        // apex and wildcard challenges simultaneously; clearing them would break that.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferron_core::config::{ServerConfigurationDirectiveEntry, ServerConfigurationValue};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    fn record(value: &str) -> DnsRecord {
        DnsRecord {
            name: "_acme-challenge.example.org".into(),
            record_type: DnsRecordType::TXT,
            value: value.into(),
            ttl: 60,
        }
    }

    async fn server(status: &str) -> (Url, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let status = status.to_string();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut data = Vec::new();
            let mut buf = [0; 2048];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..n]);
                let request = String::from_utf8_lossy(&data);
                if let Some((headers, body)) = request.split_once("\r\n\r\n") {
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .and_then(|s| s.parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if body.len() >= length {
                        break;
                    }
                }
            }
            let response =
                format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            stream.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8(data).unwrap()
        });
        (url, task)
    }

    fn client(endpoint: Url) -> AcmeDnsClient {
        AcmeDnsClient {
            endpoint,
            username: "user".into(),
            password: "secret".into(),
            subdomain: "registered-label".into(),
            http: reqwest::Client::new(),
        }
    }

    #[tokio::test]
    async fn update_sends_authenticated_txt_and_reuses_registration() {
        for value in ["first", "renewal"] {
            let (url, task) = server("200 OK").await;
            let dns = client(url);
            dns.delete_record("_acme-challenge.example.org", DnsRecordType::TXT)
                .await
                .unwrap();
            dns.update_record(&record(value)).await.unwrap();
            let request = task.await.unwrap();
            assert!(request.starts_with("POST /update HTTP/1.1"));
            assert!(request.contains("x-api-user: user\r\n"));
            assert!(request.contains("x-api-key: secret\r\n"));
            assert!(request.contains(&format!(
                "\"subdomain\":\"registered-label\",\"txt\":\"{value}\""
            )));
        }
    }

    #[tokio::test]
    async fn failed_update_is_not_treated_as_ready() {
        let (url, task) = server("403 Forbidden").await;
        let err = client(url)
            .update_record(&record("token"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("403"));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn redirects_are_not_followed_with_credentials() {
        let (url, task) = server("302 Found").await;
        let dns = AcmeDnsClient {
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            ..client(url)
        };
        let err = dns.update_record(&record("token")).await.unwrap_err();
        assert!(err.to_string().contains("302"));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_other_record_types_without_network_access() {
        let mut other = record("token");
        other.record_type = DnsRecordType::CNAME;
        let dns = client(Url::parse("http://127.0.0.1:1/").unwrap());
        assert!(dns.update_record(&other).await.is_err());
        assert!(endpoint_url("http://example.org/", false).is_err());
        assert!(endpoint_url("https://user:pass@example.org/", false).is_err());
    }

    fn configuration(
        endpoint: &str,
        allow_http: Option<ServerConfigurationValue>,
    ) -> ServerConfigurationBlock {
        let mut config = ServerConfigurationBlock::default();
        let values = [
            ("endpoint", endpoint),
            ("username", "user"),
            ("password", "secret"),
            ("subdomain", "registered-label"),
        ];
        let directives = Arc::make_mut(&mut config.directives);
        for (key, value) in values {
            directives.insert(
                key.to_string(),
                vec![ServerConfigurationDirectiveEntry {
                    args: vec![ServerConfigurationValue::String(value.to_string(), None)],
                    children: None,
                    span: None,
                }],
            );
        }
        if let Some(value) = allow_http {
            directives.insert(
                "allow_http".into(),
                vec![ServerConfigurationDirectiveEntry {
                    args: vec![value],
                    children: None,
                    span: None,
                }],
            );
        }
        config
    }

    #[test]
    fn http_requires_explicit_boolean_opt_in() {
        let endpoint = "http://acme-dns:8080/";
        assert!(client_from_config(&configuration(endpoint, None)).is_err());
        assert!(
            client_from_config(&configuration(
                endpoint,
                Some(ServerConfigurationValue::Boolean(false, None))
            ))
            .is_err()
        );
        assert!(
            client_from_config(&configuration(
                endpoint,
                Some(ServerConfigurationValue::String("true".into(), None))
            ))
            .is_err()
        );
        assert!(
            client_from_config(&configuration(
                endpoint,
                Some(ServerConfigurationValue::Boolean(true, None))
            ))
            .is_ok()
        );
        assert!(client_from_config(&configuration("https://auth.example.net/", None)).is_ok());
        assert!(client_from_config(&configuration("http://localhost:8080/", None)).is_ok());
        assert!(endpoint_url("ftp://acme-dns/", true).is_err());
        assert!(endpoint_url("http://user:pass@acme-dns/", true).is_err());
    }
}
