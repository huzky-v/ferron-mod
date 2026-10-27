use crate::definition_source::{DefinitionDownloader, ReqwestDefinitionDownloader};
use crate::matched_log::MatchedLog;
use ferron_core::config::ServerConfigurationBlock;
use maxminddb::{Reader, path};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

const COUNTRY_URL: &str =
    "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/GeoLite2-Country.mmdb";
const ASN_URL: &str =
    "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/GeoLite2-ASN.mmdb";
const MAX_BYTES: u64 = 128 * 1024 * 1024;
type GeoReader = Arc<Reader<Vec<u8>>>;

pub struct GeoState {
    pub interval: Duration,
    paths: [PathBuf; 2],
    urls: [String; 2],
    readers: RwLock<[Option<GeoReader>; 2]>,
    pub logs: Mutex<HashMap<PathBuf, MatchedLog>>,
}

#[derive(Default)]
pub struct Rules {
    enabled: bool,
    asns: HashSet<u32>,
    countries: HashSet<String>,
    continents: HashSet<String>,
    pub log: Option<PathBuf>,
}

fn value(block: &ServerConfigurationBlock, name: &str) -> Result<Option<String>, String> {
    if !block.has_directive(name) {
        return Ok(None);
    }
    block
        .get_value(name)
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(|s| Some(s.to_owned()))
        .ok_or_else(|| format!("invalid `{name}`"))
}

pub fn validate_list(block: &ServerConfigurationBlock, name: &str) -> Result<(), String> {
    for entry in block.directives.get(name).into_iter().flatten() {
        if entry.children.is_some() || entry.args.is_empty() {
            return Err(format!("invalid `{name}`"));
        }
        for arg in &entry.args {
            let text = arg
                .as_str()
                .map(str::to_owned)
                .or_else(|| arg.as_number().map(|n| n.to_string()))
                .ok_or_else(|| format!("invalid `{name}` value"))?;
            if name == "geo_block_asn" {
                text.strip_prefix("AS")
                    .or_else(|| text.strip_prefix("as"))
                    .unwrap_or(&text)
                    .parse::<u32>()
                    .ok()
                    .filter(|v| *v > 0)
                    .ok_or_else(|| format!("invalid ASN `{text}`"))?;
            } else if text.len() != 2 || !text.bytes().all(|c| c.is_ascii_alphabetic()) {
                return Err(format!("invalid code `{text}`"));
            }
        }
    }
    Ok(())
}

pub fn validate(block: &ServerConfigurationBlock) -> Result<(), String> {
    for name in ["geo_database", "geo_asn_database", "geo_log"] {
        value(block, name)?;
    }
    for name in ["geo_url", "geo_asn_url"] {
        if let Some(url) = value(block, name)? {
            let parsed = reqwest::Url::parse(&url).map_err(|_| format!("invalid `{name}`"))?;
            if parsed.scheme() != "https" || parsed.host_str().is_none() {
                return Err(format!("`{name}` must use HTTPS"));
            }
        }
    }
    if block.has_directive("geo_mode")
        && block
            .get_value("geo_mode")
            .and_then(|v| v.as_boolean())
            .is_none()
    {
        return Err("invalid `geo_mode`".into());
    }
    if block.has_directive("geo_interval") {
        let interval = block
            .get_value("geo_interval")
            .and_then(|v| v.as_duration())
            .ok_or("invalid `geo_interval`")?;
        if !(Duration::from_secs(60)..=Duration::from_secs(30 * 86400)).contains(&interval) {
            return Err("`geo_interval` must be between 1 minute and 30 days".into());
        }
    }
    for name in ["geo_block_asn", "geo_block_country", "geo_block_continent"] {
        validate_list(block, name)?;
    }
    Ok(())
}

pub fn rules(layers: &[Arc<ServerConfigurationBlock>]) -> Result<Rules, String> {
    let mut rules = Rules::default();
    for block in layers {
        if block.has_directive("geo_mode") {
            rules.enabled = block
                .get_value("geo_mode")
                .and_then(|v| v.as_boolean())
                .ok_or("invalid geo_mode")?;
        }
        if block.has_directive("geo_log") {
            rules.log = value(block, "geo_log")?.map(PathBuf::from);
        }
        for name in ["geo_block_asn", "geo_block_country", "geo_block_continent"] {
            if !block.has_directive(name) {
                continue;
            }
            validate_list(block, name)?;
            let vals = block.directives[name]
                .iter()
                .flat_map(|entry| entry.args.iter())
                .filter_map(|arg| {
                    arg.as_str()
                        .map(str::to_ascii_uppercase)
                        .or_else(|| arg.as_number().map(|n| n.to_string()))
                });
            match name {
                "geo_block_asn" => {
                    rules.asns = vals
                        .map(|v| v.strip_prefix("AS").unwrap_or(&v).parse().unwrap())
                        .collect()
                }
                "geo_block_country" => rules.countries = vals.collect(),
                _ => rules.continents = vals.collect(),
            }
        }
    }
    Ok(rules)
}

impl GeoState {
    pub fn new(block: &ServerConfigurationBlock) -> Result<Option<Self>, String> {
        if !block.has_directive("geo_database") && !block.has_directive("geo_asn_database") {
            if block.get_value("geo_mode").and_then(|v| v.as_boolean()) == Some(true) {
                return Err("geo_mode requires geo_database and geo_asn_database".into());
            }
            return Ok(None);
        }
        validate(block)?;
        let paths = [
            PathBuf::from(value(block, "geo_database")?.ok_or("`geo_database` required")?),
            PathBuf::from(value(block, "geo_asn_database")?.ok_or("`geo_asn_database` required")?),
        ];
        if paths[0] == paths[1] {
            return Err("geo database paths must differ".into());
        }
        let urls = [
            value(block, "geo_url")?.unwrap_or_else(|| COUNTRY_URL.into()),
            value(block, "geo_asn_url")?.unwrap_or_else(|| ASN_URL.into()),
        ];
        let interval = block
            .get_value("geo_interval")
            .and_then(|v| v.as_duration())
            .unwrap_or(Duration::from_secs(7 * 86400));
        let mut readers = [None, None];
        for (i, path) in paths.iter().enumerate() {
            if path.exists() {
                readers[i] =
                    Some(Arc::new(open(path, i).map_err(|e| {
                        format!("invalid geo database {}: {e}", path.display())
                    })?));
            }
        }
        Ok(Some(Self {
            interval,
            paths,
            urls,
            readers: RwLock::new(readers),
            logs: Mutex::new(HashMap::new()),
        }))
    }

    pub fn refresh(
        &self,
        downloader: &dyn DefinitionDownloader,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        for i in 0..2 {
            let directory = self.paths[i]
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(std::path::Path::new("."));
            let temp = downloader.download(&self.urls[i], directory, MAX_BYTES)?;
            let reader = open(temp.path(), i)?;
            temp.persist(&self.paths[i])?;
            self.readers.write().unwrap()[i] = Some(Arc::new(reader));
        }
        Ok(())
    }
    pub fn fetch(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.refresh(&ReqwestDefinitionDownloader::new()?)
    }

    pub fn matches(&self, ip: IpAddr, rules: &Rules) -> Option<String> {
        if !rules.enabled {
            return None;
        }
        let readers = self.readers.read().unwrap();
        if let Some(reader) = &readers[1]
            && let Ok(result) = reader.lookup(ip)
            && let Ok(Some(asn)) = result.decode_path::<u32>(&path!["autonomous_system_number"])
            && rules.asns.contains(&asn)
        {
            return Some(format!("geo_asn_AS{asn}"));
        }
        if let Some(reader) = &readers[0]
            && let Ok(result) = reader.lookup(ip)
        {
            if let Ok(Some(country)) = result.decode_path::<String>(&path!["country", "iso_code"])
                && rules.countries.contains(&country)
            {
                return Some(format!("geo_country_{country}"));
            }
            if let Ok(Some(continent)) = result.decode_path::<String>(&path!["continent", "code"])
                && rules.continents.contains(&continent)
            {
                return Some(format!("geo_continent_{continent}"));
            }
        }
        None
    }
}

fn open(
    path: &std::path::Path,
    index: usize,
) -> Result<Reader<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
    let reader = Reader::open_readfile(path)?;
    let expected = if index == 0 { "Country" } else { "ASN" };
    if !reader.metadata.database_type.contains(expected) {
        return Err(format!("expected {expected} database").into());
    }
    Ok(reader)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferron_core::config::{ServerConfigurationDirectiveEntry, ServerConfigurationValue};

    fn block(values: &[(&str, Vec<ServerConfigurationValue>)]) -> Arc<ServerConfigurationBlock> {
        let mut block = ServerConfigurationBlock::default();
        let directives = Arc::make_mut(&mut block.directives);
        for (name, args) in values {
            directives.insert(
                (*name).into(),
                vec![ServerConfigurationDirectiveEntry {
                    args: args.clone(),
                    children: None,
                    span: None,
                }],
            );
        }
        Arc::new(block)
    }

    fn string(value: &str) -> ServerConfigurationValue {
        ServerConfigurationValue::String(value.into(), None)
    }

    #[test]
    fn site_rules_override_global_independently() {
        let global = block(&[
            (
                "geo_mode",
                vec![ServerConfigurationValue::Boolean(true, None)],
            ),
            (
                "geo_block_asn",
                vec![string("AS123"), ServerConfigurationValue::Number(456, None)],
            ),
            ("geo_block_country", vec![string("us")]),
        ]);
        let site = block(&[("geo_block_country", vec![string("GB")])]);
        let result = rules(&[global, site]).unwrap();
        assert!(result.enabled);
        assert_eq!(result.asns, [123, 456].into_iter().collect());
        assert_eq!(result.countries, ["GB".to_string()].into_iter().collect());
    }

    #[test]
    fn validates_values_and_default_interval() {
        let directory = tempfile::tempdir().unwrap();
        let country = directory
            .path()
            .join("country.mmdb")
            .to_string_lossy()
            .into_owned();
        let asn = directory
            .path()
            .join("asn.mmdb")
            .to_string_lossy()
            .into_owned();
        let settings = block(&[
            ("geo_database", vec![string(&country)]),
            ("geo_asn_database", vec![string(&asn)]),
        ]);
        let state = GeoState::new(&settings).unwrap().unwrap();
        assert_eq!(state.interval, Duration::from_secs(7 * 86400));
        let bad = block(&[("geo_block_asn", vec![string("ASinvalid")])]);
        assert!(validate(&bad).is_err());
        assert!(
            state
                .matches("1.1.1.1".parse().unwrap(), &Rules::default())
                .is_none()
        );
    }

    #[test]
    fn real_mmdb_lookups_and_failed_refresh_preserve_data() {
        let directory = tempfile::tempdir().unwrap();
        let country = directory.path().join("country.mmdb");
        let asn = directory.path().join("asn.mmdb");
        std::fs::write(
            &country,
            include_bytes!("../tests/fixtures/GeoIP2-Country-Test.mmdb"),
        )
        .unwrap();
        std::fs::write(
            &asn,
            include_bytes!("../tests/fixtures/GeoLite2-ASN-Test.mmdb"),
        )
        .unwrap();
        let settings = block(&[
            ("geo_database", vec![string(country.to_str().unwrap())]),
            ("geo_asn_database", vec![string(asn.to_str().unwrap())]),
        ]);
        let state = GeoState::new(&settings).unwrap().unwrap();
        let ip: IpAddr = "81.2.69.160".parse().unwrap();
        let rules = Rules {
            enabled: true,
            countries: ["GB".to_owned()].into_iter().collect(),
            ..Rules::default()
        };
        assert_eq!(state.matches(ip, &rules).as_deref(), Some("geo_country_GB"));
        let asn_rules = Rules {
            enabled: true,
            asns: [15169].into_iter().collect(),
            ..Rules::default()
        };
        assert_eq!(
            state
                .matches("1.0.0.0".parse().unwrap(), &asn_rules)
                .as_deref(),
            Some("geo_asn_AS15169")
        );
        struct Invalid;
        impl DefinitionDownloader for Invalid {
            fn download(
                &self,
                _: &str,
                directory: &std::path::Path,
                _: u64,
            ) -> Result<tempfile::NamedTempFile, crate::definition_source::SourceError>
            {
                Ok(tempfile::NamedTempFile::new_in(directory)?)
            }
        }
        assert!(state.refresh(&Invalid).is_err());
        assert_eq!(state.matches(ip, &rules).as_deref(), Some("geo_country_GB"));
    }
}
