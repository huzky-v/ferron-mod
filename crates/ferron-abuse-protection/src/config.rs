use abuse_core::{Limits, ProtectionConfig, canonicalize_ban_extensions};
use ferron_core::config::ServerConfigurationBlock;
use ferron_core::config::validator::{
    ConfigurationValidationError, ConfigurationValidator, ConfigurationValidatorContext,
};
use std::path::PathBuf;
use std::time::Duration;

pub const DEFAULT_IPBAN_URL: &str = "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/refs/heads/main/abuseipdb-s100-14d.ipv4";

#[derive(Debug, Clone)]
pub struct IpBanConfig {
    pub url: String,
    pub interval: Duration,
    pub log: PathBuf,
}

pub fn ipban_only(block: &ServerConfigurationBlock) -> bool {
    (block.get_value("ipban_mode").and_then(|v| v.as_boolean()) == Some(true)
        || block.has_directive("geo_mode")
        || block.has_directive("geo_database"))
        && !block.has_directive("ban_mode")
        && !block.has_directive("honeypot_mode")
}

pub(crate) fn validate_ipban_only(block: &ServerConfigurationBlock) -> Result<(), String> {
    if let Some(name) = block.directives.keys().find(|name| {
        DIRECTIVES.contains(&name.as_str())
            && !matches!(
                name.as_str(),
                "ipban_mode"
                    | "ipban_url"
                    | "ipban_interval"
                    | "ipban_log"
                    | "proxied_by"
                    | "geo_mode"
                    | "geo_database"
                    | "geo_asn_database"
                    | "geo_url"
                    | "geo_asn_url"
                    | "geo_interval"
                    | "geo_block_asn"
                    | "geo_block_country"
                    | "geo_block_continent"
                    | "geo_log"
            )
    }) {
        return Err(format!(
            "`{name}` requires the existing protection configuration"
        ));
    }
    Ok(())
}

pub fn extract_ipban_config(
    block: &ServerConfigurationBlock,
) -> Result<Option<IpBanConfig>, String> {
    let enabled = if block.has_directive("ipban_mode") {
        required_bool(block, "ipban_mode")?
    } else {
        false
    };
    let url = if block.has_directive("ipban_url") {
        block
            .get_value("ipban_url")
            .and_then(|v| v.as_str())
            .ok_or("`ipban_url` must be a string")?
            .to_owned()
    } else {
        DEFAULT_IPBAN_URL.to_owned()
    };
    let parsed = reqwest::Url::parse(&url).map_err(|_| "`ipban_url` must be a valid HTTPS URL")?;
    if parsed.scheme() != "https" || parsed.host_str().is_none() {
        return Err("`ipban_url` must be a valid HTTPS URL".to_owned());
    }
    let interval = if block.has_directive("ipban_interval") {
        required_duration(block, "ipban_interval")?
    } else {
        Duration::from_secs(24 * 60 * 60)
    };
    if !(Duration::from_secs(60)..=Duration::from_secs(30 * 24 * 60 * 60)).contains(&interval) {
        return Err("`ipban_interval` must be between 1 minute and 30 days".to_owned());
    }
    let log = optional_path(block, "ipban_log")?;
    if enabled {
        Ok(Some(IpBanConfig {
            url,
            interval,
            log: log.ok_or("`ipban_log` is required when `ipban_mode` is true")?,
        }))
    } else {
        Ok(None)
    }
}

pub const DIRECTIVES: &[&str] = &[
    "ban_mode",
    "honeypot_mode",
    "wordpress_site",
    "ban_duration",
    "ban_extensions",
    "definitions_db",
    "definitions_url",
    "definitions_bundle",
    "honeypot_templates_dir",
    "audit_log",
    "matched_log",
    "share_bans",
    "proxied_by",
    "ipban_mode",
    "ipban_url",
    "ipban_interval",
    "ipban_log",
    "geo_mode",
    "geo_database",
    "geo_asn_database",
    "geo_url",
    "geo_asn_url",
    "geo_interval",
    "geo_block_asn",
    "geo_block_country",
    "geo_block_continent",
    "geo_log",
];
pub const SITE_DIRECTIVES: &[&str] = &[
    "ban_mode",
    "honeypot_mode",
    "wordpress_site",
    "ban_duration",
    "ban_extensions",
    "audit_log",
    "matched_log",
    "share_bans",
    "geo_mode",
    "geo_block_asn",
    "geo_block_country",
    "geo_block_continent",
    "geo_log",
];
pub const LEGACY_DIRECTIVES: &[&str] = &[
    "abuse_protection",
    "abuse_event",
    "rate_limit_threshold",
    "brute_force_threshold",
    "custom_threshold",
    "error_rate_threshold",
    "allowlist",
];

#[derive(Debug, Clone)]
pub struct AdapterConfig {
    pub core: ProtectionConfig,
    pub honeypot_templates_dir: Option<PathBuf>,
    pub definitions_bundle: Option<String>,
    pub matched_log: Option<PathBuf>,
    pub share_bans: bool,
    pub cloudflare: bool,
    pub ipban: Option<IpBanConfig>,
}

/// Replace global defaults by the directives explicitly present in a site block.
pub fn extract_site_config(
    global: &ServerConfigurationBlock,
    site: &ServerConfigurationBlock,
) -> Result<AdapterConfig, String> {
    if let Some(name) = LEGACY_DIRECTIVES
        .iter()
        .find(|name| site.directives.contains_key(**name))
    {
        return Err(format!(
            "legacy Ferron abuse directive `{name}` cannot be combined with ferron-abuse-protection"
        ));
    }
    for name in site.directives.keys() {
        if DIRECTIVES.contains(&name.as_str()) && !SITE_DIRECTIVES.contains(&name.as_str()) {
            return Err(format!("`{name}` is global-only"));
        }
    }
    let mut merged = global.clone();
    let directives = std::sync::Arc::make_mut(&mut merged.directives);
    for name in SITE_DIRECTIVES {
        if let Some(entries) = site.directives.get(*name) {
            directives.insert((*name).to_owned(), entries.clone());
        }
    }
    extract_config(&merged)
}

pub fn extract_config(block: &ServerConfigurationBlock) -> Result<AdapterConfig, String> {
    if let Some(legacy) = LEGACY_DIRECTIVES
        .iter()
        .find(|directive| block.directives.contains_key(**directive))
    {
        return Err(format!(
            "legacy Ferron abuse directive `{legacy}` cannot be combined with ferron-abuse-protection"
        ));
    }
    let ban_mode = required_bool(block, "ban_mode")?;
    let cloudflare = proxied_by(block)?;
    let honeypot_mode = required_bool(block, "honeypot_mode")?;
    let wordpress_site = block
        .directives
        .contains_key("wordpress_site")
        .then(|| required_bool(block, "wordpress_site"))
        .transpose()?
        .unwrap_or(false);
    let share_bans = block
        .directives
        .contains_key("share_bans")
        .then(|| required_bool(block, "share_bans"))
        .transpose()?
        .unwrap_or(true);
    let ban_duration = required_duration(block, "ban_duration")?;
    let definitions_bundle = bundle_value(block).map_err(|error| error.to_string())?;
    let definitions_db = if definitions_bundle.is_some() {
        PathBuf::from(crate::bundle_source::DEFAULT_BUNDLE) // unused in bundle mode
    } else {
        required_path(block, "definitions_db")?
    };
    let audit_log = required_path(block, "audit_log")?;
    let definitions_url = if definitions_bundle.is_some() {
        None
    } else {
        optional_string(block, "definitions_url")?
    };
    let honeypot_templates_dir = if definitions_bundle.is_some() {
        None
    } else {
        optional_path(block, "honeypot_templates_dir")?
    };
    if honeypot_mode && honeypot_templates_dir.is_none() && definitions_bundle.is_none() {
        return Err("`honeypot_templates_dir` is required when `honeypot_mode` is true".to_owned());
    }
    let config = ProtectionConfig {
        ban_mode,
        honeypot_mode,
        wordpress_site,
        ban_extensions: ban_extensions(block)?,
        ban_duration,
        definitions_db,
        definitions_url,
        audit_log,
        limits: Limits::default(),
        fail2ban: Default::default(),
    };
    config.validate().map_err(|error| error.to_string())?;
    Ok(AdapterConfig {
        core: config,
        honeypot_templates_dir,
        definitions_bundle,
        matched_log: optional_path(block, "matched_log")?,
        share_bans,
        cloudflare,
        ipban: extract_ipban_config(block)?,
    })
}

#[derive(Default)]
pub struct AbuseProtectionConfigurationValidator;

impl ConfigurationValidator for AbuseProtectionConfigurationValidator {
    fn validate_block(
        &self,
        config: &ServerConfigurationBlock,
        context: &mut ConfigurationValidatorContext,
    ) -> Result<(), ConfigurationValidationError> {
        if !context.is_global {
            if let Some(name) = LEGACY_DIRECTIVES
                .iter()
                .find(|name| config.directives.contains_key(**name))
            {
                return Err(ConfigurationValidationError::from(format!(
                    "legacy Ferron abuse directive `{name}` cannot be combined with ferron-abuse-protection"
                )));
            }
            for name in config.directives.keys() {
                if DIRECTIVES.contains(&name.as_str()) && !SITE_DIRECTIVES.contains(&name.as_str())
                {
                    return Err(ConfigurationValidationError::from(format!(
                        "`{name}` is global-only"
                    )));
                }
            }
            for name in SITE_DIRECTIVES {
                if !config.directives.contains_key(*name) {
                    continue;
                }
                context.used_directives.insert((*name).to_owned());
                validate_site_directive(config, name)?;
            }
            return Ok(());
        }
        if let Some(legacy) = LEGACY_DIRECTIVES
            .iter()
            .find(|directive| config.directives.contains_key(**directive))
        {
            return Err(ConfigurationValidationError::from(format!(
                "legacy Ferron abuse directive `{legacy}` cannot be combined with ferron-abuse-protection"
            )));
        }
        for directive in config.directives.keys() {
            if !DIRECTIVES.contains(&directive.as_str()) {
                continue;
            }
            context.used_directives.insert(directive.clone());
        }
        let bundle = bundle_value(config)?;
        proxied_by(config).map_err(ConfigurationValidationError::from)?;
        extract_ipban_config(config).map_err(ConfigurationValidationError::from)?;
        crate::geo::validate(config).map_err(ConfigurationValidationError::from)?;
        if ipban_only(config) {
            validate_ipban_only(config).map_err(ConfigurationValidationError::from)?;
            return Ok(());
        }
        for required in ["ban_mode", "honeypot_mode", "ban_duration", "audit_log"]
            .into_iter()
            .chain((bundle.is_none()).then_some("definitions_db"))
        {
            if !config.directives.contains_key(required) {
                return Err(ConfigurationValidationError::from(format!(
                    "missing required global directive `{required}`"
                )));
            }
        }
        validate_bool(config, "ban_mode")?;
        validate_bool(config, "honeypot_mode")?;
        if config.directives.contains_key("wordpress_site") {
            validate_bool(config, "wordpress_site")?;
        }
        if config.directives.contains_key("share_bans") {
            validate_bool(config, "share_bans")?;
        }
        ban_extensions(config).map_err(ConfigurationValidationError::from)?;
        let honeypot_mode = config
            .get_value("honeypot_mode")
            .and_then(|value| value.as_boolean())
            .expect("honeypot_mode was validated as boolean");
        let duration = config
            .get_value("ban_duration")
            .and_then(|value| value.as_duration())
            .ok_or_else(|| {
                ConfigurationValidationError::from("`ban_duration` must be a positive duration")
            })?;
        if duration.is_zero() {
            return Err(ConfigurationValidationError::from(
                "`ban_duration` must be positive",
            ));
        }
        for path_directive in ["audit_log", "matched_log"]
            .into_iter()
            .filter(|name| config.directives.contains_key(*name))
            .chain((bundle.is_none()).then_some("definitions_db"))
        {
            let value = config
                .get_value(path_directive)
                .and_then(|value| value.as_str())
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    ConfigurationValidationError::from(format!(
                        "`{path_directive}` must be a non-empty string"
                    ))
                })?;
            let _ = value;
        }
        if bundle.is_none()
            && honeypot_mode
            && !config.directives.contains_key("honeypot_templates_dir")
        {
            return Err(ConfigurationValidationError::from(
                "`honeypot_templates_dir` is required when `honeypot_mode` is true",
            ));
        }
        if bundle.is_none() && config.directives.contains_key("honeypot_templates_dir") {
            config
                .get_value("honeypot_templates_dir")
                .and_then(|value| value.as_str())
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    ConfigurationValidationError::from(
                        "`honeypot_templates_dir` must be a non-empty string",
                    )
                })?;
        }
        if bundle.is_none()
            && let Some(value) = config.get_value("definitions_url")
        {
            let url = value.as_str().ok_or_else(|| {
                ConfigurationValidationError::from("`definitions_url` must be a string")
            })?;
            if !url.starts_with("https://") {
                return Err(ConfigurationValidationError::from(
                    "`definitions_url` must use HTTPS",
                ));
            }
        }
        Ok(())
    }
}

pub(crate) fn proxied_by(block: &ServerConfigurationBlock) -> Result<bool, String> {
    let Some(entries) = block.directives.get("proxied_by") else {
        return Ok(false);
    };
    if entries.len() != 1 || entries[0].args.len() != 1 || entries[0].children.is_some() {
        return Err("`proxied_by` expects exactly one value: none or cloudflare".to_owned());
    }
    match entries[0].args[0].as_str() {
        Some("none") => Ok(false),
        Some("cloudflare") => Ok(true),
        _ => Err("`proxied_by` must be none or cloudflare".to_owned()),
    }
}

fn validate_site_directive(
    block: &ServerConfigurationBlock,
    name: &str,
) -> Result<(), ConfigurationValidationError> {
    match name {
        "ban_mode" | "honeypot_mode" | "share_bans" | "wordpress_site" | "geo_mode" => {
            validate_bool(block, name)
        }
        "ban_duration" => required_duration(block, name)
            .map(|_| ())
            .map_err(ConfigurationValidationError::from),
        "ban_extensions" => ban_extensions(block)
            .map(|_| ())
            .map_err(ConfigurationValidationError::from),
        "audit_log" | "matched_log" | "geo_log" => required_path(block, name)
            .map(|_| ())
            .map_err(ConfigurationValidationError::from),
        "geo_block_asn" | "geo_block_country" | "geo_block_continent" => {
            crate::geo::validate_list(block, name).map_err(ConfigurationValidationError::from)
        }
        _ => unreachable!(),
    }
}

fn ban_extensions(block: &ServerConfigurationBlock) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    if let Some(entries) = block.directives.get("ban_extensions") {
        for entry in entries {
            if entry.children.is_some() {
                return Err("`ban_extensions` cannot have a child block".to_owned());
            }
            for arg in &entry.args {
                values.push(
                    arg.as_str()
                        .ok_or("`ban_extensions` values must be strings")?
                        .to_owned(),
                );
            }
        }
    }
    canonicalize_ban_extensions(&values).map_err(|error| error.to_string())
}

fn bundle_value(
    block: &ServerConfigurationBlock,
) -> Result<Option<String>, ConfigurationValidationError> {
    if !block.directives.contains_key("definitions_bundle") {
        return Ok(None);
    }
    let value = block
        .get_value("definitions_bundle")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ConfigurationValidationError::from("`definitions_bundle` must be a non-empty string")
        })?;
    if value.contains("://") && !value.starts_with("https://") {
        return Err(ConfigurationValidationError::from(
            "`definitions_bundle` URL must use HTTPS",
        ));
    }
    Ok(Some(value.to_owned()))
}

fn validate_bool(
    block: &ServerConfigurationBlock,
    name: &str,
) -> Result<(), ConfigurationValidationError> {
    if block
        .get_value(name)
        .and_then(|value| value.as_boolean())
        .is_none()
    {
        return Err(ConfigurationValidationError::from(format!(
            "`{name}` must be a boolean"
        )));
    }
    Ok(())
}

fn required_bool(block: &ServerConfigurationBlock, name: &str) -> Result<bool, String> {
    block
        .get_value(name)
        .and_then(|value| value.as_boolean())
        .ok_or_else(|| format!("missing or invalid `{name}`"))
}

fn required_duration(block: &ServerConfigurationBlock, name: &str) -> Result<Duration, String> {
    block
        .get_value(name)
        .and_then(|value| value.as_duration())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| format!("missing or invalid `{name}`"))
}

fn required_path(block: &ServerConfigurationBlock, name: &str) -> Result<PathBuf, String> {
    let value = block
        .get_value(name)
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("missing or invalid `{name}`"))?;
    Ok(PathBuf::from(value))
}

fn optional_path(block: &ServerConfigurationBlock, name: &str) -> Result<Option<PathBuf>, String> {
    if !block.directives.contains_key(name) {
        return Ok(None);
    }
    required_path(block, name).map(Some)
}

fn optional_string(block: &ServerConfigurationBlock, name: &str) -> Result<Option<String>, String> {
    let Some(value) = block.get_value(name) else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .ok_or_else(|| format!("`{name}` must be a string"))?;
    if !value.starts_with("https://") {
        return Err(format!("`{name}` must use HTTPS"));
    }
    Ok(Some(value.to_owned()))
}
