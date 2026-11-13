use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

pub const HARD_MAX_DEFINITIONS: usize = 100_000;
pub const HARD_MAX_REGEX_LENGTH: usize = 64 * 1024;
pub const HARD_MAX_REQUEST_FIELD_LENGTH: usize = 64 * 1024;
pub const HARD_MAX_REQUEST_HEADERS: usize = 256;
pub const HARD_MAX_HEADER_NAME_LENGTH: usize = 1_024;
pub const HARD_MAX_HEADER_VALUE_LENGTH: usize = 1024 * 1024;
pub const HARD_MAX_HEADER_VALUE_COUNT: usize = 64;
pub const HARD_MAX_AUDIT_LINE_BYTES: usize = 1024 * 1024;
pub const HARD_MAX_AUDIT_QUEUE: usize = 1_000_000;
pub const HARD_MAX_METRIC_QUEUE: usize = 1_000_000;
pub const HARD_MAX_HONEYPOT_BODY_BYTES: usize = 1024 * 1024;
pub const HARD_MAX_SQLITE_BYTES: u64 = 1024 * 1024 * 1024;
pub const HARD_MAX_AUDIT_HEADERS: usize = 128;
pub const HARD_MAX_AUDIT_VALUE_LENGTH: usize = 64 * 1024;
pub const HARD_MAX_MATCHES: usize = 1_024;
pub const HARD_MAX_BANS: usize = 1_000_000;
pub const HARD_MAX_BAN_DURATION: Duration = Duration::from_secs(30 * 24 * 60 * 60);
pub const HARD_MAX_ALLOWLIST_ROWS: usize = 100_000;
pub const HARD_MAX_PATTERN_BYTES_TOTAL: usize = 128 * 1024 * 1024;
pub const HARD_MAX_REGEX_PROGRAM_BYTES: usize = 16 * 1024 * 1024;
pub const HARD_MAX_REGEX_DFA_BYTES: usize = 16 * 1024 * 1024;
pub const HARD_MAX_COMPILED_REGEX_BYTES_TOTAL: usize = 256 * 1024 * 1024;
pub const HARD_MAX_AUDIT_RETENTION: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// Resource ceilings used by both startup validation and bounded request data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_definitions: usize,
    pub max_regex_length: usize,
    pub max_request_field_length: usize,
    pub max_request_headers: usize,
    pub max_header_name_length: usize,
    pub max_header_value_length: usize,
    pub max_header_value_count: usize,
    pub max_audit_line_bytes: usize,
    pub max_audit_queue: usize,
    pub max_metric_queue: usize,
    pub max_honeypot_body_bytes: usize,
    pub max_sqlite_bytes: u64,
    pub max_audit_headers: usize,
    pub max_audit_value_length: usize,
    pub max_audit_retention: Duration,
    pub max_matches: usize,
    pub max_bans: usize,
    pub max_ban_duration: Duration,
    pub max_allowlist_rows: usize,
    pub max_pattern_bytes_total: usize,
    pub max_regex_program_bytes: usize,
    pub max_regex_dfa_bytes: usize,
    pub max_compiled_regex_bytes_total: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_definitions: 10_000,
            max_regex_length: 4_096,
            max_request_field_length: 8_192,
            max_request_headers: 64,
            max_header_name_length: 256,
            max_header_value_length: 8_192,
            max_header_value_count: 8,
            max_audit_line_bytes: 64 * 1024,
            max_audit_queue: 4_096,
            max_metric_queue: 1_024,
            max_honeypot_body_bytes: 16 * 1024,
            max_sqlite_bytes: 64 * 1024 * 1024,
            max_audit_headers: 32,
            max_audit_value_length: 1_024,
            max_audit_retention: Duration::from_secs(90 * 24 * 60 * 60),
            max_matches: 64,
            max_bans: 100_000,
            max_ban_duration: Duration::from_secs(7 * 24 * 60 * 60),
            max_allowlist_rows: 10_000,
            max_pattern_bytes_total: 8 * 1024 * 1024,
            max_regex_program_bytes: 256 * 1024,
            max_regex_dfa_bytes: 256 * 1024,
            max_compiled_regex_bytes_total: 64 * 1024 * 1024,
        }
    }
}

impl Limits {
    pub fn validate(&self) -> Result<(), ConfigError> {
        let values = [
            ("max_definitions", self.max_definitions as u64),
            ("max_regex_length", self.max_regex_length as u64),
            (
                "max_request_field_length",
                self.max_request_field_length as u64,
            ),
            ("max_request_headers", self.max_request_headers as u64),
            ("max_header_name_length", self.max_header_name_length as u64),
            (
                "max_header_value_length",
                self.max_header_value_length as u64,
            ),
            ("max_header_value_count", self.max_header_value_count as u64),
            ("max_audit_line_bytes", self.max_audit_line_bytes as u64),
            ("max_audit_queue", self.max_audit_queue as u64),
            ("max_metric_queue", self.max_metric_queue as u64),
            (
                "max_honeypot_body_bytes",
                self.max_honeypot_body_bytes as u64,
            ),
            ("max_sqlite_bytes", self.max_sqlite_bytes),
            ("max_audit_headers", self.max_audit_headers as u64),
            ("max_audit_value_length", self.max_audit_value_length as u64),
            ("max_matches", self.max_matches as u64),
            ("max_bans", self.max_bans as u64),
            ("max_allowlist_rows", self.max_allowlist_rows as u64),
            (
                "max_pattern_bytes_total",
                self.max_pattern_bytes_total as u64,
            ),
            (
                "max_regex_program_bytes",
                self.max_regex_program_bytes as u64,
            ),
            ("max_regex_dfa_bytes", self.max_regex_dfa_bytes as u64),
            (
                "max_compiled_regex_bytes_total",
                self.max_compiled_regex_bytes_total as u64,
            ),
        ];
        if let Some((name, _)) = values.into_iter().find(|(_, value)| *value == 0) {
            return Err(ConfigError::Invalid(format!("{name} must be positive")));
        }
        if self.max_audit_queue < 2 {
            return Err(ConfigError::Invalid(
                "max_audit_queue must reserve normal and emergency lanes".to_owned(),
            ));
        }
        if self.max_audit_retention.is_zero() {
            return Err(ConfigError::Invalid(
                "max_audit_retention must be positive".to_owned(),
            ));
        }
        let maximums = [
            (
                "max_definitions",
                self.max_definitions,
                HARD_MAX_DEFINITIONS,
            ),
            (
                "max_regex_length",
                self.max_regex_length,
                HARD_MAX_REGEX_LENGTH,
            ),
            (
                "max_request_field_length",
                self.max_request_field_length,
                HARD_MAX_REQUEST_FIELD_LENGTH,
            ),
            (
                "max_request_headers",
                self.max_request_headers,
                HARD_MAX_REQUEST_HEADERS,
            ),
            (
                "max_header_name_length",
                self.max_header_name_length,
                HARD_MAX_HEADER_NAME_LENGTH,
            ),
            (
                "max_header_value_length",
                self.max_header_value_length,
                HARD_MAX_HEADER_VALUE_LENGTH,
            ),
            (
                "max_header_value_count",
                self.max_header_value_count,
                HARD_MAX_HEADER_VALUE_COUNT,
            ),
            (
                "max_audit_line_bytes",
                self.max_audit_line_bytes,
                HARD_MAX_AUDIT_LINE_BYTES,
            ),
            (
                "max_audit_queue",
                self.max_audit_queue,
                HARD_MAX_AUDIT_QUEUE,
            ),
            (
                "max_metric_queue",
                self.max_metric_queue,
                HARD_MAX_METRIC_QUEUE,
            ),
            (
                "max_honeypot_body_bytes",
                self.max_honeypot_body_bytes,
                HARD_MAX_HONEYPOT_BODY_BYTES,
            ),
            (
                "max_audit_headers",
                self.max_audit_headers,
                HARD_MAX_AUDIT_HEADERS,
            ),
            (
                "max_audit_value_length",
                self.max_audit_value_length,
                HARD_MAX_AUDIT_VALUE_LENGTH,
            ),
            ("max_matches", self.max_matches, HARD_MAX_MATCHES),
            ("max_bans", self.max_bans, HARD_MAX_BANS),
            (
                "max_allowlist_rows",
                self.max_allowlist_rows,
                HARD_MAX_ALLOWLIST_ROWS,
            ),
            (
                "max_pattern_bytes_total",
                self.max_pattern_bytes_total,
                HARD_MAX_PATTERN_BYTES_TOTAL,
            ),
            (
                "max_regex_program_bytes",
                self.max_regex_program_bytes,
                HARD_MAX_REGEX_PROGRAM_BYTES,
            ),
            (
                "max_regex_dfa_bytes",
                self.max_regex_dfa_bytes,
                HARD_MAX_REGEX_DFA_BYTES,
            ),
            (
                "max_compiled_regex_bytes_total",
                self.max_compiled_regex_bytes_total,
                HARD_MAX_COMPILED_REGEX_BYTES_TOTAL,
            ),
        ];
        if let Some((name, _, maximum)) = maximums
            .into_iter()
            .find(|(_, value, maximum)| value > maximum)
        {
            return Err(ConfigError::Invalid(format!(
                "{name} exceeds hard maximum {maximum}"
            )));
        }
        if self.max_sqlite_bytes > HARD_MAX_SQLITE_BYTES {
            return Err(ConfigError::Invalid(
                "max_sqlite_bytes exceeds hard maximum".to_owned(),
            ));
        }
        if self.max_ban_duration > HARD_MAX_BAN_DURATION {
            return Err(ConfigError::Invalid(
                "max_ban_duration exceeds hard maximum".to_owned(),
            ));
        }
        if self.max_audit_retention > HARD_MAX_AUDIT_RETENTION {
            return Err(ConfigError::Invalid(
                "max_audit_retention exceeds hard maximum".to_owned(),
            ));
        }
        if self.max_ban_duration.is_zero() {
            return Err(ConfigError::Invalid(
                "max_ban_duration must be positive".to_owned(),
            ));
        }
        if self.max_audit_line_bytes < 512 {
            return Err(ConfigError::Invalid(
                "max_audit_line_bytes is too small for the required schema".to_owned(),
            ));
        }
        if self.max_honeypot_body_bytes < 128 {
            return Err(ConfigError::Invalid(
                "max_honeypot_body_bytes is too small for a decoy".to_owned(),
            ));
        }
        if self.max_header_name_length > self.max_request_field_length
            || self.max_header_value_length > self.max_request_field_length
            || self.max_audit_value_length > self.max_request_field_length
        {
            return Err(ConfigError::Invalid(
                "header and audit limits cannot exceed request field limit".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Fixed response policy. Definitions cannot override this policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fail2banPolicy {
    pub status_code: u16,
    pub retry_after: Duration,
}

impl Default for Fail2banPolicy {
    fn default() -> Self {
        Self {
            status_code: 403,
            retry_after: Duration::from_secs(60),
        }
    }
}

impl Fail2banPolicy {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !(400..=599).contains(&self.status_code) {
            return Err(ConfigError::Invalid(
                "fail2ban status must be an HTTP error status".to_owned(),
            ));
        }
        if self.retry_after.as_secs() == 0 || self.retry_after > Duration::from_secs(86_400) {
            return Err(ConfigError::Invalid(
                "fail2ban retry-after must be between one second and one day".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Global operational settings. The database contains definitions; this
/// structure intentionally has no per-definition policy fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionConfig {
    pub ban_mode: bool,
    pub honeypot_mode: bool,
    pub wordpress_site: bool,
    /// Canonical lowercase extensions without a leading dot. Empty disables the trigger.
    pub ban_extensions: Vec<String>,
    pub ban_duration: Duration,
    pub definitions_db: PathBuf,
    pub definitions_url: Option<String>,
    pub audit_log: PathBuf,
    pub limits: Limits,
    pub fail2ban: Fail2banPolicy,
}

impl ProtectionConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        let canonical = canonicalize_ban_extensions(&self.ban_extensions)?;
        if canonical != self.ban_extensions {
            return Err(ConfigError::Invalid(
                "ban_extensions must be canonical and unique".to_owned(),
            ));
        }
        if self.ban_duration.is_zero() || self.ban_duration > self.limits.max_ban_duration {
            return Err(ConfigError::Invalid(
                "ban_duration must be positive and within max_ban_duration".to_owned(),
            ));
        }
        if (self.ban_mode || self.honeypot_mode) && self.definitions_db.as_os_str().is_empty() {
            return Err(ConfigError::Invalid(
                "definitions_db must not be empty".to_owned(),
            ));
        }
        if let Some(url) = &self.definitions_url
            && !url.starts_with("https://")
        {
            return Err(ConfigError::Invalid(
                "definitions_url must use HTTPS".to_owned(),
            ));
        }
        self.limits.validate()?;
        self.fail2ban.validate()
    }
}

/// Accept an optional single leading dot followed by 1..=32 ASCII letters/digits,
/// starting with a letter. No whitespace, punctuation, separators, or paths.
/// Preserve first-seen order while lowercasing and removing duplicates.
pub fn canonicalize_ban_extensions(values: &[String]) -> Result<Vec<String>, ConfigError> {
    let mut unique = HashSet::new();
    let mut result = Vec::new();
    for value in values {
        let extension = value.strip_prefix('.').unwrap_or(value);
        if extension.is_empty()
            || extension.len() > 32
            || !extension.as_bytes()[0].is_ascii_alphabetic()
            || !extension.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            return Err(ConfigError::Invalid(
                "ban_extensions values must be 1..=32 ASCII letters/digits starting with a letter, optionally prefixed by one dot".to_owned(),
            ));
        }
        let extension = extension.to_ascii_lowercase();
        if unique.insert(extension.clone()) {
            result.push(extension);
        }
    }
    Ok(result)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("{0}")]
    Invalid(String),
}
