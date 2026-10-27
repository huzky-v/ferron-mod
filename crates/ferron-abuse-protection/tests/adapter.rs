use abuse_core::Limits;
use bytes::Bytes;
use ferron_abuse_protection::{
    AbuseProtectionConfigurationValidator, AbuseProtectionStage, DIRECTIVES,
    FerronAbuseProtectionModuleLoader, extract_config, request_input,
};
use ferron_core::config::validator::{ConfigurationValidator, ConfigurationValidatorContext};
use ferron_core::config::{
    ServerConfigurationBlock, ServerConfigurationDirectiveEntry, ServerConfigurationValue,
};
use ferron_core::directives::DirectiveRegistry;
use ferron_core::loader::ModuleLoader;
use ferron_core::pipeline::Stage;
use ferron_http::{HttpContext, HttpRequest};
use http::{Request, Uri};
use http_body_util::{BodyExt, Empty};
use rustc_hash::FxHashMap;
use std::sync::{Arc, OnceLock};

fn block(values: &[(&str, ServerConfigurationValue)]) -> ServerConfigurationBlock {
    let mut directives = FxHashMap::default();
    for (name, value) in values {
        directives.insert(
            (*name).to_owned(),
            vec![ServerConfigurationDirectiveEntry {
                args: vec![value.clone()],
                children: None,
                span: None,
            }],
        );
    }
    ServerConfigurationBlock {
        directives: Arc::new(directives),
        matchers: FxHashMap::default(),
        span: None,
    }
}

#[test]
fn extracts_required_global_settings_and_https_url() {
    let block = block(&[
        ("ban_mode", ServerConfigurationValue::Boolean(true, None)),
        (
            "honeypot_mode",
            ServerConfigurationValue::Boolean(true, None),
        ),
        (
            "ban_duration",
            ServerConfigurationValue::String("15m".to_owned(), None),
        ),
        (
            "definitions_db",
            ServerConfigurationValue::String("definitions.sqlite".to_owned(), None),
        ),
        (
            "honeypot_templates_dir",
            ServerConfigurationValue::String("/tmp/honeypot-responses".to_owned(), None),
        ),
        (
            "definitions_url",
            ServerConfigurationValue::String(
                "https://security.invalid/definitions.sqlite".to_owned(),
                None,
            ),
        ),
        (
            "audit_log",
            ServerConfigurationValue::String("audit.ndjson".to_owned(), None),
        ),
    ]);
    let config = extract_config(&block).unwrap();
    assert!(config.core.ban_mode);
    assert_eq!(config.core.ban_duration.as_secs(), 900);
    assert_eq!(
        config.honeypot_templates_dir.as_deref(),
        Some(std::path::Path::new("/tmp/honeypot-responses"))
    );
}

#[test]
fn matched_log_is_optional_and_requires_a_nonempty_path() {
    let settings = base_settings(false);
    assert!(
        extract_config(&block(&settings))
            .unwrap()
            .matched_log
            .is_none()
    );
    let mut settings = settings;
    settings.push((
        "matched_log",
        ServerConfigurationValue::String("matched.log".into(), None),
    ));
    assert_eq!(
        extract_config(&block(&settings))
            .unwrap()
            .matched_log
            .as_deref(),
        Some(std::path::Path::new("matched.log"))
    );
    settings.pop();
    settings.push((
        "matched_log",
        ServerConfigurationValue::String(" ".into(), None),
    ));
    assert!(extract_config(&block(&settings)).is_err());
}

#[test]
fn proxied_by_defaults_to_none_and_accepts_only_cloudflare_or_none() {
    let settings = base_settings(false);
    assert!(!extract_config(&block(&settings)).unwrap().cloudflare);
    for (value, expected) in [
        ("none", Some(false)),
        ("cloudflare", Some(true)),
        ("other", None),
    ] {
        let mut settings = settings.clone();
        settings.push((
            "proxied_by",
            ServerConfigurationValue::String(value.into(), None),
        ));
        assert_eq!(
            extract_config(&block(&settings))
                .ok()
                .map(|config| config.cloudflare),
            expected
        );
    }
}

#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn wordpress_site_defaults_off_and_can_be_overridden_per_site() {
    use ferron_abuse_protection::extract_site_config;
    let global = block(&base_settings(false));
    assert!(!extract_config(&global).unwrap().core.wordpress_site);
    let site = block(&[(
        "wordpress_site",
        ServerConfigurationValue::Boolean(true, None),
    )]);
    assert!(
        extract_site_config(&global, &site)
            .unwrap()
            .core
            .wordpress_site
    );
    let invalid = block(&[(
        "wordpress_site",
        ServerConfigurationValue::String("true".into(), None),
    )]);
    assert!(extract_site_config(&global, &invalid).is_err());
}

fn base_settings(honeypot_mode: bool) -> Vec<(&'static str, ServerConfigurationValue)> {
    vec![
        ("ban_mode", ServerConfigurationValue::Boolean(true, None)),
        (
            "honeypot_mode",
            ServerConfigurationValue::Boolean(honeypot_mode, None),
        ),
        (
            "ban_duration",
            ServerConfigurationValue::String("15m".into(), None),
        ),
        (
            "definitions_db",
            ServerConfigurationValue::String("definitions.sqlite".into(), None),
        ),
        (
            "audit_log",
            ServerConfigurationValue::String("audit.ndjson".into(), None),
        ),
    ]
}

#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn site_overrides_modes_logs_and_share_bans_without_changing_definition_source() {
    use ferron_abuse_protection::extract_site_config;
    let global = block(&base_settings(false));
    assert!(extract_config(&global).unwrap().share_bans);
    let site = block(&[
        ("ban_mode", ServerConfigurationValue::Boolean(false, None)),
        (
            "honeypot_mode",
            ServerConfigurationValue::Boolean(true, None),
        ),
        ("share_bans", ServerConfigurationValue::Boolean(false, None)),
        (
            "audit_log",
            ServerConfigurationValue::String("site.ndjson".into(), None),
        ),
        (
            "matched_log",
            ServerConfigurationValue::String("site.log".into(), None),
        ),
        (
            "ban_duration",
            ServerConfigurationValue::String("1h".into(), None),
        ),
    ]);
    // Honeypot resources remain exclusively global.
    assert!(extract_site_config(&global, &site).is_err());
    let mut global_with_templates = global.clone();
    Arc::make_mut(&mut global_with_templates.directives).insert(
        "honeypot_templates_dir".into(),
        block(&[(
            "honeypot_templates_dir",
            ServerConfigurationValue::String("/templates".into(), None),
        )])
        .directives["honeypot_templates_dir"]
            .clone(),
    );
    let effective = extract_site_config(&global_with_templates, &site).unwrap();
    assert!(!effective.core.ban_mode);
    assert!(effective.core.honeypot_mode);
    assert!(!effective.share_bans);
    assert_eq!(effective.core.ban_duration.as_secs(), 3600);
    assert_eq!(
        effective.core.definitions_db.to_string_lossy(),
        "definitions.sqlite"
    );
    assert_eq!(effective.core.audit_log.to_string_lossy(), "site.ndjson");
    assert_eq!(effective.matched_log.unwrap().to_string_lossy(), "site.log");

    let mut context = ConfigurationValidatorContext {
        used_directives: Default::default(),
        is_global: false,
        scoped_validators: Arc::new(Default::default()),
        diagnostics: vec![],
        scope: None,
    };
    assert!(
        AbuseProtectionConfigurationValidator
            .validate_block(&site, &mut context)
            .is_ok()
    );
    assert!(context.used_directives.contains("share_bans"));
    assert!(context.used_directives.contains("audit_log"));
    assert!(context.used_directives.contains("matched_log"));
    let forbidden = block(&[(
        "definitions_db",
        ServerConfigurationValue::String("other.db".into(), None),
    )]);
    assert!(extract_site_config(&global, &forbidden).is_err());
    assert!(
        AbuseProtectionConfigurationValidator
            .validate_block(&forbidden, &mut context)
            .is_err()
    );
}

fn extension_block(entries: Vec<Vec<ServerConfigurationValue>>) -> ServerConfigurationBlock {
    let base = block(&base_settings(false));
    let mut directives = (*base.directives).clone();
    directives.insert(
        "ban_extensions".to_owned(),
        entries
            .into_iter()
            .map(|args| ServerConfigurationDirectiveEntry {
                args,
                children: None,
                span: None,
            })
            .collect(),
    );
    ServerConfigurationBlock {
        directives: Arc::new(directives),
        ..base
    }
}

#[test]
fn site_extension_list_replaces_global_list() {
    let global = extension_block(vec![vec![ServerConfigurationValue::String(
        "php".into(),
        None,
    )]]);
    let site = block(&[(
        "ban_extensions",
        ServerConfigurationValue::String("asp".into(), None),
    )]);
    assert_eq!(
        ferron_abuse_protection::extract_site_config(&global, &site)
            .unwrap()
            .core
            .ban_extensions,
        ["asp"]
    );
    assert_eq!(
        ferron_abuse_protection::extract_site_config(&global, &block(&[]))
            .unwrap()
            .core
            .ban_extensions,
        ["php"]
    );
}

#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn ban_extension_list_is_canonical_and_validated_in_both_scopes() {
    let string = |value: &str| ServerConfigurationValue::String(value.to_owned(), None);
    let block = extension_block(vec![
        vec![string(".PHP"), string("asp")],
        vec![string("php"), string("ASP")],
    ]);
    assert_eq!(
        extract_config(&block).unwrap().core.ban_extensions,
        ["php", "asp"]
    );
    assert!(
        extract_config(&extension_block(vec![]))
            .unwrap()
            .core
            .ban_extensions
            .is_empty()
    );
    assert!(
        extract_config(&extension_block(vec![vec![]]))
            .unwrap()
            .core
            .ban_extensions
            .is_empty()
    );
    let mut registry = DirectiveRegistry::new();
    FerronAbuseProtectionModuleLoader::default().register_directives(&mut registry);
    assert!(
        !registry
            .directives
            .values()
            .flatten()
            .find(|entry| entry.name == "ban_extensions")
            .unwrap()
            .global_only
    );
    let validate = |block: &ServerConfigurationBlock, is_global| {
        let mut context = ConfigurationValidatorContext {
            used_directives: Default::default(),
            is_global,
            scoped_validators: Arc::new(Default::default()),
            diagnostics: vec![],
            scope: None,
        };
        let result = AbuseProtectionConfigurationValidator.validate_block(block, &mut context);
        (result, context)
    };
    let (result, context) = validate(&block, true);
    assert!(result.is_ok());
    assert!(context.used_directives.contains("ban_extensions"));
    let site_extensions = |block: &ServerConfigurationBlock| {
        let mut site = ServerConfigurationBlock::default();
        Arc::make_mut(&mut site.directives).insert(
            "ban_extensions".into(),
            block.directives["ban_extensions"].clone(),
        );
        site
    };
    assert!(validate(&site_extensions(&block), false).0.is_ok());
    for invalid in [
        "", "  ", " php", "php ", ".", "..php", "a.b", "a/b", "a\\b", "php,asp", "1php", "é",
        "a-php",
    ] {
        let block = extension_block(vec![vec![string(invalid)]]);
        assert!(
            extract_config(&block)
                .unwrap_err()
                .contains("ban_extensions"),
            "{invalid}"
        );
        assert!(validate(&block, true).0.is_err(), "{invalid}");
        assert!(
            validate(&site_extensions(&block), false).0.is_err(),
            "{invalid}"
        );
    }
    let block = extension_block(vec![vec![ServerConfigurationValue::Boolean(true, None)]]);
    assert!(extract_config(&block).is_err());
    assert!(validate(&block, true).0.is_err());
    let block = extension_block(vec![vec![ServerConfigurationValue::Number(123, None)]]);
    assert!(extract_config(&block).is_err());
    assert!(validate(&block, true).0.is_err());
}

#[test]
fn template_directory_is_conditionally_required_and_never_loaded_during_extraction() {
    let settings = base_settings(false);
    let disabled = extract_config(&block(&settings)).unwrap();
    assert!(disabled.honeypot_templates_dir.is_none());

    let settings = base_settings(true);
    assert!(
        extract_config(&block(&settings))
            .unwrap_err()
            .contains("honeypot_templates_dir")
    );

    for invalid in [
        ServerConfigurationValue::String(String::new(), None),
        ServerConfigurationValue::String("  ".into(), None),
        ServerConfigurationValue::Boolean(true, None),
    ] {
        let mut settings = base_settings(true);
        settings.push(("honeypot_templates_dir", invalid));
        assert!(
            extract_config(&block(&settings))
                .unwrap_err()
                .contains("honeypot_templates_dir")
        );
    }
    let mut settings = base_settings(true);
    settings.push((
        "honeypot_templates_dir",
        ServerConfigurationValue::String("/nonexistent/catalog".into(), None),
    ));
    assert_eq!(
        extract_config(&block(&settings))
            .unwrap()
            .honeypot_templates_dir
            .as_deref(),
        Some(std::path::Path::new("/nonexistent/catalog"))
    );

    let mut disabled_with_path = base_settings(false);
    disabled_with_path.push((
        "honeypot_templates_dir",
        ServerConfigurationValue::String("/nonexistent/catalog".into(), None),
    ));
    assert!(
        !extract_config(&block(&disabled_with_path))
            .unwrap()
            .core
            .honeypot_mode
    );
}

#[test]
#[allow(clippy::arc_with_non_send_sync)] // Ferron's validator context requires this Arc of non-Send trait objects.
fn validator_registers_global_directive_and_checks_conditional_presence_and_type() {
    let mut registry = DirectiveRegistry::new();
    FerronAbuseProtectionModuleLoader::default().register_directives(&mut registry);
    let directive = registry
        .directives
        .values()
        .flatten()
        .find(|directive| directive.name == "honeypot_templates_dir")
        .unwrap();
    assert!(directive.global_only);

    let validate = |settings: &[(&str, ServerConfigurationValue)], is_global| {
        let mut context = ConfigurationValidatorContext {
            used_directives: Default::default(),
            is_global,
            scoped_validators: Arc::new(Default::default()),
            diagnostics: vec![],
            scope: None,
        };
        let result =
            AbuseProtectionConfigurationValidator.validate_block(&block(settings), &mut context);
        (result, context)
    };

    let enabled = base_settings(true);
    assert!(validate(&enabled, true).0.is_err());
    assert!(validate(&base_settings(false), true).0.is_ok());

    for invalid in [
        ServerConfigurationValue::String(String::new(), None),
        ServerConfigurationValue::String("  ".into(), None),
        ServerConfigurationValue::Boolean(true, None),
    ] {
        let mut settings = base_settings(false);
        settings.push(("honeypot_templates_dir", invalid));
        assert!(validate(&settings, true).0.is_err());
    }

    let mut settings = enabled;
    settings.push((
        "honeypot_templates_dir",
        ServerConfigurationValue::String("/catalog".into(), None),
    ));
    let (result, context) = validate(&settings, true);
    assert!(result.is_ok());
    assert!(context.used_directives.contains("honeypot_templates_dir"));
    assert!(validate(&settings, false).0.is_err());
}

#[test]
fn rejects_non_https_definition_url() {
    let block = block(&[
        ("ban_mode", ServerConfigurationValue::Boolean(true, None)),
        (
            "honeypot_mode",
            ServerConfigurationValue::Boolean(false, None),
        ),
        (
            "ban_duration",
            ServerConfigurationValue::String("15m".to_owned(), None),
        ),
        (
            "definitions_db",
            ServerConfigurationValue::String("definitions.sqlite".to_owned(), None),
        ),
        (
            "definitions_url",
            ServerConfigurationValue::String("http://invalid".to_owned(), None),
        ),
        (
            "audit_log",
            ServerConfigurationValue::String("audit.ndjson".to_owned(), None),
        ),
    ]);
    assert!(extract_config(&block).is_err());
}

#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn bundle_config_overrides_legacy_sources_and_is_global_only() {
    let mut registry = DirectiveRegistry::new();
    FerronAbuseProtectionModuleLoader::default().register_directives(&mut registry);
    let directive = registry
        .directives
        .values()
        .flatten()
        .find(|entry| entry.name == "definitions_bundle")
        .unwrap();
    assert!(directive.global_only);
    for source in [
        "default",
        "/tmp/bundle.zip",
        "https://example.invalid/bundle.zip",
    ] {
        let mut settings = base_settings(true);
        settings.retain(|(key, _)| *key != "definitions_db");
        settings.push((
            "definitions_bundle",
            ServerConfigurationValue::String(source.into(), None),
        ));
        settings.push((
            "definitions_url",
            ServerConfigurationValue::String("http://ignored".into(), None),
        ));
        settings.push((
            "honeypot_templates_dir",
            ServerConfigurationValue::Boolean(true, None),
        ));
        let config = extract_config(&block(&settings)).unwrap();
        assert_eq!(config.definitions_bundle.as_deref(), Some(source));
        assert!(config.core.definitions_url.is_none());
        assert!(config.honeypot_templates_dir.is_none());
        let mut context = ConfigurationValidatorContext {
            used_directives: Default::default(),
            is_global: true,
            scoped_validators: Arc::new(Default::default()),
            diagnostics: vec![],
            scope: None,
        };
        assert!(
            AbuseProtectionConfigurationValidator
                .validate_block(&block(&settings), &mut context)
                .is_ok()
        );
        assert!(context.used_directives.contains("definitions_bundle"));
        context.is_global = false;
        assert!(
            AbuseProtectionConfigurationValidator
                .validate_block(&block(&settings), &mut context)
                .is_err()
        );
        settings.push((
            "definitions_db",
            ServerConfigurationValue::Boolean(false, None),
        ));
        assert!(extract_config(&block(&settings)).is_ok());
        context.is_global = true;
        assert!(
            AbuseProtectionConfigurationValidator
                .validate_block(&block(&settings), &mut context)
                .is_ok()
        );
    }
    for invalid in ["", " ", "http://invalid/bundle.zip"] {
        let mut settings = base_settings(false);
        settings.push((
            "definitions_bundle",
            ServerConfigurationValue::String(invalid.into(), None),
        ));
        assert!(extract_config(&block(&settings)).is_err());
    }
}

#[test]
fn rejects_legacy_abuse_configuration() {
    let block = block(&[
        (
            "abuse_protection",
            ServerConfigurationValue::Boolean(true, None),
        ),
        ("ban_mode", ServerConfigurationValue::Boolean(true, None)),
        (
            "honeypot_mode",
            ServerConfigurationValue::Boolean(false, None),
        ),
        (
            "ban_duration",
            ServerConfigurationValue::String("15m".to_owned(), None),
        ),
        (
            "definitions_db",
            ServerConfigurationValue::String("definitions.sqlite".to_owned(), None),
        ),
        (
            "audit_log",
            ServerConfigurationValue::String("audit.ndjson".to_owned(), None),
        ),
    ]);
    let error = extract_config(&block).unwrap_err();
    assert!(error.contains("legacy Ferron abuse directive"));
}

#[test]
fn stage_has_early_ordering_and_only_expected_directives_are_owned() {
    assert_eq!(DIRECTIVES.len(), 27);
    assert!(DIRECTIVES.contains(&"geo_mode"));
    assert!(DIRECTIVES.contains(&"wordpress_site"));
    assert!(DIRECTIVES.contains(&"share_bans"));
    assert!(DIRECTIVES.contains(&"matched_log"));
    assert!(DIRECTIVES.contains(&"honeypot_templates_dir"));
    assert!(DIRECTIVES.contains(&"ban_extensions"));
    assert!(DIRECTIVES.contains(&"ipban_mode"));
    let state = Arc::new(OnceLock::new());
    let stage = AbuseProtectionStage::new(state);
    assert_eq!(stage.name(), "ferron_abuse_protection");
    let constraints = stage.constraints();
    assert!(constraints.len() >= 6);
    assert!(constraints.iter().any(|constraint| {
        matches!(constraint, ferron_core::registry::StageConstraint::Before(name) if name == "abuse_protection")
    }));
}

#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn ipban_settings_are_global_and_standalone() {
    let global = block(&[
        ("ipban_mode", ServerConfigurationValue::Boolean(true, None)),
        (
            "ipban_log",
            ServerConfigurationValue::String("blocked.log".into(), None),
        ),
    ]);
    let mut context = ConfigurationValidatorContext {
        used_directives: Default::default(),
        is_global: true,
        scoped_validators: Arc::new(Default::default()),
        diagnostics: vec![],
        scope: None,
    };
    assert!(
        AbuseProtectionConfigurationValidator
            .validate_block(&global, &mut context)
            .is_ok()
    );
    assert!(AbuseProtectionStage::new(Arc::new(OnceLock::new())).is_applicable(Some(&global)));
    assert!(context.used_directives.contains("ipban_mode"));
    context.is_global = false;
    assert!(
        AbuseProtectionConfigurationValidator
            .validate_block(&global, &mut context)
            .is_err()
    );
    let mut registry = DirectiveRegistry::new();
    FerronAbuseProtectionModuleLoader::default().register_directives(&mut registry);
    assert!(
        registry
            .directives
            .values()
            .flatten()
            .find(|entry| entry.name == "ipban_mode")
            .unwrap()
            .global_only
    );

    let missing_log = block(&[("ipban_mode", ServerConfigurationValue::Boolean(true, None))]);
    context.is_global = true;
    assert!(
        AbuseProtectionConfigurationValidator
            .validate_block(&missing_log, &mut context)
            .is_err()
    );
    for (name, value) in [
        ("ipban_url", "http://insecure.invalid/list"),
        ("ipban_interval", "0s"),
    ] {
        let mut settings = (*global.directives).clone();
        settings.insert(
            name.into(),
            block(&[(name, ServerConfigurationValue::String(value.into(), None))]).directives[name]
                .clone(),
        );
        let invalid = ServerConfigurationBlock {
            directives: Arc::new(settings),
            ..global.clone()
        };
        assert!(
            AbuseProtectionConfigurationValidator
                .validate_block(&invalid, &mut context)
                .is_err()
        );
    }
}

fn context_with_original_uri(uri: &str) -> HttpContext {
    let request: HttpRequest = Request::builder()
        .uri("/routed")
        .header("host", "example.invalid")
        .body(
            Empty::<Bytes>::new()
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .unwrap();
    let mut context = HttpContext::default();
    context.req = Some(request);
    context.original_uri = Some(uri.parse::<Uri>().unwrap());
    context.remote_address = Some("198.51.100.7:443".parse().unwrap());
    context
}

#[test]
fn request_source_uses_original_uri_and_canonical_ip() {
    let context = context_with_original_uri("/original?x=1");
    let input = request_input(&context, &Limits::default()).unwrap();
    assert_eq!(input.target, "/original?x=1");
    assert_eq!(input.client_ip.to_string(), "198.51.100.7");
}

#[test]
fn request_source_rejects_invalid_headers_and_bounds_before_ownership() {
    let mut context = context_with_original_uri("/original");
    let request = context.req.as_mut().unwrap();
    request
        .headers_mut()
        .append("x-invalid", http::HeaderValue::from_bytes(&[0xff]).unwrap());
    assert!(request_input(&context, &Limits::default()).is_err());

    let limited = Limits {
        max_request_field_length: 4,
        ..Limits::default()
    };
    let long_context = context_with_original_uri("/this-target-is-too-long");
    assert!(request_input(&long_context, &limited).is_err());
}
