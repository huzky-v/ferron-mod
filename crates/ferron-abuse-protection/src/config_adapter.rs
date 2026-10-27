use ferron_core::config::ServerConfiguration;
use ferron_core::config::ServerConfigurationHostFilters;

pub(crate) fn add_abuse_catch_all(config: &mut ServerConfiguration) {
    let global = &config.global_config;
    let protection_enabled = ["ban_mode", "honeypot_mode", "ipban_mode", "geo_mode"]
        .into_iter()
        .any(|directive| {
            global
                .get_value(directive)
                .and_then(|value| value.as_boolean())
                == Some(true)
        });
    if !protection_enabled {
        return;
    }

    let Some(ports) = config.ports.get_mut("http") else {
        return;
    };
    for port in ports {
        let has_catch_all = port
            .hosts
            .iter()
            .any(|(filters, _)| filters.ip.is_none() && filters.host.is_none());
        if !has_catch_all {
            port.hosts.push((
                ServerConfigurationHostFilters::default(),
                Default::default(),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferron_core::config::{
        ServerConfigurationBlock, ServerConfigurationDirectiveEntry, ServerConfigurationPort,
        ServerConfigurationValue,
    };
    use std::sync::Arc;

    fn enabled_config() -> ServerConfiguration {
        let mut directives = rustc_hash::FxHashMap::default();
        directives.insert(
            "ban_mode".to_owned(),
            vec![ServerConfigurationDirectiveEntry {
                args: vec![ServerConfigurationValue::Boolean(true, None)],
                children: None,
                span: None,
            }],
        );
        ServerConfiguration {
            global_config: Arc::new(ServerConfigurationBlock {
                directives: Arc::new(directives),
                ..ServerConfigurationBlock::default()
            }),
            ports: [("http".to_owned(), vec![ServerConfigurationPort::default()])]
                .into_iter()
                .collect(),
        }
    }

    #[test]
    fn adds_an_empty_default_host_only_when_global_protection_is_enabled() {
        let mut config = enabled_config();
        add_abuse_catch_all(&mut config);
        assert_eq!(config.ports["http"][0].hosts.len(), 1);
        assert_eq!(
            config.ports["http"][0].hosts[0].0,
            ServerConfigurationHostFilters::default()
        );

        add_abuse_catch_all(&mut config);
        assert_eq!(config.ports["http"][0].hosts.len(), 1);

        let mut disabled = ServerConfiguration {
            ports: [("http".to_owned(), vec![ServerConfigurationPort::default()])]
                .into_iter()
                .collect(),
            ..ServerConfiguration::default()
        };
        add_abuse_catch_all(&mut disabled);
        assert!(disabled.ports["http"][0].hosts.is_empty());
    }
}
