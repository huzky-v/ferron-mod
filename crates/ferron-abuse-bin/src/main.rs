fn main() {
    ferron_entrypoint::init();
    // Register managed nodes before the default HTTP loader constructs TLS resolvers.
    let mut loaders: Vec<Box<dyn ferron_core::loader::ModuleLoader>> = vec![Box::new(
        ferron_tls_tailscale::TlsTailscaleModuleLoader::default(),
    )];
    loaders.extend(ferron_entrypoint::default_profile());
    loaders.push(Box::new(
        ferron_abuse_protection::FerronAbuseProtectionModuleLoader::default(),
    ));
    loaders.push(Box::new(ferron_text_errors::FerronTextErrorsModuleLoader));
    loaders.push(Box::new(ferron_dns_acmedns::AcmeDnsModuleLoader));
    ferron_entrypoint::main(loaders);
}
