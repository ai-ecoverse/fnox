use crate::child_env::{self, Selection};
use crate::commands::Cli;
use crate::config::{Config, ProxyConfig, SecretConfig};
use crate::error::{FnoxError, Result};
use crate::lease::{self, LEASE_REUSE_BUFFER_SECS, ResolvedLease};
use crate::lease_backends::LeaseBackendConfig;
use crate::proxy::{ProxyPlan, ProxyValues, RunningProxy};
use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

/// The shortest wait before renewing a lease credential, so a lease that is
/// already due, or that the backend issues with a very short lifetime, cannot
/// make the proxy spin.
const MIN_LEASE_REFRESH_DELAY: Duration = Duration::from_secs(1);

/// How long to wait before trying again after a lease renewal fails, unless
/// the credential expires sooner.
const LEASE_RETRY_DELAY: Duration = Duration::from_secs(30);

const AMBIENT_CREDENTIAL_ENV_VARS: &[&str] = &[
    "FNOX_AGE_KEY",
    "FNOX_AGE_KEY_FILE",
    "OP_SERVICE_ACCOUNT_TOKEN",
    "BW_SESSION",
    "BWS_ACCESS_TOKEN",
    "INFISICAL_TOKEN",
    "KEEPASS_PASSWORD",
    "PASSWORDSTATE_API_KEY",
    "DOPPLER_TOKEN",
    "FNOX_DOPPLER_TOKEN",
    "KSM_CONFIG",
    "FNOX_KEEPER_CONFIG",
    "KSM_TOKEN",
    "FNOX_KEEPER_TOKEN",
    "FOKS_BOT_TOKEN",
    "FNOX_FOKS_BOT_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS",
    // AWS SDK credential-chain inputs, including selectors and alternate
    // credential sources that can bypass explicitly brokered placeholders.
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_CONFIG_FILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
    "AWS_ROLE_SESSION_NAME",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "AWS_EC2_METADATA_SERVICE_ENDPOINT",
    "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE",
    "AWS_SDK_LOAD_CONFIG",
    // Vault configuration can point a child at an authenticated local agent or
    // supply enough TLS context to use credentials outside the proxy policy.
    "VAULT_TOKEN",
    "VAULT_ADDR",
    "VAULT_AGENT_ADDR",
    "VAULT_NAMESPACE",
    "VAULT_CLIENT_CERT",
    "VAULT_CLIENT_KEY",
    "VAULT_CACERT",
    "VAULT_CAPATH",
    "VAULT_TLS_SERVER_NAME",
    "VAULT_SKIP_VERIFY",
    "FNOX_VAULT_TOKEN",
    "FNOX_VAULT_ADDR",
    // Azure Identity treats these as credential-chain inputs rather than only
    // secret values, so remove the complete environment credential shape.
    "AZURE_CLIENT_ID",
    "AZURE_CLIENT_SECRET",
    "AZURE_TENANT_ID",
    "AZURE_CLIENT_CERTIFICATE_PATH",
    "AZURE_CLIENT_CERTIFICATE_PASSWORD",
    "AZURE_USERNAME",
    "AZURE_PASSWORD",
    "AZURE_FEDERATED_TOKEN_FILE",
    "AZURE_AUTHORITY_HOST",
    "AZURE_CONFIG_DIR",
    "AZURE_ACCESS_TOKEN",
    // pass-cli accepts both native and fnox-prefixed login/session controls.
    "PROTON_PASS_PASSWORD",
    "PROTON_PASS_TOTP",
    "PROTON_PASS_EXTRA_PASSWORD",
    "PROTON_PASS_PASSWORD_FILE",
    "PROTON_PASS_TOTP_FILE",
    "PROTON_PASS_EXTRA_PASSWORD_FILE",
    "PROTON_PASS_PERSONAL_ACCESS_TOKEN",
    "PROTON_PASS_AGENT_REASON",
    "PROTON_PASS_SESSION_DIR",
    "PROTON_PASS_KEY_PROVIDER",
    "PROTON_PASS_ENCRYPTION_KEY",
    "PROTON_PASS_LINUX_KEYRING",
    "FNOX_PROTON_PASS_PASSWORD",
    "FNOX_PROTON_PASS_TOTP",
    "FNOX_PROTON_PASS_EXTRA_PASSWORD",
    "FNOX_PROTON_PASS_PASSWORD_FILE",
    "FNOX_PROTON_PASS_TOTP_FILE",
    "FNOX_PROTON_PASS_EXTRA_PASSWORD_FILE",
    "FNOX_PROTON_PASS_PERSONAL_ACCESS_TOKEN",
    "FNOX_PROTON_PASS_AGENT_REASON",
    "FNOX_PROTON_PASS_SESSION_DIR",
    "FNOX_PROTON_PASS_KEY_PROVIDER",
    "FNOX_PROTON_PASS_ENCRYPTION_KEY",
    "FNOX_PROTON_PASS_LINUX_KEYRING",
];

#[derive(Debug, usage_rs::Args)]
pub struct ProxyCommand {
    #[usage(subcommand)]
    command: ProxySubcommand,
}

#[derive(Debug, usage_rs::Subcommands)]
enum ProxySubcommand {
    /// Show the effective credential proxy rules
    Rules,

    /// Run a command with placeholder credentials through the local proxy
    Run(ProxyRunCommand),
}

#[derive(Debug, usage_rs::Args)]
struct ProxyRunCommand {
    /// Command to run
    #[usage(
        arg,
        double_dash = "automatic",
        value_hint = usage_rs::ValueHint::CommandWithArguments
    )]
    command: Vec<String>,
}

impl ProxyCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        let proxy = config.proxy.as_ref().ok_or_else(|| {
            FnoxError::Config(
                "No [proxy] configuration found; add one or more [[proxy.rules]]".to_string(),
            )
        })?;
        match &self.command {
            ProxySubcommand::Rules => show_rules(proxy),
            ProxySubcommand::Run(command) => command.run(cli, config).await,
        }
    }
}

fn show_rules(proxy: &ProxyConfig) -> Result<()> {
    crate::proxy::validate_config(proxy)?;
    println!("egress: {:?}", proxy.egress);
    println!("audit: {}", proxy.audit);
    for rule in &proxy.rules {
        let methods = if rule.methods.is_empty() {
            "*".to_string()
        } else {
            rule.methods.join(",")
        };
        let paths = if rule.paths.is_empty() {
            "*".to_string()
        } else {
            rule.paths.join(",")
        };
        println!(
            "{} -> https://{} methods={} paths={} header={} env={}",
            rule.secret,
            rule.domain,
            methods,
            paths,
            rule.header,
            rule.env.as_deref().unwrap_or(&rule.secret)
        );
    }
    Ok(())
}

/// Leases that may supply the secret of a proxy rule: every lease that
/// declares one of the rule names, and every `command` lease, whose credential
/// names are only known once it runs.
fn proxy_leases(proxy: &ProxyConfig, leases: &IndexMap<String, LeaseBackendConfig>) -> Vec<String> {
    leases
        .iter()
        .filter(|(_, lease)| {
            matches!(lease, LeaseBackendConfig::Command { .. })
                || proxy
                    .rules
                    .iter()
                    .any(|rule| lease.produces_env_var(&rule.secret))
        })
        .map(|(name, _)| name.clone())
        .collect()
}

fn collect_requested_secrets(
    config: &Config,
    profile: &[String],
    proxy: &ProxyConfig,
    all_secrets: &IndexMap<String, SecretConfig>,
    leases: &IndexMap<String, LeaseBackendConfig>,
) -> Result<IndexMap<String, SecretConfig>> {
    let providers = config.get_providers(profile)?;
    let default_provider = config.get_default_provider(profile)?;
    let mut requested = IndexMap::new();

    for rule in &proxy.rules {
        // A secret is resolved even when a lease may supply the same name: the
        // lease wins when it runs, and the secret is used when it is skipped.
        match all_secrets.get(&rule.secret) {
            Some(secret) => {
                requested.insert(rule.secret.clone(), secret.clone());
            }
            None if leases.values().any(|lease| {
                matches!(lease, LeaseBackendConfig::Command { .. })
                    || lease.produces_env_var(&rule.secret)
            }) => {}
            None => {
                return Err(FnoxError::Config(format!(
                    "Proxy rule references unknown secret '{}'; no secret or lease credential has that name",
                    rule.secret
                )));
            }
        }
    }

    loop {
        let mut added = false;
        let keys: Vec<_> = requested.keys().cloned().collect();
        for key in keys {
            let secret = &requested[&key];
            let provider_name = secret
                .sync
                .as_ref()
                .map(|sync| sync.provider.as_str())
                .or_else(|| secret.provider())
                .or_else(|| {
                    secret
                        .value()
                        .is_some()
                        .then_some(default_provider.as_deref())
                        .flatten()
                });
            let Some(provider) = provider_name.and_then(|name| providers.get(name)) else {
                continue;
            };
            for dependency in provider.env_dependencies() {
                if requested.contains_key(*dependency) {
                    continue;
                }
                if let Some(secret) = all_secrets.get(*dependency) {
                    requested.insert((*dependency).to_string(), secret.clone());
                    added = true;
                }
            }
        }
        if !added {
            break;
        }
    }

    Ok(requested)
}

impl ProxyRunCommand {
    async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        if self.command.is_empty() {
            return Err(FnoxError::CommandNotSpecified);
        }
        let proxy_config = config
            .proxy
            .as_ref()
            .ok_or_else(|| FnoxError::Config("No [proxy] configuration found".to_string()))?;
        crate::proxy::validate_config(proxy_config)?;
        let profile = Config::get_profiles(&cli.profile);
        let all_secrets = config.get_secrets(&profile)?;
        let leases = config.get_leases(&profile)?;
        let selected_leases = proxy_leases(proxy_config, &leases);
        let mut requested =
            collect_requested_secrets(&config, &profile, proxy_config, &all_secrets, &leases)?;
        if !selected_leases.is_empty() {
            // The secrets the leases need to run, as `fnox exec` resolves them.
            let selection = Selection {
                leases: selected_leases.clone(),
                ..Selection::default()
            };
            for (key, secret) in
                child_env::resolve_set(&config, &profile, &all_secrets, &leases, &selection)?
            {
                requested.entry(key).or_insert(secret);
            }
        }
        let resolved = crate::daemon::resolve_batch(
            cli,
            &config,
            &profile,
            &requested,
            crate::daemon::Purpose::Proxy,
            true,
        )
        .await?;
        let (ran, _lease_files) = child_env::run_leases(
            cli,
            &config,
            &profile,
            &leases,
            &selected_leases,
            &resolved,
            &all_secrets,
            "proxy",
        )
        .await?;
        let (values, sources) = rule_values(proxy_config, &resolved, &ran)?;
        let mut refresher = LeaseRefresher::new(
            RefreshContext {
                config: config.clone(),
                profile: profile.clone(),
                project_dir: lease::project_dir_from_config(&config, &cli.config),
                resolved: resolved.clone(),
                secrets: all_secrets.clone(),
            },
            &leases,
            &ran,
            &sources,
        );

        let plan = ProxyPlan::new(proxy_config, &values)?;
        let proxy_values = plan.values();
        let child_env = plan.child_env.clone();
        let running = RunningProxy::start(plan).await?;
        let proxy_url = format!("http://{}", running.address);
        let ca_path = running.ca_path().to_string_lossy().to_string();

        tracing::warn!(
            "fnox proxy does not sandbox the child process yet; same-user code may bypass the proxy"
        );

        let mut command = tokio::process::Command::new(&self.command[0]);
        command
            .args(&self.command[1..])
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        // Do not inherit secrets already loaded by shell integration. Proxy
        // rules add back placeholders for the explicitly brokered values.
        for key in all_secrets.keys() {
            command.env_remove(key);
        }
        for name in &selected_leases {
            for key in leases[name].produced_env_vars() {
                command.env_remove(key);
            }
        }
        for (_, lease) in &ran {
            for key in lease.credentials.keys() {
                command.env_remove(key);
            }
        }
        for key in AMBIENT_CREDENTIAL_ENV_VARS {
            command.env_remove(key);
        }
        for provider in config.get_providers(&profile)?.values() {
            for dependency in provider.env_dependencies() {
                command.env_remove(dependency);
            }
        }
        command.env("FNOX_DAEMON", "off");
        command.env("FNOX_NON_INTERACTIVE", "1");
        for (key, placeholder) in child_env {
            command.env(key, placeholder);
        }
        for key in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            command.env(key, &proxy_url);
        }
        command.env("NO_PROXY", "localhost,127.0.0.1,::1");
        command.env("no_proxy", "localhost,127.0.0.1,::1");
        command.env("NODE_USE_ENV_PROXY", "1");
        for key in [
            "SSL_CERT_FILE",
            "NODE_EXTRA_CA_CERTS",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
            "GIT_SSL_CAINFO",
            "CARGO_HTTP_CAINFO",
            "DENO_CERT",
        ] {
            command.env(key, &ca_path);
        }

        let status = {
            let child = command.status();
            tokio::pin!(child);
            loop {
                tokio::select! {
                    // Poll the child first, so it is spawned before any
                    // renewal sets secrets in this process's environment.
                    biased;
                    status = &mut child => break status,
                    () = refresher.renew_next(&proxy_values) => {}
                }
            }
        };
        running.shutdown().await;
        let status = status.map_err(|source| FnoxError::CommandExecutionFailed {
            command: self.command.join(" "),
            source,
        })?;

        if !status.success() {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                if let Some(signal) = status.signal() {
                    std::process::exit(128 + signal);
                }
            }
            std::process::exit(status.code().unwrap_or(1));
        }
        Ok(())
    }
}

/// The value of each proxy rule's secret, and the lease it came from, if any.
///
/// A lease credential wins over a same-name secret, and a later lease wins
/// over an earlier one, as in `fnox exec`.
fn rule_values(
    proxy: &ProxyConfig,
    resolved: &IndexMap<String, Option<String>>,
    ran: &[(String, ResolvedLease)],
) -> Result<(IndexMap<String, String>, IndexMap<String, String>)> {
    let mut values = IndexMap::new();
    let mut sources = IndexMap::new();
    for rule in &proxy.rules {
        if let Some((name, lease)) = ran
            .iter()
            .rev()
            .find(|(_, lease)| lease.credentials.contains_key(&rule.secret))
        {
            values.insert(rule.secret.clone(), lease.credentials[&rule.secret].clone());
            sources.insert(rule.secret.clone(), name.clone());
            continue;
        }
        let value = resolved
            .get(&rule.secret)
            .cloned()
            .flatten()
            .ok_or_else(|| {
                FnoxError::Config(format!("Proxy secret '{}' did not resolve", rule.secret))
            })?;
        values.insert(rule.secret.clone(), value);
    }
    Ok((values, sources))
}

/// How long to wait before renewing a lease credential that expires at
/// `expires_at`: until five minutes before it expires, as `fnox exec` stops
/// reusing a cached lease then, or halfway to expiry for a shorter lease.
fn refresh_delay(expires_at: DateTime<Utc>, now: DateTime<Utc>) -> Duration {
    let remaining = (expires_at - now).to_std().unwrap_or_default();
    let buffer = Duration::from_secs(LEASE_REUSE_BUFFER_SECS as u64);
    let early = if remaining > buffer * 2 {
        buffer
    } else {
        remaining / 2
    };
    remaining.saturating_sub(early).max(MIN_LEASE_REFRESH_DELAY)
}

/// How long to wait before retrying a failed renewal.
fn retry_delay(expires_at: DateTime<Utc>, now: DateTime<Utc>) -> Duration {
    let remaining = (expires_at - now).to_std().unwrap_or_default();
    LEASE_RETRY_DELAY
        .min(remaining / 2)
        .max(MIN_LEASE_REFRESH_DELAY)
}

/// What a lease renewal needs once the proxy is running.
struct RefreshContext {
    config: Config,
    profile: Vec<String>,
    project_dir: PathBuf,
    resolved: IndexMap<String, Option<String>>,
    secrets: IndexMap<String, SecretConfig>,
}

/// A lease that supplies proxy rule secrets and expires.
struct RefreshedLease {
    name: String,
    config: LeaseBackendConfig,
    secrets: Vec<String>,
    expires_at: DateTime<Utc>,
    due: tokio::time::Instant,
}

/// Renews the lease credentials a running proxy injects before they expire,
/// keeping their placeholders.
struct LeaseRefresher {
    context: RefreshContext,
    leases: Vec<RefreshedLease>,
}

impl LeaseRefresher {
    fn new(
        context: RefreshContext,
        configs: &IndexMap<String, LeaseBackendConfig>,
        ran: &[(String, ResolvedLease)],
        sources: &IndexMap<String, String>,
    ) -> Self {
        let now = Utc::now();
        let leases = ran
            .iter()
            .filter_map(|(name, lease)| {
                let expires_at = lease.expires_at?;
                let secrets: Vec<String> = sources
                    .iter()
                    .filter(|(_, source)| *source == name)
                    .map(|(secret, _)| secret.clone())
                    .collect();
                if secrets.is_empty() {
                    return None;
                }
                Some(RefreshedLease {
                    name: name.clone(),
                    config: configs[name].clone(),
                    secrets,
                    expires_at,
                    due: tokio::time::Instant::now() + refresh_delay(expires_at, now),
                })
            })
            .collect();
        Self { context, leases }
    }

    /// Wait until the next lease is due and renew it. Never finishes when no
    /// lease needs renewing.
    async fn renew_next(&mut self, values: &ProxyValues) {
        let Some(index) = (0..self.leases.len()).min_by_key(|index| self.leases[*index].due) else {
            return std::future::pending().await;
        };
        tokio::time::sleep_until(self.leases[index].due).await;

        let lease = &self.leases[index];
        match self.renew(lease).await {
            Ok(renewed) => {
                let updates: IndexMap<String, String> = lease
                    .secrets
                    .iter()
                    .filter_map(|secret| {
                        renewed
                            .credentials
                            .get(secret)
                            .map(|value| (secret.clone(), value.clone()))
                    })
                    .collect();
                if updates.len() < lease.secrets.len() {
                    tracing::warn!(
                        "Renewed lease '{}' no longer provides every proxied secret; keeping the previous values for the missing ones",
                        lease.name
                    );
                }
                if let Err(error) = values.update(&updates) {
                    tracing::warn!("Could not use renewed lease '{}': {error}", lease.name);
                }
                match renewed.expires_at {
                    Some(expires_at) => {
                        let lease = &mut self.leases[index];
                        lease.expires_at = expires_at;
                        lease.due =
                            tokio::time::Instant::now() + refresh_delay(expires_at, Utc::now());
                        tracing::debug!(
                            "Renewed lease '{}' for the proxy (expires {expires_at})",
                            lease.name
                        );
                    }
                    None => {
                        self.leases.remove(index);
                    }
                }
            }
            Err(error) => {
                let delay = retry_delay(lease.expires_at, Utc::now());
                tracing::warn!(
                    "Could not renew lease '{}' for the proxy, retrying in {}s: {error}",
                    lease.name,
                    delay.as_secs()
                );
                self.leases[index].due = tokio::time::Instant::now() + delay;
            }
        }
    }

    async fn renew(&self, lease: &RefreshedLease) -> Result<ResolvedLease> {
        let context = &self.context;
        let mut temp_env_guard = lease::TempEnvGuard::default();
        let _temp_files =
            lease::set_secrets_as_env(&context.resolved, &context.secrets, &mut temp_env_guard)?;
        let prereq_missing = lease.config.check_prerequisites();
        lease::resolve_lease_with_expiry(
            &lease.name,
            &lease.config,
            &context.config,
            &context.profile,
            &context.project_dir,
            prereq_missing.as_deref(),
            "proxy",
            true,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requested_secrets_include_provider_dependencies() {
        let config: Config = toml_edit::de::from_str(
            r#"
[providers.doppler]
type = "doppler"

[providers.plain]
type = "plain"

[secrets]
DOPPLER_TOKEN = { provider = "plain", value = "provider-token" }
API_TOKEN = { provider = "doppler", value = "api-token" }

[proxy]
[[proxy.rules]]
secret = "API_TOKEN"
domain = "api.example.com"
"#,
        )
        .unwrap();
        let profile = vec!["default".to_string()];
        let all_secrets = config.get_secrets(&profile).unwrap();

        let requested = collect_requested_secrets(
            &config,
            &profile,
            config.proxy.as_ref().unwrap(),
            &all_secrets,
            &config.get_leases(&profile).unwrap(),
        )
        .unwrap();

        assert!(requested.contains_key("API_TOKEN"));
        assert!(requested.contains_key("DOPPLER_TOKEN"));
    }

    fn lease_config(leases: &str) -> Config {
        toml_edit::de::from_str(&format!(
            r#"
[providers.plain]
type = "plain"

[secrets]
API_TOKEN = {{ provider = "plain", value = "api-token" }}

{leases}

[proxy]
[[proxy.rules]]
secret = "API_TOKEN"
domain = "api.example.com"

[[proxy.rules]]
secret = "GH_TOKEN"
domain = "api.github.com"
"#
        ))
        .unwrap()
    }

    fn requested_for(config: &Config) -> Result<IndexMap<String, SecretConfig>> {
        let profile = vec!["default".to_string()];
        collect_requested_secrets(
            config,
            &profile,
            config.proxy.as_ref().unwrap(),
            &config.get_secrets(&profile).unwrap(),
            &config.get_leases(&profile).unwrap(),
        )
    }

    fn leased(credentials: &[(&str, &str)], expires_at: Option<DateTime<Utc>>) -> ResolvedLease {
        ResolvedLease {
            credentials: credentials
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
            expires_at,
        }
    }

    #[test]
    fn rule_secrets_can_name_lease_credentials() {
        let config = lease_config(
            r#"
[leases.github]
type = "command"
create_command = "jerk github lease"
"#,
        );

        let requested = requested_for(&config).unwrap();

        assert!(requested.contains_key("API_TOKEN"));
        assert!(!requested.contains_key("GH_TOKEN"));
        assert_eq!(
            proxy_leases(
                config.proxy.as_ref().unwrap(),
                &config.get_leases(&["default".to_string()]).unwrap()
            ),
            ["github"]
        );
    }

    #[test]
    fn rule_secrets_must_name_a_secret_or_lease_credential() {
        let config = lease_config(
            r#"
[leases.aws]
type = "aws-sts"
region = "us-east-1"
role_arn = "arn:aws:iam::1:role/r"
"#,
        );

        let error = requested_for(&config).unwrap_err();

        assert!(error.to_string().contains("unknown secret 'GH_TOKEN'"));
    }

    #[test]
    fn proxy_runs_only_leases_that_may_supply_a_rule() {
        let config = lease_config(
            r#"
[leases.aws]
type = "aws-sts"
region = "us-east-1"
role_arn = "arn:aws:iam::1:role/r"

[leases.app]
type = "github-app"
app_id = "1"
installation_id = "2"
env_var = "GH_TOKEN"

[leases.script]
type = "command"
create_command = "true"
"#,
        );
        let leases = config.get_leases(&["default".to_string()]).unwrap();

        assert!(requested_for(&config).is_ok());
        assert_eq!(
            proxy_leases(config.proxy.as_ref().unwrap(), &leases),
            ["app", "script"]
        );
    }

    #[test]
    fn lease_credentials_win_over_secrets_and_later_leases_win() {
        let config = lease_config("");
        let resolved = [
            ("API_TOKEN".to_string(), Some("from-secret".to_string())),
            ("GH_TOKEN".to_string(), Some("from-secret".to_string())),
        ]
        .into_iter()
        .collect();
        let ran = vec![
            ("first".to_string(), leased(&[("GH_TOKEN", "first")], None)),
            (
                "second".to_string(),
                leased(&[("GH_TOKEN", "second")], None),
            ),
        ];

        let (values, sources) =
            rule_values(config.proxy.as_ref().unwrap(), &resolved, &ran).unwrap();

        assert_eq!(values["API_TOKEN"], "from-secret");
        assert_eq!(values["GH_TOKEN"], "second");
        assert_eq!(sources.get("GH_TOKEN").map(String::as_str), Some("second"));
        assert!(!sources.contains_key("API_TOKEN"));
    }

    #[test]
    fn missing_rule_values_are_reported() {
        let config = lease_config("");
        let resolved = [("API_TOKEN".to_string(), Some("api".to_string()))]
            .into_iter()
            .collect();
        let ran = vec![("other".to_string(), leased(&[("OTHER", "value")], None))];

        let error = rule_values(config.proxy.as_ref().unwrap(), &resolved, &ran).unwrap_err();

        assert!(error.to_string().contains("'GH_TOKEN' did not resolve"));
    }

    #[test]
    fn refresher_tracks_only_expiring_leases_that_feed_rules() {
        let config = lease_config(
            r#"
[leases.github]
type = "command"
create_command = "true"

[leases.forever]
type = "command"
create_command = "true"

[leases.unused]
type = "command"
create_command = "true"
"#,
        );
        let profile = vec!["default".to_string()];
        let leases = config.get_leases(&profile).unwrap();
        let soon = Utc::now() + chrono::Duration::hours(1);
        let ran = vec![
            (
                "github".to_string(),
                leased(&[("GH_TOKEN", "a")], Some(soon)),
            ),
            ("forever".to_string(), leased(&[("API_TOKEN", "b")], None)),
            ("unused".to_string(), leased(&[("OTHER", "c")], Some(soon))),
        ];
        let resolved = IndexMap::new();
        let (_, sources) = rule_values(config.proxy.as_ref().unwrap(), &resolved, &ran).unwrap();

        let refresher = LeaseRefresher::new(
            RefreshContext {
                config: config.clone(),
                profile,
                project_dir: PathBuf::from("."),
                resolved,
                secrets: IndexMap::new(),
            },
            &leases,
            &ran,
            &sources,
        );

        assert_eq!(refresher.leases.len(), 1);
        assert_eq!(refresher.leases[0].name, "github");
        assert_eq!(refresher.leases[0].secrets, ["GH_TOKEN"]);
    }

    #[test]
    fn refresh_happens_before_the_lease_stops_being_reusable() {
        let now = Utc::now();
        let at = |seconds| now + chrono::Duration::seconds(seconds);

        assert_eq!(refresh_delay(at(3600), now), Duration::from_secs(3300));
        assert_eq!(refresh_delay(at(600), now), Duration::from_secs(300));
        assert_eq!(refresh_delay(at(20), now), Duration::from_secs(10));
        assert_eq!(refresh_delay(at(1), now), MIN_LEASE_REFRESH_DELAY);
        assert_eq!(refresh_delay(at(-60), now), MIN_LEASE_REFRESH_DELAY);
    }

    #[test]
    fn failed_renewals_retry_before_the_credential_expires() {
        let now = Utc::now();
        let at = |seconds| now + chrono::Duration::seconds(seconds);

        assert_eq!(retry_delay(at(3600), now), LEASE_RETRY_DELAY);
        assert_eq!(retry_delay(at(20), now), Duration::from_secs(10));
        assert_eq!(retry_delay(at(-60), now), MIN_LEASE_REFRESH_DELAY);
    }

    #[test]
    fn ambient_credential_scrub_covers_provider_chains() {
        for key in [
            "KSM_CONFIG",
            "FNOX_KEEPER_CONFIG",
            "KSM_TOKEN",
            "FNOX_KEEPER_TOKEN",
            "AWS_PROFILE",
            "AWS_REGION",
            "AWS_WEB_IDENTITY_TOKEN_FILE",
            "VAULT_ADDR",
            "VAULT_AGENT_ADDR",
            "AZURE_CLIENT_ID",
            "AZURE_TENANT_ID",
            "AZURE_FEDERATED_TOKEN_FILE",
            "PROTON_PASS_PASSWORD",
            "PROTON_PASS_SESSION_DIR",
            "FNOX_PROTON_PASS_ENCRYPTION_KEY",
        ] {
            assert!(
                AMBIENT_CREDENTIAL_ENV_VARS.contains(&key),
                "{key} must be removed from proxy children"
            );
        }
    }
}
