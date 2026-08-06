use crate::config::NativeAddress;
use crate::provider::{Address, Provider, ProviderCredentials, ProviderUrl};
use crate::{Result, SecretSpecError};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::process::{Command, Output, Stdio};

const DEVO_CLI_PATH_ENV: &str = "SECRETSPEC_DEVO_CLI_PATH";
const DEVO_VALUE_ENV: &str = "SECRETSPEC_DEVO_VALUE";
const SQLITE_PASSPHRASE: &str = "passphrase";
const DEVO_SQLITE_PASSPHRASE_ENV: &str = "DEVO_SQLITE_PASSPHRASE";
const DEVO_SQLITE_PASSPHRASE_CHILD_ENV: &str = "SECRETSPEC_DEVO_SQLITE_PASSPHRASE";

/// The Devolutions workspace source selected by a Devo provider URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DevoSource {
    Server,
    Cloud,
    Sqlite,
}

impl DevoSource {
    fn from_scheme(scheme: &str) -> Result<Self> {
        match scheme {
            "devo" | "devo+server" => Ok(Self::Server),
            "devo+cloud" | "devo+hub" => Ok(Self::Cloud),
            "devo+sqlite" => Ok(Self::Sqlite),
            _ => Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{scheme}' for devo provider. Use devo, devo+server, devo+cloud, or devo+sqlite."
            ))),
        }
    }

    fn command(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Cloud => "cloud",
            Self::Sqlite => "sqlite",
        }
    }

    fn not_found_error_code(self) -> &'static str {
        match self {
            Self::Server => "serverSecretNotFound",
            Self::Cloud => "cloudSecretNotFound",
            Self::Sqlite => "sqliteSecretNotFound",
        }
    }
}

/// Configuration for a Devolutions workspace source.
///
/// Server and Cloud URIs identify an optional saved CLI context and default
/// vault. SQLite URIs identify a local datasource through `?datasource=`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevoConfig {
    /// The selected Devolutions workspace source.
    pub source: DevoSource,
    /// Optional saved `devo server` or `devo cloud` context. When omitted, the
    /// respective command uses its configured default context.
    pub context: Option<String>,
    /// Required local SQLite datasource ID for the SQLite source.
    pub datasource_id: Option<String>,
    /// Optional vault ID used unless a secret reference supplies one.
    pub vault_id: Option<String>,
    #[serde(skip)]
    uri_scheme: String,
}

impl TryFrom<&ProviderUrl> for DevoConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> Result<Self> {
        let source = DevoSource::from_scheme(url.scheme())?;

        if url.password().is_some() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "devo provider credentials belong in a saved CLI context, not its URI".to_string(),
            ));
        }

        let path = url.path();
        if !path.trim_matches('/').is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "the devo provider URI names a vault only; name the entry and data property with \
                 a secret's `ref`"
                    .to_string(),
            ));
        }

        let username = url.username();
        let (context, datasource_id) = match source {
            DevoSource::Sqlite => {
                if !username.is_empty() {
                    return Err(SecretSpecError::ProviderOperationFailed(
                        "devo+sqlite uses ?datasource=<canonical-datasource-id>, not URI userinfo"
                            .to_string(),
                    ));
                }

                let mut datasource_id = None;
                for (key, value) in url.query_pairs() {
                    if key != "datasource" {
                        return Err(SecretSpecError::ProviderOperationFailed(format!(
                            "devo+sqlite does not support the `{key}` query parameter; use `datasource`"
                        )));
                    }
                    if value.is_empty() || datasource_id.replace(value.into_owned()).is_some() {
                        return Err(SecretSpecError::ProviderOperationFailed(
                            "devo+sqlite needs exactly one non-empty `datasource` query parameter"
                                .to_string(),
                        ));
                    }
                }
                let datasource_id = datasource_id.ok_or_else(|| {
                    SecretSpecError::ProviderOperationFailed(
                        "devo+sqlite needs ?datasource=<canonical-datasource-id>, \
                         e.g. devo+sqlite://vault-guid?datasource=sqlite%3AConnections.db"
                            .to_string(),
                    )
                })?;
                (None, Some(datasource_id))
            }
            DevoSource::Server | DevoSource::Cloud => {
                if url.query_pairs().next().is_some() {
                    return Err(SecretSpecError::ProviderOperationFailed(format!(
                        "{} does not support query parameters; name the saved context before `@`",
                        url.scheme()
                    )));
                }
                ((!username.is_empty()).then_some(username), None)
            }
        };

        Ok(Self {
            source,
            context,
            datasource_id,
            vault_id: url.host(),
            uri_scheme: url.scheme().to_string(),
        })
    }
}

/// A Devolutions workspace secret property addressed by the `devo` CLI.
struct DevoReference {
    vault_id: String,
    entry_id: String,
    field: String,
}

/// Provider for existing Devolutions workspace secret entries via the `devo` CLI.
///
/// Every source uses explicit vault and entry IDs; it does not offer safe
/// entry-name lookup. Every secret therefore uses a native `ref`: `item` is
/// the entry ID, `field` is its data property, and `vault` optionally
/// overrides the vault selected by the provider URI.
pub struct DevoProvider {
    config: DevoConfig,
    cli_path: String,
    credentials: ProviderCredentials,
}

crate::register_provider! {
    struct: DevoProvider,
    config: DevoConfig,
    name: "devo",
    description: "Devolutions Server, Cloud, and SQLite secrets via devo CLI (0.20+)",
    schemes: ["devo", "devo+server", "devo+cloud", "devo+hub", "devo+sqlite"],
    examples: [
        "devo://vault-guid",
        "devo+cloud://production@vault-guid",
        "devo+sqlite://vault-guid?datasource=sqlite%3AConnections.db",
    ],
    credential_names: [SQLITE_PASSPHRASE],
}

impl DevoProvider {
    pub fn new(config: DevoConfig) -> Self {
        Self {
            config,
            cli_path: std::env::var(DEVO_CLI_PATH_ENV).unwrap_or_else(|_| "devo".to_string()),
            credentials: ProviderCredentials::new(),
        }
    }

    fn convention_error() -> SecretSpecError {
        SecretSpecError::ProviderOperationFailed(
            "the devo provider requires a secret `ref` because Devolutions sources address \
             secrets by explicit entry IDs. For example: \
             DATABASE_URL = { description = \"Production database\", ref = { \
             item = \"entry-guid\", field = \"Password\" }, providers = \
             [\"devo://vault-guid\"] }"
                .to_string(),
        )
    }

    fn reference(&self, addr: Address<'_>) -> Result<DevoReference> {
        let coords = self.resolve_coords(addr)?;
        let field = coords
            .field
            .clone()
            .filter(|field| !field.is_empty())
            .ok_or_else(|| {
                SecretSpecError::ProviderOperationFailed(
                    "devo references need a `field` naming the Devolutions data property, \
                 e.g. ref = { item = \"entry-guid\", field = \"Password\" }"
                        .to_string(),
                )
            })?;
        Ok(DevoReference {
            vault_id: coords
                .vault
                .clone()
                .or_else(|| self.config.vault_id.clone())
                .ok_or_else(|| {
                    SecretSpecError::ProviderOperationFailed(
                        "devo references need a `vault` when the provider URI does not name one, \
                         e.g. ref = { vault = \"vault-guid\", item = \"entry-guid\", \
                         field = \"Password\" }"
                            .to_string(),
                    )
                })?,
            entry_id: coords.item.clone(),
            field,
        })
    }

    fn arguments(
        &self,
        operation: &str,
        reference: &DevoReference,
        include_value_env: bool,
    ) -> Result<Vec<String>> {
        let mut args = vec![
            self.config.source.command().to_string(),
            "secret".to_string(),
            operation.to_string(),
        ];
        match self.config.source {
            DevoSource::Server | DevoSource::Cloud => {
                if let Some(context) = &self.config.context {
                    args.push(context.clone());
                }
            }
            DevoSource::Sqlite => {
                let datasource_id = self.config.datasource_id.as_ref().ok_or_else(|| {
                    SecretSpecError::ProviderOperationFailed(
                        "devo+sqlite needs a local datasource ID in its URI".to_string(),
                    )
                })?;
                args.extend(["--datasource-id".to_string(), datasource_id.clone()]);
            }
        }
        args.extend([
            "--vault-id".to_string(),
            reference.vault_id.clone(),
            "--entry-id".to_string(),
            reference.entry_id.clone(),
            "--field".to_string(),
            reference.field.clone(),
        ]);
        if include_value_env {
            if self.config.source == DevoSource::Sqlite {
                args.extend([
                    "--passphrase-env".to_string(),
                    DEVO_SQLITE_PASSPHRASE_CHILD_ENV.to_string(),
                ]);
            }
            args.extend([
                "--value-env".to_string(),
                DEVO_VALUE_ENV.to_string(),
                "--yes".to_string(),
            ]);
        }
        Ok(args)
    }

    fn uri_scheme(&self) -> &str {
        if self.config.uri_scheme.is_empty() {
            match self.config.source {
                DevoSource::Server => "devo",
                DevoSource::Cloud => "devo+cloud",
                DevoSource::Sqlite => "devo+sqlite",
            }
        } else {
            &self.config.uri_scheme
        }
    }

    fn command(
        &self,
        args: &[String],
        value: Option<&SecretString>,
        sqlite_passphrase: Option<&SecretString>,
    ) -> Command {
        let mut command = Command::new(&self.cli_path);
        command
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if self.config.source == DevoSource::Sqlite {
            command
                .env_remove(DEVO_SQLITE_PASSPHRASE_ENV)
                .env_remove(DEVO_SQLITE_PASSPHRASE_CHILD_ENV);
            if let Some(passphrase) = sqlite_passphrase {
                // The passphrase is scoped to the child and never appears in an
                // argument or provider diagnostic.
                command.env(DEVO_SQLITE_PASSPHRASE_CHILD_ENV, passphrase.expose_secret());
            }
        }
        if let Some(value) = value {
            // The value is scoped to the child process and never appears in the
            // command line or provider diagnostics.
            command.env(DEVO_VALUE_ENV, value.expose_secret());
        }
        command
    }

    fn execute(
        &self,
        args: &[String],
        value: Option<&SecretString>,
        sqlite_passphrase: Option<&SecretString>,
    ) -> Result<Output> {
        self.command(args, value, sqlite_passphrase)
            .output()
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    SecretSpecError::ProviderOperationFailed(
                        "Devolutions CLI (devo) is not installed. Install devo and configure the \
                     selected Devolutions source before using the devo provider."
                            .to_string(),
                    )
                } else {
                    error.into()
                }
            })
    }

    fn stderr(output: &Output) -> String {
        String::from_utf8_lossy(&output.stderr).trim().to_string()
    }

    fn command_error(&self, output: &Output) -> SecretSpecError {
        let stderr = Self::stderr(output);
        SecretSpecError::ProviderOperationFailed(if stderr.is_empty() {
            format!(
                "devo {} secret command failed without an error message",
                self.config.source.command()
            )
        } else {
            format!(
                "devo {} secret command failed: {stderr}",
                self.config.source.command()
            )
        })
    }

    fn is_not_found_error(source: DevoSource, stderr: &str) -> bool {
        stderr
            .trim()
            .split_once(':')
            .is_some_and(|(code, _)| code.trim() == source.not_found_error_code())
    }

    fn cloud_write_unsupported_error() -> SecretSpecError {
        SecretSpecError::ProviderOperationFailed(
            "cloudSecretWriteUnsupported: the devo cloud provider is read-only: Devolutions \
             Cloud does not support updating secret fields through the devo CLI"
                .to_string(),
        )
    }

    fn sqlite_passphrase_configured(&self) -> bool {
        self.credentials
            .get(SQLITE_PASSPHRASE)
            .is_some_and(|passphrase| !passphrase.expose_secret().is_empty())
            || std::env::var(DEVO_SQLITE_PASSPHRASE_ENV)
                .is_ok_and(|passphrase| !passphrase.is_empty())
    }

    fn sqlite_passphrase_required_error() -> SecretSpecError {
        SecretSpecError::ProviderOperationFailed(
            "sqlitePassphraseRequired: the devo sqlite provider needs a `passphrase` provider \
             credential or DEVO_SQLITE_PASSPHRASE"
                .to_string(),
        )
    }

    fn sqlite_passphrase_from(&self, fallback: Option<String>) -> Result<SecretString> {
        if let Some(passphrase) = self
            .credentials
            .get(SQLITE_PASSPHRASE)
            .filter(|passphrase| !passphrase.expose_secret().is_empty())
        {
            return Ok(passphrase.clone());
        }

        fallback
            .filter(|passphrase| !passphrase.is_empty())
            .map(|passphrase| SecretString::new(passphrase.into()))
            .ok_or_else(Self::sqlite_passphrase_required_error)
    }

    fn sqlite_passphrase(&self) -> Result<SecretString> {
        self.sqlite_passphrase_from(std::env::var(DEVO_SQLITE_PASSPHRASE_ENV).ok())
    }

    fn output_value(output: Output) -> Result<SecretString> {
        String::from_utf8(output.stdout)
            .map(|value| SecretString::new(value.into()))
            .map_err(|error| SecretSpecError::ProviderOperationFailed(error.to_string()))
    }
}

impl Provider for DevoProvider {
    fn convention_address(
        &self,
        _project: &str,
        _profile: &str,
        _key: &str,
    ) -> Result<NativeAddress> {
        Err(Self::convention_error())
    }

    fn supported_coords(&self) -> &'static [&'static str] {
        &["field", "vault"]
    }

    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        let reference = self.reference(addr)?;
        match self.config.source {
            DevoSource::Cloud => return Err(Self::cloud_write_unsupported_error()),
            DevoSource::Sqlite => {
                if reference.field != "password" {
                    return Err(SecretSpecError::ProviderOperationFailed(
                        "sqliteSecretFieldUnsupported: the devo sqlite provider can update only \
                         the `password` field"
                            .to_string(),
                    ));
                }
                if !self.sqlite_passphrase_configured() {
                    return Err(Self::sqlite_passphrase_required_error());
                }
            }
            DevoSource::Server => {}
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        let mut uri = format!("{}://", self.uri_scheme());
        if self.config.source != DevoSource::Sqlite {
            if let Some(context) = &self.config.context {
                uri.push_str(&ProviderUrl::encode(context));
                uri.push('@');
            }
        }
        if let Some(vault_id) = &self.config.vault_id {
            uri.push_str(&ProviderUrl::encode(vault_id));
        }
        if let Some(datasource_id) = &self.config.datasource_id {
            uri.push_str("?datasource=");
            uri.push_str(&ProviderUrl::encode_query(datasource_id));
        }
        uri
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let reference = self.reference(addr)?;
        let arguments = self.arguments("get", &reference, false)?;
        let output = self.execute(&arguments, None, None)?;
        if !output.status.success() {
            if Self::is_not_found_error(self.config.source, &Self::stderr(&output)) {
                return Ok(None);
            }
            return Err(self.command_error(&output));
        }
        Self::output_value(output).map(Some)
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        self.check_writable(addr)?;
        let reference = self.reference(addr)?;
        let arguments = self.arguments("set", &reference, true)?;
        let sqlite_passphrase = (self.config.source == DevoSource::Sqlite)
            .then(|| self.sqlite_passphrase())
            .transpose()?;
        let output = self.execute(&arguments, Some(value), sqlite_passphrase.as_ref())?;
        if output.status.success() {
            Ok(())
        } else {
            Err(self.command_error(&output))
        }
    }

    fn with_credentials(&mut self, credentials: ProviderCredentials) {
        self.credentials = credentials;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::ffi::{OsStr, OsString};
    use url::Url;

    fn config(uri: &str) -> DevoConfig {
        DevoConfig::try_from(&ProviderUrl::new(Url::parse(uri).unwrap())).unwrap()
    }

    #[test]
    fn uri_parses_context_and_vault() {
        let config = config("devo://production@e20ad6fb-e991-4f1e-84a0-b12e63832f3a");
        assert_eq!(config.source, DevoSource::Server);
        assert_eq!(config.context.as_deref(), Some("production"));
        assert_eq!(
            config.vault_id.as_deref(),
            Some("e20ad6fb-e991-4f1e-84a0-b12e63832f3a")
        );
    }

    #[test]
    fn cloud_and_sqlite_uris_select_their_sources() {
        let cloud = config("devo+cloud://production@e20ad6fb-e991-4f1e-84a0-b12e63832f3a");
        assert_eq!(cloud.source, DevoSource::Cloud);
        assert_eq!(cloud.context.as_deref(), Some("production"));

        let sqlite = config(
            "devo+sqlite://e20ad6fb-e991-4f1e-84a0-b12e63832f3a?datasource=sqlite%3AConnections.db",
        );
        assert_eq!(sqlite.source, DevoSource::Sqlite);
        assert_eq!(sqlite.context, None);
        assert_eq!(
            sqlite.datasource_id.as_deref(),
            Some("sqlite:Connections.db")
        );
    }

    #[test]
    fn uri_can_omit_the_default_vault_and_rejects_paths_or_credentials() {
        let config = config("devo://");
        assert_eq!(config.vault_id, None);

        for uri in [
            "devo://vault-guid/entry-guid",
            "devo://context:secret@vault-guid",
        ] {
            assert!(DevoConfig::try_from(&ProviderUrl::new(Url::parse(uri).unwrap())).is_err());
        }
    }

    #[test]
    fn sqlite_uri_requires_only_one_datasource_query_parameter() {
        for uri in [
            "devo+sqlite://vault-guid",
            "devo+sqlite://context@vault-guid?datasource=sqlite%3AConnections.db",
            "devo+sqlite://vault-guid?datasource=sqlite%3AConnections.db&datasource=other",
            "devo+sqlite://vault-guid?source=sqlite",
        ] {
            assert!(DevoConfig::try_from(&ProviderUrl::new(Url::parse(uri).unwrap())).is_err());
        }
    }

    #[test]
    fn uri_round_trips_without_credentials() {
        let provider = DevoProvider::new(config(
            "devo://production@e20ad6fb-e991-4f1e-84a0-b12e63832f3a",
        ));
        assert_eq!(
            provider.uri(),
            "devo://production@e20ad6fb-e991-4f1e-84a0-b12e63832f3a"
        );

        let provider = DevoProvider::new(config(
            "devo+sqlite://e20ad6fb-e991-4f1e-84a0-b12e63832f3a?datasource=sqlite%3AConnections.db",
        ));
        assert_eq!(
            provider.uri(),
            "devo+sqlite://e20ad6fb-e991-4f1e-84a0-b12e63832f3a?datasource=sqlite:Connections.db"
        );
    }

    #[test]
    fn provider_declares_the_sqlite_passphrase_credential() {
        assert_eq!(
            crate::provider::credential_names_for_spec(
                "devo+sqlite://vault-guid?datasource=sqlite%3AConnections.db"
            ),
            [SQLITE_PASSPHRASE]
        );
    }

    #[test]
    fn command_arguments_follow_devo_secret_contract() {
        let provider = DevoProvider::new(config(
            "devo://production@e20ad6fb-e991-4f1e-84a0-b12e63832f3a",
        ));
        let reference = DevoReference {
            vault_id: "e20ad6fb-e991-4f1e-84a0-b12e63832f3a".to_string(),
            entry_id: "ff676a0a-0b5b-4d31-ae2e-4cc34f56a124".to_string(),
            field: "Password".to_string(),
        };

        assert_eq!(
            provider.arguments("get", &reference, false).unwrap(),
            [
                "server",
                "secret",
                "get",
                "production",
                "--vault-id",
                "e20ad6fb-e991-4f1e-84a0-b12e63832f3a",
                "--entry-id",
                "ff676a0a-0b5b-4d31-ae2e-4cc34f56a124",
                "--field",
                "Password",
            ]
        );
        assert_eq!(
            provider.arguments("set", &reference, true).unwrap(),
            [
                "server",
                "secret",
                "set",
                "production",
                "--vault-id",
                "e20ad6fb-e991-4f1e-84a0-b12e63832f3a",
                "--entry-id",
                "ff676a0a-0b5b-4d31-ae2e-4cc34f56a124",
                "--field",
                "Password",
                "--value-env",
                DEVO_VALUE_ENV,
                "--yes",
            ]
        );
    }

    #[test]
    fn cloud_and_sqlite_arguments_follow_source_contracts() {
        let reference = DevoReference {
            vault_id: "vault-guid".to_string(),
            entry_id: "entry-guid".to_string(),
            field: "password".to_string(),
        };

        let cloud = DevoProvider::new(config("devo+cloud://hub-context@vault-guid"));
        assert_eq!(
            cloud.arguments("get", &reference, false).unwrap(),
            [
                "cloud",
                "secret",
                "get",
                "hub-context",
                "--vault-id",
                "vault-guid",
                "--entry-id",
                "entry-guid",
                "--field",
                "password",
            ]
        );

        let sqlite = DevoProvider::new(config(
            "devo+sqlite://vault-guid?datasource=sqlite%3AConnections.db",
        ));
        assert_eq!(
            sqlite.arguments("get", &reference, false).unwrap(),
            [
                "sqlite",
                "secret",
                "get",
                "--datasource-id",
                "sqlite:Connections.db",
                "--vault-id",
                "vault-guid",
                "--entry-id",
                "entry-guid",
                "--field",
                "password",
            ]
        );
        assert_eq!(
            sqlite.arguments("set", &reference, true).unwrap(),
            [
                "sqlite",
                "secret",
                "set",
                "--datasource-id",
                "sqlite:Connections.db",
                "--vault-id",
                "vault-guid",
                "--entry-id",
                "entry-guid",
                "--field",
                "password",
                "--passphrase-env",
                DEVO_SQLITE_PASSPHRASE_CHILD_ENV,
                "--value-env",
                DEVO_VALUE_ENV,
                "--yes",
            ]
        );
    }

    #[test]
    fn sqlite_secrets_are_scoped_to_the_devo_child_environment() {
        let sqlite = DevoProvider::new(config(
            "devo+sqlite://vault-guid?datasource=sqlite%3AConnections.db",
        ));
        let server = DevoProvider::new(config("devo://vault-guid"));
        let reference = DevoReference {
            vault_id: "vault-guid".to_string(),
            entry_id: "entry-guid".to_string(),
            field: "password".to_string(),
        };
        let replacement = SecretString::new("replacement value".to_string().into());
        let passphrase = SecretString::new("workspace passphrase".to_string().into());
        let sqlite_args = sqlite.arguments("set", &reference, true).unwrap();
        let sqlite_command = sqlite.command(&sqlite_args, Some(&replacement), Some(&passphrase));
        let sqlite_environment: HashMap<OsString, Option<OsString>> = sqlite_command
            .get_envs()
            .map(|(name, value)| (name.to_os_string(), value.map(|value| value.to_os_string())))
            .collect();

        assert!(matches!(
            sqlite_environment.get(OsStr::new(DEVO_SQLITE_PASSPHRASE_ENV)),
            Some(None)
        ));
        assert_eq!(
            sqlite_environment
                .get(OsStr::new(DEVO_SQLITE_PASSPHRASE_CHILD_ENV))
                .and_then(|value| value.as_deref()),
            Some(OsStr::new("workspace passphrase"))
        );
        assert_eq!(
            sqlite_environment
                .get(OsStr::new(DEVO_VALUE_ENV))
                .and_then(|value| value.as_deref()),
            Some(OsStr::new("replacement value"))
        );
        assert!(
            !sqlite_environment.contains_key(OsStr::new("DEVO_RDM_SOURCE"))
                && !sqlite_environment.contains_key(OsStr::new("DEVO_RDM_CLOUD_SOURCE"))
        );
        assert!(
            sqlite_command
                .get_args()
                .all(|argument| argument != OsStr::new("workspace passphrase")
                    && argument != OsStr::new("replacement value"))
        );

        let server_args = server.arguments("set", &reference, true).unwrap();
        let server_command = server.command(&server_args, Some(&replacement), None);
        assert!(
            server_command
                .get_envs()
                .all(|(name, _)| name != OsStr::new(DEVO_SQLITE_PASSPHRASE_CHILD_ENV))
        );
    }

    #[test]
    fn native_reference_uses_field_and_optional_vault_override() {
        let provider = DevoProvider::new(config("devo://default-vault"));
        let address = NativeAddress {
            item: "entry-guid".to_string(),
            field: Some("ApiKey".to_string()),
            vault: Some("override-vault".to_string()),
            ..Default::default()
        };

        let reference = provider.reference(Address::Native(&address)).unwrap();
        assert_eq!(reference.vault_id, "override-vault");
        assert_eq!(reference.entry_id, "entry-guid");
        assert_eq!(reference.field, "ApiKey");
    }

    #[test]
    fn references_require_a_field_or_vault_and_reject_unsupported_coordinates() {
        let provider = DevoProvider::new(config("devo://default-vault"));
        let without_field = NativeAddress {
            item: "entry-guid".to_string(),
            ..Default::default()
        };
        let error = provider.get(Address::Native(&without_field)).unwrap_err();
        assert!(error.to_string().contains("need a `field`"), "{error}");

        let versioned = NativeAddress {
            item: "entry-guid".to_string(),
            field: Some("Password".to_string()),
            version: Some("2".to_string()),
            ..Default::default()
        };
        let error = provider.get(Address::Native(&versioned)).unwrap_err();
        assert!(error.to_string().contains("`version`"), "{error}");

        let provider = DevoProvider::new(config("devo://"));
        let without_vault = NativeAddress {
            item: "entry-guid".to_string(),
            field: Some("Password".to_string()),
            ..Default::default()
        };
        let error = provider.get(Address::Native(&without_vault)).unwrap_err();
        assert!(error.to_string().contains("need a `vault`"), "{error}");
    }

    #[test]
    fn convention_addresses_explain_that_a_reference_is_required() {
        let provider = DevoProvider::new(config("devo://default-vault"));
        let error = provider
            .get(Address::convention("project", "production", "DATABASE_URL"))
            .unwrap_err();
        assert!(
            error.to_string().contains("requires a secret `ref`"),
            "{error}"
        );
    }

    #[test]
    fn stdout_value_preserves_crlf_without_trimming() {
        let output = Output {
            status: success_status(),
            stdout: b"line one\r\nline two\r\n".to_vec(),
            stderr: Vec::new(),
        };
        let value = DevoProvider::output_value(output).unwrap();
        assert_eq!(value.expose_secret(), "line one\r\nline two\r\n");
    }

    #[test]
    fn source_specific_not_found_errors_are_provider_misses() {
        assert!(DevoProvider::is_not_found_error(
            DevoSource::Server,
            "serverSecretNotFound: The requested vault, entry, or secret field was not found."
        ));
        assert!(!DevoProvider::is_not_found_error(
            DevoSource::Server,
            "serverSecretUnauthorized: DVLS did not authorize access to the requested secret."
        ));
        assert!(DevoProvider::is_not_found_error(
            DevoSource::Cloud,
            "cloudSecretNotFound: The requested vault, entry, or secret field was not found."
        ));
        assert!(DevoProvider::is_not_found_error(
            DevoSource::Sqlite,
            "sqliteSecretNotFound: The requested vault, entry, or secret field was not found."
        ));
    }

    #[test]
    fn cloud_provider_is_read_only() {
        let address = NativeAddress {
            item: "entry-guid".to_string(),
            field: Some("password".to_string()),
            ..Default::default()
        };

        let error = DevoProvider::new(config("devo+cloud://vault-guid"))
            .check_writable(Address::Native(&address))
            .unwrap_err();
        assert!(error.to_string().contains("read-only"), "{error}");
        assert!(error.to_string().contains("cloudSecretWriteUnsupported"));
    }

    #[test]
    fn sqlite_password_writes_require_a_passphrase_credential() {
        let mut provider = DevoProvider::new(config(
            "devo+sqlite://vault-guid?datasource=sqlite%3AConnections.db",
        ));
        let password = NativeAddress {
            item: "entry-guid".to_string(),
            field: Some("password".to_string()),
            ..Default::default()
        };

        let error = provider
            .check_writable(Address::Native(&password))
            .unwrap_err();
        assert!(
            error.to_string().contains("sqlitePassphraseRequired"),
            "{error}"
        );

        let mut credentials = ProviderCredentials::new();
        credentials.insert(
            SQLITE_PASSPHRASE.to_string(),
            SecretString::new("workspace passphrase".to_string().into()),
        );
        provider.with_credentials(credentials);
        provider.check_writable(Address::Native(&password)).unwrap();
        assert_eq!(
            provider
                .sqlite_passphrase_from(Some("fallback passphrase".to_string()))
                .unwrap()
                .expose_secret(),
            "workspace passphrase"
        );
    }

    #[test]
    fn sqlite_writes_reject_non_password_fields_before_requesting_a_passphrase() {
        let provider = DevoProvider::new(config(
            "devo+sqlite://vault-guid?datasource=sqlite%3AConnections.db",
        ));
        let address = NativeAddress {
            item: "entry-guid".to_string(),
            field: Some("username".to_string()),
            ..Default::default()
        };

        let error = provider
            .check_writable(Address::Native(&address))
            .unwrap_err();
        assert!(
            error.to_string().contains("sqliteSecretFieldUnsupported"),
            "{error}"
        );
    }

    #[cfg(unix)]
    fn success_status() -> std::process::ExitStatus {
        use std::os::unix::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(0)
    }

    #[cfg(windows)]
    fn success_status() -> std::process::ExitStatus {
        use std::os::windows::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(0)
    }
}
