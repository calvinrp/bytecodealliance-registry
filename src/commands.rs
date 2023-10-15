//! Commands for the `warg` tool.

use anyhow::{bail, Context, Result};
use clap::Args;
use std::path::PathBuf;
use std::str::FromStr;
use warg_client::RegistryUrl;
use warg_client::{ClientError, Config, FileSystemClient, StorageLockResult};
use warg_crypto::signing::PrivateKey;
use warg_protocol::registry::PackageId;
use wasmparser::names::KebabStr;

mod clear;
mod config;
mod download;
mod info;
mod key;
mod publish;
mod reset;
mod run;
mod update;

use crate::keyring::get_signing_key;

pub use self::clear::*;
pub use self::config::*;
pub use self::download::*;
pub use self::info::*;
pub use self::key::*;
pub use self::publish::*;
pub use self::reset::*;
pub use self::run::*;
pub use self::update::*;

/// Common options for commands.
#[derive(Args)]
pub struct CommonOptions {
    /// The URL of the registry to use.
    #[clap(long, value_name = "URL")]
    pub registry: Option<String>,
    /// The URL of the monitor to use.
    #[clap(long, value_name = "MONITOR")]
    pub monitor: Option<String>,
    /// The name to use for the signing key.
    #[clap(long, short, value_name = "KEY_NAME", default_value = "default")]
    pub key_name: String,
    /// The path to the signing key file.
    #[clap(long, value_name = "KEY_FILE", env = "WARG_SIGNING_KEY_FILE")]
    pub key_file: Option<PathBuf>,
    /// The path to the client configuration file to use.
    ///
    /// If not specified, the following locations are searched in order: `./warg-config.json`, `<system-config-dir>/warg/config.json`.
    ///
    /// If no configuration file is found, a default configuration is used.
    #[clap(long, value_name = "CONFIG")]
    pub config: Option<PathBuf>,
}

impl CommonOptions {
    /// Reads the client configuration.
    ///
    /// If a client configuration was not specified, a default configuration is returned.
    pub fn read_config(&self) -> Result<Config> {
        Ok(self
            .config
            .as_ref()
            .map_or_else(Config::from_default_file, |p| {
                Config::from_file(p).map(Some)
            })?
            .unwrap_or_default())
    }

    /// Creates the warg client to use.
    pub fn create_client(&self, config: &Config) -> Result<FileSystemClient, ClientError> {
        match FileSystemClient::try_new_with_config(
            self.registry.as_deref(),
            self.monitor.as_deref(),
            config,
        )? {
            StorageLockResult::Acquired(client) => Ok(client),
            StorageLockResult::NotAcquired(path) => {
                println!(
                    "blocking on lock for directory `{path}`...",
                    path = path.display()
                );

                FileSystemClient::new_with_config(
                    self.registry.as_deref(),
                    self.monitor.as_deref(),
                    config,
                )
            }
        }
    }

    /// Gets the signing key for the given registry URL.
    pub fn signing_key(&self, registry_url: &RegistryUrl) -> Result<PrivateKey> {
        if let Some(file) = &self.key_file {
            let key_str = std::fs::read_to_string(file)
                .with_context(|| format!("failed to read key from {file:?}"))?
                .trim_end()
                .to_string();
            PrivateKey::decode(key_str)
                .with_context(|| format!("failed to parse key from {file:?}"))
        } else {
            get_signing_key(registry_url, &self.key_name)
        }
    }
}

/// Mapping namespace from a source registry.
#[derive(Clone, Debug)]
pub struct NamespaceMapping {
    /// Source registry's namespace
    source_namespace: String,
    /// Source registry's URL
    source_registry: RegistryUrl,
    /// If mapping to a different namespace, the target registry's namespace
    target_namespace: Option<String>,
}

impl NamespaceMapping {
    /// Creates a new namespace mapping from a source registry.
    pub fn new(s: impl Into<String>) -> anyhow::Result<Self> {
        let s = s.into();

        if let Some(delim) = s.find('@') {
            let source_namespace = &s[..delim];
            let mut source_registry = &s[delim + 1..];

            let target_namespace = if let Some(delim) = source_registry.rfind('=') {
                let target_namespace = &source_registry[delim + 1..];
                if !PackageId::is_valid_namespace(target_namespace) {
                    bail!("invalid namespace mapping `{s}`: expected format is `<namespace>@<url>=<namespace>`");
                }
                source_registry = &source_registry[..delim];
                Some(target_namespace)
            } else {
                None
            };

            let source_registry = RegistryUrl::new(source_registry)?;

            // Validate the namespace is valid kebab strings
            if PackageId::is_valid_namespace(source_namespace) {
                return Ok(Self {
                    source_namespace: source_namespace.to_string(),
                    source_registry,
                    target_namespace: target_namespace.map(|s| s.to_string()),
                });
            }
        }

        bail!("invalid namespace mapping `{s}`: expected format is `<namespace>@<url>=<namespace>`")
    }
}

impl FromStr for NamespaceMapping {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}
