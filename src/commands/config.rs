use super::NamespaceMapping;
use anyhow::{bail, Context, Result};
use clap::Args;
use std::path::PathBuf;
use warg_client::{Config, RegistryUrl};

/// Creates a new warg configuration file.
#[derive(Args)]
pub struct ConfigCommand {
    /// The default registry URL to use.
    #[clap(long, value_name = "URL")]
    pub registry: Option<String>,

    /// The default monitor URL to use.
    #[clap(long, value_name = "MONITOR")]
    pub monitor: Option<String>,

    /// The path to the registries directory to use.
    #[clap(long, value_name = "REGISTRIES")]
    pub registries_dir: Option<PathBuf>,

    /// The path to the content directory to use.
    #[clap(long, value_name = "CONTENT")]
    pub content_dir: Option<PathBuf>,

    /// Overwrite the existing configuration file.
    #[clap(long)]
    pub overwrite: bool,

    /// The path to the configuration file to create.
    ///
    /// If not specified, the default of `$CONFIG_DIR/warg/config.json` is used.
    #[clap(value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// The namespaces to map another namespace and optionally another registry.
    #[clap(long = "namespace", value_delimiter = ',')]
    pub namespace_map: Vec<NamespaceMapping>,

    /// The registries to proxy to through the default registry server.
    #[clap(long = "proxy", value_delimiter = ',')]
    pub proxy_registries: Vec<RegistryUrl>,

    /// Proxy all registries through the default registry server.
    #[clap(long = "proxy-all")]
    pub proxy_all: bool,
}

impl ConfigCommand {
    /// Executes the command.
    pub async fn exec(self) -> Result<()> {
        let path = self
            .path
            .map(Ok)
            .unwrap_or_else(Config::default_config_path)?;

        if !self.overwrite && path.is_file() {
            bail!(
                "configuration file `{path}` already exists; use `--overwrite` to overwrite it",
                path = path.display()
            );
        }

        let default_url = self
            .registry
            .map(RegistryUrl::new)
            .transpose()?
            .map(|u| u.to_string());

        let default_monitor_url = self
            .monitor
            .map(RegistryUrl::new)
            .transpose()?
            .map(|u| u.to_string());

        if default_url == default_monitor_url {
            println!("WARNING: registry and monitor should be independent services");
        }

        // The paths specified on the command line are relative to the current
        // directory.
        //
        // `write_to_file` will handle normalizing the paths to be relative to
        // the configuration file's directory.
        let cwd = std::env::current_dir().context("failed to determine current directory")?;
        let config = Config {
            default_url,
            default_monitor_url,
            registries_dir: self.registries_dir.map(|p| cwd.join(p)),
            content_dir: self.content_dir.map(|p| cwd.join(p)),
        };

        config.write_to_file(&path)?;

        println!(
            "created warg configuration file `{path}`",
            path = path.display(),
        );

        Ok(())
    }
}
