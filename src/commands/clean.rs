use super::CommonOptions;
use anyhow::Result;
use clap::Args;

/// Deletes local content cache.
#[derive(Args)]
pub struct CleanCommand {
    /// The common command options.
    #[clap(flatten)]
    pub common: CommonOptions,
}

impl CleanCommand {
    /// Executes the command.
    pub async fn exec(self) -> Result<()> {
        let config = self.common.read_config()?;
        let client = self.common.create_client(&config)?;

        println!("removing local content cache...");
        client.remove_content_cache().await?;
        Ok(())
    }
}
