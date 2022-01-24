use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[clap(name = "cargo")]
#[clap(bin_name = "cargo")]
#[clap(
    setting = clap::AppSettings::DeriveDisplayOrder,
    setting = clap::AppSettings::DontCollapseArgsInUsage
)]
pub enum Command {
    #[clap(name = "msix")]
    #[clap(about, author, version)]
    #[clap(
        setting = clap::AppSettings::DeriveDisplayOrder,
        setting = clap::AppSettings::DontCollapseArgsInUsage,
        setting = clap::AppSettings::ArgsNegateSubcommands,
    )]
    Msix(Cli),
}

#[derive(Debug, Clone, clap::Args)]
pub struct Cli {
    #[clap(flatten)]
    pub manifest: clap_cargo::Manifest,
    #[clap(flatten)]
    pub workspace: clap_cargo::Workspace,
    #[clap(flatten)]
    pub features: clap_cargo::Features,
    #[clap(long)]
    pub release: bool,
    #[clap(long)]
    pub unsigned: bool,
    #[clap(long)]
    pub store_publisher: Option<String>,
    #[clap(long)]
    pub store_name: Option<String>,
    #[clap(long)]
    pub store_publisher_display_name: Option<String>,
    #[clap(subcommand)]
    pub subcommands: Option<MySubcommands>,
}

#[derive(Debug, Clone, Subcommand)]
pub enum MySubcommands {
    Init {},
}
