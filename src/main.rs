#[macro_use]
extern crate yaserde_derive;

pub mod packagelayout;
pub mod args;
pub mod command_default;
pub mod command_init;

use clap::Parser;
use anyhow::Result;
use crate::command_init::run_command_init;
use crate::command_default::run_command_default;
use log::info;
use windows::Win32::System::Com::CoInitialize;

fn main() -> Result<()> {
    human_panic::setup_panic!(human_panic::Metadata {
        name: "cargo-msix".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        authors: "".into(),
        homepage: "https://github.com/davidanthoff/cargo-msix".into(),
    });

    let env = env_logger::Env::new();
    env_logger::init_from_env(env);

    info!("Parsing command line arguments");
    let args::Command::Msix(ref args) = args::Command::parse();

    info!("Initializig COM");
    unsafe { CoInitialize(std::ptr::null_mut()) }.unwrap();

    info!("Reading Cargo.toml");
    let mut metadata_cmd = args.manifest.metadata();
    args.features.forward_metadata(&mut metadata_cmd);
    let metadata = metadata_cmd.exec()?;

    info!("Branching for specific command");
    match args.subcommands {
        Some(_) => run_command_init(&args, &metadata)?,
        None => run_command_default(&args, &metadata)?
    };

    Ok(())
}
