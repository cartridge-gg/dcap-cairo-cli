use clap::{Parser, Subcommand};
use eyre::Result;

mod commands;
use commands::Preprocess;

mod quote;

mod constants;

mod cairo;

#[derive(Debug, Parser)]
struct Cli {
    #[clap(subcommand)]
    command: Subcommands,
}

#[derive(Debug, Subcommand)]
enum Subcommands {
    /// Pre-process test data from `dcap-rs` to be used in `dcap-cairo`.
    Preprocess(Preprocess),
}

fn main() -> Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();

    match cli.command {
        Subcommands::Preprocess(cmd) => cmd.run(),
    }
}
