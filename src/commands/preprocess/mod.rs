use clap::{Parser, Subcommand};
use eyre::Result;

mod quote;
use quote::QuoteCommand;

mod pem;
use pem::PemCommand;

mod include_bytes;
use include_bytes::IncludeBytes;

mod qeidentity;
use qeidentity::QeidentityCommand;

mod tcbinfo;
use tcbinfo::TcbinfoCommand;

#[derive(Debug, Parser)]
pub struct Preprocess {
    #[clap(subcommand)]
    command: Subcommands,
}

#[derive(Debug, Subcommand)]
enum Subcommands {
    /// Pre-process quote to convert cert chain from PEM to DER format.
    Quote(QuoteCommand),
    /// Pre-process PEM-encoded file to convert to DER format in the form of Cairo byte array
    /// definition.
    Pem(PemCommand),
    /// Pre-process any file to be interpreted as binary as defined as Cairo byte array.
    IncludeBytes(IncludeBytes),
    /// Pre-process qeidentity JSON file to convert to Cairo struct definition.
    Qeidentity(QeidentityCommand),
    /// Pre-process tcbinfo JSON file to convert to Cairo struct definition.
    Tcbinfo(TcbinfoCommand),
}

impl Preprocess {
    pub fn run(self) -> Result<()> {
        match self.command {
            Subcommands::Quote(cmd) => cmd.run(),
            Subcommands::Pem(cmd) => cmd.run(),
            Subcommands::IncludeBytes(cmd) => cmd.run(),
            Subcommands::Qeidentity(cmd) => cmd.run(),
            Subcommands::Tcbinfo(cmd) => cmd.run(),
        }
    }
}
