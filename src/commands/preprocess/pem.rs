use std::path::PathBuf;

use clap::Parser;
use eyre::Result;
use x509_parser::pem::Pem;

use crate::cairo::write_cairo_bytes;

#[derive(Debug, Parser)]
pub struct PemCommand {
    /// Path to the PEM file.
    #[clap(long)]
    input: PathBuf,
    /// Path to the output Cairo file.
    #[clap(long)]
    output: PathBuf,
}

impl PemCommand {
    pub fn run(self) -> Result<()> {
        let raw_bytes = std::fs::read(&self.input)?;
        let mut pem_iter = Pem::iter_from_buffer(&raw_bytes);
        let pem = match pem_iter.next() {
            Some(Ok(pem)) => pem,
            Some(Err(err)) => eyre::bail!("Failed to parse PEM file: {err}"),
            None => eyre::bail!("Empty PEM file"),
        };

        // Cert-chain not supported for now
        if pem_iter.next().is_some() {
            eyre::bail!("This command can only be used for a single PEM-certificate");
        }

        let mut output_file = std::fs::File::create(&self.output)?;
        write_cairo_bytes(&mut output_file, &pem.contents)?;

        Ok(())
    }
}
