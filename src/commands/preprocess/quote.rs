use std::path::PathBuf;

use clap::Parser;
use eyre::Result;
use x509_parser::pem::Pem;

use crate::quote::{CertData, Quote};

#[derive(Debug, Parser)]
pub struct QuoteCommand {
    /// Path to the quote file.
    #[clap(long)]
    input: PathBuf,
    /// Path to the modified quote file.
    #[clap(long)]
    output: PathBuf,
}

impl QuoteCommand {
    pub fn run(self) -> Result<()> {
        let raw_bytes = std::fs::read(&self.input)?;
        let mut quote = Quote::from_bytes(&raw_bytes)?;

        // Sanity check
        if raw_bytes != quote.to_bytes() {
            eyre::bail!("Quote serde roundtrip failed");
        }

        match &mut quote.signature.cert_data {
            CertData::QeReportCertData(qe_report) => match qe_report.qe_cert_data.get_mut() {
                CertData::Certificates(payload) => {
                    let mut transformed = vec![];

                    for pem in Pem::iter_from_buffer(payload) {
                        let mut pem = pem?;

                        if pem.label != "CERTIFICATE" {
                            eyre::bail!("Unexpected PEM label: {}", pem.label);
                        }

                        transformed.append(&mut pem.contents);
                    }

                    payload.clear();
                    payload.append(&mut transformed);
                }
                _ => eyre::bail!("Unexpected cert data type"),
            },
            _ => eyre::bail!("Unexpected cert data type"),
        }

        std::fs::write(self.output, quote.to_bytes())?;

        Ok(())
    }
}
