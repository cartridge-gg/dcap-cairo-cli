use std::path::PathBuf;

use clap::Parser;
use eyre::Result;

use crate::cairo::write_cairo_bytes;

#[derive(Debug, Parser)]
pub struct IncludeBytes {
    /// Path to the input binary file.
    #[clap(long)]
    input: PathBuf,
    /// Path to the output Cairo file.
    #[clap(long)]
    output: PathBuf,
}

impl IncludeBytes {
    pub fn run(self) -> Result<()> {
        let raw_bytes = std::fs::read(&self.input)?;

        let mut output_file = std::fs::File::create(&self.output)?;
        write_cairo_bytes(&mut output_file, &raw_bytes)?;

        Ok(())
    }
}
