use std::io::{Result, Write};

pub fn write_cairo_bytes<W>(mut writer: W, bytes: &[u8]) -> Result<()>
where
    W: Write,
{
    writeln!(writer, "pub const DATA: [u8; {}] = [", bytes.len())?;

    for chunk in bytes.chunks(20) {
        write!(writer, "   ")?;

        for byte in chunk {
            write!(writer, " {byte:#02x},")?;
        }

        writeln!(writer,)?;
    }

    writeln!(writer, "];")?;

    Ok(())
}
