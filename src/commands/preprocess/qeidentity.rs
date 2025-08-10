use std::fmt::Write;
use std::path::PathBuf;

use clap::Parser;
use eyre::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Parser)]
pub struct QeidentityCommand {
    /// Path to the input JSON file.
    #[clap(long)]
    input: PathBuf,
    /// Path to the output Cairo file.
    #[clap(long)]
    output: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct QeIdentityJson {
    enclave_identity: EnclaveIdentityInnerJson,
    signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct EnclaveIdentityInnerJson {
    id: String,
    version: u32,
    issue_date: String,
    next_update: String,
    tcb_evaluation_data_number: u32,
    miscselect: String,
    miscselect_mask: String,
    attributes: String,
    attributes_mask: String,
    mrsigner: String,
    isvprodid: u16,
    tcb_levels: Vec<TcbLevelJson>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TcbLevelJson {
    tcb: TcbJson,
    tcb_date: String,
    tcb_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    advisory_ids: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TcbJson {
    isvsvn: u16,
}

impl QeidentityCommand {
    pub fn run(self) -> Result<()> {
        let json_content = std::fs::read_to_string(&self.input)?;
        let qe_identity: QeIdentityJson = serde_json::from_str(&json_content)?;

        let mut output = String::new();

        // Add imports
        output.push_str("use time::{DateTrait, Month, OffsetDateTimeTrait, TimeTrait};\n");
        output.push_str("use crate::types::enclave_identity::{\n");
        output.push_str(
            "    EnclaveIdentityV2, EnclaveIdentityV2Inner, EnclaveIdentityV2TcbLevel,\n",
        );
        output.push_str("    EnclaveIdentityV2TcbLevelItem,\n");
        output.push_str("};\n\n");

        output.push_str("pub fn data() -> EnclaveIdentityV2 {\n");

        // Parse and generate issue_date
        let issue_date = parse_datetime(&qe_identity.enclave_identity.issue_date)?;
        writeln!(
            &mut output,
            "    // {}",
            qe_identity.enclave_identity.issue_date
        )?;
        output.push_str("    let issue_date = OffsetDateTimeTrait::new_utc(\n");
        writeln!(
            &mut output,
            "        DateTrait::from_calendar_date({}, Month::{}, {}).unwrap(),",
            issue_date.year,
            month_name(issue_date.month),
            issue_date.day
        )?;
        writeln!(
            &mut output,
            "        TimeTrait::from_hms_milli({}, {}, {}, {}).unwrap(),",
            issue_date.hour, issue_date.minute, issue_date.second, issue_date.millisecond
        )?;
        output.push_str("    );\n\n");

        // Parse and generate next_update
        let next_update = parse_datetime(&qe_identity.enclave_identity.next_update)?;
        writeln!(
            &mut output,
            "    // {}",
            qe_identity.enclave_identity.next_update
        )?;
        output.push_str("    let next_update = OffsetDateTimeTrait::new_utc(\n");
        writeln!(
            &mut output,
            "        DateTrait::from_calendar_date({}, Month::{}, {}).unwrap(),",
            next_update.year,
            month_name(next_update.month),
            next_update.day
        )?;
        writeln!(
            &mut output,
            "        TimeTrait::from_hms_milli({}, {}, {}, {}).unwrap(),",
            next_update.hour, next_update.minute, next_update.second, next_update.millisecond
        )?;
        output.push_str("    );\n\n");

        // Parse and generate tcb_date if there are tcb_levels
        if !qe_identity.enclave_identity.tcb_levels.is_empty() {
            let tcb_date = parse_datetime(&qe_identity.enclave_identity.tcb_levels[0].tcb_date)?;
            writeln!(
                &mut output,
                "    // {}",
                qe_identity.enclave_identity.tcb_levels[0].tcb_date
            )?;
            output.push_str("    let tcb_date = OffsetDateTimeTrait::new_utc(\n");
            writeln!(
                &mut output,
                "        DateTrait::from_calendar_date({}, Month::{}, {}).unwrap(),",
                tcb_date.year,
                month_name(tcb_date.month),
                tcb_date.day
            )?;
            writeln!(
                &mut output,
                "        TimeTrait::from_hms_milli({}, {}, {}, {}).unwrap(),",
                tcb_date.hour, tcb_date.minute, tcb_date.second, tcb_date.millisecond
            )?;
            output.push_str("    );\n\n");
        }

        // Start generating the struct
        output.push_str("    EnclaveIdentityV2 {\n");
        output.push_str("        enclave_identity: EnclaveIdentityV2Inner {\n");
        writeln!(
            &mut output,
            "            id: \"{}\",",
            qe_identity.enclave_identity.id
        )?;
        writeln!(
            &mut output,
            "            version: {},",
            qe_identity.enclave_identity.version
        )?;
        output.push_str("            issue_date,\n");
        output.push_str("            next_update,\n");
        writeln!(
            &mut output,
            "            tcb_evaluation_data_number: {},",
            qe_identity.enclave_identity.tcb_evaluation_data_number
        )?;

        // miscselect
        let miscselect_bytes = hex::decode(&qe_identity.enclave_identity.miscselect)?;
        output.push_str("            miscselect: array![");
        output.push_str(&format_bytes_inline(&miscselect_bytes));
        output.push_str("].span(),\n");

        // miscselect_mask
        let miscselect_mask_bytes = hex::decode(&qe_identity.enclave_identity.miscselect_mask)?;
        output.push_str("            miscselect_mask: array![");
        output.push_str(&format_bytes_from_hex_string(
            &qe_identity.enclave_identity.miscselect_mask,
            &miscselect_mask_bytes,
            false,
        ));
        output.push_str("].span(),\n");

        // attributes
        let attributes_bytes = hex::decode(&qe_identity.enclave_identity.attributes)?;
        output.push_str("            attributes: array![");
        output.push_str(&format_bytes_multiline(
            &attributes_bytes,
            16,
            "                ",
        ));
        output.push_str("].span(),\n");

        // attributes_mask
        let attributes_mask_bytes = hex::decode(&qe_identity.enclave_identity.attributes_mask)?;
        output.push_str("            attributes_mask: array![");
        output.push_str(&format_bytes_from_hex_string_multiline(
            &qe_identity.enclave_identity.attributes_mask,
            &attributes_mask_bytes,
            16,
            "                ",
        ));
        output.push_str("].span(),\n");

        // mrsigner
        let mrsigner_bytes = hex::decode(&qe_identity.enclave_identity.mrsigner)?;
        output.push_str("            mrsigner: array![");
        output.push_str(&format_bytes_from_hex_string_multiline(
            &qe_identity.enclave_identity.mrsigner,
            &mrsigner_bytes,
            16,
            "                ",
        ));
        output.push_str("].span(),\n");

        writeln!(
            &mut output,
            "            isvprodid: {},",
            qe_identity.enclave_identity.isvprodid
        )?;

        // tcb_levels
        output.push_str("            tcb_levels: array![\n");
        for tcb_level in &qe_identity.enclave_identity.tcb_levels {
            output.push_str("                EnclaveIdentityV2TcbLevelItem {\n");
            writeln!(
                &mut output,
                "                    tcb: EnclaveIdentityV2TcbLevel {{ isvsvn: {} }},",
                tcb_level.tcb.isvsvn
            )?;
            output.push_str("                    tcb_date,\n");
            writeln!(
                &mut output,
                "                    tcb_status: \"{}\",",
                tcb_level.tcb_status
            )?;

            if let Some(advisory_ids) = &tcb_level.advisory_ids {
                output.push_str("                    advisory_ids: Option::Some(array![");
                for (i, id) in advisory_ids.iter().enumerate() {
                    if i > 0 {
                        output.push_str(", ");
                    }
                    write!(&mut output, "\"{}\"", id)?;
                }
                output.push_str("].span()),\n");
            } else {
                output.push_str("                    advisory_ids: Option::None,\n");
            }
            output.push_str("                },\n");
        }
        output.push_str("            ].span(),\n");

        output.push_str("        },\n");

        // signature
        let signature_bytes = hex::decode(&qe_identity.signature)?;
        output.push_str("        signature: array![");
        output.push_str(&format_bytes_from_hex_string_multiline(
            &qe_identity.signature,
            &signature_bytes,
            16,
            "            ",
        ));
        output.push_str("].span(),\n");

        output.push_str("    }\n");
        output.push_str("}\n");

        std::fs::write(&self.output, output)?;

        Ok(())
    }
}

fn format_bytes_inline(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("0x{:02X}", b))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_bytes_multiline(bytes: &[u8], per_line: usize, indent: &str) -> String {
    let mut result = String::new();
    for (i, chunk) in bytes.chunks(per_line).enumerate() {
        if i > 0 {
            result.push(',');
        }
        result.push('\n');
        result.push_str(indent);
        result.push_str(
            &chunk
                .iter()
                .map(|b| format!("0x{:02x}", b))
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    result.push_str(",\n");
    result.push_str(&indent[..indent.len() - 4]);
    result
}

fn format_bytes_from_hex_string(hex_str: &str, bytes: &[u8], multiline: bool) -> String {
    let is_uppercase = hex_str.chars().any(|c| c.is_ascii_uppercase());

    if multiline {
        format_bytes_from_hex_string_multiline_impl(bytes, 16, "", is_uppercase)
    } else {
        bytes
            .iter()
            .map(|b| {
                if is_uppercase {
                    format!("0x{:02X}", b)
                } else {
                    format!("0x{:02x}", b)
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn format_bytes_from_hex_string_multiline(
    hex_str: &str,
    bytes: &[u8],
    per_line: usize,
    indent: &str,
) -> String {
    let is_uppercase = hex_str.chars().any(|c| c.is_ascii_uppercase());
    format_bytes_from_hex_string_multiline_impl(bytes, per_line, indent, is_uppercase)
}

fn format_bytes_from_hex_string_multiline_impl(
    bytes: &[u8],
    per_line: usize,
    indent: &str,
    uppercase: bool,
) -> String {
    let mut result = String::new();
    for (i, chunk) in bytes.chunks(per_line).enumerate() {
        if i > 0 {
            result.push(',');
        }
        result.push('\n');
        result.push_str(indent);
        result.push_str(
            &chunk
                .iter()
                .map(|b| {
                    if uppercase {
                        format!("0x{:02X}", b)
                    } else {
                        format!("0x{:02x}", b)
                    }
                })
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    result.push_str(",\n");
    result.push_str(&indent[..indent.len() - 4]);
    result
}

struct DateTime {
    year: i32,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    millisecond: u16,
}

fn parse_datetime(datetime_str: &str) -> Result<DateTime> {
    // Parse ISO 8601 datetime string like "2025-02-13T03:39:00Z"
    let datetime_str = datetime_str.trim_end_matches('Z');
    let parts: Vec<&str> = datetime_str.split('T').collect();
    if parts.len() != 2 {
        return Err(eyre::eyre!("Invalid datetime format"));
    }

    let date_parts: Vec<&str> = parts[0].split('-').collect();
    if date_parts.len() != 3 {
        return Err(eyre::eyre!("Invalid date format"));
    }

    let time_parts: Vec<&str> = parts[1].split(':').collect();
    if time_parts.len() != 3 {
        return Err(eyre::eyre!("Invalid time format"));
    }

    Ok(DateTime {
        year: date_parts[0].parse()?,
        month: date_parts[1].parse()?,
        day: date_parts[2].parse()?,
        hour: time_parts[0].parse()?,
        minute: time_parts[1].parse()?,
        second: time_parts[2].parse()?,
        millisecond: 0,
    })
}

fn month_name(month: u8) -> &'static str {
    match month {
        1 => "January",
        2 => "February",
        3 => "March",
        4 => "April",
        5 => "May",
        6 => "June",
        7 => "July",
        8 => "August",
        9 => "September",
        10 => "October",
        11 => "November",
        12 => "December",
        _ => panic!("Invalid month"),
    }
}
