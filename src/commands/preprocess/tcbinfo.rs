use std::path::PathBuf;

use clap::Parser;
use eyre::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Parser)]
pub struct TcbinfoCommand {
    /// Path to the input JSON file.
    #[clap(long)]
    input: PathBuf,
    /// Path to the output Cairo file.
    #[clap(long)]
    output: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TcbInfoJson {
    tcb_info: TcbInfoInnerJson,
    signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TcbInfoInnerJson {
    id: String,
    version: u32,
    issue_date: String,
    next_update: String,
    fmspc: String,
    pce_id: String,
    tcb_type: u8,
    tcb_evaluation_data_number: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    tdx_module: Option<TdxModuleJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tdx_module_identities: Option<Vec<TdxModuleIdentitiesJson>>,
    tcb_levels: Vec<TcbLevelJson>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TdxModuleJson {
    mrsigner: String,
    attributes: String,
    attributes_mask: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TdxModuleIdentitiesJson {
    id: String,
    mrsigner: String,
    attributes: String,
    attributes_mask: String,
    tcb_levels: Vec<TdxModuleIdentitiesTcbLevelJson>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TdxModuleIdentitiesTcbLevelJson {
    tcb: TdxModuleIdentitiesTcbJson,
    tcb_date: String,
    tcb_status: String,
    #[serde(rename = "advisoryIDs", skip_serializing_if = "Option::is_none")]
    advisory_ids: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TdxModuleIdentitiesTcbJson {
    isvsvn: u8,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TcbLevelJson {
    tcb: TcbJson,
    tcb_date: String,
    tcb_status: String,
    #[serde(rename = "advisoryIDs", skip_serializing_if = "Option::is_none")]
    advisory_ids: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TcbJson {
    sgxtcbcomponents: Vec<TcbComponentJson>,
    pcesvn: u16,
    tdxtcbcomponents: Vec<TcbComponentJson>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TcbComponentJson {
    svn: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    type_: Option<String>,
}

impl TcbinfoCommand {
    pub fn run(self) -> Result<()> {
        let json_content = std::fs::read_to_string(&self.input)?;
        let tcb_info: TcbInfoJson = serde_json::from_str(&json_content)?;

        let mut output = String::new();

        // Add imports
        output.push_str("use time::{DateTrait, Month, OffsetDateTimeTrait, TimeTrait};\n");
        output.push_str("use crate::types::tcbinfo::{\n");
        output.push_str("    TcbComponent, TcbInfoV3, TcbInfoV3Inner, TcbInfoV3TcbLevel, TcbInfoV3TcbLevelItem, TdxModule,\n");
        output.push_str("    TdxModuleIdentities, TdxModuleIdentitiesTcbLevel, TdxModuleIdentitiesTcbLevelItem,\n");
        output.push_str("};\n\n");

        output.push_str("pub fn data() -> TcbInfoV3 {\n");

        // Parse and generate issue_date
        let issue_date = parse_datetime(&tcb_info.tcb_info.issue_date)?;
        output.push_str(&format!("    // {}\n", tcb_info.tcb_info.issue_date));
        output.push_str("    let issue_date = OffsetDateTimeTrait::new_utc(\n");
        output.push_str(&format!(
            "        DateTrait::from_calendar_date({}, Month::{}, {}).unwrap(),\n",
            issue_date.year,
            month_name(issue_date.month),
            issue_date.day
        ));
        output.push_str(&format!(
            "        TimeTrait::from_hms_milli({}, {}, {}, {}).unwrap(),\n",
            issue_date.hour, issue_date.minute, issue_date.second, issue_date.millisecond
        ));
        output.push_str("    );\n\n");

        // Parse and generate next_update
        let next_update = parse_datetime(&tcb_info.tcb_info.next_update)?;
        output.push_str(&format!("    // {}\n", tcb_info.tcb_info.next_update));
        output.push_str("    let next_update = OffsetDateTimeTrait::new_utc(\n");
        output.push_str(&format!(
            "        DateTrait::from_calendar_date({}, Month::{}, {}).unwrap(),\n",
            next_update.year,
            month_name(next_update.month),
            next_update.day
        ));
        output.push_str(&format!(
            "        TimeTrait::from_hms_milli({}, {}, {}, {}).unwrap(),\n",
            next_update.hour, next_update.minute, next_update.second, next_update.millisecond
        ));
        output.push_str("    );\n\n");

        // Collect unique tcb_dates
        let mut unique_dates = std::collections::HashSet::new();
        for tcb_level in &tcb_info.tcb_info.tcb_levels {
            unique_dates.insert(&tcb_level.tcb_date);
        }
        if let Some(tdx_module_identities) = &tcb_info.tcb_info.tdx_module_identities {
            for identity in tdx_module_identities {
                for tcb_level in &identity.tcb_levels {
                    unique_dates.insert(&tcb_level.tcb_date);
                }
            }
        }

        // Sort dates and generate variables
        let mut sorted_dates: Vec<_> = unique_dates.into_iter().collect();
        sorted_dates.sort();
        sorted_dates.reverse(); // Most recent first

        for date_str in &sorted_dates {
            let date = parse_datetime(date_str)?;
            let var_name = format!("tcb_date_{}_{:02}_{:02}", date.year, date.month, date.day);
            output.push_str(&format!("    // {}\n", date_str));
            output.push_str(&format!(
                "    let {} = OffsetDateTimeTrait::new_utc(\n",
                var_name
            ));
            output.push_str(&format!(
                "        DateTrait::from_calendar_date({}, Month::{}, {}).unwrap(),\n",
                date.year,
                month_name(date.month),
                date.day
            ));
            output.push_str(&format!(
                "        TimeTrait::from_hms_milli({}, {}, {}, {}).unwrap(),\n",
                date.hour, date.minute, date.second, date.millisecond
            ));
            output.push_str("    );\n\n");
        }

        // Start generating the struct
        output.push_str("    TcbInfoV3 {\n");
        output.push_str("        tcb_info: TcbInfoV3Inner {\n");
        output.push_str(&format!("            id: \"{}\",\n", tcb_info.tcb_info.id));
        output.push_str(&format!(
            "            version: {},\n",
            tcb_info.tcb_info.version
        ));
        output.push_str("            issue_date,\n");
        output.push_str("            next_update,\n");

        // fmspc
        let fmspc_bytes = hex::decode(&tcb_info.tcb_info.fmspc)?;
        output.push_str("            fmspc: [");
        for (i, byte) in fmspc_bytes.iter().enumerate() {
            if i > 0 {
                output.push_str(", ");
            }
            output.push_str(&format!("0x{:02x}", byte));
        }
        output.push_str("].span(),\n");

        // pce_id
        let pce_id_bytes = hex::decode(&tcb_info.tcb_info.pce_id)?;
        output.push_str("            pce_id: [");
        for (i, byte) in pce_id_bytes.iter().enumerate() {
            if i > 0 {
                output.push_str(", ");
            }
            output.push_str(&format!("0x{:02x}", byte));
        }
        output.push_str("].span(),\n");

        output.push_str(&format!(
            "            tcb_type: {},\n",
            tcb_info.tcb_info.tcb_type
        ));
        output.push_str(&format!(
            "            tcb_evaluation_data_number: {},\n",
            tcb_info.tcb_info.tcb_evaluation_data_number
        ));

        // tdx_module
        if let Some(tdx_module) = &tcb_info.tcb_info.tdx_module {
            output.push_str("            tdx_module: Option::Some(\n");
            output.push_str("                TdxModule {\n");

            // mrsigner
            let mrsigner_bytes = hex::decode(&tdx_module.mrsigner)?;
            output.push_str("                    mrsigner: array![\n");
            for (i, chunk) in mrsigner_bytes.chunks(12).enumerate() {
                if i > 0 {
                    output.push_str(",\n");
                }
                output.push_str("                        ");
                for (j, byte) in chunk.iter().enumerate() {
                    if j > 0 {
                        output.push_str(", ");
                    }
                    output.push_str(&format!("0x{:02x}", byte));
                }
            }
            output.push_str(",\n                    ]\n                        .span(),\n");

            // attributes
            let attributes_bytes = hex::decode(&tdx_module.attributes)?;
            output.push_str("                    attributes: array![");
            for (i, byte) in attributes_bytes.iter().enumerate() {
                if i > 0 {
                    output.push_str(", ");
                }
                output.push_str(&format!("0x{:02x}", byte));
            }
            output.push_str("].span(),\n");

            // attributes_mask
            let attributes_mask_bytes = hex::decode(&tdx_module.attributes_mask)?;
            output.push_str("                    attributes_mask: array![");
            for (i, byte) in attributes_mask_bytes.iter().enumerate() {
                if i > 0 {
                    output.push_str(", ");
                }
                let is_uppercase = tdx_module
                    .attributes_mask
                    .chars()
                    .any(|c| c.is_ascii_uppercase());
                if is_uppercase {
                    output.push_str(&format!("0x{:02X}", byte));
                } else {
                    output.push_str(&format!("0x{:02x}", byte));
                }
            }
            output.push_str("].span(),\n");

            output.push_str("                },\n");
            output.push_str("            ),\n");
        } else {
            output.push_str("            tdx_module: Option::None,\n");
        }

        // tdx_module_identities
        if let Some(identities) = &tcb_info.tcb_info.tdx_module_identities {
            output.push_str("            tdx_module_identities: Option::Some(\n");
            output.push_str("                array![\n");

            for identity in identities {
                output.push_str("                    TdxModuleIdentities {\n");
                output.push_str(&format!(
                    "                        id: \"{}\",\n",
                    identity.id
                ));

                // mrsigner
                let mrsigner_bytes = hex::decode(&identity.mrsigner)?;
                output.push_str("                        mrsigner: array![\n");
                for (i, chunk) in mrsigner_bytes.chunks(12).enumerate() {
                    if i > 0 {
                        output.push_str(",\n");
                    }
                    output.push_str("                            ");
                    for (j, byte) in chunk.iter().enumerate() {
                        if j > 0 {
                            output.push_str(", ");
                        }
                        output.push_str(&format!("0x{:02x}", byte));
                    }
                }
                output.push_str(
                    ",\n                        ]\n                            .span(),\n",
                );

                // attributes
                let attributes_bytes = hex::decode(&identity.attributes)?;
                output.push_str("                        attributes: array![");
                for (i, byte) in attributes_bytes.iter().enumerate() {
                    if i > 0 {
                        output.push_str(", ");
                    }
                    output.push_str(&format!("0x{:02x}", byte));
                }
                output.push_str("].span(),\n");

                // attributes_mask
                let attributes_mask_bytes = hex::decode(&identity.attributes_mask)?;
                output.push_str("                        attributes_mask: array![");
                for (i, byte) in attributes_mask_bytes.iter().enumerate() {
                    if i > 0 {
                        output.push_str(", ");
                    }
                    let is_uppercase = identity
                        .attributes_mask
                        .chars()
                        .any(|c| c.is_ascii_uppercase());
                    if is_uppercase {
                        output.push_str(&format!("0x{:02X}", byte));
                    } else {
                        output.push_str(&format!("0x{:02x}", byte));
                    }
                }
                output.push_str("]\n                            .span(),\n");

                // tcb_levels
                output.push_str("                        tcb_levels: array![\n");
                for tcb_level in &identity.tcb_levels {
                    output.push_str(
                        "                            TdxModuleIdentitiesTcbLevelItem {\n",
                    );
                    output.push_str(&format!("                                tcb: TdxModuleIdentitiesTcbLevel {{ isvsvn: {} }},\n", tcb_level.tcb.isvsvn));

                    let date = parse_datetime(&tcb_level.tcb_date)?;
                    let var_name =
                        format!("tcb_date_{}_{:02}_{:02}", date.year, date.month, date.day);
                    output.push_str(&format!(
                        "                                tcb_date: {},\n",
                        var_name
                    ));

                    output.push_str(&format!(
                        "                                tcb_status: \"{}\",\n",
                        tcb_level.tcb_status
                    ));

                    if let Some(advisory_ids) = &tcb_level.advisory_ids {
                        output.push_str(
                            "                                advisory_ids: Option::Some(array![",
                        );
                        for (i, id) in advisory_ids.iter().enumerate() {
                            if i > 0 {
                                output.push_str(", ");
                            }
                            output.push_str(&format!("\"{}\"", id));
                        }
                        output.push_str("].span()),\n");
                    } else {
                        output.push_str(
                            "                                advisory_ids: Option::None,\n",
                        );
                    }

                    output.push_str("                            },\n");
                }
                output.push_str("                        ],\n");

                output.push_str("                    },\n");
            }

            output.push_str("                ],\n");
            output.push_str("            ),\n");
        } else {
            output.push_str("            tdx_module_identities: Option::None,\n");
        }

        // tcb_levels
        output.push_str("            tcb_levels: array![\n");
        for tcb_level in &tcb_info.tcb_info.tcb_levels {
            output.push_str("                TcbInfoV3TcbLevelItem {\n");
            output.push_str("                    tcb: TcbInfoV3TcbLevel {\n");

            // sgxtcbcomponents
            output.push_str("                        sgxtcbcomponents: array![\n");
            for component in &tcb_level.tcb.sgxtcbcomponents {
                output.push_str("                            TcbComponent {\n");
                output.push_str(&format!(
                    "                                svn: {},\n",
                    component.svn
                ));

                if let Some(category) = &component.category {
                    output.push_str(&format!(
                        "                                category: Option::Some(\"{}\"),\n",
                        category
                    ));
                } else {
                    output.push_str("                                category: Option::None,\n");
                }

                if let Some(type_) = &component.type_ {
                    output.push_str(&format!(
                        "                                type_: Option::Some(\"{}\"),\n",
                        type_
                    ));
                } else {
                    output.push_str("                                type_: Option::None,\n");
                }

                output.push_str("                            },\n");
            }
            output.push_str("                        ],\n");

            output.push_str(&format!(
                "                        pcesvn: {},\n",
                tcb_level.tcb.pcesvn
            ));

            // tdxtcbcomponents
            output.push_str("                        tdxtcbcomponents: Option::Some(\n");
            output.push_str("                            array![\n");
            for component in &tcb_level.tcb.tdxtcbcomponents {
                output.push_str("                                TcbComponent {\n");
                output.push_str(&format!(
                    "                                    svn: {},\n",
                    component.svn
                ));

                if let Some(category) = &component.category {
                    output.push_str(&format!(
                        "                                    category: Option::Some(\"{}\"),\n",
                        category
                    ));
                } else {
                    output
                        .push_str("                                    category: Option::None,\n");
                }

                if let Some(type_) = &component.type_ {
                    output.push_str(&format!(
                        "                                    type_: Option::Some(\"{}\"),\n",
                        type_
                    ));
                } else {
                    output.push_str("                                    type_: Option::None,\n");
                }

                output.push_str("                                },\n");
            }
            output.push_str("                            ],\n");
            output.push_str("                        ),\n");

            output.push_str("                    },\n");

            let date = parse_datetime(&tcb_level.tcb_date)?;
            let var_name = format!("tcb_date_{}_{:02}_{:02}", date.year, date.month, date.day);
            output.push_str(&format!("                    tcb_date: {},\n", var_name));

            output.push_str(&format!(
                "                    tcb_status: \"{}\",\n",
                tcb_level.tcb_status
            ));

            if let Some(advisory_ids) = &tcb_level.advisory_ids {
                output.push_str("                    advisory_ids: Option::Some(array![");
                for (i, id) in advisory_ids.iter().enumerate() {
                    if i > 0 {
                        output.push_str(", ");
                    }
                    output.push_str(&format!("\"{}\"", id));
                }
                output.push_str("].span()),\n");
            } else {
                output.push_str("                    advisory_ids: Option::None,\n");
            }

            output.push_str("                },\n");
        }
        output.push_str("            ],\n");

        output.push_str("        },\n");

        // signature
        let signature_bytes = hex::decode(&tcb_info.signature)?;
        output.push_str("        signature: array![");
        for (i, chunk) in signature_bytes.chunks(16).enumerate() {
            if i > 0 {
                output.push(',');
            }
            output.push_str("\n            ");
            for (j, byte) in chunk.iter().enumerate() {
                if j > 0 {
                    output.push_str(", ");
                }
                output.push_str(&format!("0x{:02x}", byte));
            }
        }
        output.push_str(",\n        ].span(),\n");

        output.push_str("    }\n");
        output.push_str("}\n");

        std::fs::write(&self.output, output)?;

        Ok(())
    }
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
