use anyhow::{Context, Result};
use either::Either;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use rusqlite::{params, Connection};
use sbpf_common::opcode::Opcode;
use sbpf_disassembler::program::Program;
use solana_client::rpc_client::RpcClient;
use solana_client::rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig};
use solana_client::rpc_filter::{Memcmp, RpcFilterType};
use solana_program::pubkey::Pubkey;
use solana_commitment_config::CommitmentConfig;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Loader program IDs and their versions
const BPF_LOADER_V1: &str = "BPFLoader1111111111111111111111111111111111";
const BPF_LOADER_V2: &str = "BPFLoader2111111111111111111111111111111111";
const BPF_LOADER_UPGRADEABLE: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
const LOADER_V4: &str = "LoaderV411111111111111111111111111111111111";

const PROGRAMDATA_DISCRIMINATOR: u32 = 3;
const ELF_MAGIC: &[u8] = &[0x7f, 0x45, 0x4c, 0x46];

/// Represents a program account with its metadata
struct ProgramAccount {
    pubkey: Pubkey,
    lamports: u64,
    rent_epoch: u64,
    space: usize,
    loader_version: i32,
    derived_executable_pubkey: Option<Pubkey>,
    last_updated_slot: Option<u64>,
}

/// Map loader version number to pubkey string
fn version_to_loader(version: i32) -> Option<&'static str> {
    match version {
        1 => Some(BPF_LOADER_V1),
        2 => Some(BPF_LOADER_V2),
        3 => Some(BPF_LOADER_UPGRADEABLE),
        4 => Some(LOADER_V4),
        _ => None,
    }
}

/// Map loader pubkey to version integer
#[allow(dead_code)]
fn loader_to_version(loader: &str) -> i32 {
    match loader {
        BPF_LOADER_V1 => 1,
        BPF_LOADER_V2 => 2,
        BPF_LOADER_UPGRADEABLE => 3,
        LOADER_V4 => 4,
        _ => -1,
    }
}

/// Derive the ProgramData address from a program ID
fn derive_programdata_address(program_id: &Pubkey) -> Result<Pubkey> {
    let loader_pubkey =
        Pubkey::from_str(BPF_LOADER_UPGRADEABLE).context("Failed to parse loader pubkey")?;

    let (programdata_address, _bump) =
        Pubkey::find_program_address(&[program_id.as_ref()], &loader_pubkey);

    Ok(programdata_address)
}

/// Extract slot from ProgramData account (bytes 4-12)
fn extract_slot_from_programdata(data: &[u8]) -> Result<u64> {
    if data.len() < 12 {
        anyhow::bail!("Data too small to contain slot information");
    }

    let discriminator = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if discriminator != PROGRAMDATA_DISCRIMINATOR {
        anyhow::bail!("Invalid ProgramData discriminator: {}", discriminator);
    }

    let slot = u64::from_le_bytes([
        data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
    ]);

    Ok(slot)
}

/// Parse complete ProgramData account
fn parse_programdata(data: &[u8]) -> Result<(u64, Option<Pubkey>, Vec<u8>)> {
    if data.len() < 45 {
        anyhow::bail!("Data too small to be a valid ProgramData account");
    }

    let slot = extract_slot_from_programdata(data)?;

    let option_tag = data[12];
    let pubkey_bytes: [u8; 32] = data[13..45].try_into()?;
    let upgrade_authority = match option_tag {
        0 => None,
        1 => Some(Pubkey::new_from_array(pubkey_bytes)),
        _ => anyhow::bail!("Invalid Option tag: {}", option_tag),
    };

    let elf_offset = 45;
    if data.len() < elf_offset + 4 {
        anyhow::bail!("No ELF data found");
    }

    if &data[elf_offset..elf_offset + 4] != ELF_MAGIC {
        anyhow::bail!(
            "Invalid ELF magic bytes: {:02x?}",
            &data[elf_offset..elf_offset + 4]
        );
    }

    let elf_data = data[elf_offset..].to_vec();
    Ok((slot, upgrade_authority, elf_data))
}

/// Create or update database schema
fn create_database(db_path: &str) -> Result<Connection> {
    let conn = Connection::open(db_path).context("Failed to open database")?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS programs (
            pubkey TEXT PRIMARY KEY,
            loader_version INTEGER NOT NULL,
            derived_executable_pubkey TEXT,
            last_updated_slot INTEGER DEFAULT 0,
            upgrade_authority TEXT,
            is_closed INTEGER DEFAULT 0,
            lamports INTEGER,
            rent_epoch INTEGER,
            space INTEGER
        )",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_loader_version ON programs(loader_version)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_last_updated_slot ON programs(last_updated_slot)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_is_closed ON programs(is_closed)",
        [],
    )?;

    Ok(conn)
}

/// Sync filesystem with database - reset slot to 0 for missing files
fn sync_filesystem_with_database(conn: &Connection, output_dir: &str) -> Result<()> {
    println!("\nSyncing filesystem with database...");

    let mut stmt =
        conn.prepare("SELECT pubkey, last_updated_slot FROM programs WHERE last_updated_slot > 0")?;

    let programs: Vec<(String, i64)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;

    let mut reset_count = 0;

    for (pubkey, slot) in programs {
        let file_path = Path::new(output_dir).join(format!("{}.so", pubkey));
        if !file_path.exists() {
            println!(
                "  Resetting {} (slot {} -> 0): file not found",
                pubkey, slot
            );
            conn.execute(
                "UPDATE programs SET last_updated_slot = 0 WHERE pubkey = ?1",
                params![pubkey],
            )?;
            reset_count += 1;
        }
    }

    println!("✓ Filesystem sync complete: {} programs reset", reset_count);
    Ok(())
}

/// Get the discriminator filter for each loader type
/// BPFUpgradeable Program accounts have discriminator 2u32 LE = [2, 0, 0, 0]
fn get_program_discriminator_filter(loader_version: i32) -> Option<Vec<RpcFilterType>> {
    match loader_version {
        3 => {
            // BPFUpgradeable Program discriminator
            Some(vec![RpcFilterType::Memcmp(Memcmp::new_raw_bytes(
                0,
                vec![2, 0, 0, 0],
            ))])
        }
        _ => None, // Other loaders don't use discriminators
    }
}

/// Fetch all programs for a given loader from RPC
fn fetch_programs_for_loader(
    rpc_client: &RpcClient,
    loader_version: i32,
) -> Result<Vec<(Pubkey, u64, u64, usize)>> {
    let loader_str = version_to_loader(loader_version)
        .ok_or_else(|| anyhow::anyhow!("Invalid loader version: {}", loader_version))?;

    let loader_pubkey = Pubkey::from_str(loader_str)?;

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    spinner.set_message(format!(
        ">>> FETCHING LOADER V{} PROGRAMS FROM RPC",
        loader_version
    ));
    spinner.enable_steady_tick(std::time::Duration::from_millis(80));

    // Use discriminator filter if available, otherwise fetch all
    let filters = get_program_discriminator_filter(loader_version);

    // Use data slice to only fetch 4 bytes (discriminator) for BPFUpgradeable, 0 for others
    let data_length = if loader_version == 3 { 4 } else { 0 };

    let config = RpcProgramAccountsConfig {
        filters,
        account_config: RpcAccountInfoConfig {
            encoding: Some(solana_account_decoder::UiAccountEncoding::Base64),
            commitment: Some(CommitmentConfig::confirmed()),
            data_slice: Some(solana_account_decoder::UiDataSliceConfig {
                offset: 0,
                length: data_length,
            }),
            min_context_slot: None,
        },
        with_context: None,
        sort_results: None,
    };

    let accounts = rpc_client.get_program_accounts_with_config(&loader_pubkey, config)?;

    let programs: Vec<(Pubkey, u64, u64, usize)> = accounts
        .into_iter()
        .filter_map(|(pubkey, account)| {
            if account.executable {
                Some((
                    pubkey,
                    account.lamports,
                    account.rent_epoch,
                    account.data.len(),
                ))
            } else {
                None
            }
        })
        .collect();

    spinner.finish_with_message(format!(
        ">>> FOUND {} PROGRAMS FOR LOADER V{}",
        programs.len(),
        loader_version
    ));
    Ok(programs)
}

/// Fetch all ProgramData accounts (executable data accounts for BPFUpgradeable)
fn fetch_all_programdata_accounts(rpc_client: &RpcClient) -> Result<HashMap<Pubkey, u64>> {
    let loader_pubkey = Pubkey::from_str(BPF_LOADER_UPGRADEABLE)?;

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    spinner.set_message(">>> FETCHING PROGRAMDATA ACCOUNTS FROM RPC");
    spinner.enable_steady_tick(std::time::Duration::from_millis(80));

    // Filter for ProgramData discriminator (3u32 LE = [3, 0, 0, 0])
    let filters = Some(vec![RpcFilterType::Memcmp(Memcmp::new_raw_bytes(
        0,
        vec![3, 0, 0, 0],
    ))]);

    // Fetch first 12 bytes: discriminator (4) + slot (8)
    let config = RpcProgramAccountsConfig {
        filters,
        account_config: RpcAccountInfoConfig {
            encoding: Some(solana_account_decoder::UiAccountEncoding::Base64),
            commitment: Some(CommitmentConfig::confirmed()),
            data_slice: Some(solana_account_decoder::UiDataSliceConfig {
                offset: 0,
                length: 12, // discriminator (4) + slot (8)
            }),
            min_context_slot: None,
        },
        with_context: None,
        sort_results: None,
    };

    let accounts = rpc_client.get_program_accounts_with_config(&loader_pubkey, config)?;

    let mut programdata_map = HashMap::new();

    for (pubkey, account) in accounts {
        if account.data.len() >= 12 {
            match extract_slot_from_programdata(&account.data) {
                Ok(slot) => {
                    programdata_map.insert(pubkey, slot);
                }
                Err(e) => {
                    spinner.println(format!(
                        "  Warning: Failed to parse slot from {}: {}",
                        pubkey, e
                    ));
                }
            }
        }
    }

    spinner.finish_with_message(format!(
        ">>> FOUND {} PROGRAMDATA ACCOUNTS",
        programdata_map.len()
    ));
    Ok(programdata_map)
}

/// Store or update programs in database
/// For new programs: sets last_updated_slot = 0
/// For existing programs: resets to 0 if RPC slot differs from stored slot
fn store_programs_in_database(conn: &Connection, programs: Vec<ProgramAccount>) -> Result<()> {
    for program in programs {
        let ProgramAccount {
            pubkey,
            lamports,
            rent_epoch,
            space,
            loader_version,
            derived_executable_pubkey: derived_exec,
            last_updated_slot: rpc_slot,
        } = program;
        let is_closed = if rpc_slot.is_none() && derived_exec.is_some() {
            1 // Program exists but has no executable account (closed)
        } else {
            0
        };

        // Check if program already exists and get its current slot
        let existing_slot: Option<i64> = conn
            .query_row(
                "SELECT last_updated_slot FROM programs WHERE pubkey = ?1",
                params![pubkey.to_string()],
                |row| row.get(0),
            )
            .ok();

        let new_slot = if let Some(stored_slot) = existing_slot {
            // Program exists in database
            if let Some(rpc_slot_val) = rpc_slot {
                // Active program with RPC slot
                if rpc_slot_val as i64 != stored_slot {
                    // RPC slot differs from stored slot - reset to 0 to force re-download
                    0
                } else {
                    // Same slot - keep current value
                    stored_slot
                }
            } else {
                // Program is closed - keep current slot value
                stored_slot
            }
        } else {
            // New program - start with 0
            0
        };

        if existing_slot.is_some() {
            // Update existing record
            conn.execute(
                "UPDATE programs
                 SET loader_version = ?2, derived_executable_pubkey = ?3, last_updated_slot = ?4,
                     is_closed = ?5, lamports = ?6, rent_epoch = ?7, space = ?8
                 WHERE pubkey = ?1",
                params![
                    pubkey.to_string(),
                    loader_version,
                    derived_exec.map(|p| p.to_string()),
                    new_slot,
                    is_closed,
                    lamports as i64,
                    rent_epoch as i64,
                    space as i64,
                ],
            )?;
        } else {
            // Insert new record with last_updated_slot = 0
            conn.execute(
                "INSERT INTO programs
                 (pubkey, loader_version, derived_executable_pubkey, last_updated_slot, is_closed, lamports, rent_epoch, space)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    pubkey.to_string(),
                    loader_version,
                    derived_exec.map(|p| p.to_string()),
                    new_slot,
                    is_closed,
                    lamports as i64,
                    rent_epoch as i64,
                    space as i64,
                ],
            )?;
        }
    }

    Ok(())
}

struct DownloadResult {
    program_id: String,
    status: DownloadStatus,
}

enum DownloadStatus {
    Downloaded {
        slot: u64,
        upgrade_authority: Option<String>,
        elf_data: Vec<u8>,
    },
    Skipped,
    Closed,
    Error,
}

/// Download programs that need updating (with parallel processing and batch updates)
fn download_programs(
    conn: &Connection,
    rpc_client: &RpcClient,
    output_dir: &str,
    loader_version: i32,
    verbose: bool,
) -> Result<(usize, usize, usize)> {
    const BATCH_SIZE: usize = 100;

    // Get all programs from database that need downloading (last_updated_slot = 0)
    // For v1, v2 (BPFLoader): download from pubkey directly (derived_executable_pubkey will be NULL)
    // For v3 (BPFUpgradeable): download from derived_executable_pubkey (ProgramData account)
    // For v4 (LoaderV4): download from pubkey directly (similar to v1/v2)
    let mut stmt = conn.prepare(
        "SELECT pubkey, derived_executable_pubkey, last_updated_slot, loader_version
         FROM programs
         WHERE is_closed = 0
         AND last_updated_slot = 0
         AND loader_version = ?1
         ORDER BY pubkey",
    )?;

    let programs: Vec<(String, Option<String>, i64, i32)> = stmt
        .query_map([loader_version], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    drop(stmt);

    let total = programs.len();
    let mut total_downloaded = 0;
    let mut total_skipped = 0;
    let mut total_errors = 0;

    if total == 0 {
        return Ok((0, 0, 0));
    }

    // Create simple progress bar
    let pb = ProgressBar::new(total as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("  [{bar:40.green/black}] {pos}/{len}")
            .unwrap()
            .progress_chars("█▓░"),
    );

    let rpc_client_arc = Arc::new(rpc_client);

    // Process in batches
    for batch in programs.chunks(BATCH_SIZE) {
        // Download batch in parallel
        let results: Vec<DownloadResult> = batch
            .par_iter()
            .map(
                |(program_id, exec_pubkey_opt, stored_slot, loader_version)| {
                    // Determine which account to fetch from
                    // v3 (BPFUpgradeable): fetch from derived executable account
                    // v1, v2: fetch from program account directly
                    let account_to_fetch = if *loader_version == 3 {
                        // BPFUpgradeable - use derived executable account
                        match exec_pubkey_opt {
                            Some(exec_str) => exec_str.clone(),
                            None => {
                                return DownloadResult {
                                    program_id: program_id.clone(),
                                    status: DownloadStatus::Error,
                                };
                            }
                        }
                    } else {
                        // v0, v1, v2 - use program account directly
                        program_id.clone()
                    };

                    let fetch_pubkey = match Pubkey::from_str(&account_to_fetch) {
                        Ok(pk) => pk,
                        Err(_e) => {
                            return DownloadResult {
                                program_id: program_id.clone(),
                                status: DownloadStatus::Error,
                            };
                        }
                    };

                    // Fetch account data
                    let account_data = match rpc_client_arc.get_account_data(&fetch_pubkey) {
                        Ok(data) => data,
                        Err(e) => {
                            let error_str = e.to_string();
                            let error_lower = error_str.to_lowercase();

                            if error_lower.contains("could not find account")
                                || error_lower.contains("account")
                                    && error_lower.contains("not found")
                                || error_lower.contains("accountnotfound")
                            {
                                return DownloadResult {
                                    program_id: program_id.clone(),
                                    status: DownloadStatus::Closed,
                                };
                            } else {
                                return DownloadResult {
                                    program_id: program_id.clone(),
                                    status: DownloadStatus::Error,
                                };
                            }
                        }
                    };

                    // Parse based on loader version
                    let (current_slot, upgrade_authority, elf_data) = if *loader_version == 3 {
                        // BPFUpgradeable - parse ProgramData structure
                        match parse_programdata(&account_data) {
                            Ok(data) => data,
                            Err(_) => {
                                return DownloadResult {
                                    program_id: program_id.clone(),
                                    status: DownloadStatus::Error,
                                };
                            }
                        }
                    } else {
                        // v1, v2 - raw program data (no slot tracking, no upgrade authority)
                        // Use 1 as a dummy slot since these loaders don't have slot tracking
                        // v0 is already filtered out above
                        (1, None, account_data)
                    };

                    // Check if we need to update (only for v3 with slot tracking)
                    if *loader_version == 3 && current_slot as i64 == *stored_slot {
                        return DownloadResult {
                            program_id: program_id.clone(),
                            status: DownloadStatus::Skipped,
                        };
                    }

                    DownloadResult {
                        program_id: program_id.clone(),
                        status: DownloadStatus::Downloaded {
                            slot: current_slot,
                            upgrade_authority: upgrade_authority.map(|pk| pk.to_string()),
                            elf_data,
                        },
                    }
                },
            )
            .collect();

        // Write files and update database in batch
        let mut batch_downloaded = 0;
        let mut batch_skipped = 0;
        let mut batch_errors = 0;

        for result in results {
            match result.status {
                DownloadStatus::Downloaded {
                    slot,
                    upgrade_authority,
                    elf_data,
                } => {
                    // Write ELF to file
                    let file_path = Path::new(output_dir).join(format!("{}.so", result.program_id));
                    if File::create(&file_path)
                        .and_then(|mut f| f.write_all(&elf_data))
                        .is_err()
                    {
                        batch_errors += 1;
                        if verbose {
                            pb.println(format!("  ERROR: {}", result.program_id));
                        }
                        pb.inc(1);
                        continue;
                    }

                    // Update database
                    if conn.execute(
                        "UPDATE programs SET last_updated_slot = ?1, upgrade_authority = ?2, is_closed = 0 WHERE pubkey = ?3",
                        params![slot as i64, upgrade_authority, result.program_id],
                    ).is_err() {
                        batch_errors += 1;
                        if verbose {
                            pb.println(format!("  ERROR: {}", result.program_id));
                        }
                        pb.inc(1);
                        continue;
                    }

                    batch_downloaded += 1;
                }
                DownloadStatus::Skipped => {
                    if verbose {
                        pb.println(format!("  SKIPPED: {}", result.program_id));
                    }
                    batch_skipped += 1;
                }
                DownloadStatus::Closed => {
                    conn.execute(
                        "UPDATE programs SET last_updated_slot = 0, is_closed = 1 WHERE pubkey = ?1",
                        params![result.program_id],
                    )?;
                    if verbose {
                        pb.println(format!("  SKIPPED: {} (closed)", result.program_id));
                    }
                    batch_skipped += 1;
                }
                DownloadStatus::Error => {
                    if verbose {
                        pb.println(format!("  ERROR: {}", result.program_id));
                    }
                    batch_errors += 1;
                }
            }

            // Update progress bar
            pb.inc(1);
        }

        total_downloaded += batch_downloaded;
        total_skipped += batch_skipped;
        total_errors += batch_errors;
    }

    pb.finish_and_clear();

    Ok((total_downloaded, total_skipped, total_errors))
}

/// Main sync command
fn sync_command(
    loader_versions: Vec<i32>,
    _rpc_endpoint: String,
    db_path: String,
    output_dir: String,
    verbose: bool,
) -> Result<()> {
    println!("\nSolana Program Sync");
    println!("Output: {}", output_dir);
    println!();

    // Create database
    let conn = create_database(&db_path)?;

    // Create output directory
    fs::create_dir_all(&output_dir).context("Failed to create output directory")?;

    // Create RPC client
    let rpc_client = RpcClient::new(_rpc_endpoint);

    // Step 1: Sync filesystem with database
    sync_filesystem_with_database(&conn, &output_dir)?;

    // Step 2: For BPFUpgradeable, fetch all ProgramData accounts once (single pass)
    let programdata_slots: HashMap<Pubkey, u64> = if loader_versions.contains(&3) {
        fetch_all_programdata_accounts(&rpc_client)?
    } else {
        HashMap::new()
    };

    // Step 3: Fetch and download programs for each loader
    let mut total_downloaded = 0;
    let mut total_skipped = 0;
    let mut total_errors = 0;

    for loader_version in &loader_versions {
        let loader_name = match loader_version {
            1 => "BPFLoader v1",
            2 => "BPFLoader v2",
            3 => "BPFLoaderUpgradeable",
            4 => "LoaderV4",
            _ => "Unknown",
        };

        println!("{}:", loader_name);

        let programs = fetch_programs_for_loader(&rpc_client, *loader_version)?;

        if programs.is_empty() {
            println!("  No programs found\n");
            continue;
        }

        // For BPFUpgradeable (v3), look up slots from pre-fetched ProgramData accounts
        let programs_with_exec: Vec<ProgramAccount> = if *loader_version == 3 {
            let mut result = Vec::new();

            for (pubkey, lamports, rent_epoch, space) in programs {
                let exec_pubkey = match derive_programdata_address(&pubkey) {
                    Ok(pk) => pk,
                    Err(_) => continue,
                };

                let slot = programdata_slots.get(&exec_pubkey).copied();
                result.push(ProgramAccount {
                    pubkey,
                    lamports,
                    rent_epoch,
                    space,
                    loader_version: *loader_version,
                    derived_executable_pubkey: Some(exec_pubkey),
                    last_updated_slot: slot,
                });
            }

            result
        } else {
            programs
                .into_iter()
                .map(|(pk, lam, re, sp)| ProgramAccount {
                    pubkey: pk,
                    lamports: lam,
                    rent_epoch: re,
                    space: sp,
                    loader_version: *loader_version,
                    derived_executable_pubkey: None,
                    last_updated_slot: None,
                })
                .collect()
        };

        store_programs_in_database(&conn, programs_with_exec)?;

        // Download programs for this loader
        let (downloaded, skipped, errors) =
            download_programs(&conn, &rpc_client, &output_dir, *loader_version, verbose)?;

        if downloaded + skipped + errors > 0 {
            println!(
                "  Downloaded: {}, Skipped: {}, Errors: {}\n",
                downloaded, skipped, errors
            );
        } else {
            println!("  All programs up to date\n");
        }

        total_downloaded += downloaded;
        total_skipped += skipped;
        total_errors += errors;
    }

    // Final summary
    println!("Total Downloaded: {}", total_downloaded);
    println!("Total Skipped: {}", total_skipped);
    println!("Total Errors: {}", total_errors);

    Ok(())
}

#[derive(Debug)]
enum AnalyzeMode {
    Aggregate { field: String },
    Count { filters: HashMap<String, i64> },
}

fn analyze_command(opcode_str: String, mode: AnalyzeMode, program_dir: String) -> Result<()> {
    println!("\nsBPF Instruction Analyzer");
    println!("{}", "=".repeat(60));

    // Parse opcode - "all" means scan all opcodes
    let target_opcode: Option<Opcode> = if opcode_str.eq_ignore_ascii_case("all") {
        None
    } else {
        Some(
            opcode_str
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid opcode '{}': {}", opcode_str, e))?,
        )
    };

    // Check if directory exists
    if !Path::new(&program_dir).exists() {
        anyhow::bail!("Directory '{}' not found. Run sync first.", program_dir);
    }

    // Count .so files
    let entries = fs::read_dir(&program_dir)?;
    let so_files: Vec<_> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|ext| ext == "so").unwrap_or(false))
        .collect();

    println!("Found {} .so files to analyze", so_files.len());
    match &target_opcode {
        Some(op) => println!("Analyzing opcode: {}", op),
        None => println!("Analyzing all opcodes"),
    }
    println!();

    let pb = ProgressBar::new(so_files.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("  [{bar:40.green/black}] {pos}/{len}")
            .unwrap()
            .progress_chars("█▓░"),
    );

    match mode {
        AnalyzeMode::Aggregate { field } => {
            // Thread-safe counters for aggregation
            // When target_opcode is None (all), we track (opcode, field_value) pairs.
            // When target_opcode is Some, we just track field_value.
            let field_counts = Mutex::new(HashMap::<(Opcode, i64), usize>::new());
            let total_matches = AtomicUsize::new(0);
            let files_processed = AtomicUsize::new(0);
            let files_with_errors = AtomicUsize::new(0);
            let error_log = Mutex::new(Vec::<(String, String)>::new());

            // Process files in parallel
            so_files.par_iter().for_each(|entry| {
                let path = entry.path();
                let filename = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();

                // Read the ELF file
                let elf_data = match fs::read(&path) {
                    Ok(data) => data,
                    Err(e) => {
                        files_with_errors.fetch_add(1, Ordering::Relaxed);
                        error_log
                            .lock()
                            .unwrap()
                            .push((filename, format!("Read error: {}", e)));
                        pb.inc(1);
                        return;
                    }
                };

                // Parse ELF
                let program = match Program::from_bytes(&elf_data) {
                    Ok(p) => p,
                    Err(e) => {
                        files_with_errors.fetch_add(1, Ordering::Relaxed);
                        error_log
                            .lock()
                            .unwrap()
                            .push((filename, format!("Parse error: {}", e)));
                        pb.inc(1);
                        return;
                    }
                };

                // Extract instructions
                let instructions = match program.to_ixs() {
                    Ok(i) => i,
                    Err(e) => {
                        files_with_errors.fetch_add(1, Ordering::Relaxed);
                        error_log
                            .lock()
                            .unwrap()
                            .push((filename, format!("Disassembly error: {}", e)));
                        pb.inc(1);
                        return;
                    }
                };

                let mut local_counts = HashMap::<(Opcode, i64), usize>::new();
                let mut local_matches = 0;

                for instruction in &instructions.0 {
                    let opcode_matches = target_opcode
                        .map(|op| instruction.opcode == op)
                        .unwrap_or(true);

                    if opcode_matches {
                        let field_value = match field.as_str() {
                            "src" => instruction.src.as_ref().map(|r| r.n as i64),
                            "dst" => instruction.dst.as_ref().map(|r| r.n as i64),
                            "imm" => instruction.imm.as_ref().and_then(|imm| match imm {
                                Either::Right(num) => Some(num.to_i64()),
                                Either::Left(_) => None,
                            }),
                            "off" => instruction.off.as_ref().and_then(|off| match off {
                                Either::Right(offset) => Some(*offset as i64),
                                Either::Left(_) => None,
                            }),
                            _ => None,
                        };

                        if let Some(value) = field_value {
                            *local_counts
                                .entry((instruction.opcode, value))
                                .or_insert(0) += 1;
                            local_matches += 1;
                        }
                    }
                }

                // Merge local counts into global counts
                if !local_counts.is_empty() {
                    let mut counts = field_counts.lock().unwrap();
                    for (key, count) in local_counts {
                        *counts.entry(key).or_insert(0) += count;
                    }
                }

                total_matches.fetch_add(local_matches, Ordering::Relaxed);
                files_processed.fetch_add(1, Ordering::Relaxed);
                pb.inc(1);
            });

            pb.finish_and_clear();

            // Extract final values
            let field_counts = field_counts.into_inner().unwrap();
            let total_matches = total_matches.load(Ordering::Relaxed);
            let files_processed = files_processed.load(Ordering::Relaxed);
            let files_with_errors = files_with_errors.load(Ordering::Relaxed);
            let error_log = error_log.into_inner().unwrap();

            println!("\n{}", "=".repeat(60));
            println!("ANALYSIS RESULTS");
            println!("{}", "=".repeat(60));
            println!("Files processed:       {}", files_processed);
            println!("Files with errors:     {}", files_with_errors);
            match &target_opcode {
                Some(op) => println!("Total {} instructions: {}", op, total_matches),
                None => println!("Total instructions:    {}", total_matches),
            }
            println!();

            if !error_log.is_empty() {
                println!("Errors encountered:");
                println!("{}", "-".repeat(60));
                for (filename, error) in &error_log {
                    println!("  {}: {}", filename, error);
                }
                println!();
            }

            if total_matches == 0 {
                match &target_opcode {
                    Some(op) => println!("No {} instructions found!", op),
                    None => println!("No instructions found!"),
                }
                return Ok(());
            }

            // Output format depends on whether we're analyzing all opcodes or a specific one.
            if target_opcode.is_some() {
                // Single opcode: aggregate by field value only.
                let mut value_counts = HashMap::<i64, usize>::new();
                for ((_, value), count) in &field_counts {
                    *value_counts.entry(*value).or_insert(0) += count;
                }

                let mut sorted_values: Vec<_> = value_counts.iter().collect();
                sorted_values.sort_by_key(|(value, _)| *value);

                println!(
                    "{} instruction {} field distribution:",
                    target_opcode.unwrap(),
                    field
                );
                println!("{}", "-".repeat(60));
                println!(
                    "{:<15} {:<15} {:<15}",
                    field.to_uppercase(),
                    "Count",
                    "Percentage"
                );
                println!("{}", "-".repeat(60));

                for (value, count) in sorted_values {
                    let percentage = (*count as f64 / total_matches as f64) * 100.0;
                    println!("{:<15} {:<15} {:<14.2}%", value, count, percentage);
                }
            } else {
                // All opcodes: long-form table with opcode column.
                // First, calculate per-opcode totals for percentage calculation.
                let mut opcode_totals = HashMap::<Opcode, usize>::new();
                for ((opcode, _), count) in &field_counts {
                    *opcode_totals.entry(*opcode).or_insert(0) += count;
                }

                let mut sorted_entries: Vec<_> = field_counts.iter().collect();
                // Sort by opcode name, then by field value.
                sorted_entries.sort_by(|a, b| {
                    let opcode_cmp = a.0 .0.to_string().cmp(&b.0 .0.to_string());
                    if opcode_cmp == std::cmp::Ordering::Equal {
                        a.0 .1.cmp(&b.0 .1)
                    } else {
                        opcode_cmp
                    }
                });

                println!(
                    "{} field distribution by opcode:",
                    field.to_uppercase()
                );
                println!("{}", "-".repeat(60));
                println!(
                    "{:<15} {:<15} {:<15} {:<15}",
                    "OPCODE",
                    field.to_uppercase(),
                    "Count",
                    "Percentage"
                );
                println!("{}", "-".repeat(60));

                for ((opcode, value), count) in sorted_entries {
                    let opcode_total = opcode_totals.get(opcode).unwrap_or(&1);
                    let percentage = (*count as f64 / *opcode_total as f64) * 100.0;
                    println!(
                        "{:<15} {:<15} {:<15} {:<14.2}%",
                        opcode.to_string(),
                        value,
                        count,
                        percentage
                    );
                }
            }

            println!("{}", "=".repeat(60));
        }

        AnalyzeMode::Count { filters } => {
            // When target_opcode is None (all), track counts per opcode.
            let opcode_counts = Mutex::new(HashMap::<Opcode, usize>::new());
            let total_matches = AtomicUsize::new(0);
            let files_processed = AtomicUsize::new(0);
            let files_with_errors = AtomicUsize::new(0);
            let error_log = Mutex::new(Vec::<(String, String)>::new());

            // Process files in parallel
            so_files.par_iter().for_each(|entry| {
                let path = entry.path();
                let filename = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();

                // Read the ELF file
                let elf_data = match fs::read(&path) {
                    Ok(data) => data,
                    Err(e) => {
                        files_with_errors.fetch_add(1, Ordering::Relaxed);
                        error_log
                            .lock()
                            .unwrap()
                            .push((filename, format!("Read error: {}", e)));
                        pb.inc(1);
                        return;
                    }
                };

                // Parse ELF
                let program = match Program::from_bytes(&elf_data) {
                    Ok(p) => p,
                    Err(e) => {
                        files_with_errors.fetch_add(1, Ordering::Relaxed);
                        error_log
                            .lock()
                            .unwrap()
                            .push((filename, format!("Parse error: {}", e)));
                        pb.inc(1);
                        return;
                    }
                };

                // Extract instructions
                let instructions = match program.to_ixs() {
                    Ok(i) => i,
                    Err(e) => {
                        files_with_errors.fetch_add(1, Ordering::Relaxed);
                        error_log
                            .lock()
                            .unwrap()
                            .push((filename, format!("Disassembly error: {}", e)));
                        pb.inc(1);
                        return;
                    }
                };

                let mut local_counts = HashMap::<Opcode, usize>::new();
                let mut local_matches = 0;

                for instruction in &instructions.0 {
                    let opcode_matches = target_opcode
                        .map(|op| instruction.opcode == op)
                        .unwrap_or(true);

                    if opcode_matches {
                        // Check if instruction matches all filters
                        let mut matches_all = true;

                        for (field, expected_value) in &filters {
                            let actual_value = match field.as_str() {
                                "src" => instruction.src.as_ref().map(|r| r.n as i64),
                                "dst" => instruction.dst.as_ref().map(|r| r.n as i64),
                                "imm" => instruction.imm.as_ref().and_then(|imm| match imm {
                                    Either::Right(num) => Some(num.to_i64()),
                                    Either::Left(_) => None,
                                }),
                                "off" => instruction.off.as_ref().and_then(|off| match off {
                                    Either::Right(offset) => Some(*offset as i64),
                                    Either::Left(_) => None,
                                }),
                                _ => None,
                            };

                            if actual_value != Some(*expected_value) {
                                matches_all = false;
                                break;
                            }
                        }

                        if matches_all {
                            *local_counts.entry(instruction.opcode).or_insert(0) += 1;
                            local_matches += 1;
                        }
                    }
                }

                // Merge local counts into global counts.
                if !local_counts.is_empty() {
                    let mut counts = opcode_counts.lock().unwrap();
                    for (opcode, count) in local_counts {
                        *counts.entry(opcode).or_insert(0) += count;
                    }
                }

                total_matches.fetch_add(local_matches, Ordering::Relaxed);
                files_processed.fetch_add(1, Ordering::Relaxed);
                pb.inc(1);
            });

            pb.finish_and_clear();

            let opcode_counts = opcode_counts.into_inner().unwrap();
            let total_matches = total_matches.load(Ordering::Relaxed);
            let files_processed = files_processed.load(Ordering::Relaxed);
            let files_with_errors = files_with_errors.load(Ordering::Relaxed);
            let error_log = error_log.into_inner().unwrap();

            println!("\n{}", "=".repeat(60));
            println!("ANALYSIS RESULTS");
            println!("{}", "=".repeat(60));
            println!("Files processed:       {}", files_processed);
            println!("Files with errors:     {}", files_with_errors);

            if !error_log.is_empty() {
                println!();
                println!("Errors encountered:");
                println!("{}", "-".repeat(60));
                for (filename, error) in &error_log {
                    println!("  {}: {}", filename, error);
                }
            }

            println!();

            // Output format depends on whether we're analyzing all opcodes or a specific one.
            if let Some(op) = target_opcode {
                // Single opcode: simple count.
                if filters.is_empty() {
                    println!("Total {} instructions: {}", op, total_matches);
                } else {
                    print!("Total {} instructions matching", op);
                    for (field, value) in &filters {
                        print!(" {}={}", field, value);
                    }
                    println!(": {}", total_matches);
                }
            } else {
                // All opcodes: per-opcode table.
                if !filters.is_empty() {
                    print!("Instruction counts by opcode (matching");
                    for (field, value) in &filters {
                        print!(" {}={}", field, value);
                    }
                    println!("):");
                } else {
                    println!("Instruction counts by opcode:");
                }
                println!("{}", "-".repeat(60));
                println!("{:<20} {:<15} {:<15}", "OPCODE", "Count", "Percentage");
                println!("{}", "-".repeat(60));

                // Sort by count descending.
                let mut sorted_counts: Vec<_> = opcode_counts.iter().collect();
                sorted_counts.sort_by(|a, b| b.1.cmp(a.1));

                for (opcode, count) in &sorted_counts {
                    let percentage = (**count as f64 / total_matches as f64) * 100.0;
                    println!(
                        "{:<20} {:<15} {:<14.2}%",
                        opcode.to_string(),
                        count,
                        percentage
                    );
                }

                println!("{}", "-".repeat(60));
                println!("{:<20} {:<15}", "TOTAL", total_matches);
            }

            println!("{}", "=".repeat(60));
        }
    }

    Ok(())
}

fn print_help() {
    println!("SOLANA PROGRAM SYNC");
    println!("\nUSAGE:");
    println!("  program-sync <COMMAND> [OPTIONS]");
    println!("\nCOMMANDS:");
    println!("  sync        Sync programs from RPC and download binaries");
    println!("  analyze     Analyze sBPF instructions across all programs");
    println!("  help        Show this help message");
    println!("\nFor command-specific options, use:");
    println!("  program-sync sync --help");
    println!("  program-sync analyze --help");
    println!();
}

fn print_sync_help() {
    println!("SYNC");
    println!("\nUSAGE:");
    println!("  program-sync sync [OPTIONS]");
    println!("\nDESCRIPTION:");
    println!("  Fetch program accounts from Solana RPC and download their binaries.");
    println!("\nOPTIONS:");
    println!("  --loader <VERSION>    Loader version (1-4), can be specified multiple times");
    println!("                        Default: loaders 1-3 if not specified");
    println!("  --rpc-url <URL>       RPC endpoint URL");
    println!("                        Default: RPC_ENDPOINT env var or mainnet");
    println!("  --verbose, -v         Log skipped and errored program IDs");
    println!("  --help, -h            Show this help message");
    println!("\nLOADER VERSIONS:");
    println!("  1  BPFLoader v1");
    println!("  2  BPFLoader v2");
    println!("  3  BPFLoaderUpgradeable  (most common)");
    println!("  4  LoaderV4  (experimental)");
    println!("\nEXAMPLES:");
    println!("  # Sync all BPFLoaderUpgradeable programs from mainnet");
    println!("  program-sync sync --loader 3");
    println!();
    println!("  # Sync multiple loader versions");
    println!("  program-sync sync --loader 2 --loader 3");
    println!();
    println!("  # Use custom RPC endpoint");
    println!("  program-sync sync --loader 3 --rpc-url https://custom-rpc.com");
    println!();
    println!("  # Sync all loaders with verbose logging");
    println!("  program-sync sync --verbose");
    println!("\nOUTPUT:");
    println!("  Database:   solana_programs.db");
    println!("  Binaries:   programs/<pubkey>.so");
    println!();
}

fn print_analyze_help() {
    println!("ANALYZE");
    println!("\nUSAGE:");
    println!("  program-sync analyze --opcode <OPCODE> [OPTIONS]");
    println!("\nDESCRIPTION:");
    println!("  Analyze sBPF instructions across all downloaded program binaries.");
    println!("\nOPTIONS:");
    println!("  --opcode <OPCODE>     sBPF opcode to analyze, or \"all\" for all opcodes (required)");
    println!("  --agg <FIELD>         Aggregate by field: src, dst, imm, or off");
    println!("  --count [FILTERS]     Count instructions (optionally with filters)");
    println!("                        Filters format: field=value,field2=value2");
    println!("  --dir <PATH>          Program directory (default: programs)");
    println!("  --help, -h            Show this help message");
    println!("\nNOTE:");
    println!("  Either --agg or --count must be specified (not both)");
    println!("\nEXAMPLES:");
    println!("  # Count all call instructions");
    println!("  program-sync analyze --opcode call --count");
    println!();
    println!("  # Show distribution of src registers for call instructions");
    println!("  program-sync analyze --opcode call --agg src");
    println!();
    println!("  # Count sub32 instructions where imm=1");
    println!("  program-sync analyze --opcode sub32 --count imm=1");
    println!();
    println!("  # Count add64 instructions where src=1 and dst=2");
    println!("  program-sync analyze --opcode add64 --count src=1,dst=2");
    println!();
    println!("  # Show distribution of imm values for mov64 (warning: may be large!)");
    println!("  program-sync analyze --opcode mov64 --agg imm");
    println!();
    println!("  # Count all instructions with src=2 across ALL opcodes");
    println!("  program-sync analyze --opcode all --count src=2");
    println!();
    println!("  # Distribution of src registers across ALL opcodes");
    println!("  program-sync analyze --opcode all --agg src");
    println!();
}

fn main() -> Result<()> {
    // Check if .env exists, create it with default RPC if not
    let env_path = Path::new(".env");
    if !env_path.exists() {
        let default_env = "RPC_ENDPOINT=https://api.mainnet-beta.solana.com\n";
        fs::write(env_path, default_env).context("Failed to create .env file")?;
        println!("Created .env file with default RPC endpoint");
    }

    dotenv::dotenv().ok();

    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_help();
        std::process::exit(1);
    }

    let command = &args[1];

    match command.as_str() {
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        "sync" => {
            let mut loader_versions = Vec::new();
            let mut rpc_url = std::env::var("RPC_ENDPOINT")
                .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());
            let mut verbose = false;

            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--loader" => {
                        if i + 1 < args.len() {
                            let version: i32 =
                                args[i + 1].parse().context("Invalid loader version")?;
                            if !(1..=4).contains(&version) {
                                anyhow::bail!("Loader version must be between 1 and 4");
                            }
                            loader_versions.push(version);
                            i += 2;
                        } else {
                            anyhow::bail!("--loader requires a version argument");
                        }
                    }
                    "--rpc-url" => {
                        if i + 1 < args.len() {
                            rpc_url = args[i + 1].clone();
                            i += 2;
                        } else {
                            anyhow::bail!("--rpc-url requires a URL argument");
                        }
                    }
                    "--verbose" | "-v" => {
                        verbose = true;
                        i += 1;
                    }
                    "--help" | "-h" => {
                        print_sync_help();
                        return Ok(());
                    }
                    _ => {
                        anyhow::bail!(
                            "Unknown argument: {}. Use 'sync --help' for usage.",
                            args[i]
                        );
                    }
                }
            }

            // Default to loaders 1-3 if none specified
            if loader_versions.is_empty() {
                loader_versions = vec![1, 2, 3];
            }

            sync_command(
                loader_versions,
                rpc_url,
                "solana_programs.db".to_string(),
                "programs".to_string(),
                verbose,
            )
        }
        "analyze" => {
            let mut opcode: Option<String> = None;
            let mut agg_field: Option<String> = None;
            let mut count_filters: Option<String> = None;
            let mut program_dir = "programs".to_string();

            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--opcode" => {
                        if i + 1 < args.len() {
                            opcode = Some(args[i + 1].clone());
                            i += 2;
                        } else {
                            anyhow::bail!("--opcode requires an opcode argument");
                        }
                    }
                    "--agg" => {
                        if i + 1 < args.len() {
                            agg_field = Some(args[i + 1].clone());
                            i += 2;
                        } else {
                            anyhow::bail!("--agg requires a field argument (src, dst, imm, off)");
                        }
                    }
                    "--count" => {
                        if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                            count_filters = Some(args[i + 1].clone());
                            i += 2;
                        } else {
                            count_filters = Some(String::new());
                            i += 1;
                        }
                    }
                    "--dir" => {
                        if i + 1 < args.len() {
                            program_dir = args[i + 1].clone();
                            i += 2;
                        } else {
                            anyhow::bail!("--dir requires a directory path");
                        }
                    }
                    "--help" | "-h" => {
                        print_analyze_help();
                        return Ok(());
                    }
                    _ => {
                        anyhow::bail!(
                            "Unknown argument: {}. Use 'analyze --help' for usage.",
                            args[i]
                        );
                    }
                }
            }

            // Validate opcode is provided
            let opcode = opcode
                .ok_or_else(|| anyhow::anyhow!("--opcode is required for analyze command"))?;

            // Determine mode
            let mode = if let Some(field) = agg_field {
                if count_filters.is_some() {
                    anyhow::bail!("Cannot use both --agg and --count");
                }
                AnalyzeMode::Aggregate { field }
            } else if let Some(filter_str) = count_filters {
                let mut filters = HashMap::new();
                if !filter_str.is_empty() {
                    for pair in filter_str.split(',') {
                        let parts: Vec<&str> = pair.split('=').collect();
                        if parts.len() != 2 {
                            anyhow::bail!("Invalid filter format '{}'. Expected field=value", pair);
                        }
                        let field = parts[0].to_string();
                        let value: i64 = parts[1].parse().with_context(|| {
                            format!("Invalid value '{}' for field '{}'", parts[1], field)
                        })?;
                        filters.insert(field, value);
                    }
                }
                AnalyzeMode::Count { filters }
            } else {
                anyhow::bail!("Must specify either --agg or --count");
            };

            analyze_command(opcode, mode, program_dir)
        }
        _ => {
            anyhow::bail!("Unknown command: {}. Use 'sync' or 'analyze'", command);
        }
    }
}
