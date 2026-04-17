use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use solana_client::rpc_client::{GetConfirmedSignaturesForAddress2Config, RpcClient};
use solana_client::rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig};
use solana_client::rpc_filter::{Memcmp, RpcFilterType};
use solana_program::pubkey::Pubkey;
use solana_commitment_config::CommitmentConfig;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::str::FromStr;

/// Loader program IDs and their versions
pub const BPF_LOADER_V1: &str = "BPFLoader1111111111111111111111111111111111";
pub const BPF_LOADER_V2: &str = "BPFLoader2111111111111111111111111111111111";
pub const BPF_LOADER_UPGRADEABLE: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
pub const LOADER_V4: &str = "LoaderV411111111111111111111111111111111111";

const PROGRAMDATA_DISCRIMINATOR: u32 = 3;
pub const ELF_MAGIC: &[u8] = &[0x7f, 0x45, 0x4c, 0x46];

/// Represents a program account with its metadata
pub struct ProgramAccount {
    pub pubkey: Pubkey,
    pub lamports: u64,
    pub rent_epoch: u64,
    pub space: usize,
    pub loader_version: i32,
    pub derived_executable_pubkey: Option<Pubkey>,
    pub last_updated_slot: Option<u64>,
}

/// Map loader version number to pubkey string
pub fn version_to_loader(version: i32) -> Option<&'static str> {
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
pub fn loader_to_version(loader: &str) -> i32 {
    match loader {
        BPF_LOADER_V1 => 1,
        BPF_LOADER_V2 => 2,
        BPF_LOADER_UPGRADEABLE => 3,
        LOADER_V4 => 4,
        _ => -1,
    }
}

/// Human-readable loader name for display.
pub fn loader_version_name(version: i32) -> &'static str {
    match version {
        1 => "BPFLoader v1",
        2 => "BPFLoader v2",
        3 => "BPFLoaderUpgradeable",
        4 => "LoaderV4",
        _ => "Unknown",
    }
}

/// Short loader version label for file naming.
fn loader_version_label(version: i32) -> &'static str {
    match version {
        1 => "v1",
        2 => "v2",
        3 => "upgradeable",
        4 => "v4",
        _ => "unknown",
    }
}

/// Resolve the RPC network name from the URL for file naming.
fn rpc_network_name(rpc_url: &str) -> &str {
    if rpc_url.contains("devnet") {
        "devnet"
    } else if rpc_url.contains("testnet") {
        "testnet"
    } else {
        "mainnet"
    }
}

/// Derive the ProgramData address from a program ID
pub fn derive_programdata_address(program_id: &Pubkey) -> Result<Pubkey> {
    let loader_pubkey =
        Pubkey::from_str(BPF_LOADER_UPGRADEABLE).context("Failed to parse loader pubkey")?;

    let (programdata_address, _bump) =
        Pubkey::find_program_address(&[program_id.as_ref()], &loader_pubkey);

    Ok(programdata_address)
}

/// Extract slot from ProgramData account (bytes 4-12)
pub fn extract_slot_from_programdata(data: &[u8]) -> Result<u64> {
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
pub fn parse_programdata(data: &[u8]) -> Result<(u64, Option<Pubkey>, Vec<u8>)> {
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
pub fn fetch_programs_for_loader(
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
pub fn fetch_all_programdata_accounts(rpc_client: &RpcClient) -> Result<HashMap<Pubkey, u64>> {
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

/// RPC program-ids command: query for active programs and write their IDs
/// to per-loader files. Each file contains only program IDs, one per line.
pub fn program_ids_command(
    loader_versions: Vec<i32>,
    rpc_url: String,
) -> Result<()> {
    let network = rpc_network_name(&rpc_url);
    let rpc_client = RpcClient::new(&rpc_url);

    let output_dir = "rpc-out";
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("Failed to get system time")?
        .as_secs();

    fs::create_dir_all(output_dir).context("Failed to create output directory")?;

    println!("\nRPC Program IDs");
    println!("Network:  {}", network);
    println!("Output:   {}/", output_dir);
    println!();

    // For v3, pre-fetch ProgramData accounts to verify which programs are active.
    let programdata_slots: HashMap<Pubkey, u64> = if loader_versions.contains(&3) {
        fetch_all_programdata_accounts(&rpc_client)?
    } else {
        HashMap::new()
    };

    let mut grand_total: usize = 0;

    for loader_version in &loader_versions {
        let loader_name = loader_version_name(*loader_version);

        let programs = fetch_programs_for_loader(&rpc_client, *loader_version)?;

        // For v3, filter to only programs with a known ProgramData account
        // (i.e. the program is active and has an ELF deployed).
        let program_ids: Vec<Pubkey> = if *loader_version == 3 {
            programs
                .into_iter()
                .filter(|(pubkey, ..)| {
                    derive_programdata_address(pubkey)
                        .ok()
                        .is_some_and(|pd| programdata_slots.contains_key(&pd))
                })
                .map(|(pubkey, ..)| pubkey)
                .collect()
        } else {
            programs.into_iter().map(|(pubkey, ..)| pubkey).collect()
        };

        let count = program_ids.len();
        if count == 0 {
            println!("{}:  0 programs (skipped)", loader_name);
            continue;
        }

        grand_total += count;

        let file_path = format!(
            "{}/{}-program-ids-{}-{}.txt",
            output_dir, timestamp, network, loader_version_label(*loader_version)
        );
        let mut file = File::create(&file_path)
            .with_context(|| format!("Failed to create {}", file_path))?;
        for pubkey in &program_ids {
            writeln!(file, "{}", pubkey)?;
        }

        println!("{}:  {} programs -> {}", loader_name, count, file_path);
    }

    println!("\nTotal:  {} programs", grand_total);

    Ok(())
}

/// Parse program IDs from either repeated `--id` args or a file.
fn parse_program_ids(ids: Vec<String>, file: Option<String>) -> Result<Vec<Pubkey>> {
    let raw: Vec<String> = if !ids.is_empty() {
        ids
    } else if let Some(file_path) = file {
        let f = File::open(&file_path)
            .with_context(|| format!("Failed to open file: {}", file_path))?;
        BufReader::new(f)
            .lines()
            .filter_map(|line| {
                let line = line.ok()?;
                let trimmed = line.trim().to_string();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            })
            .collect()
    } else {
        anyhow::bail!("Either --ids or --file must be specified");
    };

    if raw.is_empty() {
        anyhow::bail!("No program IDs provided");
    }

    raw.iter()
        .map(|s| {
            Pubkey::from_str(s.trim())
                .with_context(|| format!("Invalid program ID: {}", s))
        })
        .collect()
}

const USAGE_SIG_LIMIT: usize = 300;
const USAGE_CHUNK_SIZE: usize = 10;
const USAGE_CHUNK_SLEEP_SECS: u64 = 5;

/// LoaderV4State size: slot(8) + authority(32) + status(8).
const LOADERV4_STATE_SIZE: usize = 48;

/// Parse the SBPF version out of an ELF header. The version is stored in
/// `e_flags` (u32 LE at byte offset 48 of the ELF header). Returns `None`
/// if the buffer is too short or lacks the ELF magic.
fn sbpf_version_from_elf_header(elf_bytes: &[u8]) -> Option<u32> {
    if elf_bytes.len() < 52 || !elf_bytes.starts_with(ELF_MAGIC) {
        return None;
    }
    Some(u32::from_le_bytes(elf_bytes[48..52].try_into().ok()?))
}

/// Parse just the upgrade authority and SBPF version from a ProgramData
/// account slice. Unlike `parse_programdata`, this does not require the full
/// ELF — only enough bytes to cover the authority (45) and ELF header (52).
fn parse_programdata_header(data: &[u8]) -> Result<(Option<Pubkey>, Option<u32>)> {
    if data.len() < 45 {
        anyhow::bail!("ProgramData slice too small");
    }
    let discriminator = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if discriminator != PROGRAMDATA_DISCRIMINATOR {
        anyhow::bail!("Invalid ProgramData discriminator: {}", discriminator);
    }
    let option_tag = data[12];
    let pubkey_bytes: [u8; 32] = data[13..45].try_into()?;
    let upgrade_authority = match option_tag {
        0 => None,
        1 => Some(Pubkey::new_from_array(pubkey_bytes)),
        _ => anyhow::bail!("Invalid Option tag: {}", option_tag),
    };
    let sbpf_version = if data.len() >= 45 + 52 {
        sbpf_version_from_elf_header(&data[45..])
    } else {
        None
    };
    Ok((upgrade_authority, sbpf_version))
}

/// Parse the LoaderV4 status and SBPF version from a program account slice.
/// Status is a `u64` LE at offset 40 (slot 8 + authority 32); the ELF starts
/// at offset 48.
fn parse_loaderv4_header(data: &[u8]) -> Result<(u64, Option<u32>)> {
    if data.len() < LOADERV4_STATE_SIZE {
        anyhow::bail!("LoaderV4 account too small");
    }
    let status = u64::from_le_bytes(data[40..48].try_into()?);
    let sbpf_version = if data.len() >= LOADERV4_STATE_SIZE + 52 {
        sbpf_version_from_elf_header(&data[LOADERV4_STATE_SIZE..])
    } else {
        None
    };
    Ok((status, sbpf_version))
}

/// Finalization classification for a program entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalizationStatus {
    /// v1/v2: no authority concept — always immutable.
    Immutable,
    /// v3 with an upgrade authority, or v4 `Deployed` (editable).
    Upgradeable,
    /// v3 with `None` authority, or v4 `Finalized`.
    Finalized,
    /// v4 `Retracted` (not executable, still editable).
    Retracted,
    /// Unparseable or unrecognized status.
    Unknown,
}

fn finalization_label(status: FinalizationStatus) -> &'static str {
    match status {
        FinalizationStatus::Immutable => "immutable",
        FinalizationStatus::Upgradeable => "upgradeable",
        FinalizationStatus::Finalized => "finalized",
        FinalizationStatus::Retracted => "retracted",
        FinalizationStatus::Unknown => "unknown",
    }
}

/// A single program's profile entry.
pub struct ProfileEntry {
    pub pubkey: Pubkey,
    pub loader_version: i32,
    /// Raw `e_flags` value from the ELF header, or `None` if unreadable.
    pub sbpf_version: Option<u32>,
    pub finalization: FinalizationStatus,
}

fn sbpf_label(version: Option<u32>) -> String {
    match version {
        Some(v @ 0..=3) => format!("v{}", v),
        Some(v) => format!("?({})", v),
        None => "-".to_string(),
    }
}

/// Bucket index for a summary row: 0=v0, 1=v1, 2=v2, 3=v3, 4=unknown.
fn sbpf_bucket(version: Option<u32>) -> usize {
    match version {
        Some(0) => 0,
        Some(1) => 1,
        Some(2) => 2,
        Some(3) => 3,
        _ => 4,
    }
}

fn format_sbpf_row(counts: &[usize; 5]) -> String {
    format!(
        "v0: {}  v1: {}  v2: {}  v3: {}  unknown: {}",
        counts[0], counts[1], counts[2], counts[3], counts[4]
    )
}

/// Fetch v1/v2 program accounts with enough ELF header bytes to read SBPF version.
fn fetch_profile_v1_v2(
    rpc_client: &RpcClient,
    loader_version: i32,
) -> Result<Vec<ProfileEntry>> {
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
        ">>> PROFILING LOADER V{} PROGRAMS",
        loader_version
    ));
    spinner.enable_steady_tick(std::time::Duration::from_millis(80));

    let config = RpcProgramAccountsConfig {
        filters: None,
        account_config: RpcAccountInfoConfig {
            encoding: Some(solana_account_decoder::UiAccountEncoding::Base64),
            commitment: Some(CommitmentConfig::confirmed()),
            data_slice: Some(solana_account_decoder::UiDataSliceConfig {
                offset: 0,
                length: 128,
            }),
            min_context_slot: None,
        },
        with_context: None,
        sort_results: None,
    };

    let accounts = rpc_client.get_program_accounts_with_config(&loader_pubkey, config)?;

    let entries: Vec<ProfileEntry> = accounts
        .into_iter()
        .filter(|(_, acc)| acc.executable)
        .map(|(pubkey, acc)| ProfileEntry {
            pubkey,
            loader_version,
            sbpf_version: sbpf_version_from_elf_header(&acc.data),
            finalization: FinalizationStatus::Immutable,
        })
        .collect();

    spinner.finish_with_message(format!(
        ">>> PROFILED {} ACTIVE LOADER V{} PROGRAMS",
        entries.len(),
        loader_version
    ));
    Ok(entries)
}

/// Fetch v3 programs: Program accounts provide IDs, ProgramData accounts
/// provide the authority + ELF header. Joined via `derive_programdata_address`.
fn fetch_profile_v3(rpc_client: &RpcClient) -> Result<Vec<ProfileEntry>> {
    let loader_pubkey = Pubkey::from_str(BPF_LOADER_UPGRADEABLE)?;

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    spinner.set_message(">>> FETCHING BPFLoaderUpgradeable PROGRAM ACCOUNTS");
    spinner.enable_steady_tick(std::time::Duration::from_millis(80));

    // 1. Program accounts (discriminator 2): just need pubkeys.
    let program_config = RpcProgramAccountsConfig {
        filters: Some(vec![RpcFilterType::Memcmp(Memcmp::new_raw_bytes(
            0,
            vec![2, 0, 0, 0],
        ))]),
        account_config: RpcAccountInfoConfig {
            encoding: Some(solana_account_decoder::UiAccountEncoding::Base64),
            commitment: Some(CommitmentConfig::confirmed()),
            data_slice: Some(solana_account_decoder::UiDataSliceConfig {
                offset: 0,
                length: 4,
            }),
            min_context_slot: None,
        },
        with_context: None,
        sort_results: None,
    };
    let program_accounts =
        rpc_client.get_program_accounts_with_config(&loader_pubkey, program_config)?;
    let program_pubkeys: Vec<Pubkey> = program_accounts
        .into_iter()
        .filter_map(|(pk, acc)| if acc.executable { Some(pk) } else { None })
        .collect();

    spinner.set_message(format!(
        ">>> FETCHING PROGRAMDATA ({} programs)",
        program_pubkeys.len()
    ));

    // 2. ProgramData accounts (discriminator 3): pull enough to cover authority + ELF header.
    let pd_config = RpcProgramAccountsConfig {
        filters: Some(vec![RpcFilterType::Memcmp(Memcmp::new_raw_bytes(
            0,
            vec![3, 0, 0, 0],
        ))]),
        account_config: RpcAccountInfoConfig {
            encoding: Some(solana_account_decoder::UiAccountEncoding::Base64),
            commitment: Some(CommitmentConfig::confirmed()),
            data_slice: Some(solana_account_decoder::UiDataSliceConfig {
                offset: 0,
                length: 128,
            }),
            min_context_slot: None,
        },
        with_context: None,
        sort_results: None,
    };
    let pd_accounts = rpc_client.get_program_accounts_with_config(&loader_pubkey, pd_config)?;

    let mut pd_map: HashMap<Pubkey, (Option<Pubkey>, Option<u32>)> =
        HashMap::with_capacity(pd_accounts.len());
    for (pd_pubkey, acc) in pd_accounts {
        if let Ok(parsed) = parse_programdata_header(&acc.data) {
            pd_map.insert(pd_pubkey, parsed);
        }
    }

    // 3. Join Program → ProgramData.
    let mut entries = Vec::with_capacity(program_pubkeys.len());
    for pk in program_pubkeys {
        let pd_addr = derive_programdata_address(&pk)?;
        if let Some((authority, sbpf)) = pd_map.get(&pd_addr) {
            let finalization = if authority.is_none() {
                FinalizationStatus::Finalized
            } else {
                FinalizationStatus::Upgradeable
            };
            entries.push(ProfileEntry {
                pubkey: pk,
                loader_version: 3,
                sbpf_version: *sbpf,
                finalization,
            });
        }
    }

    spinner.finish_with_message(format!(
        ">>> PROFILED {} ACTIVE BPFLoaderUpgradeable PROGRAMS",
        entries.len()
    ));
    Ok(entries)
}

/// Fetch v4 program accounts: state (48 bytes) + ELF header in a single slice.
fn fetch_profile_v4(rpc_client: &RpcClient) -> Result<Vec<ProfileEntry>> {
    let loader_pubkey = Pubkey::from_str(LOADER_V4)?;

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    spinner.set_message(">>> PROFILING LoaderV4 PROGRAMS");
    spinner.enable_steady_tick(std::time::Duration::from_millis(80));

    let config = RpcProgramAccountsConfig {
        filters: None,
        account_config: RpcAccountInfoConfig {
            encoding: Some(solana_account_decoder::UiAccountEncoding::Base64),
            commitment: Some(CommitmentConfig::confirmed()),
            data_slice: Some(solana_account_decoder::UiDataSliceConfig {
                offset: 0,
                length: 128,
            }),
            min_context_slot: None,
        },
        with_context: None,
        sort_results: None,
    };
    let accounts = rpc_client.get_program_accounts_with_config(&loader_pubkey, config)?;

    let entries: Vec<ProfileEntry> = accounts
        .into_iter()
        .filter_map(|(pk, acc)| {
            let (status, sbpf) = parse_loaderv4_header(&acc.data).ok()?;
            let finalization = match status {
                0 => FinalizationStatus::Retracted,
                1 => FinalizationStatus::Upgradeable,
                2 => FinalizationStatus::Finalized,
                _ => FinalizationStatus::Unknown,
            };
            Some(ProfileEntry {
                pubkey: pk,
                loader_version: 4,
                sbpf_version: sbpf,
                finalization,
            })
        })
        .collect();

    spinner.finish_with_message(format!(
        ">>> PROFILED {} ACTIVE LoaderV4 PROGRAMS",
        entries.len()
    ));
    Ok(entries)
}

/// Fetch profile entries for a given loader.
pub fn fetch_profile_for_loader(
    rpc_client: &RpcClient,
    loader_version: i32,
) -> Result<Vec<ProfileEntry>> {
    match loader_version {
        1 | 2 => fetch_profile_v1_v2(rpc_client, loader_version),
        3 => fetch_profile_v3(rpc_client),
        4 => fetch_profile_v4(rpc_client),
        _ => anyhow::bail!("Invalid loader version: {}", loader_version),
    }
}

/// RPC profile command: for each loader, report a per-program SBPF version
/// and finalization classification. Writes a per-program CSV-ish table to
/// `rpc-out/<ts>-profile-<network>.txt` and a summary to stdout.
pub fn profile_command(loader_versions: Vec<i32>, rpc_url: String) -> Result<()> {
    let network = rpc_network_name(&rpc_url);
    let rpc_client = RpcClient::new(&rpc_url);

    let output_dir = "rpc-out";
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("Failed to get system time")?
        .as_secs();

    fs::create_dir_all(output_dir).context("Failed to create output directory")?;
    let file_path = format!("{}/{}-profile-{}.txt", output_dir, timestamp, network);

    println!("\nRPC Profile");
    println!("Network:  {}", network);
    println!("Output:   {}", file_path);
    println!();

    let mut out_file =
        File::create(&file_path).with_context(|| format!("Failed to create {}", file_path))?;
    writeln!(out_file, "# RPC Profile Report")?;
    writeln!(out_file, "# Network:   {}", network)?;
    writeln!(out_file, "# Timestamp: {}", timestamp)?;
    writeln!(out_file, "#")?;
    writeln!(
        out_file,
        "# {:<44}  {:<6}  {:<6}  Status",
        "Program", "Loader", "SBPF"
    )?;

    let mut grand_total = 0usize;

    for loader_version in &loader_versions {
        let name = loader_version_name(*loader_version);
        let entries = fetch_profile_for_loader(&rpc_client, *loader_version)?;
        let count = entries.len();
        if count == 0 {
            println!("{}:  0 programs (skipped)", name);
            println!();
            continue;
        }
        grand_total += count;

        // Summary counts, bucketed by SBPF version (v0, v1, v2, v3, unknown).
        let mut total = [0usize; 5];
        let mut immutable = [0usize; 5];
        let mut upgradeable = [0usize; 5];
        let mut finalized = [0usize; 5];
        let mut retracted = [0usize; 5];
        for e in &entries {
            let b = sbpf_bucket(e.sbpf_version);
            total[b] += 1;
            match e.finalization {
                FinalizationStatus::Immutable => immutable[b] += 1,
                FinalizationStatus::Upgradeable => upgradeable[b] += 1,
                FinalizationStatus::Finalized => finalized[b] += 1,
                FinalizationStatus::Retracted => retracted[b] += 1,
                FinalizationStatus::Unknown => {}
            }
        }

        println!("{}  ({} programs)", name, count);
        println!("  SBPF:      {}", format_sbpf_row(&total));
        match loader_version {
            1 | 2 => println!("  Finalized: {}", format_sbpf_row(&immutable)),
            3 => println!("  Finalized: {}", format_sbpf_row(&finalized)),
            4 => {
                println!("  Finalized: {}", format_sbpf_row(&finalized));
                println!("  Deployed:  {}", format_sbpf_row(&upgradeable));
                println!("  Retracted: {}", format_sbpf_row(&retracted));
            }
            _ => {}
        }
        println!();

        // Per-program rows.
        for e in &entries {
            writeln!(
                out_file,
                "  {:<44}  v{:<5}  {:<6}  {}",
                e.pubkey,
                e.loader_version,
                sbpf_label(e.sbpf_version),
                finalization_label(e.finalization),
            )?;
        }
    }

    println!("Total:  {} programs", grand_total);
    println!("Output: {}", file_path);

    Ok(())
}

/// Build a slot distribution sparkline for a set of signature slots.
///
/// Divides the range [oldest_slot, current_slot] into `num_buckets` equal-width
/// buckets and counts how many signatures land in each. Returns a string like
/// "▁▂▅▇█" where left = oldest, right = most recent.
fn slot_sparkline(sig_slots: &[u64], current_slot: u64, num_buckets: usize) -> String {
    if sig_slots.is_empty() || num_buckets == 0 {
        return String::new();
    }

    let oldest = *sig_slots.iter().min().unwrap();
    let range = current_slot.saturating_sub(oldest);
    if range == 0 {
        // All signatures in same slot
        return "█".repeat(num_buckets);
    }

    let bucket_width = (range as f64) / (num_buckets as f64);
    let mut buckets = vec![0u32; num_buckets];

    for &slot in sig_slots {
        let idx = ((slot.saturating_sub(oldest) as f64) / bucket_width) as usize;
        let idx = idx.min(num_buckets - 1);
        buckets[idx] += 1;
    }

    let max_count = *buckets.iter().max().unwrap_or(&1);
    let bars = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

    buckets
        .iter()
        .map(|&count| {
            if count == 0 {
                ' '
            } else {
                let level = ((count as f64 / max_count as f64) * 7.0) as usize;
                bars[level.min(7)]
            }
        })
        .collect()
}

/// Format a slot count with a human-readable time estimate.
/// Solana produces roughly 2.5 slots/sec → ~400ms per slot.
fn format_slot_age(elapsed_slots: u64) -> String {
    let seconds = elapsed_slots as f64 * 0.4;
    if seconds < 60.0 {
        format!("{:.0}s", seconds)
    } else if seconds < 3600.0 {
        format!("{:.1}m", seconds / 60.0)
    } else if seconds < 86400.0 {
        format!("{:.1}h", seconds / 3600.0)
    } else {
        format!("{:.1}d", seconds / 86400.0)
    }
}

/// Result for a single program's usage query.
struct UsageResult {
    sig_count: usize,
    oldest_slot: Option<u64>,
    newest_slot: Option<u64>,
    sig_slots: Vec<u64>,
}

/// Fetch usage signatures for a single program.
fn fetch_usage_for_program(
    rpc_client: &RpcClient,
    pubkey: &Pubkey,
) -> Result<UsageResult> {
    let config = GetConfirmedSignaturesForAddress2Config {
        limit: Some(USAGE_SIG_LIMIT),
        commitment: Some(CommitmentConfig::confirmed()),
        ..Default::default()
    };

    let sigs = rpc_client
        .get_signatures_for_address_with_config(pubkey, config)
        .with_context(|| format!("Failed to get signatures for {}", pubkey))?;

    let sig_count = sigs.len();
    let sig_slots: Vec<u64> = sigs.iter().map(|s| s.slot).collect();
    let oldest_slot = sig_slots.iter().copied().min();
    let newest_slot = sig_slots.iter().copied().max();

    Ok(UsageResult {
        sig_count,
        oldest_slot,
        newest_slot,
        sig_slots,
    })
}

/// RPC usage command: fetch transaction signature counts for a list of program
/// IDs. Outputs per-program stats to stdout and appends to a file under
/// `rpc-out/` as each program is processed.
pub fn usage_command(
    ids: Vec<String>,
    file: Option<String>,
    rpc_url: String,
) -> Result<()> {
    let program_ids = parse_program_ids(ids, file)?;
    let network = rpc_network_name(&rpc_url);
    let rpc_client = RpcClient::new(&rpc_url);

    let output_dir = "rpc-out";
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("Failed to get system time")?
        .as_secs();

    fs::create_dir_all(output_dir).context("Failed to create output directory")?;

    let file_path = format!("{}/{}-usage-{}.txt", output_dir, timestamp, network);

    // Get current slot upfront (use confirmed to match signature queries).
    let current_slot = rpc_client
        .get_slot_with_commitment(CommitmentConfig::confirmed())
        .context("Failed to get current slot")?;

    println!("\nRPC Usage");
    println!("Network:       {}", network);
    println!("Programs:      {}", program_ids.len());
    println!("Sig limit:     {} (RPC max 1000, clamped)", USAGE_SIG_LIMIT);
    println!("Current slot:  {}", current_slot);
    println!("Output:        {}", file_path);
    println!();

    // Write file header.
    {
        let mut f = File::create(&file_path)
            .with_context(|| format!("Failed to create {}", file_path))?;
        writeln!(f, "# RPC Usage Report")?;
        writeln!(f, "# Network:      {}", network)?;
        writeln!(f, "# Current slot: {}", current_slot)?;
        writeln!(f, "# Sig limit:    {}", USAGE_SIG_LIMIT)?;
        writeln!(f, "# Programs:     {}", program_ids.len())?;
        writeln!(f, "#")?;
        writeln!(
            f,
            "# {:<44}  {:>5}  {:>12}  {:>12}  {:>12}  {:>8}  {}",
            "Program", "Sigs", "Newest Slot", "Oldest Slot", "Span", "Age", "Distribution"
        )?;
    }

    let chunks: Vec<&[Pubkey]> = program_ids.chunks(USAGE_CHUNK_SIZE).collect();
    let num_chunks = chunks.len();
    let mut total_programs = 0usize;
    let mut total_sigs = 0usize;
    let mut total_errors = 0usize;

    for (chunk_idx, chunk) in chunks.iter().enumerate() {
        if chunk_idx > 0 {
            println!(
                "  ... sleeping {}s before next chunk ({}/{}) ...",
                USAGE_CHUNK_SLEEP_SECS,
                chunk_idx + 1,
                num_chunks,
            );
            std::thread::sleep(std::time::Duration::from_secs(USAGE_CHUNK_SLEEP_SECS));
        }

        for pubkey in *chunk {
            total_programs += 1;

            let result = fetch_usage_for_program(&rpc_client, pubkey);

            // Append to file immediately so partial runs are recoverable.
            let mut f = OpenOptions::new()
                .append(true)
                .open(&file_path)
                .with_context(|| format!("Failed to open {} for append", file_path))?;

            match result {
                Ok(usage) => {
                    total_sigs += usage.sig_count;

                    let capped = if usage.sig_count >= USAGE_SIG_LIMIT {
                        "+"
                    } else {
                        ""
                    };

                    if usage.sig_count == 0 {
                        println!(
                            "  {}  sigs: 0/{}",
                            pubkey, USAGE_SIG_LIMIT,
                        );
                        writeln!(
                            f,
                            "  {:<44}  {:>5}  {:>12}  {:>12}  {:>12}  {:>8}",
                            pubkey, 0, "-", "-", "-", "-",
                        )?;
                    } else {
                        let newest = usage.newest_slot.unwrap();
                        let oldest = usage.oldest_slot.unwrap();
                        let span = newest.saturating_sub(oldest);
                        let age = current_slot.saturating_sub(newest);
                        let age_str = format_slot_age(age);
                        let sparkline = slot_sparkline(&usage.sig_slots, current_slot, 10);

                        println!(
                            "  {}  sigs: {}{}/{}  newest: {}  oldest: {}  span: {}  age: {} ({} slots)  [{}]",
                            pubkey,
                            usage.sig_count,
                            capped,
                            USAGE_SIG_LIMIT,
                            newest,
                            oldest,
                            span,
                            age_str,
                            age,
                            sparkline,
                        );
                        writeln!(
                            f,
                            "  {:<44}  {:>4}{}  {:>12}  {:>12}  {:>12}  {:>8}  [{}]",
                            pubkey,
                            usage.sig_count,
                            capped,
                            newest,
                            oldest,
                            span,
                            age_str,
                            sparkline,
                        )?;
                    }
                }
                Err(e) => {
                    total_errors += 1;
                    let err_msg = format!("{}", e);
                    println!("  {}  ERROR: {}", pubkey, err_msg);
                    writeln!(f, "  {:<44}  ERROR: {}", pubkey, err_msg)?;
                }
            }
        }
    }

    println!();
    println!("Total programs:    {}", total_programs);
    println!("Total signatures:  {}", total_sigs);
    if total_errors > 0 {
        println!("Errors:            {}", total_errors);
    }
    println!("Output:            {}", file_path);

    Ok(())
}
