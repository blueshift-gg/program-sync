use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use solana_client::rpc_client::RpcClient;
use solana_client::rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig};
use solana_client::rpc_filter::{Memcmp, RpcFilterType};
use solana_program::pubkey::Pubkey;
use solana_commitment_config::CommitmentConfig;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
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
