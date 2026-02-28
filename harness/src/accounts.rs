use std::process::Command;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Field};
use eyre::Context;
use rand::Rng;

use crate::ghost::{AccountState, BurnAddressState};
use crate::util::Tools;

/// Anvil's default test mnemonic.
const ANVIL_MNEMONIC: &str = "test test test test test test test test test test test junk";

/// A derived Anvil keypair (private key + address).
pub struct AnvilAccount {
    pub private_key: String,
    pub address: String,
}

/// Derive `count` Anvil accounts (BIP-44 indices 0..count) from the test mnemonic.
///
/// Uses `cast wallet private-key` and `cast wallet address` so there are no
/// hardcoded keys or addresses to get out of sync.
pub fn derive_anvil_accounts(tools: &Tools, count: usize) -> eyre::Result<Vec<AnvilAccount>> {
    let mut accounts = Vec::with_capacity(count);
    for i in 0..count {
        let key_output = Command::new(&tools.cast)
            .args(["wallet", "private-key", ANVIL_MNEMONIC, &i.to_string()])
            .output()
            .wrap_err("failed to run cast wallet private-key")?;
        if !key_output.status.success() {
            let stderr = String::from_utf8_lossy(&key_output.stderr);
            eyre::bail!("cast wallet private-key failed for index {}: {}", i, stderr);
        }
        let private_key = String::from_utf8(key_output.stdout)
            .wrap_err("invalid utf-8 from cast wallet private-key")?
            .trim()
            .to_string();

        let addr_output = Command::new(&tools.cast)
            .args(["wallet", "address", &private_key])
            .output()
            .wrap_err("failed to run cast wallet address")?;
        if !addr_output.status.success() {
            let stderr = String::from_utf8_lossy(&addr_output.stderr);
            eyre::bail!("cast wallet address failed for index {}: {}", i, stderr);
        }
        let address = String::from_utf8(addr_output.stdout)
            .wrap_err("invalid utf-8 from cast wallet address")?
            .trim()
            .to_string();

        accounts.push(AnvilAccount { private_key, address });
    }
    Ok(accounts)
}

/// Mine a single PoW nonce, optionally with an explicit viewing key.
/// Returns (burn_address, pow_nonce).
fn mine_one(
    tools: &Tools,
    private_key: &str,
    chain_id: u64,
    viewing_key: Option<&str>,
    verbose: bool,
) -> eyre::Result<(String, String)> {
    let mut cmd = Command::new(&tools.inputgen);
    cmd.args([
        "mine",
        "--private-key", private_key,
        "--chain-id", &chain_id.to_string(),
    ]);
    if let Some(vk) = viewing_key {
        cmd.args(["--viewing-key", vk]);
    }

    let output = cmd
        .output()
        .wrap_err("failed to run input generator mine")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eyre::bail!("input generator mine failed: {}", stderr);
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if verbose {
        eprint!("{}", stderr);
    }

    let burn_address = parse_field(&stderr, "Burn address:")?;
    let pow_nonce = parse_field(&stderr, "PoW nonce:")?;

    Ok((burn_address, pow_nonce))
}

/// Mine PoW nonces for the given number of accounts.
/// Each account gets two burn addresses: primary (derived VK) and stealth (random VK).
///
/// `anvil_accounts` should contain at least `num_accounts + 1` entries
/// (index 0 is the deployer, test accounts start at index 1).
pub fn mine_accounts(
    tools: &Tools,
    anvil_accounts: &[AnvilAccount],
    num_accounts: usize,
    chain_id: u64,
    verbose: bool,
) -> eyre::Result<Vec<AccountState>> {
    eyre::ensure!(
        num_accounts + 1 <= anvil_accounts.len(),
        "requested {} test accounts but only {} derived (need deployer + N)",
        num_accounts, anvil_accounts.len(),
    );

    let mut accounts = Vec::with_capacity(num_accounts);
    let mut rng = rand::rng();

    for i in 0..num_accounts {
        let acct_idx = i + 1; // skip deployer
        let anvil = &anvil_accounts[acct_idx];

        // Primary burn address (VK derived from private key).
        eprintln!("[setup] Mining primary PoW for account {} ({})...", i, anvil.address);
        let (primary_addr, primary_nonce) =
            mine_one(tools, &anvil.private_key, chain_id, None, verbose)?;

        // Stealth burn address (random VK). Retry until from_random_bytes
        // succeeds — it returns None ~13% of the time when the random value
        // exceeds the BN254 modulus.
        let random_vk = loop {
            let limbs: [u64; 4] = [rng.random(), rng.random(), rng.random(), rng.random()];
            let bytes: Vec<u8> = limbs.iter().flat_map(|l| l.to_le_bytes()).collect();
            if let Some(fr) = Fr::from_random_bytes(&bytes) {
                break format!("0x{}", hex::encode(fr.into_bigint().to_bytes_be()));
            }
        };

        eprintln!("[setup] Mining stealth PoW for account {} (vk={})...", i, &random_vk[..10]);
        let (stealth_addr, stealth_nonce) =
            mine_one(tools, &anvil.private_key, chain_id, Some(&random_vk), verbose)?;

        accounts.push(AccountState {
            private_key: anvil.private_key.clone(),
            address: anvil.address.clone(),
            burns: vec![
                BurnAddressState {
                    burn_address: primary_addr,
                    pow_nonce: primary_nonce,
                    explicit_vk: None,
                    total_burned: 0,
                    total_minted: 0,
                    account_nonce: 0,
                },
                BurnAddressState {
                    burn_address: stealth_addr,
                    pow_nonce: stealth_nonce,
                    explicit_vk: Some(random_vk),
                    total_burned: 0,
                    total_minted: 0,
                    account_nonce: 0,
                },
            ],
        });
    }

    Ok(accounts)
}

/// Parse a "Label: value" field from input generator stderr output.
fn parse_field(output: &str, label: &str) -> eyre::Result<String> {
    for line in output.lines() {
        if let Some(rest) = line.strip_prefix(label) {
            return Ok(rest.trim().to_string());
        }
        // Handle with leading spaces (e.g., "PoW nonce:    0x...")
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(label) {
            return Ok(rest.trim().to_string());
        }
    }
    eyre::bail!("field '{}' not found in output", label)
}
