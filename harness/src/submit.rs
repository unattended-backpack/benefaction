use std::fs;

use eyre::Context;

use crate::anvil::{cast_send, cast_send_may_revert};
use crate::util::Tools;

/// Read proof artifacts from the circuit's target/proof/ directory and submit
/// the ZK mint on-chain via `cast send`.
///
/// Returns Ok(SubmitResult::Success{..}) if the transaction succeeded, or a
/// recognized revert variant, or Err for unexpected failures.
///
/// The caller supplies `recipient`, `fee_data`, and `total_minted_encrypted`
/// because these are NOT in the public inputs (bound via EIP-712 hash instead).
pub fn submit_zk_mint(
    tools: &Tools,
    rpc_url: &str,
    token: &str,
    circuit_dir: &str,
    sender_key: &str,
    recipient: &str,
    fee_tuple: &str,
    total_minted_encrypted: &[String],
    verbose: bool,
) -> eyre::Result<SubmitResult> {
    let proof_path = format!("{}/target/proof/proof", circuit_dir);
    let inputs_path = format!("{}/target/proof/public_inputs", circuit_dir);

    // Read raw proof bytes.
    let proof_bytes = fs::read(&proof_path)
        .wrap_err_with(|| format!("failed to read proof at {}", proof_path))?;
    let proof_hex = format!("0x{}", hex::encode(&proof_bytes));

    // Read public inputs as raw binary: 67 × 32-byte big-endian values.
    let inputs_bytes = fs::read(&inputs_path)
        .wrap_err_with(|| format!("failed to read public inputs at {}", inputs_path))?;

    if inputs_bytes.len() < 67 * 32 {
        eyre::bail!(
            "expected at least {} bytes of public inputs, got {}",
            67 * 32,
            inputs_bytes.len()
        );
    }

    // Decode each 32-byte chunk as a 0x-prefixed hex string.
    let inputs: Vec<String> = (0..67)
        .map(|i| {
            let chunk = &inputs_bytes[i * 32..(i + 1) * 32];
            format!("0x{}", hex::encode(chunk))
        })
        .collect();

    // Public inputs layout (Noir interleaved struct serialization):
    // [0]        amount
    // [1]        signatureHash
    // [2]        burn[0].accountNoteHash
    // [3]        burn[0].accountNoteNullifier
    // [4]        burn[1].accountNoteHash
    // [5]        burn[1].accountNoteNullifier
    // ...
    // [64]       burn[31].accountNoteHash
    // [65]       burn[31].accountNoteNullifier
    // [66]       root
    let amount = &inputs[0];

    // Collect active note hashes and nullifiers (skip zero entries).
    let mut nullifiers: Vec<String> = Vec::new();
    let mut burn_tuples: Vec<String> = Vec::new();
    for i in 0..32 {
        let hash = &inputs[2 + i * 2];
        let null = &inputs[3 + i * 2];
        let is_zero = hash == "0x0000000000000000000000000000000000000000000000000000000000000000";
        if is_zero {
            break;
        }
        nullifiers.push(null.clone());
        // BurnInput tuple: (accountNoteHash, accountNoteNullifier, totalMintedEncrypted)
        let tse = total_minted_encrypted.get(i)
            .map(|s| s.as_str())
            .unwrap_or("0x0000000000000000000000000000000000000000000000000000000000000000");
        burn_tuples.push(format!("({},{},{})", hash, null, tse));
    }

    let root = &inputs[66];

    if verbose {
        eprintln!(
            "[submit] amount={} recipient={} burns={} root={}",
            amount, recipient, burn_tuples.len(), root,
        );
    }

    // Format BurnInput[] for cast: [(hash,null,tse),(hash,null,tse),...]
    let burns_str = format!("[{}]", burn_tuples.join(","));

    // zkMint(uint256,address,(address,uint256,uint256,uint256),(uint256,uint256,bytes)[],uint256,bytes)
    let sig = "zkMint(uint256,address,(address,uint256,uint256,uint256),(uint256,uint256,bytes)[],uint256,bytes)";

    let result = cast_send_may_revert(
        tools,
        rpc_url,
        token,
        sig,
        &[amount, recipient, fee_tuple, &burns_str, root, &proof_hex],
        sender_key,
        verbose,
    );

    match result {
        Ok(_) => Ok(SubmitResult::Success {
            nullifiers,
            amount: amount.clone(),
        }),
        Err(err_msg) => {
            if err_msg.contains("RateLimitExceeded") {
                Ok(SubmitResult::RateLimited)
            } else if err_msg.contains("NullifierAlreadyExists") {
                Ok(SubmitResult::NullifierExists)
            } else if err_msg.contains("InvalidRoot") {
                Ok(SubmitResult::InvalidRoot)
            } else {
                eyre::bail!("zkMint reverted: {}", err_msg)
            }
        }
    }
}

/// Result of a ZK mint submission.
pub enum SubmitResult {
    Success {
        nullifiers: Vec<String>,
        #[allow(dead_code)]
        amount: String,
    },
    RateLimited,
    NullifierExists,
    InvalidRoot,
}

/// Submit a burn (public transfer to burn address).
pub fn submit_burn(
    tools: &Tools,
    rpc_url: &str,
    token: &str,
    burn_address: &str,
    amount: u128,
    sender_key: &str,
    verbose: bool,
) -> eyre::Result<()> {
    cast_send(
        tools,
        rpc_url,
        token,
        "transfer(address,uint256)",
        &[burn_address, &amount.to_string()],
        sender_key,
        verbose,
    )?;
    Ok(())
}

/// Submit a public transfer.
pub fn submit_public_transfer(
    tools: &Tools,
    rpc_url: &str,
    token: &str,
    recipient: &str,
    amount: u128,
    sender_key: &str,
    verbose: bool,
) -> eyre::Result<()> {
    cast_send(
        tools,
        rpc_url,
        token,
        "transfer(address,uint256)",
        &[recipient, &amount.to_string()],
        sender_key,
        verbose,
    )?;
    Ok(())
}

