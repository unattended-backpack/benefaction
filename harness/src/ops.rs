use std::fs;

use ark_bn254::Fr;
use ark_ff::Zero;
use rand::Rng;
use rand_chacha::ChaCha20Rng;

use crate::anvil::cast_rpc;
use crate::ghost::GhostState;
use crate::tree;
use crate::pipeline::{run_bb, run_inputgen, run_nargo, BurnInputSpec};
use crate::submit::{submit_burn, submit_zk_mint, submit_public_transfer, SubmitResult};
use crate::util::Tools;

/// Anvil's default chain ID.
const CHAIN_ID: u64 = 31337;

/// An operation that the harness can execute.
#[derive(Debug)]
pub enum Op {
    Burn {
        account_idx: usize,
        burn_idx: usize,
        amount: u128,
    },
    ZKMint {
        account_idx: usize,
        burn_mints: Vec<(usize, u128)>,
        amount: u128,
        recipient_idx: usize,
        relay_mode: RelayMode,
    },
    PublicTransfer {
        account_idx: usize,
        recipient_idx: usize,
        amount: u128,
    },
    WarpTime {
        seconds: u64,
    },
}

/// Relay mode for ZK mints.
#[derive(Debug)]
pub enum RelayMode {
    /// Self-relay: relayer = 0, no rewards.
    SelfRelay,
    /// msg.sender relay: relayer = 1, small reward.
    MsgSender { priority_fee: u128, conversion_rate: u128, max_reward: u128 },
    /// Specific relayer address.
    Specific { relayer_idx: usize, priority_fee: u128, conversion_rate: u128, max_reward: u128 },
}

impl std::fmt::Display for Op {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Op::Burn { account_idx, burn_idx, amount } => {
                write!(
                    f, "Burn: acct[{}].burn[{}] burns {} tokens",
                    account_idx, burn_idx, format_tokens(*amount),
                )
            }
            Op::ZKMint { account_idx, burn_mints, amount, recipient_idx, relay_mode } => {
                let mode = match relay_mode {
                    RelayMode::SelfRelay => "self",
                    RelayMode::MsgSender { .. } => "msg.sender",
                    RelayMode::Specific { .. } => "specific relayer",
                };
                if burn_mints.len() == 1 {
                    write!(
                        f, "ZKMint ({}): acct[{}].burn[{}] → acct[{}], {} tokens",
                        mode, account_idx, burn_mints[0].0, recipient_idx,
                        format_tokens(*amount),
                    )
                } else {
                    let breakdown: Vec<String> = burn_mints
                        .iter()
                        .map(|(bi, s)| format!("burn[{}]={}", bi, format_tokens(*s)))
                        .collect();
                    write!(
                        f, "ZKMint multi-burn ({}): acct[{}] [{}] → acct[{}], {} tokens",
                        mode, account_idx, breakdown.join(", "), recipient_idx,
                        format_tokens(*amount),
                    )
                }
            }
            Op::PublicTransfer { account_idx, recipient_idx, amount } => {
                write!(
                    f, "PublicTransfer: acct[{}] → acct[{}], {} tokens",
                    account_idx, recipient_idx, format_tokens(*amount),
                )
            }
            Op::WarpTime { seconds } => {
                write!(f, "WarpTime: +{}s", seconds)
            }
        }
    }
}

fn format_tokens(amount: u128) -> String {
    let whole = amount / 1_000_000_000_000_000_000;
    let frac = amount % 1_000_000_000_000_000_000;
    if frac == 0 {
        whole.to_string()
    } else {
        format!("{}.{}", whole, frac)
    }
}

/// 1 token in wei.
const ONE_TOKEN: u128 = 1_000_000_000_000_000_000;

/// Pick a random operation based on the current ghost state.
pub fn pick_operation(rng: &mut ChaCha20Rng, ghost: &GhostState) -> Op {
    let num_accounts = ghost.account_state.len();
    let mut candidates: Vec<(u32, Op)> = Vec::new();

    // Burn candidates (weight 30): for each account with positive balance, randomly pick a burn index.
    for (i, acct) in ghost.account_state.iter().enumerate() {
        let addr_lc = acct.address.to_lowercase();
        let balance = ghost.balances.get(&addr_lc).copied().unwrap_or(0);
        if balance > 0 {
            let max_burn = std::cmp::min(balance, 100 * ONE_TOKEN);
            let amount = rng.random_range(ONE_TOKEN..=max_burn);
            let burn_idx = rng.random_range(0..acct.burns.len());
            candidates.push((30, Op::Burn { account_idx: i, burn_idx, amount }));
        }
    }

    // Single-burn ZKMint (weight 25): for each (account, burn) with unminted >= 1 token.
    for (i, acct) in ghost.account_state.iter().enumerate() {
        for (bi, _burn) in acct.burns.iter().enumerate() {
            let unminted = ghost.unminted_burn_balance(i, bi);
            if unminted >= ONE_TOKEN {
                let max_amount = std::cmp::min(unminted, 50 * ONE_TOKEN);
                let amount = rng.random_range(ONE_TOKEN..=max_amount);
                let recipient_idx = rng.random_range(0..num_accounts);
                let relay_mode = pick_relay_mode(rng, ghost, amount);

                candidates.push((25, Op::ZKMint {
                    account_idx: i,
                    burn_mints: vec![(bi, amount)],
                    amount,
                    recipient_idx,
                    relay_mode,
                }));
            }
        }
    }

    // Multi-burn ZKMint (weight 15): accounts with 2+ burns each having >= 1 token unminted.
    for (i, acct) in ghost.account_state.iter().enumerate() {
        let eligible: Vec<(usize, u128)> = acct.burns.iter().enumerate()
            .map(|(bi, _)| (bi, ghost.unminted_burn_balance(i, bi)))
            .filter(|&(_, u)| u >= ONE_TOKEN)
            .collect();

        if eligible.len() >= 2 {
            // Random split across eligible burns, each >= 1 token.
            let total_available: u128 = eligible.iter().map(|&(_, u)| u).sum();
            let max_total = std::cmp::min(total_available, 80 * ONE_TOKEN);
            if max_total >= eligible.len() as u128 * ONE_TOKEN {
                let total_amount = rng.random_range(eligible.len() as u128 * ONE_TOKEN..=max_total);

                // Split: assign 1 token minimum to each, then distribute remainder randomly.
                let mut mints: Vec<(usize, u128)> = eligible.iter()
                    .map(|&(bi, _)| (bi, ONE_TOKEN))
                    .collect();
                let mut remainder = total_amount - eligible.len() as u128 * ONE_TOKEN;

                // Distribute remainder across burns, respecting per-burn caps.
                for (idx, &(_, unminted)) in eligible.iter().enumerate() {
                    let headroom = unminted - mints[idx].1;
                    if headroom == 0 || remainder == 0 {
                        continue;
                    }
                    let add = rng.random_range(0..=std::cmp::min(headroom, remainder));
                    mints[idx].1 += add;
                    remainder -= add;
                }
                // Give any leftover to the first burn that has room.
                if remainder > 0 {
                    for (idx, &(_, unminted)) in eligible.iter().enumerate() {
                        let headroom = unminted - mints[idx].1;
                        let add = std::cmp::min(headroom, remainder);
                        mints[idx].1 += add;
                        remainder -= add;
                        if remainder == 0 { break; }
                    }
                }

                let actual_total: u128 = mints.iter().map(|&(_, m)| m).sum();
                let recipient_idx = rng.random_range(0..num_accounts);
                let relay_mode = pick_relay_mode(rng, ghost, actual_total);

                candidates.push((15, Op::ZKMint {
                    account_idx: i,
                    burn_mints: mints,
                    amount: actual_total,
                    recipient_idx,
                    relay_mode,
                }));
            }
        }
    }

    // Public transfer candidates.
    for (i, acct) in ghost.account_state.iter().enumerate() {
        let addr_lc = acct.address.to_lowercase();
        let balance = ghost.balances.get(&addr_lc).copied().unwrap_or(0);
        if balance > ONE_TOKEN {
            let max_xfer = std::cmp::min(balance / 2, 50 * ONE_TOKEN);
            let amount = rng.random_range(ONE_TOKEN..=max_xfer);
            let recipient_idx = loop {
                let r = rng.random_range(0..num_accounts);
                if r != i { break r; }
            };
            candidates.push((15, Op::PublicTransfer {
                account_idx: i,
                recipient_idx,
                amount,
            }));
        }
    }

    // Warp time: always available.
    let seconds = rng.random_range(60..=86400 * 2);
    candidates.push((15, Op::WarpTime { seconds }));

    // Weighted random selection.
    if candidates.is_empty() {
        return Op::WarpTime { seconds: 3600 };
    }

    let total_weight: u32 = candidates.iter().map(|(w, _)| *w).sum();
    let mut roll = rng.random_range(0..total_weight);
    for (weight, op) in candidates {
        if roll < weight {
            return op;
        }
        roll -= weight;
    }

    Op::WarpTime { seconds: 3600 }
}

fn pick_relay_mode(rng: &mut ChaCha20Rng, ghost: &GhostState, amount: u128) -> RelayMode {
    let roll: u32 = rng.random_range(0..100);
    if roll < 70 {
        RelayMode::SelfRelay
    } else if roll < 90 {
        let priority_fee: u128 = rng.random_range(1_000_000..=1_000_000_000);
        let conversion_rate: u128 = 1;
        let max_reward = priority_fee * conversion_rate;
        if max_reward >= amount {
            RelayMode::SelfRelay
        } else {
            RelayMode::MsgSender { priority_fee, conversion_rate, max_reward }
        }
    } else {
        let num = ghost.account_state.len();
        let relayer_idx = rng.random_range(0..num);
        let priority_fee: u128 = rng.random_range(1_000_000..=1_000_000_000);
        let conversion_rate: u128 = 1;
        let max_reward = priority_fee * conversion_rate;
        if max_reward >= amount {
            RelayMode::SelfRelay
        } else {
            RelayMode::Specific { relayer_idx, priority_fee, conversion_rate, max_reward }
        }
    }
}

/// Execute an operation, updating the ghost state accordingly.
pub fn execute_op(
    op: &Op,
    ghost: &mut GhostState,
    tools: &Tools,
    rpc_url: &str,
    circuit_dir: &str,
    verbose: bool,
) -> eyre::Result<()> {
    match op {
        Op::Burn { account_idx, burn_idx, amount } => {
            let acct = &ghost.account_state[*account_idx];
            let burn_address = acct.burns[*burn_idx].burn_address.clone();
            submit_burn(
                tools,
                rpc_url,
                &ghost.token_address,
                &burn_address,
                *amount,
                &acct.private_key,
                verbose,
            )?;
            ghost.apply_burn(*account_idx, *burn_idx, *amount);
        }

        Op::ZKMint { account_idx, burn_mints, amount, recipient_idx, relay_mode } => {
            let acct = &ghost.account_state[*account_idx];
            let recipient_addr = ghost.account_state[*recipient_idx].address.clone();

            let (relayer_str, priority_fee, conversion_rate, max_reward) = match relay_mode {
                RelayMode::SelfRelay => ("0".to_string(), 0u128, 0u128, 0u128),
                RelayMode::MsgSender { priority_fee, conversion_rate, max_reward } => {
                    ("1".to_string(), *priority_fee, *conversion_rate, *max_reward)
                }
                RelayMode::Specific { relayer_idx, priority_fee, conversion_rate, max_reward } => {
                    let addr = ghost.account_state[*relayer_idx].address.clone();
                    (addr, *priority_fee, *conversion_rate, *max_reward)
                }
            };

            let prover_toml = format!("{}/Prover.toml", circuit_dir);

            // Build BurnInputSpec for each burn in this proof.
            let burn_input_specs: Vec<BurnInputSpec> = burn_mints.iter().map(|&(bi, mint)| {
                let burn = &acct.burns[bi];
                BurnInputSpec {
                    pow_nonce: burn.pow_nonce.clone(),
                    mint,
                    prev_nonce: burn.account_nonce,
                    prev_total_minted: burn.total_minted,
                    explicit_vk: burn.explicit_vk.clone(),
                }
            }).collect();

            // 1. Generate Prover.toml.
            run_inputgen(
                tools,
                &acct.private_key,
                &burn_input_specs,
                *amount,
                &recipient_addr,
                rpc_url,
                &ghost.token_address,
                CHAIN_ID,
                &relayer_str,
                priority_fee,
                conversion_rate,
                max_reward,
                &prover_toml,
                verbose,
            )?;

            // 2. Generate witness.
            run_nargo(tools, circuit_dir, verbose)?;

            // 3. Generate proof.
            run_bb(tools, circuit_dir, verbose)?;

            // 4. Submit on-chain.
            let submitter_key = match relay_mode {
                RelayMode::SelfRelay | RelayMode::MsgSender { .. } => acct.private_key.clone(),
                RelayMode::Specific { relayer_idx, .. } => {
                    ghost.account_state[*relayer_idx].private_key.clone()
                }
            };

            let reward_relayer = match relay_mode {
                RelayMode::SelfRelay => "0x0000000000000000000000000000000000000000".to_string(),
                RelayMode::MsgSender { .. } => {
                    "0x0000000000000000000000000000000000000001".to_string()
                }
                RelayMode::Specific { relayer_idx, .. } => {
                    ghost.account_state[*relayer_idx].address.clone()
                }
            };
            let reward_tuple = format!(
                "({},{},{},{})", reward_relayer, priority_fee, conversion_rate, max_reward
            );

            // Build per-burn totalMintedEncrypted entries (one per burn, in proof order).
            let total_minted_encrypted: Vec<String> = burn_mints.iter().map(|&(bi, mint)| {
                let burn = &acct.burns[bi];
                let new_total_minted = burn.total_minted + mint;
                let fr_val = u128_to_fr(new_total_minted);
                let be = tree::fr_to_be_bytes(&fr_val);
                format!("0x{}", hex::encode(be))
            }).collect();

            let result = submit_zk_mint(
                tools, rpc_url, &ghost.token_address, circuit_dir,
                &submitter_key, &recipient_addr, &reward_tuple,
                &total_minted_encrypted, verbose,
            )?;

            match result {
                SubmitResult::Success { nullifiers, amount: _ } => {
                    let inputs_path = format!("{}/target/proof/public_inputs", circuit_dir);
                    let inputs_bytes = fs::read(&inputs_path)
                        .map_err(|e| eyre::eyre!("failed to read public inputs: {}", e))?;

                    let mut account_note_hashes: Vec<Fr> = Vec::new();
                    for i in 0..32 {
                        let hash = read_fr_from_inputs(&inputs_bytes, 2 + i * 2)?;
                        if hash.is_zero() {
                            break;
                        }
                        account_note_hashes.push(hash);
                    }

                    let relayer_reward = if priority_fee > 0 {
                        let reward = priority_fee * conversion_rate;
                        std::cmp::min(reward, max_reward)
                    } else {
                        0
                    };

                    let submitter_addr = submitter_key_to_addr(&submitter_key, ghost);

                    let actual_relayer_addr = match relay_mode {
                        RelayMode::SelfRelay => String::new(),
                        RelayMode::MsgSender { .. } => {
                            submitter_addr.clone()
                        }
                        RelayMode::Specific { relayer_idx, .. } => {
                            ghost.account_state[*relayer_idx].address.clone()
                        }
                    };

                    ghost.apply_zk_mint(
                        *account_idx,
                        *amount,
                        burn_mints,
                        &recipient_addr,
                        relayer_reward,
                        &actual_relayer_addr,
                        &nullifiers,
                        &account_note_hashes,
                        &submitter_addr,
                    );
                    eprintln!("  submitted, invariants pending");
                }
                SubmitResult::RateLimited => {
                    eprintln!("  rate limited (expected: {})", ghost.would_exceed_rate_limit(*amount));
                    if !ghost.would_exceed_rate_limit(*amount) {
                        eyre::bail!("unexpected RateLimitExceeded revert");
                    }
                }
                SubmitResult::NullifierExists => {
                    eyre::bail!("unexpected NullifierAlreadyExists revert");
                }
                SubmitResult::InvalidRoot => {
                    eyre::bail!("unexpected InvalidRoot revert");
                }
            }
        }

        Op::PublicTransfer { account_idx, recipient_idx, amount } => {
            let sender_addr = ghost.account_state[*account_idx].address.clone();
            let sender_key = ghost.account_state[*account_idx].private_key.clone();
            let recipient_addr = ghost.account_state[*recipient_idx].address.clone();
            submit_public_transfer(
                tools, rpc_url, &ghost.token_address,
                &recipient_addr, *amount, &sender_key, verbose,
            )?;
            ghost.apply_public_transfer(&sender_addr, &recipient_addr, *amount);
        }

        Op::WarpTime { seconds } => {
            cast_rpc(
                tools, rpc_url, "anvil_increaseTime",
                &[&format!("{}", seconds)],
                verbose,
            )?;
            cast_rpc(
                tools, rpc_url, "anvil_mine",
                &["1"],
                verbose,
            )?;
            ghost.apply_warp(*seconds);
        }
    }

    Ok(())
}

/// Convert a u128 to an ark_bn254::Fr.
fn u128_to_fr(val: u128) -> Fr {
    let lo = Fr::from((val & 0xFFFFFFFFFFFFFFFF) as u64);
    let hi = Fr::from((val >> 64) as u64);
    let two_pow_64 = Fr::from(1u64 << 32) * Fr::from(1u64 << 32);
    hi * two_pow_64 + lo
}

/// Look up the address for a private key in the ghost state.
fn submitter_key_to_addr(key: &str, ghost: &GhostState) -> String {
    if ghost.deployer_key == key {
        return ghost.deployer_address.clone();
    }
    for acct in &ghost.account_state {
        if acct.private_key == key {
            return acct.address.clone();
        }
    }
    String::new()
}

/// Read a BN254 field element from a public inputs binary at the given index.
/// Each element is 32 bytes big-endian, so element `i` is at bytes `i*32..(i+1)*32`.
fn read_fr_from_inputs(bytes: &[u8], index: usize) -> eyre::Result<Fr> {
    let start = index * 32;
    let end = start + 32;
    if bytes.len() < end {
        eyre::bail!("public inputs too short for index {}: {} < {}", index, bytes.len(), end);
    }
    let hex_str = format!("0x{}", hex::encode(&bytes[start..end]));
    tree::parse_fr(&hex_str)
}
