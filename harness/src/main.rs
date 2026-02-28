mod accounts;
mod anvil;
mod deploy;
mod ghost;
mod tree;
mod ops;
mod pipeline;
mod submit;
mod util;
mod verify;

use std::process::Command;

use clap::Parser;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::accounts::{derive_anvil_accounts, mine_accounts};
use crate::anvil::start_anvil;
use crate::deploy::{deploy_contracts, fund_accounts};
use crate::ghost::GhostState;
use crate::ops::{execute_op, pick_operation};
use crate::util::Tools;
use crate::verify::check_invariants;

#[derive(Parser)]
#[command(name = "sigil-harness")]
#[command(about = "End-to-end ZK mint integration test harness")]
struct Cli {
    /// Randomness seed (default: random, printed at start).
    #[arg(long)]
    seed: Option<u64>,

    /// Number of operations to run.
    #[arg(long, default_value = "50")]
    rounds: usize,

    /// Number of funded test accounts.
    #[arg(long, default_value = "4")]
    accounts: usize,

    /// Anvil port.
    #[arg(long, default_value = "8555")]
    rpc_port: u16,

    /// Skip recompilation of input generator and circuit.
    #[arg(long)]
    skip_build: bool,

    /// Print all shell command output.
    #[arg(long)]
    verbose: bool,
}

/// Initial supply: 1 billion tokens (18 decimals).
const INITIAL_SUPPLY: u128 = 1_000_000_000_000_000_000_000_000_000;

/// Amount given to each test account: 10 million tokens.
const PER_ACCOUNT_AMOUNT: u128 = 10_000_000_000_000_000_000_000_000;

fn main() -> eyre::Result<()> {
    let cli = Cli::parse();

    // Determine seed.
    let seed = cli.seed.unwrap_or_else(|| {
        let s = rand::random::<u64>();
        s
    });
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    eprintln!("=== sigil-harness ===");
    eprintln!("Seed: {}", seed);
    eprintln!("Accounts: {}", cli.accounts);
    eprintln!("Rounds: {}", cli.rounds);
    eprintln!();

    // Resolve tool paths.
    eprintln!("[setup] Resolving tool paths...");
    let tools = Tools::resolve()?;
    eprintln!("[setup] Tools resolved:");
    eprintln!("  anvil:    {}", tools.anvil.display());
    eprintln!("  forge:    {}", tools.forge.display());
    eprintln!("  cast:     {}", tools.cast.display());
    eprintln!("  input generator: {}", tools.inputgen.display());
    eprintln!("  nargo:    {}", tools.nargo.display());
    eprintln!("  bb:       {}", tools.bb.display());

    // Derive Anvil accounts from mnemonic (deployer + N test accounts).
    eprintln!("[setup] Deriving {} Anvil accounts from mnemonic...", cli.accounts + 1);
    let anvil_accounts = derive_anvil_accounts(&tools, cli.accounts + 1)?;
    let deployer = &anvil_accounts[0];
    eprintln!("[setup] Deployer: {}", deployer.address);

    // Resolve project paths.
    let harness_dir = std::env::current_dir()?;
    let project_root = harness_dir
        .parent()
        .ok_or_else(|| eyre::eyre!("cannot find project root"))?;
    let contracts_root = project_root.join("contracts");
    let circuit_dir = project_root.join("circuits");
    let inputgen_dir = project_root.join("input_generator");

    let contracts_root_str = contracts_root.to_string_lossy().to_string();
    let circuit_dir_str = circuit_dir.to_string_lossy().to_string();

    // Build prerequisites.
    if !cli.skip_build {
        eprintln!("[setup] Building input generator...");
        let status = Command::new("cargo")
            .args(["build", "--release"])
            .current_dir(&inputgen_dir)
            .status()?;
        if !status.success() {
            eyre::bail!("failed to build input generator");
        }

        eprintln!("[setup] Compiling Noir circuit (this can take several minutes)...");
        let status = Command::new(tools.nargo.as_os_str())
            .arg("compile")
            .current_dir(&circuit_dir)
            .status()?;
        if !status.success() {
            eyre::bail!("failed to compile Noir circuit");
        }
    }

    // Start Anvil (deployer + N test accounts).
    let anvil = start_anvil(&tools, cli.rpc_port, cli.accounts + 1, cli.verbose)?;
    let rpc_url = anvil.rpc_url();
    eprintln!("[setup] Anvil started on port {}", cli.rpc_port);

    // Deploy contracts.
    let deployment = deploy_contracts(
        &tools, &rpc_url, &contracts_root_str, &deployer.private_key, cli.verbose,
    )?;

    // Fund accounts.
    fund_accounts(
        &tools, &rpc_url, &deployment.token,
        deployer, &anvil_accounts,
        cli.accounts, INITIAL_SUPPLY, PER_ACCOUNT_AMOUNT,
        cli.verbose,
    )?;

    // Mine PoW nonces.
    let chain_id: u64 = 31337; // Anvil default
    let accounts = mine_accounts(&tools, &anvil_accounts, cli.accounts, chain_id, cli.verbose)?;
    eprintln!("[setup] Mined PoW nonces for {} accounts", cli.accounts);
    eprintln!();

    // Initialize ghost state.
    let mut ghost = GhostState::new(
        deployment.token.clone(),
        deployer.address.clone(),
        deployer.private_key.clone(),
        accounts,
        INITIAL_SUPPLY,
        PER_ACCOUNT_AMOUNT,
    );

    // Insert initial balance leaves for funded accounts.
    // mint(deployer, 1B) is SKIPPED (tx.origin == deployer == _to).
    // transfer(deployer → account) inserts a leaf for each account.
    let deployer_addr = deployer.address.clone();
    let acct_addrs: Vec<String> = ghost.account_state.iter()
        .map(|a| a.address.clone())
        .collect();
    for addr in &acct_addrs {
        ghost.insert_balance_leaf(&deployer_addr, addr);
    }

    // Get initial block timestamp.
    let ts_result = anvil::cast_call(
        &tools, &rpc_url, &deployment.token,
        "rateLimitPeriodStart()(uint256)", &[],
        cli.verbose,
    )?;
    // Initial timestamp is 0 (no rate limit period started yet).
    // Get actual block timestamp.
    let block_ts = anvil::cast_rpc(
        &tools, &rpc_url, "eth_getBlockByNumber",
        &["latest", "false"],
        cli.verbose,
    )?;
    // Parse timestamp from the JSON response.
    if let Some(ts) = extract_timestamp(&block_ts) {
        ghost.block_timestamp = ts;
    }
    let _ = ts_result; // used above for side-effect check

    // Run initial invariant check.
    check_invariants(&tools, &rpc_url, &ghost, cli.verbose)?;
    eprintln!("[setup] Initial invariants pass");
    eprintln!();

    // Operation loop.
    for round in 1..=cli.rounds {
        let op = pick_operation(&mut rng, &ghost);
        eprint!("[round {:02}/{}] {}", round, cli.rounds, op);
        eprintln!();

        execute_op(&op, &mut ghost, &tools, &rpc_url, &circuit_dir_str, cli.verbose)?;

        // Update block timestamp after each op (Anvil auto-mines).
        let block_ts = anvil::cast_rpc(
            &tools, &rpc_url, "eth_getBlockByNumber",
            &["latest", "false"],
            cli.verbose,
        )?;
        if let Some(ts) = extract_timestamp(&block_ts) {
            ghost.block_timestamp = ts;
        }

        check_invariants(&tools, &rpc_url, &ghost, cli.verbose)?;
        eprintln!("  \u{2713} invariants pass");
    }

    eprintln!();
    eprintln!("=== ALL {} ROUNDS PASSED (seed: {}) ===", cli.rounds, seed);
    Ok(())
}

/// Extract the timestamp from an eth_getBlockByNumber JSON response.
fn extract_timestamp(json_str: &str) -> Option<u64> {
    // The response contains "timestamp":"0x..." — parse it out.
    let parsed: serde_json::Value = serde_json::from_str(json_str).ok()?;
    let ts_hex = parsed.get("timestamp")?.as_str()?;
    let hex_str = ts_hex.strip_prefix("0x").unwrap_or(ts_hex);
    u64::from_str_radix(hex_str, 16).ok()
}
