use std::process::Command;
use std::time::Instant;

use eyre::Context;

use crate::util::Tools;

/// Per-burn input specification for `run_inputgen`.
pub struct BurnInputSpec {
    pub pow_nonce: String,
    pub mint: u128,
    pub prev_nonce: u64,
    pub prev_total_minted: u128,
    pub explicit_vk: Option<String>,
}

/// Run the input generator to produce Prover.toml.
///
/// Accepts multiple burn specs for multi-burn proofs.
pub fn run_inputgen(
    tools: &Tools,
    private_key: &str,
    burns: &[BurnInputSpec],
    total_amount: u128,
    recipient: &str,
    rpc_url: &str,
    token_address: &str,
    chain_id: u64,
    relayer: &str,
    priority_fee: u128,
    conversion_rate: u128,
    max_reward: u128,
    output_path: &str,
    verbose: bool,
) -> eyre::Result<()> {
    let mut cmd = Command::new(&tools.inputgen);
    cmd.args([
        "generate",
        "--private-key", private_key,
    ]);

    // Build one --burn arg per burn spec.
    let burn_specs: Vec<String> = burns.iter().map(|b| {
        let has_history = b.prev_nonce != 0 || b.prev_total_minted != 0;
        match (has_history, &b.explicit_vk) {
            (false, None) => format!("{} {}", b.pow_nonce, b.mint),
            (false, Some(vk)) => format!("{} {} 0 0 {}", b.pow_nonce, b.mint, vk),
            (true, None) => format!("{} {} {} {}", b.pow_nonce, b.mint, b.prev_nonce, b.prev_total_minted),
            (true, Some(vk)) => format!("{} {} {} {} {}", b.pow_nonce, b.mint, b.prev_nonce, b.prev_total_minted, vk),
        }
    }).collect();

    for spec in &burn_specs {
        cmd.args(["--burn", spec]);
    }

    cmd.args([
        "--amount", &total_amount.to_string(),
        "--recipient", recipient,
        "--rpc-url", rpc_url,
        "--token-address", token_address,
        "--chain-id", &chain_id.to_string(),
        "--relayer", relayer,
        "--priority-fee", &priority_fee.to_string(),
        "--conversion-rate", &conversion_rate.to_string(),
        "--max-reward", &max_reward.to_string(),
        "-o", output_path,
    ]);

    if verbose {
        eprintln!("[input generator] generating Prover.toml ({} burns)...", burns.len());
    }

    let output = cmd.output().wrap_err("failed to run input generator")?;
    let stderr = String::from_utf8_lossy(&output.stderr);

    if verbose {
        eprint!("{}", stderr);
    }

    if !output.status.success() {
        eyre::bail!("input generator failed: {}", stderr);
    }

    Ok(())
}

/// Run `nargo execute` in the circuit directory to generate the witness.
pub fn run_nargo(
    tools: &Tools,
    circuit_dir: &str,
    verbose: bool,
) -> eyre::Result<()> {
    let start = Instant::now();

    let output = Command::new(&tools.nargo)
        .arg("execute")
        .current_dir(circuit_dir)
        .output()
        .wrap_err("failed to run nargo execute")?;

    let elapsed = start.elapsed();
    let stderr = String::from_utf8_lossy(&output.stderr);

    if verbose {
        eprint!("{}", stderr);
        eprintln!("[nargo] witness generated in {:.1}s", elapsed.as_secs_f64());
    }

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        eyre::bail!("nargo execute failed: {}\n{}", stderr, stdout);
    }

    Ok(())
}

/// Run `bb prove` to generate an UltraHonk proof.
pub fn run_bb(
    tools: &Tools,
    circuit_dir: &str,
    verbose: bool,
) -> eyre::Result<()> {
    let start = Instant::now();

    let output = Command::new(&tools.bb)
        .args([
            "prove",
            "--verifier_target", "evm",
            "--write_vk",
            "-b", "target/zk_mint.json",
            "-w", "target/zk_mint.gz",
            "-o", "target/proof",
        ])
        .current_dir(circuit_dir)
        .output()
        .wrap_err("failed to run bb prove")?;

    let elapsed = start.elapsed();
    let stderr = String::from_utf8_lossy(&output.stderr);

    if verbose {
        eprint!("{}", stderr);
    }

    eprintln!("  proof generated ({:.1}s)", elapsed.as_secs_f64());

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        eyre::bail!("bb prove failed: {}\n{}", stderr, stdout);
    }

    Ok(())
}
