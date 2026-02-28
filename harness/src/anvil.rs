use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use eyre::Context;

use crate::util::Tools;

/// A running Anvil instance. Kills the process on drop.
pub struct Anvil {
    child: Child,
    pub port: u16,
}

impl Anvil {
    pub fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The standard test mnemonic used by Anvil/Hardhat.
pub const TEST_MNEMONIC: &str =
    "test test test test test test test test test test test junk";

/// Start an Anvil instance and wait for it to be ready.
pub fn start_anvil(tools: &Tools, port: u16, num_accounts: usize, verbose: bool) -> eyre::Result<Anvil> {
    let mut cmd = Command::new(&tools.anvil);
    cmd.args([
        "--port", &port.to_string(),
        "--accounts", &num_accounts.to_string(),
        "--balance", "10000",
        "--mnemonic", TEST_MNEMONIC,
    ]);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().wrap_err("failed to start anvil")?;

    // Wait for "Listening on" in stdout (anvil prints to stdout).
    let stdout = child.stdout.take().unwrap();
    let reader = BufReader::new(stdout);
    let start = Instant::now();
    let timeout = Duration::from_secs(30);

    for line in reader.lines() {
        if start.elapsed() > timeout {
            child.kill().ok();
            eyre::bail!("anvil did not start within 30 seconds");
        }
        let line = line?;
        if verbose {
            eprintln!("[anvil] {}", line);
        }
        if line.contains("Listening on") {
            break;
        }
    }

    Ok(Anvil { child, port })
}

/// Run `cast call` and return the trimmed stdout.
pub fn cast_call(
    tools: &Tools,
    rpc_url: &str,
    to: &str,
    sig: &str,
    args: &[&str],
    verbose: bool,
) -> eyre::Result<String> {
    let mut cmd = Command::new(&tools.cast);
    cmd.args(["call", to, sig]);
    cmd.args(args);
    cmd.args(["--rpc-url", rpc_url]);

    if verbose {
        eprintln!("[cast call] {} {} {:?}", to, sig, args);
    }

    let output = cmd.output().wrap_err("failed to run cast call")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eyre::bail!("cast call failed: {}", stderr);
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run `cast send` and return the trimmed stdout. Returns the full output
/// on success, or an error with stderr on failure.
pub fn cast_send(
    tools: &Tools,
    rpc_url: &str,
    to: &str,
    sig: &str,
    args: &[&str],
    private_key: &str,
    verbose: bool,
) -> eyre::Result<String> {
    let mut cmd = Command::new(&tools.cast);
    cmd.args(["send", to, sig]);
    cmd.args(args);
    cmd.args(["--rpc-url", rpc_url, "--private-key", private_key]);

    if verbose {
        eprintln!("[cast send] {} {} {:?}", to, sig, args);
    }

    let output = cmd.output().wrap_err("failed to run cast send")?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if !output.status.success() {
        eyre::bail!("cast send failed: {}\n{}", stderr, stdout);
    }
    if verbose && !stdout.is_empty() {
        eprintln!("[cast send] {}", stdout);
    }
    Ok(stdout)
}

/// Run `cast send` for a ZK mint. Returns Ok(stdout) on success,
/// or the revert reason string on failure (so the caller can distinguish
/// expected reverts like RateLimitExceeded).
pub fn cast_send_may_revert(
    tools: &Tools,
    rpc_url: &str,
    to: &str,
    sig: &str,
    args: &[&str],
    private_key: &str,
    verbose: bool,
) -> Result<String, String> {
    let mut cmd = Command::new(&tools.cast);
    cmd.args(["send", to, sig]);
    cmd.args(args);
    cmd.args(["--rpc-url", rpc_url, "--private-key", private_key]);

    if verbose {
        eprintln!("[cast send] {} {} {:?}", to, sig, args);
    }

    let output = cmd.output().map_err(|e| format!("failed to run cast send: {}", e))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if !output.status.success() {
        Err(format!("{}\n{}", stderr, stdout))
    } else {
        Ok(stdout)
    }
}

/// Run `cast rpc` with the given method and params.
pub fn cast_rpc(
    tools: &Tools,
    rpc_url: &str,
    method: &str,
    params: &[&str],
    verbose: bool,
) -> eyre::Result<String> {
    let mut cmd = Command::new(&tools.cast);
    cmd.args(["rpc", method]);
    cmd.args(params);
    cmd.args(["--rpc-url", rpc_url]);

    if verbose {
        eprintln!("[cast rpc] {} {:?}", method, params);
    }

    let output = cmd.output().wrap_err("failed to run cast rpc")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eyre::bail!("cast rpc failed: {}", stderr);
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run `forge create` and return the deployed contract address.
pub fn forge_create(
    tools: &Tools,
    rpc_url: &str,
    contract_path: &str,
    constructor_args: &[&str],
    libraries: &[&str],
    private_key: &str,
    root: &str,
    verbose: bool,
) -> eyre::Result<String> {
    let mut cmd = Command::new(&tools.forge);
    cmd.args(["create", contract_path]);
    cmd.args(["--rpc-url", rpc_url, "--private-key", private_key, "--broadcast"]);
    cmd.args(["--root", root]);

    for lib in libraries {
        cmd.args(["--libraries", lib]);
    }

    if !constructor_args.is_empty() {
        cmd.arg("--constructor-args");
        cmd.args(constructor_args);
    }

    if verbose {
        eprintln!("[forge create] {}", contract_path);
    }

    let output = cmd.output().wrap_err("failed to run forge create")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        eyre::bail!("forge create failed: {}\n{}", stderr, stdout);
    }

    // Parse "Deployed to: 0x..." from stdout.
    for line in stdout.lines().chain(stderr.lines()) {
        if let Some(rest) = line.strip_prefix("Deployed to: ") {
            return Ok(rest.trim().to_string());
        }
    }

    eyre::bail!(
        "could not find 'Deployed to:' in forge create output:\n{}\n{}",
        stdout, stderr
    )
}
