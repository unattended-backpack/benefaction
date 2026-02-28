use std::path::PathBuf;

use eyre::Context;

/// Resolve a tool path by checking known locations then falling back to PATH.
pub fn resolve_tool(name: &str) -> eyre::Result<PathBuf> {
    // Known locations for specific tools.
    let candidates: &[&str] = match name {
        "nargo" => &["~/.nargo/bin/nargo"],
        "bb" => &["~/.bb/bb"],
        "zk-mint-input" => &["../input_generator/target/release/zk-mint-input"],
        _ => &[],
    };

    for candidate in candidates {
        let expanded = expand_tilde(candidate);
        if expanded.exists() {
            return Ok(expanded);
        }
    }

    // Fall back to PATH lookup.
    which(name)
}

/// Expand `~` prefix to the user's home directory.
fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

/// Look up a binary on PATH.
fn which(name: &str) -> eyre::Result<PathBuf> {
    let path_var = std::env::var("PATH").unwrap_or_default();
    for dir in path_var.split(':') {
        let candidate = PathBuf::from(dir).join(name);
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    eyre::bail!("tool '{}' not found in PATH or known locations", name)
}

/// Parse a hex string (with or without 0x prefix) into a u128.
pub fn hex_to_u128(s: &str) -> eyre::Result<u128> {
    let s = s.trim();
    let hex_str = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u128::from_str_radix(hex_str, 16).wrap_err_with(|| format!("invalid hex u128: {}", s))
}

/// Parse a decimal string (from cast output) into a u128.
pub fn dec_to_u128(s: &str) -> eyre::Result<u128> {
    let s = s.trim();
    // cast often returns hex for uint256 — handle both.
    if s.starts_with("0x") || s.starts_with("0X") {
        return hex_to_u128(s);
    }
    // cast may append " [1.23e4]" scientific notation hint — strip it.
    let s = s.split('[').next().unwrap_or(s).trim();
    s.parse::<u128>().wrap_err_with(|| format!("invalid decimal u128: {}", s))
}

/// Parse a value that might be decimal or hex (as returned by `cast call`).
/// cast call returns a 0x-prefixed 64-char hex string for uint256.
pub fn parse_cast_uint(s: &str) -> eyre::Result<u128> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        hex_to_u128(s)
    } else {
        dec_to_u128(s)
    }
}

/// Format a u128 as a non-padded decimal string.
pub fn u128_to_dec(v: u128) -> String {
    v.to_string()
}

/// Format a u128 as a 0x-prefixed hex string.
#[allow(dead_code)]
pub fn u128_to_hex(v: u128) -> String {
    format!("0x{:x}", v)
}

/// Resolved tool paths for the harness.
pub struct Tools {
    pub anvil: PathBuf,
    pub forge: PathBuf,
    pub cast: PathBuf,
    pub inputgen: PathBuf,
    pub nargo: PathBuf,
    pub bb: PathBuf,
}

impl Tools {
    pub fn resolve() -> eyre::Result<Self> {
        Ok(Self {
            anvil: resolve_tool("anvil")?,
            forge: resolve_tool("forge")?,
            cast: resolve_tool("cast")?,
            inputgen: resolve_tool("zk-mint-input")?,
            nargo: resolve_tool("nargo")?,
            bb: resolve_tool("bb")?,
        })
    }
}
