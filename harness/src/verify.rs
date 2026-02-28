use crate::anvil::cast_call;
use crate::ghost::GhostState;
use crate::tree;
use crate::util::{parse_cast_uint, Tools};


/// Run all invariant checks against on-chain state.
pub fn check_invariants(
    tools: &Tools,
    rpc_url: &str,
    ghost: &GhostState,
    verbose: bool,
) -> eyre::Result<()> {
    // 1. Ghost vs on-chain balances for all tracked addresses.
    let mut on_chain_sum: u128 = 0;
    for addr in &ghost.tracked_addresses {
        let result = cast_call(
            tools,
            rpc_url,
            &ghost.token_address,
            "balanceOf(address)(uint256)",
            &[addr],
            verbose,
        )?;
        let on_chain = parse_cast_uint(&result)?;
        let expected = ghost.balances.get(addr).copied().unwrap_or(0);
        if on_chain != expected {
            eyre::bail!(
                "balance mismatch for {}:\n  on-chain: {}\n  ghost:    {}",
                addr, on_chain, expected,
            );
        }
        on_chain_sum += on_chain;
    }

    // 2. Check totalSupply (visible supply = raw - reminted).
    let result = cast_call(
        tools,
        rpc_url,
        &ghost.token_address,
        "totalSupply()(uint256)",
        &[],
        verbose,
    )?;
    let on_chain_visible = parse_cast_uint(&result)?;
    let expected_visible = ghost.visible_supply();
    if on_chain_visible != expected_visible {
        eyre::bail!(
            "visible supply mismatch:\n  on-chain: {}\n  ghost:    {}",
            on_chain_visible, expected_visible,
        );
    }

    // 3. Balance sum should equal raw total supply (ERC20.totalSupply before
    //    the offset). We can't read _totalReminted directly, but we can
    //    verify: sum(balances) == visible_supply + total_private_reminted.
    let expected_raw = ghost.raw_total_supply;
    if on_chain_sum != expected_raw {
        eyre::bail!(
            "balance sum mismatch:\n  sum(balanceOf): {}\n  expected raw:   {}",
            on_chain_sum, expected_raw,
        );
    }

    // 4. Nullifier consistency.
    for (nullifier_hex, &amount) in &ghost.nullifiers {
        let result = cast_call(
            tools,
            rpc_url,
            &ghost.token_address,
            "nullifiers(uint256)(uint256)",
            &[nullifier_hex],
            verbose,
        )?;
        let on_chain_val = parse_cast_uint(&result)?;
        let expected_val = amount + 1; // stored as amount + 1
        if on_chain_val != expected_val {
            eyre::bail!(
                "nullifier mismatch for {}:\n  on-chain: {}\n  expected: {} (amount {} + 1)",
                nullifier_hex, on_chain_val, expected_val, amount,
            );
        }
    }

    // 5. Exact tree root comparison against shadow tree.
    {
        let result = cast_call(
            tools,
            rpc_url,
            &ghost.token_address,
            "root()(uint256)",
            &[],
            verbose,
        )?;
        let root_str = result.split('[').next().unwrap_or(&result).trim();
        let on_chain_root = tree::parse_fr(root_str)?;
        let expected_root = ghost.tree.root();
        if on_chain_root != expected_root {
            eyre::bail!(
                "root mismatch:\n  on-chain: {}\n  ghost:    {}",
                tree::fr_to_hex(&on_chain_root),
                tree::fr_to_hex(&expected_root),
            );
        }
    }

    Ok(())
}
