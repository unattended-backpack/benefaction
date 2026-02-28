use crate::accounts::AnvilAccount;
use crate::anvil::{cast_send, forge_create};
use crate::util::{u128_to_dec, Tools};

/// Deployed contract addresses.
#[allow(dead_code)]
pub struct Deployment {
    pub poseidon2: String,
    pub verifier: String,
    pub token: String,
}

/// Deploy all contracts and return their addresses.
pub fn deploy_contracts(
    tools: &Tools,
    rpc_url: &str,
    contracts_root: &str,
    deployer_key: &str,
    verbose: bool,
) -> eyre::Result<Deployment> {
    // 1. Deploy Poseidon2.
    let poseidon2 = forge_create(
        tools,
        rpc_url,
        "src/token/zk_mint/Poseidon2.sol:Poseidon2",
        &[],
        &[],
        deployer_key,
        contracts_root,
        verbose,
    )?;
    eprintln!("[setup] Deployed Poseidon2 at {}", poseidon2);

    // 2. Deploy ZKTranscriptLib (required by ZKMintVerifier).
    let zk_transcript_lib = forge_create(
        tools,
        rpc_url,
        "src/token/zk_mint/ZKMintVerifier.sol:ZKTranscriptLib",
        &[],
        &[],
        deployer_key,
        contracts_root,
        verbose,
    )?;
    eprintln!("[setup] Deployed ZKTranscriptLib at {}", zk_transcript_lib);

    // 3. Deploy ZKMintVerifier (linked to ZKTranscriptLib).
    let lib_link = format!(
        "src/token/zk_mint/ZKMintVerifier.sol:ZKTranscriptLib:{}",
        zk_transcript_lib
    );
    let verifier = forge_create(
        tools,
        rpc_url,
        "src/token/zk_mint/ZKMintVerifier.sol:ZKMintVerifier",
        &[],
        &[&lib_link],
        deployer_key,
        contracts_root,
        verbose,
    )?;
    eprintln!("[setup] Deployed Verifier at {}", verifier);

    // 4. Deploy MockZKMintToken (linked to ZKTranscriptLib for ZKMint base).
    let token = forge_create(
        tools,
        rpc_url,
        "test/token/utils/MockZKMintToken.sol:MockZKMintToken",
        &[&verifier, &poseidon2, "86400", "100", "1000000000000000000000000"],
        &[&lib_link],
        deployer_key,
        contracts_root,
        verbose,
    )?;
    eprintln!("[setup] Deployed MockZKMint at {}", token);

    Ok(Deployment {
        poseidon2,
        verifier,
        token,
    })
}

/// Mint the initial supply to the deployer, then transfer to test accounts.
pub fn fund_accounts(
    tools: &Tools,
    rpc_url: &str,
    token: &str,
    deployer: &AnvilAccount,
    anvil_accounts: &[AnvilAccount],
    num_accounts: usize,
    initial_supply: u128,
    per_account: u128,
    verbose: bool,
) -> eyre::Result<()> {
    // Mint initial supply to deployer.
    cast_send(
        tools,
        rpc_url,
        token,
        "mint(address,uint256)",
        &[&deployer.address, &u128_to_dec(initial_supply)],
        &deployer.private_key,
        verbose,
    )?;
    eprintln!(
        "[setup] Minted {} tokens to deployer",
        initial_supply / 1_000_000_000_000_000_000
    );

    // Transfer to each test account.
    for i in 0..num_accounts {
        let acct_idx = i + 1;
        cast_send(
            tools,
            rpc_url,
            token,
            "transfer(address,uint256)",
            &[&anvil_accounts[acct_idx].address, &u128_to_dec(per_account)],
            &deployer.private_key,
            verbose,
        )?;
    }
    eprintln!(
        "[setup] Funded {} accounts with {} tokens each",
        num_accounts,
        per_account / 1_000_000_000_000_000_000
    );

    Ok(())
}
