mod poseidon;
mod types;

use std::path::PathBuf;

use alloy::primitives::Address;
use alloy::providers::ProviderBuilder;
use alloy::sol;
use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField};
use clap::{Parser, Subcommand};
use k256::ecdsa::SigningKey;
use rand::Rng;

use crate::poseidon::{
    check_pow, compute_eip712_hash, get_private_address, hash_account_note, hash_nullifier,
    hash_total_burned_leaf, parse_fr, poseidon2_hash,
};
use crate::types::*;

sol! {
    #[sol(rpc)]
    interface ISigil {
        function root() external view returns (uint256);
        function balanceOf(address account) external view returns (uint256);
        event NewLeaf(uint256 leaf);
    }
}

#[derive(Parser)]
#[command(name = "zk-mint-input")]
#[command(about = "Generate circuit inputs for the ZK mint circuit")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Mine a PoW nonce for a private address.
    Mine {
        /// ECDSA private key (hex). Derives the public key automatically.
        #[arg(long, group = "key")]
        private_key: Option<String>,

        /// Uncompressed (65-byte, 04-prefixed) or compressed (33-byte) secp256k1 public key (hex).
        #[arg(long, group = "key")]
        public_key: Option<String>,

        /// Chain ID for address derivation (default: 31337 for Anvil).
        #[arg(long, default_value = "31337")]
        chain_id: u64,

        /// Explicit viewing key (hex field element). If omitted, derived from --private-key.
        #[arg(long)]
        viewing_key: Option<String>,
    },

    /// Derive the viewing key from an ECDSA private key.
    DeriveViewingKey {
        /// ECDSA private key (hex, 0x-prefixed)
        #[arg(long)]
        private_key: String,
    },

    /// Generate Prover.toml for a ZK mint.
    Generate {
        /// ECDSA private key (hex, 0x-prefixed)
        #[arg(long)]
        private_key: String,

        /// Burn spec: "NONCE MINT [PREV_NONCE PREV_MINTED [VK]]"
        /// Can be repeated for multi-burn proofs.
        #[arg(long, required = true)]
        burn: Vec<String>,

        /// Transfer amount (decimal or hex)
        #[arg(long)]
        amount: String,

        /// Recipient address (0x...)
        #[arg(long)]
        recipient: Address,

        /// RPC endpoint URL
        #[arg(long)]
        rpc_url: String,

        /// Sigil token contract address (0x...)
        #[arg(long)]
        token_address: Address,

        /// Chain ID for address derivation (default: 31337 for Anvil).
        #[arg(long, default_value = "31337")]
        chain_id: u64,

        /// Relayer address: 0 = self-relay, 1 = msg.sender, or a specific
        /// address (default 0)
        #[arg(long, default_value = "0")]
        relayer: String,

        /// Priority fee committed to in the proof (default 0)
        #[arg(long, default_value = "0")]
        priority_fee: String,

        /// Conversion rate committed to in the proof (default 0)
        #[arg(long, default_value = "0")]
        conversion_rate: String,

        /// Max reward the minter is willing to pay (default 0)
        #[arg(long, default_value = "0")]
        max_reward: String,

        /// EIP-712 domain name (default: "MockZKMint" for harness, use "Sigil" for
        /// the real token)
        #[arg(long, default_value = "MockZKMint")]
        domain_name: String,

        /// EIP-712 domain version (default: "1")
        #[arg(long, default_value = "1")]
        domain_version: String,

        /// Output file
        #[arg(short, long, default_value = "Prover.toml")]
        output: PathBuf,
    },
}

fn main() -> eyre::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Mine {
            private_key,
            public_key,
            chain_id,
            viewing_key,
        } => cmd_mine(private_key.as_deref(), public_key.as_deref(), chain_id, viewing_key.as_deref()),
        Commands::DeriveViewingKey { private_key } => cmd_derive_viewing_key(&private_key),
        Commands::Generate {
            private_key,
            burn,
            amount,
            recipient,
            rpc_url,
            token_address,
            chain_id,
            relayer,
            priority_fee,
            conversion_rate,
            max_reward,
            domain_name,
            domain_version,
            output,
        } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(cmd_generate(
                &private_key,
                &burn,
                &amount,
                recipient,
                &rpc_url,
                token_address,
                chain_id,
                &relayer,
                &priority_fee,
                &conversion_rate,
                &max_reward,
                &domain_name,
                &domain_version,
                &output,
            ))
        }
    }
}

/// Parse a hex private key string into a k256 SigningKey.
fn parse_signing_key(hex_str: &str) -> eyre::Result<SigningKey> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str)?;
    Ok(SigningKey::from_bytes(bytes.as_slice().into())?)
}

/// Derive the uncompressed public key (64 bytes: x || y) from a signing key.
fn derive_pub_key(signing_key: &SigningKey) -> ([u8; 32], [u8; 32]) {
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false); // uncompressed
    let x_bytes = point.x().expect("non-identity point");
    let y_bytes = point.y().expect("non-identity point");
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(x_bytes);
    y.copy_from_slice(y_bytes);
    (x, y)
}

/// Convert a 32-byte big-endian public key x-coordinate to a field element,
/// zeroing the first byte (to fit in BN254 scalar field).
fn pub_key_x_to_field(pub_key_x: &[u8; 32]) -> Fr {
    let mut bytes = *pub_key_x;
    bytes[0] = 0;
    Fr::from_be_bytes_mod_order(&bytes)
}

/// Domain message signed to derive the viewing key deterministically.
const VIEWING_KEY_DOMAIN: &[u8] = b"VIEWING_KEY";

/// Derive a viewing key from a signing key.
///
/// Signs a fixed domain message (deterministic via RFC 6979), takes the
/// signature's `r` component, and reduces it mod the BN254 scalar field.
/// The same private key always produces the same viewing key.
fn derive_viewing_key(signing_key: &SigningKey) -> Fr {
    let msg_hash = alloy::primitives::keccak256(VIEWING_KEY_DOMAIN);
    use k256::ecdsa::{signature::Signer, Signature};
    let sig: Signature = signing_key.sign(&msg_hash.0);
    let r_bytes = &sig.to_bytes()[..32];
    Fr::from_be_bytes_mod_order(r_bytes)
}

fn cmd_derive_viewing_key(private_key_hex: &str) -> eyre::Result<()> {
    let signing_key = parse_signing_key(private_key_hex)?;
    let viewing_key = derive_viewing_key(&signing_key);
    let vk_hex = format!(
        "0x{}",
        hex::encode(viewing_key.into_bigint().to_bytes_be())
    );

    eprintln!("Viewing key: {}", vk_hex);
    println!("{}", vk_hex);
    Ok(())
}

fn cmd_mine(
    private_key: Option<&str>,
    public_key: Option<&str>,
    chain_id: u64,
    viewing_key_hex: Option<&str>,
) -> eyre::Result<()> {
    let (pub_key_x, viewing_key) = match (private_key, public_key) {
        (Some(pk), _) => {
            let signing_key = parse_signing_key(pk)?;
            let (x, _) = derive_pub_key(&signing_key);
            let vk = if let Some(vk_hex) = viewing_key_hex {
                parse_fr(vk_hex)?
            } else {
                derive_viewing_key(&signing_key)
            };
            (x, vk)
        }
        (_, Some(_)) => eyre::bail!(
            "--private-key is required for mining (burn address now depends on viewing key)"
        ),
        _ => eyre::bail!("--private-key is required"),
    };
    let pub_key_x_field = pub_key_x_to_field(&pub_key_x);
    let chain_id_fr = Fr::from(chain_id);

    eprintln!("Public key x: 0x{}", hex::encode(pub_key_x));
    eprintln!("Viewing key:  {}", fr_to_hex(&viewing_key));
    eprintln!("Chain ID: {}", chain_id);
    eprintln!("Mining PoW nonce...");

    let mut rng = rand::rng();
    let mut attempts: u64 = 0;

    loop {
        attempts += 1;

        // Generate random field element as nonce
        let limbs: [u64; 4] = [rng.random(), rng.random(), rng.random(), rng.random()];
        let nonce = match Fr::from_random_bytes(
            &limbs
                .iter()
                .flat_map(|l| l.to_le_bytes())
                .collect::<Vec<_>>(),
        ) {
            Some(k) => k,
            None => continue,
        };

        let (private_address, pow_hash, _blinded) =
            get_private_address(pub_key_x_field, nonce, viewing_key, chain_id_fr)?;

        if check_pow(&pow_hash)? {
            let nonce_hex = format!(
                "0x{}",
                hex::encode(nonce.into_bigint().to_bytes_be())
            );
            let addr_bytes = private_address.into_bigint().to_bytes_be();
            let burn_address = format!(
                "0x{:>040}",
                hex::encode(&addr_bytes[addr_bytes.len() - 20..])
            );
            eprintln!("Found after {} attempts", attempts);
            eprintln!("Burn address: {}", burn_address);
            eprintln!("PoW nonce:    {}", nonce_hex);
            return Ok(());
        }

        if attempts % 100_000 == 0 {
            eprint!("\r{} attempts...", attempts);
        }
    }
}

/// Reconstruct the LeanIMT from leaves and compute a tree proof for the
/// target leaf. Returns (depth, indices, siblings) matching the circuit's
/// TreeProof struct.
fn compute_tree_proof(
    leaves: &[Fr],
    target_leaf: Fr,
) -> eyre::Result<(u32, Vec<u8>, Vec<Fr>)> {
    let max_depth = types::MAX_TREE_DEPTH;

    // Find the target leaf's index.
    let target_index = leaves
        .iter()
        .position(|&l| l == target_leaf)
        .ok_or_else(|| eyre::eyre!("target leaf not found in tree"))?;

    if leaves.len() == 1 {
        // Single leaf: root == leaf, no proof needed.
        return Ok((0, vec![0; max_depth], vec![Fr::from(0u64); max_depth]));
    }

    // Build tree level by level, collecting siblings along the proof path.
    // Uses LeanIMT semantics: when a level has an odd number of nodes, the
    // last node is promoted to the next level without hashing.
    let mut indices = vec![0u8; max_depth];
    let mut siblings = vec![Fr::from(0u64); max_depth];
    let mut current_level: Vec<Fr> = leaves.to_vec();
    let mut idx = target_index;
    let mut depth = 0u32;

    while current_level.len() > 1 {
        let n = current_level.len();
        let odd = n % 2 == 1;

        if odd && idx == n - 1 {
            // Target is the promoted odd node — skip this level (no hash).
        } else {
            // Normal case: record sibling and index bit.
            indices[depth as usize] = (idx & 1) as u8;
            siblings[depth as usize] = current_level[idx ^ 1];
            depth += 1;
        }

        // Hash pairs to produce next level.
        let mut next_level = Vec::with_capacity((n + 1) / 2);
        let mut i = 0;
        while i + 1 < n {
            next_level.push(poseidon2_hash(&[current_level[i], current_level[i + 1]]));
            i += 2;
        }
        if odd {
            next_level.push(current_level[n - 1]);
        }

        idx = if odd && idx == n - 1 {
            next_level.len() - 1
        } else {
            idx / 2
        };
        current_level = next_level;
    }

    Ok((depth, indices, siblings))
}

/// Compute EIP-712 struct hash for ZKMint.
///
/// ZKMint(address recipient,uint256 amount,address relayerAddress,
///   uint256 priorityFee,uint256 conversionRate,uint256 maxReward,
///   bytes[] totalMintedEncrypted)
fn compute_zk_mint_struct_hash(
    recipient: Address,
    amount: &Fr,
    relayer_address: Address,
    priority_fee: &Fr,
    conversion_rate: &Fr,
    max_reward: &Fr,
    total_minted_encrypted: &[Vec<u8>],
) -> [u8; 32] {
    use alloy::primitives::keccak256;
    use crate::poseidon::fr_to_be_bytes;

    let typehash = keccak256(
        b"ZKMint(address recipient,uint256 amount,address relayerAddress,uint256 priorityFee,uint256 conversionRate,uint256 maxReward,bytes[] totalMintedEncrypted)"
    );

    // Hash the totalMintedEncrypted array: keccak256(keccak256(item0) || keccak256(item1) || ...)
    let mut items_hash_data = Vec::new();
    for item in total_minted_encrypted {
        let item_hash = keccak256(item);
        items_hash_data.extend_from_slice(&item_hash.0);
    }
    let array_hash = keccak256(&items_hash_data);

    // abi.encode(typehash, recipient, amount, relayerAddress, priorityFee, conversionRate, maxReward, arrayHash)
    let mut data = Vec::with_capacity(8 * 32);
    data.extend_from_slice(&typehash.0);
    // recipient as uint256
    let mut recipient_bytes = [0u8; 32];
    recipient_bytes[12..].copy_from_slice(recipient.as_slice());
    data.extend_from_slice(&recipient_bytes);
    data.extend_from_slice(&fr_to_be_bytes(amount));
    // relayer_address as uint256
    let mut relayer_bytes = [0u8; 32];
    relayer_bytes[12..].copy_from_slice(relayer_address.as_slice());
    data.extend_from_slice(&relayer_bytes);
    data.extend_from_slice(&fr_to_be_bytes(priority_fee));
    data.extend_from_slice(&fr_to_be_bytes(conversion_rate));
    data.extend_from_slice(&fr_to_be_bytes(max_reward));
    data.extend_from_slice(&array_hash.0);

    keccak256(&data).0
}

/// Compute the EIP-712 domain separator for a contract.
fn compute_domain_separator(
    name: &str,
    version: &str,
    chain_id: u64,
    verifying_contract: Address,
) -> [u8; 32] {
    use alloy::primitives::keccak256;

    let domain_typehash = keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    let name_hash = keccak256(name.as_bytes());
    let version_hash = keccak256(version.as_bytes());

    let mut data = Vec::with_capacity(5 * 32);
    data.extend_from_slice(&domain_typehash.0);
    data.extend_from_slice(&name_hash.0);
    data.extend_from_slice(&version_hash.0);
    // chain_id as uint256
    let mut chain_id_bytes = [0u8; 32];
    chain_id_bytes[24..].copy_from_slice(&chain_id.to_be_bytes());
    data.extend_from_slice(&chain_id_bytes);
    // verifying_contract as uint256
    let mut contract_bytes = [0u8; 32];
    contract_bytes[12..].copy_from_slice(verifying_contract.as_slice());
    data.extend_from_slice(&contract_bytes);

    keccak256(&data).0
}

/// Parsed burn spec from a single `--burn` group.
struct BurnSpec {
    pow_nonce: Fr,
    mint: Fr,
    prev_nonce: Fr,
    prev_total_minted: Fr,
    /// Explicit viewing key, or None to derive from --private-key.
    explicit_vk: Option<Fr>,
}

fn parse_burn_spec(spec_str: &str) -> eyre::Result<BurnSpec> {
    let args: Vec<&str> = spec_str.split_whitespace().collect();
    eyre::ensure!(
        args.len() >= 2 && args.len() <= 5,
        "each --burn requires 2-5 values: \"NONCE MINT [PREV_NONCE PREV_MINTED [VK]]\""
    );
    let pow_nonce = parse_fr(args[0])?;
    let mint = parse_fr(args[1])?;
    let prev_nonce = if args.len() >= 3 {
        parse_fr(args[2])?
    } else {
        Fr::from(0u64)
    };
    let prev_total_minted = if args.len() >= 4 {
        parse_fr(args[3])?
    } else {
        Fr::from(0u64)
    };
    let explicit_vk = if args.len() >= 5 {
        Some(parse_fr(args[4])?)
    } else {
        None
    };
    Ok(BurnSpec { pow_nonce, mint, prev_nonce, prev_total_minted, explicit_vk })
}

async fn cmd_generate(
    private_key_hex: &str,
    burn_args: &[String],
    amount_str: &str,
    recipient: Address,
    rpc_url: &str,
    token_address: Address,
    chain_id: u64,
    relayer_str: &str,
    priority_fee_str: &str,
    conversion_rate_str: &str,
    max_reward_str: &str,
    domain_name: &str,
    domain_version: &str,
    output: &std::path::Path,
) -> eyre::Result<()> {
    let amount = parse_fr(amount_str)?;
    let priority_fee = parse_fr(priority_fee_str)?;
    let conversion_rate = parse_fr(conversion_rate_str)?;
    let max_reward = parse_fr(max_reward_str)?;
    let chain_id_fr = Fr::from(chain_id);

    // Parse relayer as an address for EIP-712 struct hash.
    let relayer_address: Address = if relayer_str == "0" {
        Address::ZERO
    } else if relayer_str == "1" {
        Address::from_slice(&{
            let mut buf = [0u8; 20];
            buf[19] = 1;
            buf
        })
    } else {
        relayer_str.parse()?
    };

    // Derive keys from the private key.
    let signing_key = parse_signing_key(private_key_hex)?;
    let (pub_key_x, _pub_key_y) = derive_pub_key(&signing_key);
    let pub_key_x_field = pub_key_x_to_field(&pub_key_x);
    let default_vk = derive_viewing_key(&signing_key);

    // Parse all burn specs.
    let burn_specs: Vec<BurnSpec> = burn_args
        .iter()
        .map(|s| parse_burn_spec(s))
        .collect::<eyre::Result<Vec<_>>>()?;
    let num_burns = burn_specs.len();
    eyre::ensure!(num_burns >= 1, "at least one --burn is required");
    eyre::ensure!(num_burns <= BURN_ADDRESSES_LEN, "too many burns (max {})", BURN_ADDRESSES_LEN);

    // Verify amount == sum of per-burn mints.
    let mint_sum: Fr = burn_specs.iter().map(|s| s.mint).sum();
    eyre::ensure!(
        mint_sum == amount,
        "sum of per-burn mints does not equal --amount"
    );

    // Connect to RPC and fetch shared on-chain state.
    let provider = ProviderBuilder::new().connect(rpc_url).await?;
    let token = ISigil::new(token_address, &provider);

    let root_u256 = token.root().call().await?;
    let root = Fr::from_be_bytes_mod_order(&root_u256.to_be_bytes::<32>());
    eprintln!("Tree root:     {}", fr_to_hex(&root));

    // Fetch all NewLeaf events to reconstruct the tree.
    let events = token
        .NewLeaf_filter()
        .from_block(0)
        .query()
        .await?;
    let leaves: Vec<Fr> = events
        .iter()
        .map(|(event, _)| Fr::from_be_bytes_mod_order(&event.leaf.to_be_bytes::<32>()))
        .collect();
    eprintln!("Tree leaves:   {}", leaves.len());

    // Process each burn.
    let mut burn_pub = vec![BurnDataPublic::zero(); BURN_ADDRESSES_LEN];
    let mut burn_priv = vec![BurnDataPrivate::zero(); BURN_ADDRESSES_LEN];
    let mut total_minted_encrypted: Vec<Vec<u8>> = Vec::new();

    for (i, spec) in burn_specs.iter().enumerate() {
        let viewing_key = spec.explicit_vk.unwrap_or(default_vk);

        // Derive burn address using two-stage derivation.
        let (private_address, pow_hash, blinded) =
            get_private_address(pub_key_x_field, spec.pow_nonce, viewing_key, chain_id_fr)?;
        eyre::ensure!(
            check_pow(&pow_hash)?,
            "burn {}: PoW nonce does not satisfy difficulty requirement", i
        );
        let addr_bytes = private_address.into_bigint().to_bytes_be();
        let burn_address = Address::from_slice(&addr_bytes[addr_bytes.len() - 20..]);
        eprintln!("Burn[{}] address:  {}", i, burn_address);

        // Fetch balance for this burn address.
        let balance_u256 = token.balanceOf(burn_address).call().await?;
        let total_burned = Fr::from_be_bytes_mod_order(&balance_u256.to_be_bytes::<32>());
        eprintln!("Burn[{}] balance:  {} ({})", i, balance_u256, fr_to_hex(&total_burned));

        if balance_u256.is_zero() {
            eprintln!("WARNING: burn[{}] address has zero balance — no tokens sent?", i);
        }

        // Compute the balance leaf hash.
        let balance_leaf = hash_total_burned_leaf(private_address, total_burned)?;
        eprintln!("Burn[{}] leaf:     {}", i, fr_to_hex(&balance_leaf));

        // Compute tree proof for the balance leaf.
        let (tr_depth, tr_indices, tr_siblings) = compute_tree_proof(&leaves, balance_leaf)?;
        eprintln!("Burn[{}] depth:    {}", i, tr_depth);

        // Compute account note hash and nullifier.
        let new_minted = spec.mint + spec.prev_total_minted;
        let current_nonce = spec.prev_nonce + Fr::from(1u64);
        let account_note_hash = hash_account_note(new_minted, current_nonce, blinded, viewing_key)?;
        let account_note_nullifier = hash_nullifier(spec.prev_nonce, viewing_key);

        eprintln!("Burn[{}] note:     {}", i, fr_to_hex(&account_note_hash));
        eprintln!("Burn[{}] nullifier:{}", i, fr_to_hex(&account_note_nullifier));
        eprintln!("Burn[{}] vk:       {}", i, fr_to_hex(&viewing_key));

        // Compute tree proof for the previous account note (if nonce > 0).
        let prev_account_note_tree_proof = if spec.prev_nonce != Fr::from(0u64) {
            let prev_note_hash = hash_account_note(
                spec.prev_total_minted, spec.prev_nonce, blinded, viewing_key
            )?;
            eprintln!("Burn[{}] prev:     {}", i, fr_to_hex(&prev_note_hash));
            let (depth, indices, siblings) = compute_tree_proof(&leaves, prev_note_hash)?;
            eprintln!("Burn[{}] prev dep: {}", i, depth);
            TreeProof::from_proof(depth, &indices, &siblings)
        } else {
            TreeProof::empty()
        };

        // Compute totalMintedEncrypted for this burn.
        let tse_bytes = poseidon::fr_to_be_bytes(&new_minted).to_vec();
        total_minted_encrypted.push(tse_bytes);

        burn_pub[i] = BurnDataPublic {
            account_note_hash: fr_to_hex(&account_note_hash),
            account_note_nullifier: fr_to_hex(&account_note_nullifier),
        };

        burn_priv[i] = BurnDataPrivate {
            viewing_key: fr_to_hex(&viewing_key),
            pow_nonce: fr_to_hex(&spec.pow_nonce),
            total_burned: fr_to_hex(&total_burned),
            prev_total_minted: fr_to_hex(&spec.prev_total_minted),
            amount_to_mint: fr_to_hex(&spec.mint),
            prev_account_nonce: fr_to_hex(&spec.prev_nonce),
            prev_account_note_tree_proof,
            total_burned_tree_proof: TreeProof::from_proof(tr_depth, &tr_indices, &tr_siblings),
        };
    }

    // Compute EIP-712 signature hash.
    let domain_separator = compute_domain_separator(
        domain_name, domain_version, chain_id, token_address,
    );
    let struct_hash = compute_zk_mint_struct_hash(
        recipient, &amount, relayer_address,
        &priority_fee, &conversion_rate, &max_reward,
        &total_minted_encrypted,
    );
    let signature_hash = compute_eip712_hash(
        &domain_separator, &struct_hash,
    )?;
    eprintln!("Sig hash:      {}", fr_to_hex(&signature_hash));

    let input = ProverInput {
        amount: fr_to_hex(&amount),
        signature_hash: fr_to_hex(&signature_hash),
        burn_data_public: burn_pub,
        root: fr_to_hex(&root),
        minting_pub_key_x: fr_to_hex(&pub_key_x_field),
        chain_id: fr_to_hex(&chain_id_fr),
        burn_data_private: burn_priv,
        num_burn_addresses: num_burns.to_string(),
    };

    let toml_str = toml::to_string_pretty(&input)?;
    std::fs::write(output, &toml_str)?;
    eprintln!("Wrote {}", output.display());

    Ok(())
}
