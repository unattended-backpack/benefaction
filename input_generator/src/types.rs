use serde::Serialize;

pub const MAX_TREE_DEPTH: usize = 44;
pub const BURN_ADDRESSES_LEN: usize = 32;

/// TOML-serializable input for the Noir ZK mint circuit.
///
/// Field names and structure match circuits/Prover.toml.
#[derive(Serialize)]
pub struct ProverInput {
    pub amount: String,
    pub signature_hash: String,
    pub burn_data_public: Vec<BurnDataPublic>,
    pub root: String,
    pub minting_pub_key_x: String,
    pub chain_id: String,
    pub burn_data_private: Vec<BurnDataPrivate>,
    pub num_burn_addresses: String,
}

#[derive(Serialize, Clone)]
pub struct BurnDataPublic {
    pub account_note_hash: String,
    pub account_note_nullifier: String,
}

#[derive(Serialize, Clone)]
pub struct BurnDataPrivate {
    pub viewing_key: String,
    pub pow_nonce: String,
    pub total_burned: String,
    pub prev_total_minted: String,
    pub amount_to_mint: String,
    pub prev_account_nonce: String,
    pub prev_account_note_tree_proof: TreeProof,
    pub total_burned_tree_proof: TreeProof,
}

#[derive(Serialize, Clone)]
pub struct TreeProof {
    pub depth: String,
    pub indices: Vec<String>,
    pub siblings: Vec<String>,
}

impl BurnDataPublic {
    pub fn zero() -> Self {
        Self {
            account_note_hash: "0x0".to_string(),
            account_note_nullifier: "0x0".to_string(),
        }
    }
}

impl BurnDataPrivate {
    pub fn zero() -> Self {
        Self {
            viewing_key: "0x0".to_string(),
            pow_nonce: "0x0".to_string(),
            total_burned: "0x0".to_string(),
            prev_total_minted: "0x0".to_string(),
            amount_to_mint: "0x0".to_string(),
            prev_account_nonce: "0x0".to_string(),
            prev_account_note_tree_proof: TreeProof::empty(),
            total_burned_tree_proof: TreeProof::empty(),
        }
    }
}

impl TreeProof {
    pub fn empty() -> Self {
        Self {
            depth: "0".to_string(),
            indices: vec!["0".to_string(); MAX_TREE_DEPTH],
            siblings: vec!["0".to_string(); MAX_TREE_DEPTH],
        }
    }

    pub fn from_proof(depth: u32, indices: &[u8], siblings: &[ark_bn254::Fr]) -> Self {
        let mut idx_strs = indices.iter().map(|&i| i.to_string()).collect::<Vec<_>>();
        let mut sib_strs = siblings.iter().map(|s| fr_to_hex(s)).collect::<Vec<_>>();
        idx_strs.resize(MAX_TREE_DEPTH, "0".to_string());
        sib_strs.resize(MAX_TREE_DEPTH, "0x0".to_string());
        Self {
            depth: depth.to_string(),
            indices: idx_strs,
            siblings: sib_strs,
        }
    }
}

/// Format a field element as a hex string for TOML output.
pub fn fr_to_hex(fr: &ark_bn254::Fr) -> String {
    use ark_ff::{BigInteger, PrimeField};
    let bytes = fr.into_bigint().to_bytes_be();
    // Strip leading zeros for cleaner output
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    if first_nonzero == bytes.len() {
        "0x0".to_string()
    } else {
        format!("0x{}", hex::encode(&bytes[first_nonzero..]))
    }
}
