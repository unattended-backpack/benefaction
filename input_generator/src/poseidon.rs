use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use taceo_poseidon2::bn254::t4;

const RATE: usize = 3;

/// Domain separators matching circuits/src/main.nr
pub const PRIVATE_ADDRESS_TYPE: &str = "0x4255524e5f41444452455353"; // UTF8("BURN_ADDRESS")
pub const TOTAL_BURNED_DOMAIN: &str = "0x4255524e5f544f54414c"; // UTF8("BURN_TOTAL")
pub const TOTAL_MINTED_DOMAIN: &str = "0x4d494e545f544f54414c"; // UTF8("MINT_TOTAL")
pub const POW_DIFFICULTY: &str =
    "0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// The BN254 scalar field modulus (for reference; Fr arithmetic reduces mod this).
#[allow(dead_code)]
pub const SNARK_SCALAR_FIELD: &str =
    "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";

/// Parse a hex (0x-prefixed) or decimal string into a BN254 field element.
pub fn parse_fr(s: &str) -> eyre::Result<Fr> {
    if let Some(hex_str) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        let bytes = hex::decode(hex_str)
            .map_err(|e| eyre::eyre!("invalid hex field element '{}': {}", s, e))?;
        // Pad to 32 bytes (big-endian)
        let mut padded = [0u8; 32];
        if bytes.len() > 32 {
            eyre::bail!("hex value '{}' exceeds 32 bytes", s);
        }
        padded[32 - bytes.len()..].copy_from_slice(&bytes);
        Ok(Fr::from_be_bytes_mod_order(&padded))
    } else {
        use std::str::FromStr;
        Fr::from_str(s).map_err(|_| eyre::eyre!("invalid field element '{}'", s))
    }
}

/// Convert Fr to 32-byte big-endian representation.
pub fn fr_to_be_bytes(fr: &Fr) -> [u8; 32] {
    let bigint = fr.into_bigint();
    let le_bytes = bigint.to_bytes_le();
    let mut be = [0u8; 32];
    for (i, &b) in le_bytes.iter().enumerate() {
        if i < 32 {
            be[31 - i] = b;
        }
    }
    be
}

/// Noir-compatible Poseidon2 sponge hash (fixed-length mode).
///
/// Matches `Poseidon2::hash(inputs, inputs.len())` in the Noir circuit:
/// - State size: 4, rate: 3
/// - IV = input_length * 2^64, placed in state[3]
/// - Absorb: add cached elements to state, then permute
/// - Squeeze: permute, return state[0]
/// - Fixed-length mode: no `1` separator appended
pub fn poseidon2_hash(inputs: &[Fr]) -> Fr {
    // IV = input_length << 64
    let two_pow_64 = Fr::from(1u64 << 32) * Fr::from(1u64 << 32);
    let iv = Fr::from(inputs.len() as u64) * two_pow_64;

    let mut state = [Fr::zero(), Fr::zero(), Fr::zero(), iv];
    let mut cache = [Fr::zero(); RATE];
    let mut cache_size = 0usize;

    for &input in inputs {
        // Flush full cache before absorbing new element (matches Noir's lazy flush)
        if cache_size == RATE {
            for i in 0..RATE {
                state[i] += cache[i];
                cache[i] = Fr::zero();
            }
            t4::permutation_in_place(&mut state);
            cache_size = 0;
        }
        cache[cache_size] = input;
        cache_size += 1;
    }

    // Final squeeze: flush remaining cache and permute
    for i in 0..cache_size {
        state[i] += cache[i];
    }
    t4::permutation_in_place(&mut state);

    state[0]
}

/// Two-stage blinded address derivation (step 1):
/// blinded = Poseidon2([pub_key_x, chain_id, viewing_key])
pub fn hash_blinded_burn_address_data(
    pub_key_x_field: Fr,
    chain_id: Fr,
    viewing_key: Fr,
) -> Fr {
    poseidon2_hash(&[pub_key_x_field, chain_id, viewing_key])
}

/// Two-stage blinded address derivation (step 2):
/// address_hash = Poseidon2([blinded, pow_nonce, PRIVATE_ADDRESS_TYPE])
/// pow_hash = Poseidon2([pow_nonce, address_hash])
/// Check pow_hash < POW_DIFFICULTY
/// Truncate address_hash to 20 bytes → burn address
///
/// Returns (burn_address, pow_hash).
pub fn get_burn_address(
    blinded: Fr,
    pow_nonce: Fr,
) -> eyre::Result<(Fr, Fr)> {
    let addr_type = parse_fr(PRIVATE_ADDRESS_TYPE)?;
    let address_hash = poseidon2_hash(&[blinded, pow_nonce, addr_type]);
    let pow_hash = poseidon2_hash(&[pow_nonce, address_hash]);

    // Zero the first 12 bytes to get 20-byte address
    let mut addr_bytes = fr_to_be_bytes(&address_hash);
    for b in addr_bytes[..12].iter_mut() {
        *b = 0;
    }
    let burn_address = Fr::from_be_bytes_mod_order(&addr_bytes);

    Ok((burn_address, pow_hash))
}

/// Full two-stage address derivation from raw inputs.
/// Returns (burn_address, pow_hash, blinded_hash).
pub fn get_private_address(
    pub_key_x_field: Fr,
    pow_nonce: Fr,
    viewing_key: Fr,
    chain_id: Fr,
) -> eyre::Result<(Fr, Fr, Fr)> {
    let blinded = hash_blinded_burn_address_data(pub_key_x_field, chain_id, viewing_key);
    let (burn_address, pow_hash) = get_burn_address(blinded, pow_nonce)?;
    Ok((burn_address, pow_hash, blinded))
}

/// Check if pow_hash < POW_DIFFICULTY.
pub fn check_pow(pow_hash: &Fr) -> eyre::Result<bool> {
    let difficulty = parse_fr(POW_DIFFICULTY)?;
    // Compare as big integers
    let pow_int = pow_hash.into_bigint();
    let diff_int = difficulty.into_bigint();
    Ok(pow_int < diff_int)
}

/// hash_nullifier(account_nonce, viewing_key) = Poseidon2([account_nonce, viewing_key])
pub fn hash_nullifier(account_nonce: Fr, viewing_key: Fr) -> Fr {
    poseidon2_hash(&[account_nonce, viewing_key])
}

/// hash_account_note — 5-element:
///   Poseidon2([total_minted, account_nonce, blinded, viewing_key, TOTAL_MINTED_DOMAIN])
pub fn hash_account_note(
    total_minted: Fr,
    account_nonce: Fr,
    blinded: Fr,
    viewing_key: Fr,
) -> eyre::Result<Fr> {
    let domain = parse_fr(TOTAL_MINTED_DOMAIN)?;
    Ok(poseidon2_hash(&[
        total_minted,
        account_nonce,
        blinded,
        viewing_key,
        domain,
    ]))
}

/// hash_total_burned_leaf(burn_address, total_burned) =
///   Poseidon2([burn_address, total_burned, TOTAL_BURNED_DOMAIN])
pub fn hash_total_burned_leaf(burn_address: Fr, total_burned: Fr) -> eyre::Result<Fr> {
    let domain = parse_fr(TOTAL_BURNED_DOMAIN)?;
    Ok(poseidon2_hash(&[burn_address, total_burned, domain]))
}

/// Compute the EIP-712 signature hash (mod SNARK_SCALAR_FIELD).
///
/// This produces `uint256(keccak256("\x19\x01" || domainSeparator || structHash)) % p`
/// where p is the BN254 scalar field.
///
/// The inputs are the raw components needed to build the EIP-712 typed data hash.
pub fn compute_eip712_hash(
    domain_separator: &[u8; 32],
    struct_hash: &[u8; 32],
) -> eyre::Result<Fr> {
    use alloy::primitives::keccak256;

    let mut pre_image = [0u8; 66];
    pre_image[0] = 0x19;
    pre_image[1] = 0x01;
    pre_image[2..34].copy_from_slice(domain_separator);
    pre_image[34..66].copy_from_slice(struct_hash);
    let digest = keccak256(pre_image);
    Ok(Fr::from_be_bytes_mod_order(&digest.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nullifier_matches_noir() {
        // Nullifier hash is unchanged: Poseidon2([nonce, vk], 2)
        let nonce = parse_fr("0").unwrap();
        let vk =
            parse_fr("0x238ffb2206d0a5477d54b22d2ca5e0fd81024119920d60bb19967170555ddca4").unwrap();
        let result = hash_nullifier(nonce, vk);
        let expected =
            parse_fr("0x20b9fc5484e7e16a96e8a9e8c648103c9a91e3d676bf73851747493b61fa0d73").unwrap();
        let result_hex = format!("0x{}", hex::encode(fr_to_be_bytes(&result)));
        let expected_hex = format!("0x{}", hex::encode(fr_to_be_bytes(&expected)));
        assert_eq!(
            result, expected,
            "nullifier mismatch:\n  got:      {}\n  expected: {}",
            result_hex, expected_hex
        );
    }

    #[test]
    fn test_blinded_hash_deterministic() {
        let pub_key_x = parse_fr("0x1234").unwrap();
        let chain_id = Fr::from(31337u64);
        let vk = parse_fr("0x5678").unwrap();
        let result = hash_blinded_burn_address_data(pub_key_x, chain_id, vk);
        assert!(!result.is_zero(), "blinded hash should be non-zero");
        // Verify determinism
        let result2 = hash_blinded_burn_address_data(pub_key_x, chain_id, vk);
        assert_eq!(result, result2, "blinded hash should be deterministic");
    }

    #[test]
    fn test_account_note_5_element() {
        let total_minted = parse_fr("100").unwrap();
        let nonce = parse_fr("1").unwrap();
        let blinded = parse_fr("0xabcd").unwrap();
        let vk = parse_fr("0x5678").unwrap();
        let result = hash_account_note(total_minted, nonce, blinded, vk).unwrap();
        assert!(!result.is_zero(), "account note hash should be non-zero");
    }

    #[test]
    fn test_total_burned_leaf() {
        let addr = parse_fr("0x1234").unwrap();
        let balance = parse_fr("100").unwrap();
        let result = hash_total_burned_leaf(addr, balance).unwrap();
        assert!(!result.is_zero(), "burned leaf hash should be non-zero");
    }

    #[test]
    fn test_eip712_hash() {
        let domain_sep = [0u8; 32];
        let struct_hash = [1u8; 32];
        let result = compute_eip712_hash(&domain_sep, &struct_hash).unwrap();
        assert!(!result.is_zero(), "EIP-712 hash should be non-zero");
    }

    // -----------------------------------------------------------------------
    // Key derivation helpers (duplicated from main.rs for test isolation)
    // -----------------------------------------------------------------------

    fn parse_signing_key(hex_str: &str) -> k256::ecdsa::SigningKey {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str).unwrap();
        k256::ecdsa::SigningKey::from_bytes(bytes.as_slice().into()).unwrap()
    }

    fn derive_pub_key(signing_key: &k256::ecdsa::SigningKey) -> [u8; 32] {
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);
        let mut x = [0u8; 32];
        x.copy_from_slice(point.x().unwrap());
        x
    }

    fn pub_key_x_to_field(pub_key_x: &[u8; 32]) -> Fr {
        let mut bytes = *pub_key_x;
        bytes[0] = 0;
        Fr::from_be_bytes_mod_order(&bytes)
    }

    fn derive_viewing_key(signing_key: &k256::ecdsa::SigningKey) -> Fr {
        let msg_hash = alloy::primitives::keccak256(crate::VIEWING_KEY_DOMAIN);
        use k256::ecdsa::{signature::Signer, Signature};
        let sig: Signature = signing_key.sign(&msg_hash.0);
        let r_bytes = &sig.to_bytes()[..32];
        Fr::from_be_bytes_mod_order(r_bytes)
    }

    fn fmt_fr(fr: &Fr) -> String {
        let bytes = fr_to_be_bytes(fr);
        let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
        if first_nonzero == bytes.len() {
            "0x00".to_string()
        } else {
            format!("0x{}", hex::encode(&bytes[first_nonzero..]))
        }
    }

    /// Generate all test vectors for the Noir circuit tests.
    ///
    /// Run with: cargo test test_generate_noir_vectors -- --nocapture
    #[test]
    fn test_generate_noir_vectors() {
        let chain_id = Fr::from(31337u64);

        // KEY1 = 0x...01
        let sk1 = parse_signing_key(
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        );
        let pub_key_x1_bytes = derive_pub_key(&sk1);
        let pub_key_x1 = pub_key_x_to_field(&pub_key_x1_bytes);
        let vk1 = derive_viewing_key(&sk1);
        let blinded1 = hash_blinded_burn_address_data(pub_key_x1, chain_id, vk1);

        // Pre-mined nonce for KEY1
        let nonce1 = parse_fr(
            "0x08e4eedca9be98c79d9a4edd6fcb0e63b3b0e5793a8fd59748fbfe9cdd1644e6",
        ).unwrap();
        let (burn_addr1, pow_hash1) = get_burn_address(blinded1, nonce1).unwrap();
        assert!(check_pow(&pow_hash1).unwrap(), "KEY1 PoW nonce is invalid");

        // KEY2 = 0x...02
        let sk2 = parse_signing_key(
            "0x0000000000000000000000000000000000000000000000000000000000000002",
        );
        let pub_key_x2_bytes = derive_pub_key(&sk2);
        let pub_key_x2 = pub_key_x_to_field(&pub_key_x2_bytes);
        let vk2 = derive_viewing_key(&sk2);
        let blinded2 = hash_blinded_burn_address_data(pub_key_x2, chain_id, vk2);

        // Pre-mined nonce for KEY2
        let nonce2 = parse_fr(
            "0x277ef6ad78514998a52ac8672150bb63261f1250f18a64a3ea458b89264a88b2",
        ).unwrap();
        let (burn_addr2, pow_hash2) = get_burn_address(blinded2, nonce2).unwrap();
        assert!(check_pow(&pow_hash2).unwrap(), "KEY2 PoW nonce is invalid");

        // ── Hash function golden values ──

        // Nullifiers
        let null1_n0 = hash_nullifier(Fr::from(0u64), vk1);
        let null1_n1 = hash_nullifier(Fr::from(1u64), vk1);
        let null2_n0 = hash_nullifier(Fr::from(0u64), vk2);

        // Total burned leaves (balance = 100)
        let total_burned = Fr::from(100u64);
        let burned_leaf1 = hash_total_burned_leaf(burn_addr1, total_burned).unwrap();
        let burned_leaf2 = hash_total_burned_leaf(burn_addr2, total_burned).unwrap();

        // Account note hashes
        // First mint: mint 50, nonce becomes 1, new_minted=50
        let mint_amount = Fr::from(50u64);
        let acct_note1_first = hash_account_note(
            mint_amount, Fr::from(1u64), blinded1, vk1,
        ).unwrap();

        // Second mint: mint 30 more, nonce becomes 2, new_minted=80
        let mint2_amount = Fr::from(30u64);
        let prev_minted = Fr::from(50u64);
        let new_minted = prev_minted + mint2_amount; // 80
        let acct_note1_second = hash_account_note(
            new_minted, Fr::from(2u64), blinded1, vk1,
        ).unwrap();

        // KEY2 first mint: mint 50, nonce becomes 1
        let acct_note2_first = hash_account_note(
            mint_amount, Fr::from(1u64), blinded2, vk2,
        ).unwrap();

        // ── Hash trees ──

        // Single-leaf tree (depth 0): root = leaf
        let root_single1 = burned_leaf1;

        // 3-leaf tree for second mint: [burned_leaf1, acct_note1_first, 0]
        // LeanIMT: level0 = [burned_leaf1, acct_note1_first, <promoted>]
        // Wait, there's no 3rd leaf in this scenario. Let me think...
        // After first mint: tree has 2 leaves: [burned_leaf1, acct_note1_first]
        // Root = Poseidon2([burned_leaf1, acct_note1_first])
        let root_two_leaf = poseidon2_hash(&[burned_leaf1, acct_note1_first]);

        // Tree proof for burned_leaf1 in 2-leaf tree: index=0, sibling=acct_note1_first
        // Tree proof for acct_note1_first in 2-leaf tree: index=1, sibling=burned_leaf1

        // Also compute: Poseidon2([a, b]) for tree hash tests
        let dummy_a = Fr::from(42u64);
        let dummy_b = Fr::from(99u64);
        let tree_hash_lr = poseidon2_hash(&[dummy_a, dummy_b]);
        let tree_hash_rl = poseidon2_hash(&[dummy_b, dummy_a]);

        // ── Print all values ──

        println!("\n=== NOIR TEST VECTORS ===\n");

        println!("// KEY1 (spending key 0x...01)");
        println!("// pub_key_x1 = {}", fmt_fr(&pub_key_x1));
        println!("// vk1        = {}", fmt_fr(&vk1));
        println!("// blinded1   = {}", fmt_fr(&blinded1));
        println!("// nonce1     = {}", fmt_fr(&nonce1));
        println!("// burn_addr1 = {}", fmt_fr(&burn_addr1));
        println!();

        println!("// KEY2 (spending key 0x...02)");
        println!("// pub_key_x2 = {}", fmt_fr(&pub_key_x2));
        println!("// vk2        = {}", fmt_fr(&vk2));
        println!("// blinded2   = {}", fmt_fr(&blinded2));
        println!("// nonce2     = {}", fmt_fr(&nonce2));
        println!("// burn_addr2 = {}", fmt_fr(&burn_addr2));
        println!();

        println!("// Hash golden values");
        println!("// null1_n0         = {}", fmt_fr(&null1_n0));
        println!("// null1_n1         = {}", fmt_fr(&null1_n1));
        println!("// null2_n0         = {}", fmt_fr(&null2_n0));
        println!("// burned_leaf1     = {}", fmt_fr(&burned_leaf1));
        println!("// burned_leaf2     = {}", fmt_fr(&burned_leaf2));
        println!("// acct_note1_first = {}", fmt_fr(&acct_note1_first));
        println!("// acct_note1_second= {}", fmt_fr(&acct_note1_second));
        println!("// acct_note2_first = {}", fmt_fr(&acct_note2_first));
        println!();

        println!("// Tree roots");
        println!("// root_single1     = {} (== burned_leaf1)", fmt_fr(&root_single1));
        println!("// root_two_leaf    = {}", fmt_fr(&root_two_leaf));
        println!();

        println!("// Tree hasher tests");
        println!("// Poseidon2([42, 99]) = {}", fmt_fr(&tree_hash_lr));
        println!("// Poseidon2([99, 42]) = {}", fmt_fr(&tree_hash_rl));
        println!();

        // Print as Noir constants block
        println!("// ─── Copy-paste block for Noir tests ───");
        println!();
        println!("// KEY1");
        println!("global TEST_PUB_KEY_X1: Field = {};", fmt_fr(&pub_key_x1));
        println!("global TEST_VK1: Field = {};", fmt_fr(&vk1));
        println!("global TEST_BLINDED1: Field = {};", fmt_fr(&blinded1));
        println!("global TEST_NONCE1: Field = {};", fmt_fr(&nonce1));
        println!("global TEST_BURN_ADDR1: Field = {};", fmt_fr(&burn_addr1));
        println!();
        println!("// KEY2");
        println!("global TEST_PUB_KEY_X2: Field = {};", fmt_fr(&pub_key_x2));
        println!("global TEST_VK2: Field = {};", fmt_fr(&vk2));
        println!("global TEST_BLINDED2: Field = {};", fmt_fr(&blinded2));
        println!("global TEST_NONCE2: Field = {};", fmt_fr(&nonce2));
        println!("global TEST_BURN_ADDR2: Field = {};", fmt_fr(&burn_addr2));
        println!();
        println!("// Nullifiers");
        println!("global TEST_NULL1_N0: Field = {};", fmt_fr(&null1_n0));
        println!("global TEST_NULL1_N1: Field = {};", fmt_fr(&null1_n1));
        println!("global TEST_NULL2_N0: Field = {};", fmt_fr(&null2_n0));
        println!();
        println!("// Burned leaves (balance=100)");
        println!("global TEST_BURNED_LEAF1: Field = {};", fmt_fr(&burned_leaf1));
        println!("global TEST_BURNED_LEAF2: Field = {};", fmt_fr(&burned_leaf2));
        println!();
        println!("// Account notes");
        println!("global TEST_ACCT_NOTE1_FIRST: Field = {};  // minted=50, nonce=1", fmt_fr(&acct_note1_first));
        println!("global TEST_ACCT_NOTE1_SECOND: Field = {}; // minted=80, nonce=2", fmt_fr(&acct_note1_second));
        println!("global TEST_ACCT_NOTE2_FIRST: Field = {};  // minted=50, nonce=1", fmt_fr(&acct_note2_first));
        println!();
        println!("// Tree roots");
        println!("global TEST_ROOT_SINGLE1: Field = {};  // == burned_leaf1", fmt_fr(&root_single1));
        println!("global TEST_ROOT_TWO_LEAF: Field = {};", fmt_fr(&root_two_leaf));
        println!();
        println!("// Tree hasher tests");
        println!("global TEST_TREE_HASH_LR: Field = {};  // Poseidon2([42, 99])", fmt_fr(&tree_hash_lr));
        println!("global TEST_TREE_HASH_RL: Field = {};  // Poseidon2([99, 42])", fmt_fr(&tree_hash_rl));

        // ── Multi-burn vectors ──
        // "multi" = KEY1 pub_key_x + VK2 (different viewing key, same spending key)
        let blinded_multi = hash_blinded_burn_address_data(pub_key_x1, chain_id, vk2);

        // Mine a nonce for (blinded_multi, nonce) until PoW passes
        // Pre-mined nonce (found on first run, then hardcoded):
        let nonce_multi = parse_fr(
            "0x1a27572e82e30d621df44a2bd41c2fe79b75e3b0d8c75cfa96d3c860dcf73193",
        ).unwrap();
        let (burn_addr_multi, pow_hash_multi) = get_burn_address(blinded_multi, nonce_multi).unwrap();
        if !check_pow(&pow_hash_multi).unwrap() {
            // If hardcoded nonce is invalid, mine a new one
            use ark_ff::Field;
            use rand::Rng;
            let mut rng = rand::rng();
            let mut attempts = 0u64;
            loop {
                attempts += 1;
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
                let (_, pow_hash) = get_burn_address(blinded_multi, nonce).unwrap();
                if check_pow(&pow_hash).unwrap() {
                    println!("\n!!! MINED NEW MULTI-BURN NONCE after {} attempts !!!", attempts);
                    println!("!!! Update NONCE_MULTI in poseidon.rs with this value:");
                    println!("!!! nonce_multi = {}", fmt_fr(&nonce));
                    panic!("Hardcoded nonce_multi is invalid — see output above for the new nonce");
                }
            }
        }

        // Nullifier for VK2 at nonce=0
        let null_multi_n0 = hash_nullifier(Fr::from(0u64), vk2);

        // Burned leaf for multi burn address (balance = 200)
        let total_burned_multi = Fr::from(200u64);
        let burned_leaf_multi = hash_total_burned_leaf(burn_addr_multi, total_burned_multi).unwrap();

        // Account note for multi: mint 70, nonce becomes 1
        let acct_note_multi_first = hash_account_note(
            Fr::from(70u64), Fr::from(1u64), blinded_multi, vk2,
        ).unwrap();

        // ── Multi-burn hash trees ──

        // 2-leaf tree: [burned_leaf1(100), burned_leaf_multi(200)]
        let root_2burn = poseidon2_hash(&[burned_leaf1, burned_leaf_multi]);
        // Proof for burned_leaf1: index=0, sibling=burned_leaf_multi
        // Proof for burned_leaf_multi: index=1, sibling=burned_leaf1

        // 4-leaf tree: [burned_leaf1, burned_leaf_multi, acct_note1_first, acct_note_multi_first]
        // Level 0: hash pairs
        let l0_left = poseidon2_hash(&[burned_leaf1, burned_leaf_multi]);
        let l0_right = poseidon2_hash(&[acct_note1_first, acct_note_multi_first]);
        let root_4leaf = poseidon2_hash(&[l0_left, l0_right]);
        // Proofs (depth=2):
        // burned_leaf1: index=[0,0], siblings=[burned_leaf_multi, l0_right]
        // burned_leaf_multi: index=[1,0], siblings=[burned_leaf1, l0_right]
        // acct_note1_first: index=[0,1], siblings=[acct_note_multi_first, l0_left]
        // acct_note_multi_first: index=[1,1], siblings=[acct_note1_first, l0_left]

        println!();
        println!("// ─── Multi-burn vectors (KEY1 pub_key_x + VK2) ───");
        println!();
        println!("// MULTI = KEY1 spending key with VK2 viewing key");
        println!("global TEST_BLINDED_MULTI: Field = {};", fmt_fr(&blinded_multi));
        println!("global TEST_NONCE_MULTI: Field = {};", fmt_fr(&nonce_multi));
        println!("global TEST_BURN_ADDR_MULTI: Field = {};", fmt_fr(&burn_addr_multi));
        println!("global TEST_NULL_MULTI_N0: Field = {};  // == TEST_NULL2_N0 (same VK2)", fmt_fr(&null_multi_n0));
        println!();
        println!("// Burned leaf for multi address (balance=200)");
        println!("global TEST_BURNED_LEAF_MULTI: Field = {};", fmt_fr(&burned_leaf_multi));
        println!();
        println!("// Account note: minted=70, nonce=1, blinded_multi, VK2");
        println!("global TEST_ACCT_NOTE_MULTI_FIRST: Field = {};", fmt_fr(&acct_note_multi_first));
        println!();
        println!("// 2-burn hash tree: [burned_leaf1, burned_leaf_multi]");
        println!("global TEST_ROOT_2BURN: Field = {};", fmt_fr(&root_2burn));
        println!();
        println!("// 4-leaf hash tree: [burned_leaf1, burned_leaf_multi, acct_note1_first, acct_note_multi_first]");
        println!("global TEST_4LEAF_L0_LEFT: Field = {};  // Poseidon2([burned_leaf1, burned_leaf_multi])", fmt_fr(&l0_left));
        println!("global TEST_4LEAF_L0_RIGHT: Field = {};  // Poseidon2([acct_note1_first, acct_note_multi_first])", fmt_fr(&l0_right));
        println!("global TEST_ROOT_4LEAF: Field = {};", fmt_fr(&root_4leaf));

        // Verify null_multi_n0 == null2_n0 (same VK2)
        assert_eq!(null_multi_n0, null2_n0, "null_multi_n0 should equal null2_n0 (same VK2)");

        // ── Stealth address vectors ──
        // Arbitrary viewing key unrelated to any ECDSA key
        let vk_stealth = Fr::from(0x42u64);
        let blinded_stealth = hash_blinded_burn_address_data(pub_key_x1, chain_id, vk_stealth);

        // Pre-mined nonce for stealth address
        let nonce_stealth = parse_fr(
            "0x05457d881145d920beb549ef7c6daa4c404676edbf14ff21fade3c9abeb26bb7",
        ).unwrap();
        let (burn_addr_stealth, pow_hash_stealth) = get_burn_address(blinded_stealth, nonce_stealth).unwrap();
        if !check_pow(&pow_hash_stealth).unwrap() {
            use ark_ff::Field;
            use rand::Rng;
            let mut rng = rand::rng();
            let mut attempts = 0u64;
            loop {
                attempts += 1;
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
                let (_, pow_hash) = get_burn_address(blinded_stealth, nonce).unwrap();
                if check_pow(&pow_hash).unwrap() {
                    println!("\n!!! MINED NEW STEALTH NONCE after {} attempts !!!", attempts);
                    println!("!!! Update nonce_stealth in poseidon.rs with this value:");
                    println!("!!! nonce_stealth = {}", fmt_fr(&nonce));
                    panic!("Hardcoded nonce_stealth is invalid — see output above for the new nonce");
                }
            }
        }

        let null_stealth_n0 = hash_nullifier(Fr::from(0u64), vk_stealth);
        let total_burned_stealth = Fr::from(150u64);
        let burned_leaf_stealth = hash_total_burned_leaf(burn_addr_stealth, total_burned_stealth).unwrap();
        let acct_note_stealth_first = hash_account_note(
            Fr::from(60u64), Fr::from(1u64), blinded_stealth, vk_stealth,
        ).unwrap();

        // 2-leaf tree: [burned_leaf1(100), burned_leaf_stealth(150)]
        let root_stealth_2leaf = poseidon2_hash(&[burned_leaf1, burned_leaf_stealth]);

        println!();
        println!("// ─── Stealth address vectors (KEY1 pub_key_x + VK=0x42) ───");
        println!();
        println!("global TEST_VK_STEALTH: Field = {};", fmt_fr(&vk_stealth));
        println!("global TEST_BLINDED_STEALTH: Field = {};", fmt_fr(&blinded_stealth));
        println!("global TEST_NONCE_STEALTH: Field = {};", fmt_fr(&nonce_stealth));
        println!("global TEST_BURN_ADDR_STEALTH: Field = {};", fmt_fr(&burn_addr_stealth));
        println!("global TEST_NULL_STEALTH_N0: Field = {};", fmt_fr(&null_stealth_n0));
        println!("global TEST_BURNED_LEAF_STEALTH: Field = {};  // balance=150", fmt_fr(&burned_leaf_stealth));
        println!("global TEST_ACCT_NOTE_STEALTH_FIRST: Field = {};  // minted=60, nonce=1", fmt_fr(&acct_note_stealth_first));
        println!("global TEST_ROOT_STEALTH_2LEAF: Field = {};  // [burned_leaf1, burned_leaf_stealth]", fmt_fr(&root_stealth_2leaf));

        println!("\n=== END NOIR TEST VECTORS ===");
    }
}
