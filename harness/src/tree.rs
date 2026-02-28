use std::collections::{HashMap, HashSet};

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use taceo_poseidon2::bn254::t4;

const RATE: usize = 3;

/// Domain separator for total-burned balance leaves.
const TOTAL_BURNED_DOMAIN: &str = "0x4255524e5f544f54414c";

/// Noir-compatible Poseidon2 sponge hash (fixed-length mode).
///
/// Matches `Poseidon2::hash(inputs, inputs.len())` in the Noir circuit:
/// - State size: 4, rate: 3
/// - IV = input_length * 2^64, placed in state[3]
/// - Lazy flush: cache is flushed when the NEXT absorb finds it full
/// - Squeeze: flush remaining cache, permute, return state[0]
pub fn poseidon2_hash(inputs: &[Fr]) -> Fr {
    let two_pow_64 = Fr::from(1u64 << 32) * Fr::from(1u64 << 32);
    let iv = Fr::from(inputs.len() as u64) * two_pow_64;

    let mut state = [Fr::zero(), Fr::zero(), Fr::zero(), iv];
    let mut cache = [Fr::zero(); RATE];
    let mut cache_size = 0usize;

    for &input in inputs {
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

    for i in 0..cache_size {
        state[i] += cache[i];
    }
    t4::permutation_in_place(&mut state);

    state[0]
}

/// Parse a hex (0x-prefixed) or decimal string into a BN254 field element.
pub fn parse_fr(s: &str) -> eyre::Result<Fr> {
    if let Some(hex_str) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        let bytes = hex::decode(hex_str)
            .map_err(|e| eyre::eyre!("invalid hex field element '{}': {}", s, e))?;
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

/// Convert Fr to 0x-prefixed hex string (for error messages).
pub fn fr_to_hex(fr: &Fr) -> String {
    format!("0x{}", hex::encode(fr_to_be_bytes(fr)))
}

/// Hash a balance leaf: poseidon2([uint256(uint160(address)), balance, TOTAL_RECEIVED_DOMAIN])
pub fn hash_balance_leaf(address: &str, balance: u128) -> eyre::Result<Fr> {
    let addr_hex = address.strip_prefix("0x").or_else(|| address.strip_prefix("0X"))
        .unwrap_or(address);
    let addr_bytes = hex::decode(addr_hex)
        .map_err(|e| eyre::eyre!("invalid address '{}': {}", address, e))?;
    // Pad to 32 bytes (address is 20 bytes, big-endian)
    let mut padded = [0u8; 32];
    if addr_bytes.len() <= 32 {
        padded[32 - addr_bytes.len()..].copy_from_slice(&addr_bytes);
    }
    let addr_fr = Fr::from_be_bytes_mod_order(&padded);
    // Handle u128 balance: split into high and low 64-bit parts
    let balance_fr = {
        let lo = Fr::from((balance & 0xFFFFFFFFFFFFFFFF) as u64);
        let hi = Fr::from((balance >> 64) as u64);
        let two_pow_64 = Fr::from(1u64 << 32) * Fr::from(1u64 << 32);
        hi * two_pow_64 + lo
    };
    let domain = parse_fr(TOTAL_BURNED_DOMAIN)?;
    Ok(poseidon2_hash(&[addr_fr, balance_fr, domain]))
}

/// Shadow LeanIMT matching `InternalLeanIMT.sol`.
///
/// The tree is append-only with dynamic depth. Side nodes store the last
/// even-position node at each level, enabling efficient single-leaf inserts.
pub struct LeanIMT {
    size: u64,
    depth: u64,
    side_nodes: HashMap<u64, Fr>,
    leaves: HashSet<Fr>,
}

impl LeanIMT {
    pub fn new() -> Self {
        Self {
            size: 0,
            depth: 0,
            side_nodes: HashMap::new(),
            leaves: HashSet::new(),
        }
    }

    /// Check if a leaf exists in the tree.
    pub fn has(&self, leaf: &Fr) -> bool {
        self.leaves.contains(leaf)
    }

    /// Return the current root (side_nodes[depth]), or zero if empty.
    pub fn root(&self) -> Fr {
        self.side_nodes.get(&self.depth).copied().unwrap_or(Fr::zero())
    }

    /// Insert a single leaf, matching `_insert` in InternalLeanIMT.sol.
    pub fn insert(&mut self, leaf: Fr) -> Fr {
        assert!(!leaf.is_zero(), "leaf cannot be zero");
        assert!(!self.leaves.contains(&leaf), "leaf already exists: {}", fr_to_hex(&leaf));

        let index = self.size;

        if (1u64 << self.depth) < index + 1 {
            self.depth += 1;
        }

        let tree_depth = self.depth;
        let mut node = leaf;

        for level in 0..tree_depth {
            if (index >> level) & 1 == 1 {
                let left = self.side_nodes.get(&level).copied().unwrap_or(Fr::zero());
                node = poseidon2_hash(&[left, node]);
            } else {
                self.side_nodes.insert(level, node);
            }
        }

        self.size = index + 1;
        self.side_nodes.insert(tree_depth, node);
        self.leaves.insert(leaf);

        node
    }

    /// Insert multiple leaves, matching `_insertMany` in InternalLeanIMT.sol.
    pub fn insert_many(&mut self, leaves: &[Fr]) -> Fr {
        assert!(!leaves.is_empty(), "insert_many: empty leaves");
        for leaf in leaves {
            assert!(!leaf.is_zero(), "leaf cannot be zero");
            assert!(!self.leaves.contains(leaf), "leaf already exists: {}", fr_to_hex(leaf));
        }

        let tree_size = self.size;

        // Register all leaves.
        for leaf in leaves {
            self.leaves.insert(*leaf);
        }

        // Compute required depth.
        while (1u64 << self.depth) < tree_size + leaves.len() as u64 {
            self.depth += 1;
        }

        let tree_depth = self.depth;
        let mut current_level_new_nodes: Vec<Fr> = leaves.to_vec();
        let mut current_level_start_index = tree_size;
        let mut current_level_size = tree_size + leaves.len() as u64;

        let mut next_level_start_index = current_level_start_index >> 1;
        let mut next_level_size = ((current_level_size - 1) >> 1) + 1;

        for level in 0..tree_depth {
            let num_next = (next_level_size - next_level_start_index) as usize;
            let mut next_level_new_nodes = Vec::with_capacity(num_next);

            for i in 0..num_next {
                let parent_idx = (i as u64) + next_level_start_index;
                let left_child_idx = parent_idx * 2;
                let right_child_idx = parent_idx * 2 + 1;

                let left = if left_child_idx < current_level_start_index {
                    self.side_nodes.get(&level).copied().unwrap_or(Fr::zero())
                } else {
                    current_level_new_nodes[(left_child_idx - current_level_start_index) as usize]
                };

                let right = if right_child_idx < current_level_size {
                    current_level_new_nodes[(right_child_idx - current_level_start_index) as usize]
                } else {
                    Fr::zero()
                };

                let parent = if !right.is_zero() {
                    poseidon2_hash(&[left, right])
                } else {
                    left
                };

                next_level_new_nodes.push(parent);
            }

            // Update side nodes.
            if current_level_size & 1 == 1 {
                self.side_nodes.insert(level,
                    current_level_new_nodes[current_level_new_nodes.len() - 1]);
            } else if current_level_new_nodes.len() > 1 {
                self.side_nodes.insert(level,
                    current_level_new_nodes[current_level_new_nodes.len() - 2]);
            }

            current_level_start_index = next_level_start_index;
            next_level_start_index >>= 1;
            current_level_new_nodes = next_level_new_nodes;
            current_level_size = next_level_size;
            next_level_size = ((next_level_size - 1) >> 1) + 1;
        }

        self.size = tree_size + leaves.len() as u64;
        let root = current_level_new_nodes[0];
        self.side_nodes.insert(tree_depth, root);

        root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_insert_root() {
        let mut tree = LeanIMT::new();
        let leaf = parse_fr("42").unwrap();
        let root = tree.insert(leaf);
        // Single leaf: root = leaf (depth=0, no hashing).
        assert_eq!(root, leaf);
        assert_eq!(tree.root(), leaf);
    }

    #[test]
    fn test_two_inserts() {
        let mut tree = LeanIMT::new();
        let a = parse_fr("1").unwrap();
        let b = parse_fr("2").unwrap();
        tree.insert(a);
        let root = tree.insert(b);
        let expected = poseidon2_hash(&[a, b]);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_three_inserts() {
        let mut tree = LeanIMT::new();
        let a = parse_fr("1").unwrap();
        let b = parse_fr("2").unwrap();
        let c = parse_fr("3").unwrap();
        tree.insert(a);
        tree.insert(b);
        let root = tree.insert(c);
        // Depth 2: level 0 hashes (a,b), (c). Level 1: hash(hash(a,b), c).
        let ab = poseidon2_hash(&[a, b]);
        let expected = poseidon2_hash(&[ab, c]);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_insert_many_matches_sequential() {
        // insert_many([a, b, c]) should produce the same root as insert(a); insert(b); insert(c).
        let a = parse_fr("10").unwrap();
        let b = parse_fr("20").unwrap();
        let c = parse_fr("30").unwrap();

        let mut sequential = LeanIMT::new();
        sequential.insert(a);
        sequential.insert(b);
        sequential.insert(c);

        let mut batch = LeanIMT::new();
        batch.insert_many(&[a, b, c]);

        assert_eq!(sequential.root(), batch.root());
    }

    #[test]
    fn test_insert_many_after_insert() {
        // insert(a); insert_many([b, c]) should equal insert(a); insert(b); insert(c).
        let a = parse_fr("100").unwrap();
        let b = parse_fr("200").unwrap();
        let c = parse_fr("300").unwrap();

        let mut sequential = LeanIMT::new();
        sequential.insert(a);
        sequential.insert(b);
        sequential.insert(c);

        let mut mixed = LeanIMT::new();
        mixed.insert(a);
        mixed.insert_many(&[b, c]);

        assert_eq!(sequential.root(), mixed.root());
    }

    #[test]
    fn test_four_inserts() {
        let mut tree = LeanIMT::new();
        let vals: Vec<Fr> = (1..=4).map(|i| parse_fr(&i.to_string()).unwrap()).collect();
        for v in &vals {
            tree.insert(*v);
        }
        let ab = poseidon2_hash(&[vals[0], vals[1]]);
        let cd = poseidon2_hash(&[vals[2], vals[3]]);
        let expected = poseidon2_hash(&[ab, cd]);
        assert_eq!(tree.root(), expected);
    }

    #[test]
    fn test_has() {
        let mut tree = LeanIMT::new();
        let a = parse_fr("42").unwrap();
        assert!(!tree.has(&a));
        tree.insert(a);
        assert!(tree.has(&a));
    }

    #[test]
    fn test_balance_leaf_hash() {
        // Sanity check that hash_balance_leaf produces a non-zero result.
        let leaf = hash_balance_leaf("0x70997970C51812dc3A010C7d01b50e0d17dc79C8", 10_000_000_000_000_000_000_000_000).unwrap();
        assert!(!leaf.is_zero());
    }
}
