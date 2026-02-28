use dep::{
  poseidon::poseidon2::Poseidon2,
  std::field::{bn254::{assert_lt, gt}, bytes32_to_field},
};
use binary_merkle_root::binary_merkle_root;

/**
  The domain separator for distinguishing burn address hashes.
  UTF8("BURN_ADDRESS")
*/
global BURN_ADDRESS_DOMAIN: Field = 0x4255524e5f41444452455353;

/**
  The domain separator for distinguishing burn total hashes.
  UTF8("BURN_TOTAL")
*/
global BURN_TOTAL_DOMAIN: Field = 0x4255524e5f544f54414c;

/**
  The domain separator for distinguishing mint total hashes.
  UTF8("MINT_TOTAL")
*/
global MINT_TOTAL_DOMAIN: Field = 0x4d494e545f544f54414c;

/**
  Burn addresses must be mined to pass a proof-of-work check; at least five
  leading zeroes are required in the computed PoW hash. This check makes it
  significantly more costly to try and generate an invalid proof to knapsack
  attack the Ethereum burn address space.
*/
global POW_DIFFICULTY: Field =
  0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

/**
  The maximum depth of the hash tree used to store account balances. This limits
  the total number of token transfers that may take place before new zero
  knowledge minting becomes impossible. A depth of 44 allows for 100+ years of
  operation at 35,000 TPS where every transaction is a burn transaction. After
  that, any tokens burned will be actually be burned without the ability to zero
  knowledge mint them again. Any tokens burned before reaching this depth would
  remain mintable still. Those burn leaves will always exist, and the contract
  always stores that root. The contract cannot prevent this because the contract
  cannot know if a particular address leaf corresponds to a burn or not.
*/
global MAX_TREE_DEPTH: u32 = 44;

/**
  The number of burn addresses provided as input to the circuit. This supports
  performing consolidated zero knowledge mints on values across 32 (or fewer)
  individual burns.
*/
global BURN_ADDRESSES_LEN: u32 = 32;

/**
  A hash tree inclusion proof for a leaf in the balance commitment tree.

  @param depth The depth of the leaf in the tree.
  @param indices The path bits (left=0, right=1) from the leaf to the root.
  @param siblings The sibling hashes along the path from the leaf to the root.
*/
struct TreeProof {
  depth: u32,
  indices: [u1; MAX_TREE_DEPTH],
  siblings: [Field; MAX_TREE_DEPTH],
}

/**
  Public inputs for a single burn slot. These are visible on-chain and verified
  by both the circuit and the contract.

  @param account_note_hash The new account note commitment inserted into the
    contract's tree after proof submission. This binds the updated total minted,
    incremented nonce, blinded address, and viewing key for a particular burn.
  @param account_note_nullifier The nullifier for the previous account note,
    preventing double-minting. Derived from the previous nonce and viewing key.
*/
struct BurnDataPublic {
  account_note_hash: Field,
  account_note_nullifier: Field,
}

/**
  Private inputs for a single burn slot. These are hidden from the verifier and
  known only to the prover.

  @param viewing_key A secret key that blinds the burn address and is mixed
    into account note hashes and nullifiers. May be derived from the minting key
    or chosen independently for stealth addresses.
  @param pow_nonce The proof-of-work nonce that, combined with the blinded
    address data, produces a burn address passing the difficulty check.
  @param total_burned The total token balance sent to this burn address, as
    recorded in the contract's commitment tree.
  @param prev_total_minted The cumulative amount previously minted from this
    burn address. Zero on first mint.
  @param amount_to_mint The amount to mint from this burn address in the
    current proof.
  @param prev_account_nonce The nonce of the previous account note. Zero on
    first mint; incremented by one for each successive mint.
  @param prev_account_note_tree_proof A tree proof for the previous account note
    in the commitment tree. Only checked when prev_account_nonce is nonzero.
  @param total_burned_tree_proof A tree proof for the total burned balance leaf
    in the commitment tree.
*/
struct BurnDataPrivate {
  viewing_key: Field,
  pow_nonce: Field,
  total_burned: Field,
  prev_total_minted: Field,
  amount_to_mint: Field,
  prev_account_nonce: Field,
  prev_account_note_tree_proof: TreeProof,
  total_burned_tree_proof: TreeProof,
}

/**
  Hash two sibling leaves to produce a parent node in the commitment tree.
  This function is passed as the hasher callback to the binary tree root
  computation.

  @param leaves The two sibling field elements to hash.

  @return _ The Poseidon2 hash of the two leaves.
*/
fn tree_hasher(leaves: [Field; 2]) -> Field {
  Poseidon2::hash(leaves, 2)
}

/**
  Compute the root of the commitment tree from a leaf and its inclusion proof.
  Walks from the leaf up to the root using the provided path bits and sibling
  hashes.

  @param leaf The leaf value to verify inclusion for.
  @param proof The tree inclusion proof containing depth, path indices, and
    sibling hashes.

  @return _ The computed tree root.
*/
fn compute_root(leaf: Field, proof: TreeProof) -> Field {
  binary_merkle_root(
    tree_hasher,
    leaf,
    proof.depth,
    proof.indices,
    proof.siblings,
  )
}

/**
  Compute the blinded burn address data from the minting public key, chain ID,
  and viewing key. This is the first stage of address derivation, separated from
  the full burn address derivation process so as to support stealth addresses.

  @param pub_key_x The x-coordinate of the minting ECDSA public key, with the
    most significant byte zeroed to fit within the BN254 scalar field.
  @param chain_id The chain ID, binding the blinded data to a specific network.
  @param viewing_key A secret key that blinds the address. May be derived from
    the minting key or chosen independently for stealth addresses.

  @return _ The blinded burn address data hash.
*/
fn hash_blinded_burn_address_data(
  pub_key_x: Field,
  chain_id: Field,
  viewing_key: Field,
) -> Field {
  Poseidon2::hash([pub_key_x, chain_id, viewing_key], 3)
}

/**
  Derive the 20-byte burn address from blinded address data and a PoW nonce.
  This is the second stage of address derivation: it hashes the blinded data
  with the nonce and domain separator, verifies the proof-of-work difficulty,
  and truncates the result to an Ethereum address.

  @param blinded The blinded burn address data from
    `hash_blinded_burn_address_data`.
  @param pow_nonce The proof-of-work nonce that must produce a hash below
    `POW_DIFFICULTY`.

  @return _ The derived 20-byte burn address as a field element.
*/
fn get_burn_address(blinded: Field, pow_nonce: Field) -> Field {
  let address_hash: Field =
    Poseidon2::hash([blinded, pow_nonce, BURN_ADDRESS_DOMAIN], 3);
  let pow_hash: Field = Poseidon2::hash([pow_nonce, address_hash], 2);
  assert_lt(pow_hash, POW_DIFFICULTY);

  // Truncate to 20 bytes (zero first 12 bytes).
  let mut address_bytes: [u8; 32] = address_hash.to_be_bytes();
  for index in 0..12 {
    address_bytes[index] = 0;
  }
  bytes32_to_field(address_bytes)
}

/**
  Hash a total-burned balance leaf for inclusion in the commitment tree. This
  leaf commits to the total token balance sent to a burn address.

  @param burn_address The 20-byte burn address as a field element.
  @param total_burned The total token balance sent to this burn address.

  @return _ The Poseidon2 hash of the balance leaf.
*/
fn hash_total_burned_leaf(burn_address: Field, total_burned: Field) -> Field {
  Poseidon2::hash([burn_address, total_burned, BURN_TOTAL_DOMAIN], 3)
}

/**
  Hash an account note commitment. This 5-element hash binds the cumulative
  minted amount, the account nonce, the blinded address data, the viewing key,
  and the mint-total domain separator into a single commitment inserted into the
  tree after each successful private transfer.

  @param total_minted The cumulative amount minted from this burn address,
    including the current mint.
  @param account_nonce The new account nonce (previous nonce + 1).
  @param blinded The blinded burn address data.
  @param viewing_key The secret viewing key for this burn address.

  @return _ The Poseidon2 hash of the account note.
*/
fn hash_account_note(
  total_minted: Field,
  account_nonce: Field,
  blinded: Field,
  viewing_key: Field,
) -> Field {
  Poseidon2::hash(
    [total_minted, account_nonce, blinded, viewing_key, MINT_TOTAL_DOMAIN],
    5,
  )
}

/**
  Hash a nullifier from the account nonce and viewing key. The nullifier
  prevents double-minting: once consumed on-chain, the same account note
  cannot be minted again.

  @param account_nonce The nonce of the account note being nullified.
  @param viewing_key The secret viewing key for this burn address.

  @return _ The Poseidon2 nullifier hash.
*/
fn hash_nullifier(account_nonce: Field, viewing_key: Field) -> Field {
  Poseidon2::hash([account_nonce, viewing_key], 2)
}

/**
  Main circuit entry point for an EIP-7503-inspired zero knowledge mint.
  Verifies that the prover knows a valid set of burn addresses, viewing keys,
  and tree proofs that justify minting `amount` tokens. For each active burn
  slot, the circuit:

  1. Derives the burn address from the minting key, chain ID, and viewing key.
  2. Verifies the total-burned balance leaf exists in the commitment tree.
  3. Verifies the previous account note exists in the tree (if not the first
     mint from this burn address).
  4. Checks the nullifier matches the public input.
  5. Ensures the new minted amount does not exceed the total burned.
  6. Verifies the new account note hash matches the public input.

  Unused burn slots must have zeroed public inputs. The sum of all per-burn
  `amount_to_mint` values must equal the declared `amount`.

  @param amount The total amount of tokens being minted across all burns.
  @param signature_hash The EIP-712 typed data hash binding the proof to
    specific transfer parameters. Verified implicitly as a public input.
  @param burn_data_public The 32 per-burn public inputs: account note hashes and
    nullifiers. All unused slots must be zeroed.
  @param root The commitment tree root the proof was generated against.
  @param minting_pub_key_x The x-coordinate of the minting ECDSA public key.
  @param chain_id The chain ID binding the proof to a specific network.
  @param burn_data_private The 32 per-burn private inputs: viewing keys, nonces,
    balances, and tree proofs.
  @param num_burn_addresses The number of active burn slots in this proof.
*/
fn main(
  amount: pub Field,
  signature_hash: pub Field,
  burn_data_public: pub [BurnDataPublic; BURN_ADDRESSES_LEN],
  root: pub Field,
  minting_pub_key_x: Field,
  chain_id: Field,
  burn_data_private: [BurnDataPrivate; BURN_ADDRESSES_LEN],
  num_burn_addresses: u32,
) {

  /*
    Bind the signature_hash as a public input. The contract recomputes the
    EIP-712 hash from calldata and verifies it matches with no ECDSA needed.
  */
  let _ = signature_hash;

  // Process every provided, unzeroed burn slot:
  let mut total_mint_sum: Field = 0;
  for i in 0..BURN_ADDRESSES_LEN {
    if (i as u32) < num_burn_addresses {
      let pub_data = burn_data_public[i];
      let priv_data = burn_data_private[i];

      // 1. Derive blinded address data and burn address.
      let blinded = hash_blinded_burn_address_data(
        minting_pub_key_x,
        chain_id,
        priv_data.viewing_key,
      );
      let burn_address = get_burn_address(blinded, priv_data.pow_nonce);

      // 2. Verify total_burned balance leaf is in the tree.
      let total_burned_leaf =
        hash_total_burned_leaf(burn_address, priv_data.total_burned);
      let root_total_burned =
        compute_root(total_burned_leaf, priv_data.total_burned_tree_proof);
      assert(
        root_total_burned == root,
        "total_burned tree proof root mismatch",
      );

      // 3. Verify previous account note if nonce is greater than zero.
      if (priv_data.prev_account_nonce != 0) {
        let prev_account_note_hash = hash_account_note(
          priv_data.prev_total_minted,
          priv_data.prev_account_nonce,
          blinded,
          priv_data.viewing_key,
        );
        let computed_prev_root = compute_root(
          prev_account_note_hash,
          priv_data.prev_account_note_tree_proof,
        );
        assert(
          computed_prev_root == root,
          "prev account note proof root mismatch",
        );

      // 3. If the nonce is zero, verify that this is truly the first mint.
      } else {
        assert(
          priv_data.prev_total_minted == 0,
          "prev_total_minted nonzero at nonce zero",
        );
      }

      // 4. Verify the nullifier to prevent double-minting.
      let computed_nullifier =
        hash_nullifier(priv_data.prev_account_nonce, priv_data.viewing_key);
      assert(
        computed_nullifier == pub_data.account_note_nullifier,
        "nullifier mismatch",
      );

      // 5. Verify the mint limit.
      let new_minted_amount =
        priv_data.amount_to_mint + priv_data.prev_total_minted;
      assert(
        !gt(priv_data.prev_total_minted, new_minted_amount),
        "mint sum overflow",
      );
      assert(
        !gt(new_minted_amount, priv_data.total_burned),
        "minted amount exceeds total burned",
      );

      // 6. Verify the new account note hash.
      let current_account_nonce = priv_data.prev_account_nonce + 1;
      let computed_account_note_hash = hash_account_note(
        new_minted_amount,
        current_account_nonce,
        blinded,
        priv_data.viewing_key,
      );
      assert(
        computed_account_note_hash == pub_data.account_note_hash,
        "account note hash mismatch",
      );

      total_mint_sum += priv_data.amount_to_mint;

    // Verify that the unused burn slots are zeroed.
    } else {
      assert(
        burn_data_public[i].account_note_hash == 0,
        "unused burn slot has non-zero account_note_hash",
      );
      assert(
        burn_data_public[i].account_note_nullifier == 0,
        "unused burn slot has non-zero nullifier",
      );
    }
  }

  // Verify the total mint across all burns is equal to the declared amount.
  assert(
    total_mint_sum == amount,
    "sum of amount_to_mint does not equal amount",
  );
}

// Tests are stored externally.
mod tests;
