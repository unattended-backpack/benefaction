use super::{
  BURN_ADDRESSES_LEN, BurnDataPrivate, BurnDataPublic, compute_root,
  hash_account_note, hash_blinded_burn_address_data, hash_nullifier,
  hash_total_burned_leaf, main, TreeProof,
};

/**
  Collects all circuit inputs (public and private) into a single struct for
  convenient forwarding to the circuit entry point.

  @param amount The total amount of tokens being minted across all burns.
  @param signature_hash The EIP-712 typed data hash binding the proof to
    specific transfer parameters.
  @param burn_data_public The per-burn public inputs: account note hashes and
    nullifiers. Unused slots must be zeroed.
  @param root The commitment tree root the proof was generated against.
  @param minting_pub_key_x The x-coordinate of the minting ECDSA public key.
  @param chain_id The chain ID binding the proof to a specific network.
  @param burn_data_private The per-burn private inputs: viewing keys, nonces,
    balances, and tree proofs.
  @param num_burn_addresses The number of active burn slots in this proof.
*/
struct TestCase {
  amount: Field,
  signature_hash: Field,
  burn_data_public: [BurnDataPublic; BURN_ADDRESSES_LEN],
  root: Field,
  minting_pub_key_x: Field,
  chain_id: Field,
  burn_data_private: [BurnDataPrivate; BURN_ADDRESSES_LEN],
  num_burn_addresses: u32,
}

/**
  Invoke the circuit entry point with all fields unpacked from a TestCase.

  @param t The test case containing all public and private circuit inputs.
*/
fn call_main(t: TestCase) {
  main(
    t.amount,
    t.signature_hash,
    t.burn_data_public,
    t.root,
    t.minting_pub_key_x,
    t.chain_id,
    t.burn_data_private,
    t.num_burn_addresses,
  );
}

/**
  Construct a tree proof with depth zero (single-leaf tree). All path indices
  and sibling hashes are zeroed.

  @return _ A TreeProof suitable for a single-leaf (depth-0) tree.
*/
fn empty_tree_proof() -> TreeProof {
  TreeProof {
    depth: 0,
    indices: [
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
    siblings: [
      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ],
  }
}

/**
  Construct zeroed public burn slot data (hash and nullifier both zero).

  @return _ A BurnDataPublic with both fields set to zero.
*/
fn zero_burn_public() -> BurnDataPublic {
  BurnDataPublic { account_note_hash: 0, account_note_nullifier: 0 }
}

/**
  Construct zeroed private burn slot data. All fields are zero and tree proofs
  are empty (depth 0).

  @return _ A BurnDataPrivate with all fields zeroed.
*/
fn zero_burn_private() -> BurnDataPrivate {
  BurnDataPrivate {
    viewing_key: 0,
    pow_nonce: 0,
    total_burned: 0,
    prev_total_minted: 0,
    amount_to_mint: 0,
    prev_account_nonce: 0,
    prev_account_note_tree_proof: empty_tree_proof(),
    total_burned_tree_proof: empty_tree_proof(),
  }
}

/**
  Build a TestCase from a single burn's parameters. All test vectors must be
  recomputed against the current derivation (two-stage blinded address,
  five-element account note, BURN_TOTAL_DOMAIN, 44-element tree proof arrays).

  Test vectors are computed by the inputgen Rust code and verified to match
  the circuit at compile time via `nargo test`.

  @param amount The total amount to mint.
  @param signature_hash The EIP-712 typed data hash (public input).
  @param account_note_hash The expected new account note commitment.
  @param account_note_nullifier The expected nullifier for the previous note.
  @param root The commitment tree root.
  @param minting_pub_key_x The x-coordinate of the minting ECDSA public key.
  @param chain_id The chain ID binding the proof to a specific network.
  @param viewing_key The secret viewing key for this burn address.
  @param pow_nonce The proof-of-work nonce for this burn address.
  @param total_burned The total balance sent to this burn address.
  @param prev_total_minted The cumulative amount previously minted.
  @param prev_account_nonce The nonce of the previous account note.
  @param prev_account_note_tree_proof The tree proof for the previous account
    note.
  @param total_burned_tree_proof The tree proof for the total burned leaf.

  @return _ A fully populated TestCase with one active burn slot.
*/
fn single_burn_test_case(
  amount: Field,
  signature_hash: Field,
  account_note_hash: Field,
  account_note_nullifier: Field,
  root: Field,
  minting_pub_key_x: Field,
  chain_id: Field,
  viewing_key: Field,
  pow_nonce: Field,
  total_burned: Field,
  prev_total_minted: Field,
  prev_account_nonce: Field,
  prev_account_note_tree_proof: TreeProof,
  total_burned_tree_proof: TreeProof,
) -> TestCase {
  let mut burn_pub: [BurnDataPublic; BURN_ADDRESSES_LEN] =
    [zero_burn_public(); BURN_ADDRESSES_LEN];
  burn_pub[0] = BurnDataPublic { account_note_hash, account_note_nullifier };

  let mut burn_priv: [BurnDataPrivate; BURN_ADDRESSES_LEN] =
    [zero_burn_private(); BURN_ADDRESSES_LEN];
  burn_priv[0] = BurnDataPrivate {
    viewing_key,
    pow_nonce,
    total_burned,
    prev_total_minted,
    amount_to_mint: amount,
    prev_account_nonce,
    prev_account_note_tree_proof,
    total_burned_tree_proof,
  };

  TestCase {
    amount,
    signature_hash,
    burn_data_public: burn_pub,
    root,
    minting_pub_key_x,
    chain_id,
    burn_data_private: burn_priv,
    num_burn_addresses: 1,
  }
}

/**
  Build a TestCase with two active burn slots. Both slots share the same
  minting key and chain ID.

  @param total_amount The declared total amount across both burns.
  @param signature_hash The EIP-712 typed data hash.
  @param note_hash_0 Slot 0 account note hash.
  @param null_0 Slot 0 nullifier.
  @param vk_0 Slot 0 viewing key.
  @param pow_0 Slot 0 PoW nonce.
  @param total_burned_0 Slot 0 total burned balance.
  @param prev_minted_0 Slot 0 previous total minted.
  @param mint_0 Slot 0 amount to mint.
  @param prev_nonce_0 Slot 0 previous account nonce.
  @param prev_tree_proof_0 Slot 0 previous account note tree proof.
  @param burned_tree_proof_0 Slot 0 total burned leaf tree proof.
  @param note_hash_1 Slot 1 account note hash.
  @param null_1 Slot 1 nullifier.
  @param vk_1 Slot 1 viewing key.
  @param pow_1 Slot 1 PoW nonce.
  @param total_burned_1 Slot 1 total burned balance.
  @param prev_minted_1 Slot 1 previous total minted.
  @param mint_1 Slot 1 amount to mint.
  @param prev_nonce_1 Slot 1 previous account nonce.
  @param prev_tree_proof_1 Slot 1 previous account note tree proof.
  @param burned_tree_proof_1 Slot 1 total burned leaf tree proof.
  @param root The commitment tree root.
  @param pub_key_x The x-coordinate of the shared minting ECDSA public key.
  @param chain_id The chain ID binding the proof to a specific network.

  @return _ A fully populated TestCase with two active burn slots.
*/
fn two_burn_test_case(
  total_amount: Field,
  signature_hash: Field,
  note_hash_0: Field,
  null_0: Field,
  vk_0: Field,
  pow_0: Field,
  total_burned_0: Field,
  prev_minted_0: Field,
  mint_0: Field,
  prev_nonce_0: Field,
  prev_tree_proof_0: TreeProof,
  burned_tree_proof_0: TreeProof,
  note_hash_1: Field,
  null_1: Field,
  vk_1: Field,
  pow_1: Field,
  total_burned_1: Field,
  prev_minted_1: Field,
  mint_1: Field,
  prev_nonce_1: Field,
  prev_tree_proof_1: TreeProof,
  burned_tree_proof_1: TreeProof,
  root: Field,
  pub_key_x: Field,
  chain_id: Field,
) -> TestCase {
  let mut burn_pub: [BurnDataPublic; BURN_ADDRESSES_LEN] =
    [zero_burn_public(); BURN_ADDRESSES_LEN];
  burn_pub[0] = BurnDataPublic {
    account_note_hash: note_hash_0,
    account_note_nullifier: null_0,
  };
  burn_pub[1] = BurnDataPublic {
    account_note_hash: note_hash_1,
    account_note_nullifier: null_1,
  };

  let mut burn_priv: [BurnDataPrivate; BURN_ADDRESSES_LEN] =
    [zero_burn_private(); BURN_ADDRESSES_LEN];
  burn_priv[0] = BurnDataPrivate {
    viewing_key: vk_0,
    pow_nonce: pow_0,
    total_burned: total_burned_0,
    prev_total_minted: prev_minted_0,
    amount_to_mint: mint_0,
    prev_account_nonce: prev_nonce_0,
    prev_account_note_tree_proof: prev_tree_proof_0,
    total_burned_tree_proof: burned_tree_proof_0,
  };
  burn_priv[1] = BurnDataPrivate {
    viewing_key: vk_1,
    pow_nonce: pow_1,
    total_burned: total_burned_1,
    prev_total_minted: prev_minted_1,
    amount_to_mint: mint_1,
    prev_account_nonce: prev_nonce_1,
    prev_account_note_tree_proof: prev_tree_proof_1,
    total_burned_tree_proof: burned_tree_proof_1,
  };

  TestCase {
    amount: total_amount,
    signature_hash,
    burn_data_public: burn_pub,
    root,
    minting_pub_key_x: pub_key_x,
    chain_id,
    burn_data_private: burn_priv,
    num_burn_addresses: 2,
  }
}

/// The chain ID used for testing.
global TEST_CHAIN_ID: Field = 31337;

/**
  Test vectors computed by inputgen (cargo test test_generate_noir_vectors).
  KEY1 = minting key 0x...01, KEY2 = 0x...02, chain_id = 31337.
*/
global TEST_PUB_KEY_X1: Field =
  0xbe667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798;
global TEST_VK1: Field =
  0x177dd193439c1986fad9454984b17e3162f59ad3dfc5d1f66ed0790c68400f87;
global TEST_BLINDED1: Field =
  0x2c4a2a6aca452cf1a17f72eda915c6b025af2f302171474b99a192a2647dcefb;
global TEST_NONCE1: Field =
  0x08e4eedca9be98c79d9a4edd6fcb0e63b3b0e5793a8fd59748fbfe9cdd1644e6;
global TEST_BURN_ADDR1: Field = 0xaaae88c9d59da8724cd824af8774c6d3c2f3d690;

global TEST_PUB_KEY_X2: Field =
  0x047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5;
global TEST_VK2: Field =
  0x2ec39fbeb38d2645ef1d297c244f82d4ffa9d8bb9a2c73a3cea8e38266cb50a5;
global TEST_BLINDED2: Field =
  0x214a7b3aa031697476fd545e7081a1c8411337738f872de6483b51c434655367;
global TEST_NONCE2: Field =
  0x277ef6ad78514998a52ac8672150bb63261f1250f18a64a3ea458b89264a88b2;

global TEST_NULL1_N0: Field =
  0x0e518ab252465b7e0443d87d13e85de588153a2013fd7cebd6e2566e36562fa7;
global TEST_NULL1_N1: Field =
  0x23b2b7de6a3c7287f2539caa79ce0e0b4137d623e0d011e447706962b0451a7a;
global TEST_NULL2_N0: Field =
  0x305a318aae8a2c69d08aace9967cc2eac114715528211050a7de1667d9e8ff62;
global TEST_BURNED_LEAF1: Field =
  0x20d90327c9c9a19a4e78a22429b067d4683f51d5b141e129d561961541557922;
global TEST_BURNED_LEAF2: Field =
  0x059cf5c1d8305619c03474022a28e759993bdd7293657356283e52c9d8013be1;
global TEST_ACCT_NOTE1_FIRST: Field =
  0x1ef80b32193faa357e48e1101b34d6406bb9af864935a8ced8cb458c616672c3;
global TEST_ROOT_SINGLE1: Field =
  0x20d90327c9c9a19a4e78a22429b067d4683f51d5b141e129d561961541557922;
global TEST_ROOT_TWO_LEAF: Field =
  0x2872def9cf6e2484203d467accef9eb80b3ecbb11b649bfdc8e6d3dc96bfd569;
global TEST_TREE_HASH_LR: Field =
  0x08880ed96adc902ecd83221346d476db5ceaf3ce9af51bc291396b3ee80a0f09;
global TEST_TREE_HASH_RL: Field =
  0x2ab601374b0e2bc7109060daa966310efcda1e3a181510b7153443ac45bb2398;

/**
  Multi-burn test vectors. MULTI = KEY1 minting key with VK2 viewing key.
*/
global TEST_BLINDED_MULTI: Field =
  0x0316360faffaa53478e6ab98d8aa8d6fa1b69183f6707bfc1238fb378844ae60;
global TEST_NONCE_MULTI: Field =
  0x1a27572e82e30d621df44a2bd41c2fe79b75e3b0d8c75cfa96d3c860dcf73193;
global TEST_NULL_MULTI_N0: Field =
  0x305a318aae8a2c69d08aace9967cc2eac114715528211050a7de1667d9e8ff62;
global TEST_BURNED_LEAF_MULTI: Field =
  0x1d32decca8c0b81e564ece1ee8493b66c81eb0428acfea9f8249310b52bf7d9e;
global TEST_ACCT_NOTE_MULTI_FIRST: Field =
  0x22c97a78f881efb33bd564f88a13c7c6614705c4b4fe90cfa2ef8d9fbecc082d;
global TEST_ROOT_2BURN: Field =
  0x29c8e3e45a220d0eab1ecc4d7ab58bfb04f0707b576951d27ec1a2932c939ed2;
global TEST_4LEAF_L0_LEFT: Field =
  0x29c8e3e45a220d0eab1ecc4d7ab58bfb04f0707b576951d27ec1a2932c939ed2;
global TEST_4LEAF_L0_RIGHT: Field =
  0x0b14ca5c013eb85a5aaf8e7b433238bac1e69d8396f614ca93c1b871e58df7f2;
global TEST_ROOT_4LEAF: Field =
  0x0ead2a960ef264225037f9aed62c25abf44eabcdf9ed612c90827645df7465cb;

/**
  Stealth address test vectors. STEALTH = KEY1 minting key with arbitrary
  viewing key 0x42 (not derived from any ECDSA key).
*/
global TEST_VK_STEALTH: Field = 0x42;
global TEST_BLINDED_STEALTH: Field =
  0x2d969b8ed37ec5cc17120be60e26c2240a642a1505033e0282a85e6c7072bfb2;
global TEST_NONCE_STEALTH: Field =
  0x05457d881145d920beb549ef7c6daa4c404676edbf14ff21fade3c9abeb26bb7;
global TEST_NULL_STEALTH_N0: Field =
  0x1d8f46f7b093449093ec6d152d0610f96b31267dbd07f57cb2b49614272d9b40;
global TEST_BURNED_LEAF_STEALTH: Field =
  0x2c2aab4786e97a159b4751527b9be718e0f2224e64841bae2301b66f0f388162;
global TEST_ROOT_STEALTH_2LEAF: Field =
  0x1f46d470d2471f33f7fea61c2b7d17fce90b8d8777d01abf1010fd1c92424fbb;

/**
  Construct a depth-1 tree proof with a single sibling.

  @param index The path bit for the leaf (0 = left, 1 = right).
  @param sibling The sibling hash at depth 1.

  @return _ A TreeProof with depth 1.
*/
fn depth1_tree_proof(index: u1, sibling: Field) -> TreeProof {
  let mut m = empty_tree_proof();
  m.depth = 1;
  m.indices[0] = index;
  m.siblings[0] = sibling;
  m
}

/**
  Construct a depth-2 tree proof with two siblings.

  @param indices The path bits from leaf to root.
  @param siblings The sibling hashes at each level.

  @return _ A TreeProof with depth 2.
*/
fn depth2_tree_proof(indices: [u1; 2], siblings: [Field; 2]) -> TreeProof {
  let mut m = empty_tree_proof();
  m.depth = 2;
  m.indices[0] = indices[0];
  m.indices[1] = indices[1];
  m.siblings[0] = siblings[0];
  m.siblings[1] = siblings[1];
  m
}

/**
  Build a valid first-mint TestCase for KEY1. Mints the given amount from a
  total burned balance of 100. Single-leaf tree (depth 0), nonce 0.

  @param amount The amount to mint.

  @return _ A TestCase ready to pass to call_main.
*/
fn key1_first_mint(amount: Field) -> TestCase {
  let account_note_hash = hash_account_note(amount, 1, TEST_BLINDED1, TEST_VK1);
  single_burn_test_case(
    amount,
    0,
    account_note_hash,
    TEST_NULL1_N0,
    TEST_ROOT_SINGLE1,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
    TEST_VK1,
    TEST_NONCE1,
    100,
    0,
    0,
    empty_tree_proof(),
    empty_tree_proof(),
  )
}


/**
  H1: Verify blinded address data hash against golden value.
  blinded = Poseidon2([pub_key_x, chain_id, vk]).
*/
#[test]
fn test_hash_blinded_golden() {
  let result =
    hash_blinded_burn_address_data(TEST_PUB_KEY_X1, TEST_CHAIN_ID, TEST_VK1);
  assert(result == TEST_BLINDED1, "blinded hash golden value mismatch");
}

/**
  H2: Verify nullifier hash at nonce 0 against golden value.
*/
#[test]
fn test_hash_nullifier_nonce0_golden() {
  let result = hash_nullifier(0, TEST_VK1);
  assert(result == TEST_NULL1_N0, "nullifier nonce=0 golden value mismatch");
}

/**
  H3: Verify nullifier hash at nonce 1 against golden value.
*/
#[test]
fn test_hash_nullifier_nonce1_golden() {
  let result = hash_nullifier(1, TEST_VK1);
  assert(result == TEST_NULL1_N1, "nullifier nonce=1 golden value mismatch");
}

/**
  H4: Verify account note hash against golden value.
  account_note(50, 1, blinded1, vk1).
*/
#[test]
fn test_hash_account_note_golden() {
  let result = hash_account_note(50, 1, TEST_BLINDED1, TEST_VK1);
  assert(result == TEST_ACCT_NOTE1_FIRST, "account note golden value mismatch");
}

/**
  H5: Verify total burned leaf hash against golden value.
  total_burned_leaf(burn_addr1, 100).
*/
#[test]
fn test_hash_total_burned_leaf_golden() {
  let result = hash_total_burned_leaf(TEST_BURN_ADDR1, 100);
  assert(
    result == TEST_BURNED_LEAF1,
    "total burned leaf golden value mismatch",
  );
}

/**
  H6: Verify that different inputs to account note hash produce distinct
  outputs. Each of the four parameters is varied independently.
*/
#[test]
fn test_hash_account_note_different_inputs() {
  let h1 = hash_account_note(50, 1, TEST_BLINDED1, TEST_VK1);
  let h2 = hash_account_note(51, 1, TEST_BLINDED1, TEST_VK1);
  let h3 = hash_account_note(50, 2, TEST_BLINDED1, TEST_VK1);
  let h4 = hash_account_note(50, 1, TEST_BLINDED2, TEST_VK1);
  let h5 = hash_account_note(50, 1, TEST_BLINDED1, TEST_VK2);
  assert(h1 != h2, "different total_minted should produce different hash");
  assert(h1 != h3, "different nonce should produce different hash");
  assert(h1 != h4, "different blinded should produce different hash");
  assert(h1 != h5, "different vk should produce different hash");
}

/**
  H7: Verify that a depth-0 (single-leaf) tree root equals the leaf itself.
*/
#[test]
fn test_tree_root_depth0() {
  let leaf: Field = 0xabcd;
  let root = compute_root(leaf, empty_tree_proof());
  assert(root == leaf, "depth-0 root should equal the leaf");
}

/**
  H8: Verify depth-1 tree root with leaf at index 0.
  root = Poseidon2([leaf, sibling]).
*/
#[test]
fn test_tree_root_depth1() {
  let leaf: Field = 42;
  let sibling: Field = 99;
  let root = compute_root(leaf, depth1_tree_proof(0, sibling));
  assert(root == TEST_TREE_HASH_LR, "depth-1 index=0 root mismatch");
}

/**
  H9: Verify depth-1 tree root with leaf at index 1.
  root = Poseidon2([sibling, leaf]).
*/
#[test]
fn test_tree_root_depth1_right() {
  let leaf: Field = 42;
  let sibling: Field = 99;
  let root = compute_root(leaf, depth1_tree_proof(1, sibling));
  assert(root == TEST_TREE_HASH_RL, "depth-1 index=1 root mismatch");
}

/**
  P1: Mint entire balance (amount == total_burned == 100), nonce 0, depth-0
  tree.
*/
#[test]
fn test_first_mint_exact() {
  let amount: Field = 100;
  let account_note_hash = hash_account_note(amount, 1, TEST_BLINDED1, TEST_VK1);
  let tc = single_burn_test_case(
    amount,
    0,
    account_note_hash,
    TEST_NULL1_N0,
    TEST_ROOT_SINGLE1,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
    TEST_VK1,
    TEST_NONCE1,
    100,
    0,
    0,
    empty_tree_proof(),
    empty_tree_proof(),
  );
  call_main(tc);
}

/**
  P2: Mint half the balance (amount 50, total_burned 100), nonce 0, depth-0
  tree.
*/
#[test]
fn test_first_mint_partial() {
  let tc = key1_first_mint(50);
  call_main(tc);
}

/**
  P3: Mint 1 wei (smallest possible amount), nonce 0, depth-0 tree.
*/
#[test]
fn test_first_mint_minimal() {
  let tc = key1_first_mint(1);
  call_main(tc);
}

/**
  P4: Second mint at nonce 1. prev_total_minted 50, mint 30 more,
  new_minted 80. Two-leaf tree: [burned_leaf1, acct_note1_first] with root
  TEST_ROOT_TWO_LEAF. The burned leaf sits at index 0 with the previous
  account note as its sibling, and vice versa.
*/
#[test]
fn test_second_mint() {
  let amount: Field = 30;
  let new_minted: Field = 80;
  let account_note_hash =
    hash_account_note(new_minted, 2, TEST_BLINDED1, TEST_VK1);
  let tc = single_burn_test_case(
    amount,
    0,
    account_note_hash,
    TEST_NULL1_N1,
    TEST_ROOT_TWO_LEAF,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
    TEST_VK1,
    TEST_NONCE1,
    100,
    50,
    1,
    depth1_tree_proof(1, TEST_BURNED_LEAF1),
    depth1_tree_proof(0, TEST_ACCT_NOTE1_FIRST),
  );
  call_main(tc);
}

/**
  P5: First mint using KEY2 instead of KEY1. Depth-0 tree with burned_leaf2.
*/
#[test]
fn test_different_key() {
  let amount: Field = 50;
  let account_note_hash = hash_account_note(amount, 1, TEST_BLINDED2, TEST_VK2);
  let root = TEST_BURNED_LEAF2;
  let tc = single_burn_test_case(
    amount,
    0,
    account_note_hash,
    TEST_NULL2_N0,
    root,
    TEST_PUB_KEY_X2,
    TEST_CHAIN_ID,
    TEST_VK2,
    TEST_NONCE2,
    100,
    0,
    0,
    empty_tree_proof(),
    empty_tree_proof(),
  );
  call_main(tc);
}

/**
  P6: Non-zero signature_hash (0xdeadbeef1234). The circuit accepts any
  value since signature_hash is a public input verified externally by the
  contract.
*/
#[test]
fn test_signature_hash_passthrough() {
  let amount: Field = 50;
  let account_note_hash = hash_account_note(amount, 1, TEST_BLINDED1, TEST_VK1);
  let tc = single_burn_test_case(
    amount,
    0xdeadbeef1234,
    account_note_hash,
    TEST_NULL1_N0,
    TEST_ROOT_SINGLE1,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
    TEST_VK1,
    TEST_NONCE1,
    100,
    0,
    0,
    empty_tree_proof(),
    empty_tree_proof(),
  );
  call_main(tc);
}

/**
  N1: Invalid PoW nonce (0xbad) that does not satisfy the difficulty
  requirement. The assert_lt check has no message so we use should_fail
  without a specific message.
*/
#[test(should_fail)]
fn test_fail_invalid_pow() {
  let amount: Field = 50;
  let account_note_hash = hash_account_note(amount, 1, TEST_BLINDED1, TEST_VK1);
  let tc = single_burn_test_case(
    amount,
    0,
    account_note_hash,
    TEST_NULL1_N0,
    TEST_ROOT_SINGLE1,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
    TEST_VK1,
    0xbad,
    100,
    0,
    0,
    empty_tree_proof(),
    empty_tree_proof(),
  );
  call_main(tc);
}

/**
  N2: Valid PoW but wrong root (0xdeadbeef instead of the correct
  single-leaf root).
*/
#[test(should_fail_with = "total_burned tree proof root mismatch")]
fn test_fail_wrong_burned_root() {
  let amount: Field = 50;
  let account_note_hash = hash_account_note(amount, 1, TEST_BLINDED1, TEST_VK1);
  let tc = single_burn_test_case(
    amount,
    0,
    account_note_hash,
    TEST_NULL1_N0,
    0xdeadbeef,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
    TEST_VK1,
    TEST_NONCE1,
    100,
    0,
    0,
    empty_tree_proof(),
    empty_tree_proof(),
  );
  call_main(tc);
}

/**
  N3: Correct root but wrong total_burned (999 instead of 100). The
  recomputed burned leaf will not match the tree.
*/
#[test(should_fail_with = "total_burned tree proof root mismatch")]
fn test_fail_wrong_total_burned() {
  let amount: Field = 50;
  let account_note_hash = hash_account_note(amount, 1, TEST_BLINDED1, TEST_VK1);
  let tc = single_burn_test_case(
    amount,
    0,
    account_note_hash,
    TEST_NULL1_N0,
    TEST_ROOT_SINGLE1,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
    TEST_VK1,
    TEST_NONCE1,
    999,
    0,
    0,
    empty_tree_proof(),
    empty_tree_proof(),
  );
  call_main(tc);
}

/**
  N4: Nonce 0 but prev_total_minted is nonzero (10). The circuit requires
  prev_total_minted to be zero when the account nonce is zero.
*/
#[test(should_fail_with = "prev_total_minted nonzero at nonce zero")]
fn test_fail_prev_minted_nonzero_at_nonce_zero() {
  let amount: Field = 50;
  let account_note_hash = hash_account_note(amount, 1, TEST_BLINDED1, TEST_VK1);
  let tc = single_burn_test_case(
    amount,
    0,
    account_note_hash,
    TEST_NULL1_N0,
    TEST_ROOT_SINGLE1,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
    TEST_VK1,
    TEST_NONCE1,
    100,
    10,
    0,
    empty_tree_proof(),
    empty_tree_proof(),
  );
  call_main(tc);
}

/**
  N5: Nonce 1 but the previous account note tree proof has a wrong sibling
  (0xbad). The recomputed root will not match.
*/
#[test(should_fail_with = "prev account note proof root mismatch")]
fn test_fail_wrong_prev_note_tree_proof() {
  let amount: Field = 30;
  let new_minted: Field = 80;
  let account_note_hash =
    hash_account_note(new_minted, 2, TEST_BLINDED1, TEST_VK1);
  let tc = single_burn_test_case(
    amount,
    0,
    account_note_hash,
    TEST_NULL1_N1,
    TEST_ROOT_TWO_LEAF,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
    TEST_VK1,
    TEST_NONCE1,
    100,
    50,
    1,
    depth1_tree_proof(1, 0xbad),
    depth1_tree_proof(0, TEST_ACCT_NOTE1_FIRST),
  );
  call_main(tc);
}

/**
  N6: Valid PoW but the nullifier in public inputs is wrong (0xbad0 instead
  of the correct computed nullifier).
*/
#[test(should_fail_with = "nullifier mismatch")]
fn test_fail_wrong_nullifier() {
  let amount: Field = 50;
  let account_note_hash = hash_account_note(amount, 1, TEST_BLINDED1, TEST_VK1);
  let tc = single_burn_test_case(
    amount,
    0,
    account_note_hash,
    0xbad0,
    TEST_ROOT_SINGLE1,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
    TEST_VK1,
    TEST_NONCE1,
    100,
    0,
    0,
    empty_tree_proof(),
    empty_tree_proof(),
  );
  call_main(tc);
}

/**
  N7: Overmint at nonce 0. amount_to_mint (101) exceeds total_burned (100).
*/
#[test(should_fail_with = "minted amount exceeds total burned")]
fn test_fail_overmint() {
  let amount: Field = 101;
  let account_note_hash = hash_account_note(amount, 1, TEST_BLINDED1, TEST_VK1);
  let tc = single_burn_test_case(
    amount,
    0,
    account_note_hash,
    TEST_NULL1_N0,
    TEST_ROOT_SINGLE1,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
    TEST_VK1,
    TEST_NONCE1,
    100,
    0,
    0,
    empty_tree_proof(),
    empty_tree_proof(),
  );
  call_main(tc);
}

/**
  N8: Overmint at nonce 1. prev_minted 50, amount 51, new_minted 101
  exceeds total_burned 100.
*/
#[test(should_fail_with = "minted amount exceeds total burned")]
fn test_fail_overmint_with_prev() {
  let amount: Field = 51;
  let new_minted: Field = 101;
  let account_note_hash =
    hash_account_note(new_minted, 2, TEST_BLINDED1, TEST_VK1);
  let tc = single_burn_test_case(
    amount,
    0,
    account_note_hash,
    TEST_NULL1_N1,
    TEST_ROOT_TWO_LEAF,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
    TEST_VK1,
    TEST_NONCE1,
    100,
    50,
    1,
    depth1_tree_proof(1, TEST_BURNED_LEAF1),
    depth1_tree_proof(0, TEST_ACCT_NOTE1_FIRST),
  );
  call_main(tc);
}

/**
  N9: Valid PoW but the account_note_hash in public inputs is wrong (0xbad1
  instead of the correctly computed hash).
*/
#[test(should_fail_with = "account note hash mismatch")]
fn test_fail_wrong_account_note_hash() {
  let amount: Field = 50;
  let tc = single_burn_test_case(
    amount,
    0,
    0xbad1,
    TEST_NULL1_N0,
    TEST_ROOT_SINGLE1,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
    TEST_VK1,
    TEST_NONCE1,
    100,
    0,
    0,
    empty_tree_proof(),
    empty_tree_proof(),
  );
  call_main(tc);
}

/**
  N10: Declared amount (public input) does not match the sum of per-burn
  amount_to_mint values. Uses num_burn_addresses 0 with amount 100 to
  trigger the sum check without needing PoW.
*/
#[test(should_fail_with = "sum of amount_to_mint does not equal amount")]
fn test_fail_amount_sum_mismatch() {
  let burn_pub: [BurnDataPublic; BURN_ADDRESSES_LEN] =
    [zero_burn_public(); BURN_ADDRESSES_LEN];
  let burn_priv: [BurnDataPrivate; BURN_ADDRESSES_LEN] =
    [zero_burn_private(); BURN_ADDRESSES_LEN];
  main(100, 0, burn_pub, 0, 0, TEST_CHAIN_ID, burn_priv, 0);
}

/**
  N11: Unused slot (index 1) has a non-zero account_note_hash (0xdead).
*/
#[test(should_fail_with = "unused burn slot has non-zero account_note_hash")]
fn test_fail_unused_slot_hash() {
  let mut burn_pub: [BurnDataPublic; BURN_ADDRESSES_LEN] =
    [zero_burn_public(); BURN_ADDRESSES_LEN];
  burn_pub[1] =
    BurnDataPublic { account_note_hash: 0xdead, account_note_nullifier: 0 };
  let burn_priv: [BurnDataPrivate; BURN_ADDRESSES_LEN] =
    [zero_burn_private(); BURN_ADDRESSES_LEN];
  main(0, 0, burn_pub, 0, 0, TEST_CHAIN_ID, burn_priv, 0);
}

/**
  N12: Unused slot (index 1) has a non-zero nullifier (0xdead).
*/
#[test(should_fail_with = "unused burn slot has non-zero nullifier")]
fn test_fail_unused_slot_nullifier() {
  let mut burn_pub: [BurnDataPublic; BURN_ADDRESSES_LEN] =
    [zero_burn_public(); BURN_ADDRESSES_LEN];
  burn_pub[1] =
    BurnDataPublic { account_note_hash: 0, account_note_nullifier: 0xdead };
  let burn_priv: [BurnDataPrivate; BURN_ADDRESSES_LEN] =
    [zero_burn_private(); BURN_ADDRESSES_LEN];
  main(0, 0, burn_pub, 0, 0, TEST_CHAIN_ID, burn_priv, 0);
}

/**
  M1: Two burns, both at nonce 0 with different viewing keys. Two-leaf tree
  containing both burned leaves. Slot 0 uses VK1 and mints 50 from balance
  100. Slot 1 uses VK2 (with KEY1's pub_key_x) and mints 70 from balance
  200. Total amount 120.
*/
#[test]
fn test_multi_two_burns_first_mint() {
  let mint_0: Field = 50;
  let mint_1: Field = 70;
  let note_hash_0 = hash_account_note(mint_0, 1, TEST_BLINDED1, TEST_VK1);
  let note_hash_1 = hash_account_note(mint_1, 1, TEST_BLINDED_MULTI, TEST_VK2);
  let tc = two_burn_test_case(
    120,
    0,
    note_hash_0,
    TEST_NULL1_N0,
    TEST_VK1,
    TEST_NONCE1,
    100,
    0,
    mint_0,
    0,
    empty_tree_proof(),
    depth1_tree_proof(0, TEST_BURNED_LEAF_MULTI),
    note_hash_1,
    TEST_NULL_MULTI_N0,
    TEST_VK2,
    TEST_NONCE_MULTI,
    200,
    0,
    mint_1,
    0,
    empty_tree_proof(),
    depth1_tree_proof(1, TEST_BURNED_LEAF1),
    TEST_ROOT_2BURN,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
  );
  call_main(tc);
}

/**
  M2: Two burns, both at nonce 0. Slot 0 mints 1 (minimal), slot 1 mints
  99. Total amount 100.
*/
#[test]
fn test_multi_two_burns_different_amounts() {
  let mint_0: Field = 1;
  let mint_1: Field = 99;
  let note_hash_0 = hash_account_note(mint_0, 1, TEST_BLINDED1, TEST_VK1);
  let note_hash_1 = hash_account_note(mint_1, 1, TEST_BLINDED_MULTI, TEST_VK2);
  let tc = two_burn_test_case(
    100,
    0,
    note_hash_0,
    TEST_NULL1_N0,
    TEST_VK1,
    TEST_NONCE1,
    100,
    0,
    mint_0,
    0,
    empty_tree_proof(),
    depth1_tree_proof(0, TEST_BURNED_LEAF_MULTI),
    note_hash_1,
    TEST_NULL_MULTI_N0,
    TEST_VK2,
    TEST_NONCE_MULTI,
    200,
    0,
    mint_1,
    0,
    empty_tree_proof(),
    depth1_tree_proof(1, TEST_BURNED_LEAF1),
    TEST_ROOT_2BURN,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
  );
  call_main(tc);
}

/**
  M3: Two burns, both mint their entire balance (100 + 200 = 300).
*/
#[test]
fn test_multi_two_burns_exact_mint() {
  let mint_0: Field = 100;
  let mint_1: Field = 200;
  let note_hash_0 = hash_account_note(mint_0, 1, TEST_BLINDED1, TEST_VK1);
  let note_hash_1 = hash_account_note(mint_1, 1, TEST_BLINDED_MULTI, TEST_VK2);
  let tc = two_burn_test_case(
    300,
    0,
    note_hash_0,
    TEST_NULL1_N0,
    TEST_VK1,
    TEST_NONCE1,
    100,
    0,
    mint_0,
    0,
    empty_tree_proof(),
    depth1_tree_proof(0, TEST_BURNED_LEAF_MULTI),
    note_hash_1,
    TEST_NULL_MULTI_N0,
    TEST_VK2,
    TEST_NONCE_MULTI,
    200,
    0,
    mint_1,
    0,
    empty_tree_proof(),
    depth1_tree_proof(1, TEST_BURNED_LEAF1),
    TEST_ROOT_2BURN,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
  );
  call_main(tc);
}

/**
  M4: Slot 0 at nonce 1 (has previous account note in tree), slot 1 at
  nonce 0. Four-leaf tree: [burned_leaf1, burned_leaf_multi,
  acct_note1_first, acct_note_multi_first]. Slot 0 uses VK1, prev_minted
  50, mints 30 more (new_minted 80, nonce becomes 2). Slot 1 uses VK2,
  first mint of 70 (nonce becomes 1). Total amount 100.
*/
#[test]
fn test_multi_two_burns_with_prev_nonce() {
  let mint_0: Field = 30;
  let new_minted_0: Field = 80;
  let mint_1: Field = 70;
  let note_hash_0 = hash_account_note(new_minted_0, 2, TEST_BLINDED1, TEST_VK1);
  let note_hash_1 = hash_account_note(mint_1, 1, TEST_BLINDED_MULTI, TEST_VK2);
  let tc = two_burn_test_case(
    100,
    0,
    note_hash_0,
    TEST_NULL1_N1,
    TEST_VK1,
    TEST_NONCE1,
    100,
    50,
    mint_0,
    1,
    depth2_tree_proof([0, 1], [TEST_ACCT_NOTE_MULTI_FIRST, TEST_4LEAF_L0_LEFT]),
    depth2_tree_proof([0, 0], [TEST_BURNED_LEAF_MULTI, TEST_4LEAF_L0_RIGHT]),
    note_hash_1,
    TEST_NULL_MULTI_N0,
    TEST_VK2,
    TEST_NONCE_MULTI,
    200,
    0,
    mint_1,
    0,
    empty_tree_proof(),
    depth2_tree_proof([1, 0], [TEST_BURNED_LEAF1, TEST_4LEAF_L0_RIGHT]),
    TEST_ROOT_4LEAF,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
  );
  call_main(tc);
}

/**
  Multi-Burn Negative Tests (M5-M9)
*/

/**
  M5: Two valid burns but declared amount (999) does not match the sum of
  per-burn amount_to_mint values (50 + 70 = 120).
*/
#[test(should_fail_with = "sum of amount_to_mint does not equal amount")]
fn test_multi_fail_amount_sum_mismatch() {
  let mint_0: Field = 50;
  let mint_1: Field = 70;
  let note_hash_0 = hash_account_note(mint_0, 1, TEST_BLINDED1, TEST_VK1);
  let note_hash_1 = hash_account_note(mint_1, 1, TEST_BLINDED_MULTI, TEST_VK2);
  let tc = two_burn_test_case(
    999,
    0,
    note_hash_0,
    TEST_NULL1_N0,
    TEST_VK1,
    TEST_NONCE1,
    100,
    0,
    mint_0,
    0,
    empty_tree_proof(),
    depth1_tree_proof(0, TEST_BURNED_LEAF_MULTI),
    note_hash_1,
    TEST_NULL_MULTI_N0,
    TEST_VK2,
    TEST_NONCE_MULTI,
    200,
    0,
    mint_1,
    0,
    empty_tree_proof(),
    depth1_tree_proof(1, TEST_BURNED_LEAF1),
    TEST_ROOT_2BURN,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
  );
  call_main(tc);
}

/**
  M6: Slot 0 valid, slot 1 has a wrong sibling (0xbad) in the burned leaf
  tree proof.
*/
#[test(should_fail_with = "total_burned tree proof root mismatch")]
fn test_multi_fail_second_slot_wrong_root() {
  let mint_0: Field = 50;
  let mint_1: Field = 70;
  let note_hash_0 = hash_account_note(mint_0, 1, TEST_BLINDED1, TEST_VK1);
  let note_hash_1 = hash_account_note(mint_1, 1, TEST_BLINDED_MULTI, TEST_VK2);
  let tc = two_burn_test_case(
    120,
    0,
    note_hash_0,
    TEST_NULL1_N0,
    TEST_VK1,
    TEST_NONCE1,
    100,
    0,
    mint_0,
    0,
    empty_tree_proof(),
    depth1_tree_proof(0, TEST_BURNED_LEAF_MULTI),
    note_hash_1,
    TEST_NULL_MULTI_N0,
    TEST_VK2,
    TEST_NONCE_MULTI,
    200,
    0,
    mint_1,
    0,
    empty_tree_proof(),
    depth1_tree_proof(1, 0xbad),
    TEST_ROOT_2BURN,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
  );
  call_main(tc);
}

/**
  M7: Slot 0 valid, slot 1 has a wrong nullifier (0xbad) in public inputs.
*/
#[test(should_fail_with = "nullifier mismatch")]
fn test_multi_fail_second_slot_wrong_nullifier() {
  let mint_0: Field = 50;
  let mint_1: Field = 70;
  let note_hash_0 = hash_account_note(mint_0, 1, TEST_BLINDED1, TEST_VK1);
  let note_hash_1 = hash_account_note(mint_1, 1, TEST_BLINDED_MULTI, TEST_VK2);
  let tc = two_burn_test_case(
    120,
    0,
    note_hash_0,
    TEST_NULL1_N0,
    TEST_VK1,
    TEST_NONCE1,
    100,
    0,
    mint_0,
    0,
    empty_tree_proof(),
    depth1_tree_proof(0, TEST_BURNED_LEAF_MULTI),
    note_hash_1,
    0xbad,
    TEST_VK2,
    TEST_NONCE_MULTI,
    200,
    0,
    mint_1,
    0,
    empty_tree_proof(),
    depth1_tree_proof(1, TEST_BURNED_LEAF1),
    TEST_ROOT_2BURN,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
  );
  call_main(tc);
}

/**
  M8: Slot 0 valid, slot 1 overmints (201 from balance of 200).
*/
#[test(should_fail_with = "minted amount exceeds total burned")]
fn test_multi_fail_second_slot_overmint() {
  let mint_0: Field = 50;
  let mint_1: Field = 201;
  let note_hash_0 = hash_account_note(mint_0, 1, TEST_BLINDED1, TEST_VK1);
  let note_hash_1 = hash_account_note(mint_1, 1, TEST_BLINDED_MULTI, TEST_VK2);
  let tc = two_burn_test_case(
    251,
    0,
    note_hash_0,
    TEST_NULL1_N0,
    TEST_VK1,
    TEST_NONCE1,
    100,
    0,
    mint_0,
    0,
    empty_tree_proof(),
    depth1_tree_proof(0, TEST_BURNED_LEAF_MULTI),
    note_hash_1,
    TEST_NULL_MULTI_N0,
    TEST_VK2,
    TEST_NONCE_MULTI,
    200,
    0,
    mint_1,
    0,
    empty_tree_proof(),
    depth1_tree_proof(1, TEST_BURNED_LEAF1),
    TEST_ROOT_2BURN,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
  );
  call_main(tc);
}

/**
  M9: num_burn_addresses is 2 but slot 2 (unused) has non-zero public data
  (account_note_hash 0xdead).
*/
#[test(should_fail_with = "unused burn slot has non-zero account_note_hash")]
fn test_multi_fail_unused_slot_nonzero() {
  let mint_0: Field = 50;
  let mint_1: Field = 70;
  let note_hash_0 = hash_account_note(mint_0, 1, TEST_BLINDED1, TEST_VK1);
  let note_hash_1 = hash_account_note(mint_1, 1, TEST_BLINDED_MULTI, TEST_VK2);

  let mut burn_pub: [BurnDataPublic; BURN_ADDRESSES_LEN] =
    [zero_burn_public(); BURN_ADDRESSES_LEN];
  burn_pub[0] = BurnDataPublic {
    account_note_hash: note_hash_0,
    account_note_nullifier: TEST_NULL1_N0,
  };
  burn_pub[1] = BurnDataPublic {
    account_note_hash: note_hash_1,
    account_note_nullifier: TEST_NULL_MULTI_N0,
  };
  burn_pub[2] =
    BurnDataPublic { account_note_hash: 0xdead, account_note_nullifier: 0 };

  let mut burn_priv: [BurnDataPrivate; BURN_ADDRESSES_LEN] =
    [zero_burn_private(); BURN_ADDRESSES_LEN];
  burn_priv[0] = BurnDataPrivate {
    viewing_key: TEST_VK1,
    pow_nonce: TEST_NONCE1,
    total_burned: 100,
    prev_total_minted: 0,
    amount_to_mint: mint_0,
    prev_account_nonce: 0,
    prev_account_note_tree_proof: empty_tree_proof(),
    total_burned_tree_proof: depth1_tree_proof(0, TEST_BURNED_LEAF_MULTI),
  };
  burn_priv[1] = BurnDataPrivate {
    viewing_key: TEST_VK2,
    pow_nonce: TEST_NONCE_MULTI,
    total_burned: 200,
    prev_total_minted: 0,
    amount_to_mint: mint_1,
    prev_account_nonce: 0,
    prev_account_note_tree_proof: empty_tree_proof(),
    total_burned_tree_proof: depth1_tree_proof(1, TEST_BURNED_LEAF1),
  };

  main(
    120,
    0,
    burn_pub,
    TEST_ROOT_2BURN,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
    burn_priv,
    2,
  );
}

/**
  S1: KEY1 mints from a stealth burn address derived from an arbitrary
  viewing key (0x42). Single-leaf tree (depth 0), nonce 0, mint 60 from
  balance 150.
*/
#[test]
fn test_stealth_first_mint() {
  let amount: Field = 60;
  let account_note_hash =
    hash_account_note(amount, 1, TEST_BLINDED_STEALTH, TEST_VK_STEALTH);
  let root = TEST_BURNED_LEAF_STEALTH;
  let tc = single_burn_test_case(
    amount,
    0,
    account_note_hash,
    TEST_NULL_STEALTH_N0,
    root,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
    TEST_VK_STEALTH,
    TEST_NONCE_STEALTH,
    150,
    0,
    0,
    empty_tree_proof(),
    empty_tree_proof(),
  );
  call_main(tc);
}

/**
  S2: KEY1 mints from a regular address (VK1, balance 100) and a stealth
  address (VK_STEALTH, balance 150) in one proof. Two-leaf tree:
  [burned_leaf1, burned_leaf_stealth]. Slot 0 mints 40, slot 1 mints 60.
  Total amount 100.
*/
#[test]
fn test_stealth_multi_burn_with_regular() {
  let mint_0: Field = 40;
  let mint_1: Field = 60;
  let note_hash_0 = hash_account_note(mint_0, 1, TEST_BLINDED1, TEST_VK1);
  let note_hash_1 =
    hash_account_note(mint_1, 1, TEST_BLINDED_STEALTH, TEST_VK_STEALTH);
  let tc = two_burn_test_case(
    100,
    0,
    note_hash_0,
    TEST_NULL1_N0,
    TEST_VK1,
    TEST_NONCE1,
    100,
    0,
    mint_0,
    0,
    empty_tree_proof(),
    depth1_tree_proof(0, TEST_BURNED_LEAF_STEALTH),
    note_hash_1,
    TEST_NULL_STEALTH_N0,
    TEST_VK_STEALTH,
    TEST_NONCE_STEALTH,
    150,
    0,
    mint_1,
    0,
    empty_tree_proof(),
    depth1_tree_proof(1, TEST_BURNED_LEAF1),
    TEST_ROOT_STEALTH_2LEAF,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
  );
  call_main(tc);
}

/**
  S3: KEY2's minting_pub_key_x used instead of KEY1's. Same VK_STEALTH and
  nonce_stealth. Different blinded data causes a different address_hash so
  the PoW assertion fails.
*/
#[test(should_fail)]
fn test_stealth_fail_wrong_minting_key() {
  let amount: Field = 60;
  let account_note_hash =
    hash_account_note(amount, 1, TEST_BLINDED_STEALTH, TEST_VK_STEALTH);
  let root = TEST_BURNED_LEAF_STEALTH;
  let tc = single_burn_test_case(
    amount,
    0,
    account_note_hash,
    TEST_NULL_STEALTH_N0,
    root,
    TEST_PUB_KEY_X2,
    TEST_CHAIN_ID,
    TEST_VK_STEALTH,
    TEST_NONCE_STEALTH,
    150,
    0,
    0,
    empty_tree_proof(),
    empty_tree_proof(),
  );
  call_main(tc);
}

/**
  S4: KEY1's minting_pub_key_x but wrong viewing key (0x43 instead of
  0x42). Correct nonce_stealth. Different blinded data causes the PoW
  assertion to fail.
*/
#[test(should_fail)]
fn test_stealth_fail_wrong_viewing_key() {
  let amount: Field = 60;
  let wrong_vk: Field = 0x43;
  let account_note_hash =
    hash_account_note(amount, 1, TEST_BLINDED_STEALTH, TEST_VK_STEALTH);
  let root = TEST_BURNED_LEAF_STEALTH;
  let tc = single_burn_test_case(
    amount,
    0,
    account_note_hash,
    TEST_NULL_STEALTH_N0,
    root,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
    wrong_vk,
    TEST_NONCE_STEALTH,
    150,
    0,
    0,
    empty_tree_proof(),
    empty_tree_proof(),
  );
  call_main(tc);
}

/**
  Additional Coverage Tests (C1-C5)
*/

/**
  C1: Wrong chain_id (99999 instead of 31337). Different blinded data
  causes the PoW assertion to fail.
*/
#[test(should_fail)]
fn test_fail_wrong_chain_id() {
  let amount: Field = 50;
  let account_note_hash = hash_account_note(amount, 1, TEST_BLINDED1, TEST_VK1);
  let tc = single_burn_test_case(
    amount,
    0,
    account_note_hash,
    TEST_NULL1_N0,
    TEST_ROOT_SINGLE1,
    TEST_PUB_KEY_X1,
    99999,
    TEST_VK1,
    TEST_NONCE1,
    100,
    0,
    0,
    empty_tree_proof(),
    empty_tree_proof(),
  );
  call_main(tc);
}

/**
  C2: Second mint with wrong prev_total_minted (10 instead of 50). The
  recomputed previous account note hash will not match the leaf in the tree.
*/
#[test(should_fail_with = "prev account note proof root mismatch")]
fn test_fail_wrong_prev_total_minted() {
  let amount: Field = 30;
  let new_minted: Field = 40;
  let account_note_hash =
    hash_account_note(new_minted, 2, TEST_BLINDED1, TEST_VK1);
  let tc = single_burn_test_case(
    amount,
    0,
    account_note_hash,
    TEST_NULL1_N1,
    TEST_ROOT_TWO_LEAF,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
    TEST_VK1,
    TEST_NONCE1,
    100,
    10,
    1,
    depth1_tree_proof(1, TEST_BURNED_LEAF1),
    depth1_tree_proof(0, TEST_ACCT_NOTE1_FIRST),
  );
  call_main(tc);
}

/**
  C3: Active slot with amount_to_mint 0. The circuit allows zero-amount
  mints.
*/
#[test]
fn test_zero_amount_mint() {
  let amount: Field = 0;
  let account_note_hash = hash_account_note(0, 1, TEST_BLINDED1, TEST_VK1);
  let tc = single_burn_test_case(
    amount,
    0,
    account_note_hash,
    TEST_NULL1_N0,
    TEST_ROOT_SINGLE1,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
    TEST_VK1,
    TEST_NONCE1,
    100,
    0,
    0,
    empty_tree_proof(),
    empty_tree_proof(),
  );
  call_main(tc);
}

/**
  C4: num_burn_addresses set to 33, which exceeds BURN_ADDRESSES_LEN (32).
  All 32 slots enter the active branch, bypassing unused-slot zero-checks.
  Slot 1 (zeroed private data) fails the PoW check.
*/
#[test(should_fail)]
fn test_num_burn_addresses_exceeds_max() {
  let amount: Field = 50;
  let account_note_hash = hash_account_note(amount, 1, TEST_BLINDED1, TEST_VK1);
  let mut burn_pub: [BurnDataPublic; BURN_ADDRESSES_LEN] =
    [zero_burn_public(); BURN_ADDRESSES_LEN];
  burn_pub[0] =
    BurnDataPublic { account_note_hash, account_note_nullifier: TEST_NULL1_N0 };

  let mut burn_priv: [BurnDataPrivate; BURN_ADDRESSES_LEN] =
    [zero_burn_private(); BURN_ADDRESSES_LEN];
  burn_priv[0] = BurnDataPrivate {
    viewing_key: TEST_VK1,
    pow_nonce: TEST_NONCE1,
    total_burned: 100,
    prev_total_minted: 0,
    amount_to_mint: amount,
    prev_account_nonce: 0,
    prev_account_note_tree_proof: empty_tree_proof(),
    total_burned_tree_proof: empty_tree_proof(),
  };

  main(
    amount,
    0,
    burn_pub,
    TEST_ROOT_SINGLE1,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
    burn_priv,
    33,
  );
}

/**
  C5: Field overflow attack. prev_total_minted = p-1, amount_to_mint = 1.
  The sum wraps to 0 mod p. Without the overflow check this would pass
  (0 <= p-1), allowing infinite minting.
*/
#[test(should_fail_with = "mint sum overflow")]
fn test_fail_mint_sum_overflow() {
  let large_val: Field = 0 - 1;
  let burned_leaf = hash_total_burned_leaf(TEST_BURN_ADDR1, large_val);
  let prev_note = hash_account_note(large_val, 1, TEST_BLINDED1, TEST_VK1);
  let root = compute_root(burned_leaf, depth1_tree_proof(0, prev_note));

  let amount: Field = 1;
  let new_minted: Field = 0;
  let account_note_hash =
    hash_account_note(new_minted, 2, TEST_BLINDED1, TEST_VK1);

  let tc = single_burn_test_case(
    amount,
    0,
    account_note_hash,
    TEST_NULL1_N1,
    root,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
    TEST_VK1,
    TEST_NONCE1,
    large_val,
    large_val,
    1,
    depth1_tree_proof(1, burned_leaf),
    depth1_tree_proof(0, prev_note),
  );
  call_main(tc);
}

/**
  Fuzz Tests (F1-F10)

  Run with: nargo fuzz [--timeout N]

  These use the #[fuzz] attribute. The fuzzer generates random inputs and
  checks properties. For #[fuzz(should_fail)], the fuzzer tries to find
  inputs that make the test pass; if it can, that is a bug.
*/

/**
  F1: Poseidon2 nullifier hash is deterministic. The same inputs must
  always produce the same output.
*/
#[fuzz]
fn fuzz_nullifier_deterministic(nonce: Field, vk: Field) {
  let h1 = hash_nullifier(nonce, vk);
  let h2 = hash_nullifier(nonce, vk);
  assert(h1 == h2, "hash_nullifier should be deterministic");
}

/**
  F2: Different nonces must produce different nullifiers (collision
  resistance). If nonces are equal the check is skipped.
*/
#[fuzz]
fn fuzz_nullifier_nonce_sensitivity(nonce_a: Field, nonce_b: Field, vk: Field) {
  if nonce_a != nonce_b {
    let h1 = hash_nullifier(nonce_a, vk);
    let h2 = hash_nullifier(nonce_b, vk);
    assert(h1 != h2, "different nonces should produce different nullifiers");
  }
}

/**
  F3: Different viewing keys must produce different nullifiers. If viewing
  keys are equal the check is skipped.
*/
#[fuzz]
fn fuzz_nullifier_vk_sensitivity(nonce: Field, vk_a: Field, vk_b: Field) {
  if vk_a != vk_b {
    let h1 = hash_nullifier(nonce, vk_a);
    let h2 = hash_nullifier(nonce, vk_b);
    assert(h1 != h2, "different VKs should produce different nullifiers");
  }
}

/**
  F4: Different total_minted values produce different account note hashes.
  If values are equal the check is skipped.
*/
#[fuzz]
fn fuzz_account_note_minted_sensitivity(minted_a: Field, minted_b: Field) {
  if minted_a != minted_b {
    let h1 = hash_account_note(minted_a, 1, TEST_BLINDED1, TEST_VK1);
    let h2 = hash_account_note(minted_b, 1, TEST_BLINDED1, TEST_VK1);
    assert(
      h1 != h2,
      "different total_minted should produce different account notes",
    );
  }
}

/**
  F5: hash_account_note and hash_total_burned_leaf use different domain
  separators, so they should never collide even with overlapping input
  patterns.
*/
#[fuzz]
fn fuzz_domain_separation_note_vs_leaf(a: Field, b: Field) {
  let note = hash_account_note(a, b, TEST_BLINDED1, TEST_VK1);
  let leaf = hash_total_burned_leaf(a, b);
  assert(note != leaf, "account note and burned leaf should not collide");
}

/**
  F6: Different chain IDs produce different blinded addresses. If chain IDs
  are equal the check is skipped.
*/
#[fuzz]
fn fuzz_blinded_chain_id_sensitivity(chain_a: Field, chain_b: Field) {
  if chain_a != chain_b {
    let b1 = hash_blinded_burn_address_data(TEST_PUB_KEY_X1, chain_a, TEST_VK1);
    let b2 = hash_blinded_burn_address_data(TEST_PUB_KEY_X1, chain_b, TEST_VK1);
    assert(
      b1 != b2,
      "different chain IDs should produce different blinded addresses",
    );
  }
}

/**
  F7: Any valid first-mint amount in [0, 100] should be accepted. Uses
  KEY1's pre-computed PoW nonce and single-leaf tree.
*/
#[fuzz]
fn fuzz_valid_first_mint(amount_raw: u64) {
  let amount_u64 = amount_raw % 101;
  let amount = amount_u64 as Field;
  let account_note_hash = hash_account_note(amount, 1, TEST_BLINDED1, TEST_VK1);
  let tc = single_burn_test_case(
    amount,
    0,
    account_note_hash,
    TEST_NULL1_N0,
    TEST_ROOT_SINGLE1,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
    TEST_VK1,
    TEST_NONCE1,
    100,
    0,
    0,
    empty_tree_proof(),
    empty_tree_proof(),
  );
  call_main(tc);
}

/**
  F8: Any valid split across two burns where mint_0 + mint_1 = 100 should
  be accepted. Slot 0 uses KEY1/VK1 (balance 100), slot 1 uses KEY1/VK2
  (balance 200).
*/
#[fuzz]
fn fuzz_valid_multi_burn_split(split_raw: u64) {
  let mint_0_u64 = split_raw % 101;
  let mint_1_u64 = 100 - mint_0_u64;
  let mint_0 = mint_0_u64 as Field;
  let mint_1 = mint_1_u64 as Field;
  let note_hash_0 = hash_account_note(mint_0, 1, TEST_BLINDED1, TEST_VK1);
  let note_hash_1 = hash_account_note(mint_1, 1, TEST_BLINDED_MULTI, TEST_VK2);
  let tc = two_burn_test_case(
    100,
    0,
    note_hash_0,
    TEST_NULL1_N0,
    TEST_VK1,
    TEST_NONCE1,
    100,
    0,
    mint_0,
    0,
    empty_tree_proof(),
    depth1_tree_proof(0, TEST_BURNED_LEAF_MULTI),
    note_hash_1,
    TEST_NULL_MULTI_N0,
    TEST_VK2,
    TEST_NONCE_MULTI,
    200,
    0,
    mint_1,
    0,
    empty_tree_proof(),
    depth1_tree_proof(1, TEST_BURNED_LEAF1),
    TEST_ROOT_2BURN,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
  );
  call_main(tc);
}

/**
  F9: Minting more than total_burned must always be rejected. The mint
  amount is 101 + (extra % 1000) against a balance of 100, which always
  overmints.
*/
#[fuzz(should_fail_with = "minted amount exceeds total burned")]
fn fuzz_overmint_rejected(extra_raw: u64) {
  let extra = extra_raw % 1000;
  let mint_u64: u64 = 101 + extra;
  let mint = mint_u64 as Field;
  let account_note_hash = hash_account_note(mint, 1, TEST_BLINDED1, TEST_VK1);
  let tc = single_burn_test_case(
    mint,
    0,
    account_note_hash,
    TEST_NULL1_N0,
    TEST_ROOT_SINGLE1,
    TEST_PUB_KEY_X1,
    TEST_CHAIN_ID,
    TEST_VK1,
    TEST_NONCE1,
    100,
    0,
    0,
    empty_tree_proof(),
    empty_tree_proof(),
  );
  call_main(tc);
}

/**
  F10: Declared amount must equal the actual sum of per-burn amount_to_mint
  values. Uses num_burn_addresses 0 with a nonzero declared amount (1 to
  1000) so the actual sum is always 0, guaranteeing a mismatch.
*/
#[fuzz(should_fail_with = "sum of amount_to_mint does not equal amount")]
fn fuzz_amount_mismatch_rejected(declared_raw: u64, mint_raw: u64) {
  let declared = (declared_raw % 1000 + 1) as Field;
  let _ = mint_raw;
  let burn_pub: [BurnDataPublic; BURN_ADDRESSES_LEN] =
    [zero_burn_public(); BURN_ADDRESSES_LEN];
  let burn_priv: [BurnDataPrivate; BURN_ADDRESSES_LEN] =
    [zero_burn_private(); BURN_ADDRESSES_LEN];
  main(declared, 0, burn_pub, 0, 0, TEST_CHAIN_ID, burn_priv, 0);
}
