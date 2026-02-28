use std::collections::HashMap;

use ark_bn254::Fr;

use crate::tree::{self, LeanIMT};

/// Per-burn-address state within an account.
pub struct BurnAddressState {
    /// The derived burn address (0x-prefixed).
    pub burn_address: String,
    /// The mined PoW nonce (0x-prefixed hex field element).
    pub pow_nonce: String,
    /// Explicit viewing key (hex), or None to derive from private key.
    pub explicit_vk: Option<String>,
    /// Total tokens burned (sent to this burn address).
    pub total_burned: u128,
    /// Total tokens ZK minted out via this burn address.
    pub total_minted: u128,
    /// Per-burn-address nonce (circuit uses independent nonces per burn address).
    pub account_nonce: u64,
}

/// Per-account ZK mint state.
pub struct AccountState {
    /// The account's private key (hex, 0x-prefixed).
    pub private_key: String,
    /// The account's public address (checksummed, 0x-prefixed).
    pub address: String,
    /// Burn addresses: [0]=primary (derived VK), [1]=stealth (random VK).
    pub burns: Vec<BurnAddressState>,
}

/// Ghost ledger tracking expected on-chain state.
pub struct GhostState {
    /// Expected token balances for each address (lowercase).
    pub balances: HashMap<String, u128>,
    /// Expected ERC20.totalSupply() (raw, includes private re-mints).
    pub raw_total_supply: u128,
    /// Expected _totalReminted.
    pub total_private_reminted: u128,
    /// Set of consumed nullifiers (hex string → amount).
    pub nullifiers: HashMap<String, u128>,
    /// Per-account ZK mint state (indexed by account address, lowercase).
    pub account_state: Vec<AccountState>,
    /// Current rate limit window start timestamp.
    pub rate_limit_period_start: u64,
    /// Amount ZK-minted in current window.
    pub rate_limit_minted_in_period: u128,
    /// Current block timestamp (tracked via warp).
    pub block_timestamp: u64,
    /// Token contract address.
    pub token_address: String,
    /// Deployer address.
    pub deployer_address: String,
    /// Deployer private key.
    pub deployer_key: String,
    /// All tracked addresses (for balance sum checks).
    pub tracked_addresses: Vec<String>,
    /// Shadow hash tree mirroring the on-chain LeanIMT.
    pub tree: LeanIMT,
}

impl GhostState {
    /// Create initial ghost state after deployment and funding.
    pub fn new(
        token_address: String,
        deployer_address: String,
        deployer_key: String,
        accounts: Vec<AccountState>,
        initial_supply: u128,
        per_account_amount: u128,
    ) -> Self {
        let mut balances = HashMap::new();
        let mut tracked = Vec::new();

        // Deployer gets initial_supply minus what's distributed.
        let deployer_balance = initial_supply - per_account_amount * accounts.len() as u128;
        let deployer_lc = deployer_address.to_lowercase();
        balances.insert(deployer_lc.clone(), deployer_balance);
        tracked.push(deployer_lc);

        // Token contract itself (starts at 0).
        let token_lc = token_address.to_lowercase();
        balances.insert(token_lc.clone(), 0);
        tracked.push(token_lc);

        for acct in &accounts {
            let addr_lc = acct.address.to_lowercase();
            balances.insert(addr_lc.clone(), per_account_amount);
            tracked.push(addr_lc);

            // All burn addresses start at 0.
            for burn in &acct.burns {
                let burn_lc = burn.burn_address.to_lowercase();
                balances.insert(burn_lc.clone(), 0);
                tracked.push(burn_lc);
            }
        }

        Self {
            balances,
            raw_total_supply: initial_supply,
            total_private_reminted: 0,
            nullifiers: HashMap::new(),
            account_state: accounts,
            rate_limit_period_start: 0,
            rate_limit_minted_in_period: 0,
            block_timestamp: 0,
            token_address,
            deployer_address,
            deployer_key,
            tracked_addresses: tracked,
            tree: LeanIMT::new(),
        }
    }

    /// Insert a balance leaf into the shadow tree, skipping if tx.origin == to.
    ///
    /// Mirrors `_updateBalanceInTree(address _to, uint256 _newBalance)` in
    /// ZKMint.sol: the leaf is `poseidon2([uint160(to), balance, DOMAIN])`
    /// and is only inserted if it doesn't already exist in the tree.
    pub fn insert_balance_leaf(&mut self, tx_origin: &str, to: &str) {
        if tx_origin.to_lowercase() == to.to_lowercase() {
            return;
        }
        let to_lc = to.to_lowercase();
        let balance = self.balances.get(&to_lc).copied().unwrap_or(0);
        let leaf = tree::hash_balance_leaf(&to_lc, balance)
            .expect("hash_balance_leaf failed");
        if !self.tree.has(&leaf) {
            self.tree.insert(leaf);
        }
    }

    /// Apply a public transfer (sender → recipient).
    pub fn apply_public_transfer(&mut self, from: &str, to: &str, amount: u128) {
        let from_lc = from.to_lowercase();
        let to_lc = to.to_lowercase();
        *self.balances.get_mut(&from_lc).unwrap() -= amount;
        *self.balances.entry(to_lc.clone()).or_insert(0) += amount;
        if !self.tracked_addresses.contains(&to_lc) {
            self.tracked_addresses.push(to_lc.clone());
        }
        // The contract calls _updateBalanceInTree in _afterTokenTransfer.
        // tx.origin = from (the EOA signing the tx).
        self.insert_balance_leaf(from, &to_lc);
    }

    /// Apply a burn (sender → burn_address).
    pub fn apply_burn(&mut self, account_idx: usize, burn_idx: usize, amount: u128) {
        let from_lc = self.account_state[account_idx].address.to_lowercase();
        let burn_lc = self.account_state[account_idx].burns[burn_idx].burn_address.to_lowercase();
        *self.balances.get_mut(&from_lc).unwrap() -= amount;
        *self.balances.entry(burn_lc.clone()).or_insert(0) += amount;
        self.account_state[account_idx].burns[burn_idx].total_burned += amount;
        // tx.origin = account (the EOA signing), _to = burn_address.
        self.insert_balance_leaf(&from_lc, &burn_lc);
    }

    /// Apply a successful ZK mint (multi-burn aware).
    ///
    /// `burn_mints` is a list of `(burn_idx, mint_amount)` pairs — one per
    /// burn address used in the proof. Each burn's `total_minted` and
    /// `account_nonce` are updated independently.
    pub fn apply_zk_mint(
        &mut self,
        account_idx: usize,
        amount: u128,
        burn_mints: &[(usize, u128)],
        recipient: &str,
        relayer_reward: u128,
        relayer_addr: &str,
        nullifier_hexes: &[String],
        account_note_hashes: &[Fr],
        submitter_addr: &str,
    ) {
        let recipient_lc = recipient.to_lowercase();
        let recipient_amount = amount - relayer_reward;

        // Mint to recipient (private re-mint).
        *self.balances.entry(recipient_lc.clone()).or_insert(0) += recipient_amount;
        if !self.tracked_addresses.contains(&recipient_lc) {
            self.tracked_addresses.push(recipient_lc.clone());
        }
        self.raw_total_supply += recipient_amount;
        self.total_private_reminted += recipient_amount;

        // Insert tree leaves for _remint.
        // The contract's _remint calls
        //   _updateBalanceInTree(_to, newBalance, _accountNoteHashes)
        // which checks tx.origin vs _to:
        //   - tx.origin == _to → insert only accountNoteHashes
        //   - otherwise → batch [balanceLeaf, noteHash0, noteHash1, ...] or just noteHashes
        let submitter_lc = submitter_addr.to_lowercase();
        if submitter_lc == recipient_lc {
            // tx.origin == recipient: only insert account note hashes.
            if account_note_hashes.len() == 1 {
                self.tree.insert(account_note_hashes[0]);
            } else {
                self.tree.insert_many(account_note_hashes);
            }
        } else {
            let balance = self.balances.get(&recipient_lc).copied().unwrap_or(0);
            let balance_leaf = tree::hash_balance_leaf(&recipient_lc, balance)
                .expect("hash_balance_leaf failed");
            if self.tree.has(&balance_leaf) {
                // Balance leaf already exists, just insert account note hashes.
                if account_note_hashes.len() == 1 {
                    self.tree.insert(account_note_hashes[0]);
                } else {
                    self.tree.insert_many(account_note_hashes);
                }
            } else {
                // Batch insert: [balanceLeaf, noteHash0, noteHash1, ...]
                let mut leaves = vec![balance_leaf];
                leaves.extend_from_slice(account_note_hashes);
                self.tree.insert_many(&leaves);
            }
        }

        // Mint relayer reward if applicable.
        // _mintTo(relayer, reward) calls _update which calls _afterTokenTransfer
        // → _updateBalanceInTree(relayer, newBalance).
        // In our harness the submitter IS the relayer, so tx.origin == _to → SKIP.
        if relayer_reward > 0 {
            let relayer_lc = relayer_addr.to_lowercase();
            *self.balances.entry(relayer_lc.clone()).or_insert(0) += relayer_reward;
            if !self.tracked_addresses.contains(&relayer_lc) {
                self.tracked_addresses.push(relayer_lc.clone());
            }
            self.raw_total_supply += relayer_reward;
            self.total_private_reminted += relayer_reward;
            // Relayer leaf: tx.origin == relayer in all our cases → skip.
            // (insert_balance_leaf would skip anyway due to tx.origin == _to)
        }

        // Update per-burn-address state.
        for &(burn_idx, mint) in burn_mints {
            self.account_state[account_idx].burns[burn_idx].total_minted += mint;
            self.account_state[account_idx].burns[burn_idx].account_nonce += 1;
        }

        // Record all nullifiers.
        for nullifier_hex in nullifier_hexes {
            self.nullifiers.insert(nullifier_hex.to_lowercase(), amount);
        }

        // Update rate limit.
        let period: u64 = 86400; // 1 day
        if self.block_timestamp >= self.rate_limit_period_start + period {
            self.rate_limit_period_start = self.block_timestamp;
            self.rate_limit_minted_in_period = amount;
        } else {
            self.rate_limit_minted_in_period += amount;
        }
    }

    /// Apply a time warp.
    pub fn apply_warp(&mut self, seconds: u64) {
        self.block_timestamp += seconds;
    }

    /// Expected visible total supply.
    pub fn visible_supply(&self) -> u128 {
        self.raw_total_supply - self.total_private_reminted
    }

    /// Check if a ZK mint of the given amount would exceed the rate limit.
    pub fn would_exceed_rate_limit(&self, amount: u128) -> bool {
        let period: u64 = 86400;
        let minted = if self.block_timestamp >= self.rate_limit_period_start + period {
            amount
        } else {
            self.rate_limit_minted_in_period + amount
        };

        // 1% of visible supply, floored at 1M tokens.
        let limit_from_supply = self.visible_supply() / 100;
        let floor: u128 = 1_000_000_000_000_000_000_000_000; // 1M * 1e18
        let limit = std::cmp::max(limit_from_supply, floor);
        minted > limit
    }

    /// Get the unminted balance for a specific burn address.
    pub fn unminted_burn_balance(&self, account_idx: usize, burn_idx: usize) -> u128 {
        let burn = &self.account_state[account_idx].burns[burn_idx];
        burn.total_burned.saturating_sub(burn.total_minted)
    }

    /// Get the total unminted burn balance across all burn addresses for an account.
    pub fn total_unminted_burn_balance(&self, account_idx: usize) -> u128 {
        self.account_state[account_idx]
            .burns
            .iter()
            .map(|b| b.total_burned.saturating_sub(b.total_minted))
            .sum()
    }
}
