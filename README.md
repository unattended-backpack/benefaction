# Benefaction

> For who among you, wanting to build a tower, would not first sit down and determine the costs that are required, to see if he has the means to complete it? Otherwise, after he will have laid the foundation and not been able to finish it, everyone who sees it may begin to mock him, saying: ‘This man began to build what he was not able to finish.’

We began Sigil and are proud of the work we have performed to finish it. We would love to continue working on it. Benefaction is a solution.

## Building Contracts

The contents of [`contracts`](./contracts/) are a standard `forge` project. We have helper goals in the [Makefile](./Makefile) for building and deploying. To build the contracts, simply `make build`. To test, simply `make test`. Refer to specific deployment scripts for more information. Most of the deployment scripts and other helpers consume environment variables for configuration, but some configuration is performed directly in each script depending on the operation.

## Building Circuits

The ZK mint circuit is written in [Noir](https://noir-lang.org/) and proven with [Barretenberg](https://github.com/AztecProtocol/barretenberg) using UltraHonk. Three tools are required:

- [nargo](https://noir-lang.org/docs/getting_started/quick_start): the Noir compiler and witness generator.
- [bb](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg/bbup): the Barretenberg prover. If you install via `bbup` this will automatically select a version compatible with your `nargo` installation.
- [cargo](https://rustup.rs/): standard Rust tooling is required to build `zk-mint-input`, the circuit input generator.

### Trusted Setup

Proof generation uses [KZG](https://dankradfeist.de/ethereum/2020/06/16/kate-polynomial-commitments.html) polynomial commitments over the BN254 curve. KZG requires a structured reference string (SRS) produced by a trusted setup ceremony. We use the [Aztec Ignition](https://aztec.network/blog/aztec-crs-the-biggest-mpc-setup-in-history-has-successfully-finished) output, a widely-trusted ceremony where 176 participants each contributed randomness. The security guarantee is **1-of-N honest**: if even a single participant destroyed their secret, the Aztec Ignition SRS is sound.

The `bb` tool downloads the SRS automatically on first use and caches it at `~/.bb-crs/bn254_g1.dat`. To verify the local SRS and the G2 ceremony point embedded in the on-chain verifier contract, run `make verify-ceremony`.

This goal checks that the verifier's G2 point matches the known Aztec Ignition output and that the cached SRS begins with the expected BN254 generator. For full ceremony verification (signature and inclusion checks on all 176 contributions), you can refer to [AztecProtocol/ignition-verification](https://github.com/AztecProtocol/ignition-verification).

### Workflow

The end-to-end ZK mint workflow proceeds through the following steps.

**0. Verify the trusted setup is correct.**

Run `make verify-ceremony` per the description above to confirm that the verifier being used matches that of the widely-trusted Aztec Ignition ceremony.

**1. Compile the circuit.**

Run `make circuit`, which in turn runs `nargo compile` and produces the circuit bytecode at `circuits/target/zk_mint.json`.

**2. Mine a burn address.**

```
make mine
```

This searches for a PoW nonce that, combined with the ECDSA public key derived from `BURN_PRIVATE_KEY`, produces a valid private address (the burn address). The difficulty requirement ensures the address is bound to the key. Record the output `PoW nonce` and `Burn address` values.

**3. Send tokens to the burn address.**

Transfer the desired amount of tokens to the burn address. The contract's hash tree records a balance leaf for every receive.

**4. Generate circuit inputs.**

```
make generate-input
```

Requires `BURN_PRIVATE_KEY`, `POW_NONCE`, `MINT_AMOUNT`, and `MINT_RECIPIENT` to be set in `.env`. The input generator connects to `RPC_URL`, fetches the current tree root, the burn address balance, and all tree leaves, then computes the tree proof and ECDSA signature. Output is written to `circuits/Prover.toml`.

**5. Generate the witness.**

```
make witness
```

Runs `nargo execute`, which evaluates the circuit against `Prover.toml`. If all constraints are satisfied, a witness is saved. A failure here means the inputs are inconsistent (such as a wrong nonce, incorrect balance, or invalid signature).

**6. Generate the proof.**

```
make proof
```

Runs `bb prove` with `--verifier_target evm`, producing an UltraHonk proof at `circuits/target/proof/proof` along with a verification key. This is the cryptographic proof that the prover knows a valid witness without revealing any private inputs.

**7. Submit the ZK mint.**

```
make zk-mint
```

Broadcasts a transaction calling `zkMint` on the Sigil contract. The Forge script reads the proof and public inputs from the proof directory and submits them on-chain. The contract verifies the proof, checks the tree root and nullifier, then re-mints tokens to the recipient.

### Integration Test Harness

The test harness (`make harness`) runs a randomized end-to-end integration test against a local Anvil instance. It deploys contracts, funds test accounts, then executes a configurable number of random operations: public transfers, burns, ZK mints (with full proof generation), and time warps. After every operation the harness verifies five invariants against on-chain state:

1. Balance consistency for all tracked addresses.
2. Visible total supply.
3. Balance sum equals raw total supply.
4. Nullifier correctness (stored as `amount + 1`).
5. Exact tree root match against a shadow LeanIMT maintained in Rust with Poseidon2 hashing.

ZK mints exercise all three relay modes (self-relay, `msg.sender`, specific relayer) with randomized fee parameters.

```
make harness
```

Configure via environment variables or `.env`:

| Variable | Default | Description |
|---|---|---|
| `HARNESS_SEED` | _(random)_ | RNG seed for reproducible runs. |
| `HARNESS_ROUNDS` | `50` | Number of random operations per run. |
| `HARNESS_ACCOUNTS` | `4` | Number of funded test accounts. |

To reproduce a failure, re-run with the seed printed at the start of the output:

```
HARNESS_SEED=42 make harness
```

# Security

If you discover any bug; flaw; issue; dæmonic incursion; or other malicious, negligent, or incompetent action that impacts the security of any of these projects please responsibly disclose them to us; instructions are available [here](./SECURITY.md).

# License

The [license](./LICENSE) for all of our original work is `LicenseRef-VPL WITH AGPL-3.0-only`. This includes every asset in this repository: code, documentation, images, branding, and more. You are licensed to use all of it so long as you maintain _maximum possible virality_ and our copyleft licenses.

Permissive open source licenses are tools for the corporate subversion of libre software; visible source licenses are an even more malignant scourge. All original works in this project are to be licensed under the most aggressive, virulently-contagious copyleft terms possible. To that end everything is licensed under the [Viral Public License](./licenses/LicenseRef-VPL) coupled with the [GNU Affero General Public License v3.0](./licenses/AGPL-3.0-only) for use in the event that some unaligned party attempts to weasel their way out of copyleft protections. In short: if you use or modify anything in this project for any reason, your project must be licensed under these same terms.

For art assets specifically, in case you want to further split hairs or attempt to weasel out of this virality, we explicitly license those under the viral and copyleft [Free Art License 1.3](./licenses/FreeArtLicense-1.3).

# Original Licenses

We stand on the shoulders of giants. This repository contains a fork of upstream the upstream [Uniswap Continuous Clearing Auction](https://github.com/Uniswap/continuous-clearing-auction) which we modify and run for Sigil's own needs. This original project is licensed under the [`MIT`](./original_licenses/MIT) license, the original text of which has been maintained in the [`original_licenses/`](./original_licenses/) directory. The commit hash of initial divergence is `968e4251bfb0595155a11b94ffd0c8e05adc2701`; our license only applies to any of our own code or modifications that have not been upstreamed and absolutely does not apply to any original code or future upstream code we may choose to merge.
