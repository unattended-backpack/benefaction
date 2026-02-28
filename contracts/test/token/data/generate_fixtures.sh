#!/usr/bin/env bash
# Generate proof fixtures for Solidity tests.
#
# Usage: ./contracts/test/token/data/generate_fixtures.sh
#
# Requires: anvil, cast, forge, nargo, bb,
#   zk-mint-input (cargo build --release)
set -euo pipefail

# Paths
ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
INPUTGEN="$ROOT/input_generator/target/release/zk-mint-input"
CIRCUIT_DIR="$ROOT/circuits"
DATA_DIR="$ROOT/contracts/test/token/data"
NARGO="${NARGO:-$HOME/.nargo/bin/nargo}"
BB="${BB:-$HOME/.bb/bb}"

# Constants

# Forge test contract address (deterministic).
TEST_CONTRACT=0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496

# Token address: CREATE(TEST_CONTRACT, nonce=4).
TOKEN=0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9

# makeAddr("recipient") in Forge.
RECIPIENT=0x006217c47ffA5Eb3F3c92247ffFE22AD998242c5

# Separate deployer for the ZKTranscriptLib library
# (anvil account 0). Forge auto-links libraries outside
# the test contract's nonce sequence, so we must deploy
# the library from a different address.
LIB_DEPLOYER=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266

CHAIN_ID=31337
ANVIL_PORT=18545
RPC="http://127.0.0.1:$ANVIL_PORT"

# Spending keys.
KEY1=0x0000000000000000000000000000000000000000000000000000000000000001
KEY2=0x0000000000000000000000000000000000000000000000000000000000000002

# Pre-mined PoW nonces.
NONCE1=0x08e4eedca9be98c79d9a4edd6fcb0e63b3b0e5793a8fd59748fbfe9cdd1644e6
NONCE2=0x277ef6ad78514998a52ac8672150bb63261f1250f18a64a3ea458b89264a88b2
NONCE_STEALTH=0x05457d881145d920beb549ef7c6daa4c404676edbf14ff21fade3c9abeb26bb7

# Burn addresses (derived from keys + nonces + chain_id).
BURN1=0xaaae88c9d59da8724cd824af8774c6d3c2f3d690
BURN2=0x91c2025db39da9cd456344ac7cdcf64969ebfd61
BURN_STEALTH=0x20accbcc714e2044b5325b9ea1a3bdba7fadba13

# 100 ether.
BURN_AMOUNT="100000000000000000000"
# 50 ether.
MINT_AMOUNT="50000000000000000000"

# Multi-burn amounts.
# 30 ether from BURN1.
MB_MINT0="30000000000000000000"
# 70 ether from BURN_STEALTH.
MB_MINT1="70000000000000000000"
# 100 ether total.
MB_TOTAL="100000000000000000000"

# Helpers

cleanup() {
  if [ -n "${ANVIL_PID:-}" ]; then
    kill "$ANVIL_PID" 2>/dev/null || true
    wait "$ANVIL_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

log() { echo "==> $*" >&2; }

cast_rpc() {
  cast rpc "$@" --rpc-url "$RPC" 2>/dev/null
}

cast_send_raw() {
  cast send "$@" \
    --rpc-url "$RPC" \
    --from "$TEST_CONTRACT" \
    --unlocked \
    --gas-limit 30000000 \
    2>/dev/null
}

# Generate proof from Prover.toml.
# Usage: gen_proof <output_name>
gen_proof() {
  local name="$1"
  log "Generating proof: $name"
  cd "$CIRCUIT_DIR"

  # Execute circuit to produce witness.
  "$NARGO" execute 2>&1 \
    | grep -v "^warning:" || true

  # Prove with EVM target.
  mkdir -p target/proof
  "$BB" prove \
    -b target/zk_mint.json \
    -w target/zk_mint.gz \
    -o target/proof \
    --write_vk -t evm 2>&1 | tail -1

  # Copy artifacts.
  cp target/proof/proof \
    "$DATA_DIR/${name}_proof"
  cp target/proof/public_inputs \
    "$DATA_DIR/${name}_public_inputs"
  log "Wrote ${name}_proof and ${name}_public_inputs"
}

# Deploy a fresh Sigil instance matching Forge test setUp
# nonces. Sets: POSEIDON2, VERIFIER, SIGIL.
deploy_sigil() {
  # Fund test contract with 100 ETH.
  cast_rpc anvil_setBalance \
    "$TEST_CONTRACT" "0x56bc75e2d63100000" \
    > /dev/null
  # Nonce 1 is the Forge test default.
  cast_rpc anvil_setNonce \
    "$TEST_CONTRACT" "0x1" > /dev/null
  cast_rpc anvil_impersonateAccount \
    "$TEST_CONTRACT" > /dev/null

  # Deploy ZKTranscriptLib from a separate account.
  # This avoids consuming test contract nonces.
  VSOL=src/token/zk_mint/ZKMintVerifier.sol
  LIB_ADDR=$(forge create \
    --rpc-url "$RPC" \
    --from "$LIB_DEPLOYER" \
    --unlocked --broadcast \
    --root "$ROOT/contracts" \
    "$VSOL:ZKTranscriptLib" \
    2>&1 | grep "Deployed to:" | awk '{print $3}')
  log "ZKTranscriptLib: $LIB_ADDR"
  LIB_FLAG="$VSOL:ZKTranscriptLib:$LIB_ADDR"

  # Nonce 1: Poseidon2.
  PSOL=src/token/zk_mint/Poseidon2.sol
  POSEIDON2=$(forge create \
    --rpc-url "$RPC" \
    --from "$TEST_CONTRACT" \
    --unlocked --broadcast \
    --root "$ROOT/contracts" \
    "$PSOL:Poseidon2" \
    2>&1 | grep "Deployed to:" | awk '{print $3}')
  log "Poseidon2: $POSEIDON2"

  # Nonce 2: dummy (consume nonce for MockWETH slot).
  cast send \
    --rpc-url "$RPC" \
    --from "$TEST_CONTRACT" \
    --unlocked \
    --gas-limit 30000000 \
    --create "0x60006000f3" \
    2>/dev/null > /dev/null
  log "Dummy (nonce 2): consumed"

  # Nonce 3: ZKMintVerifier.
  VERIFIER=$(forge create \
    --rpc-url "$RPC" \
    --from "$TEST_CONTRACT" \
    --unlocked --broadcast \
    --root "$ROOT/contracts" \
    --libraries "$LIB_FLAG" \
    "$VSOL:ZKMintVerifier" \
    2>&1 | grep "Deployed to:" | awk '{print $3}')
  log "Verifier: $VERIFIER"

  # Nonce 4: Sigil.
  SIGIL=$(forge create \
    --rpc-url "$RPC" \
    --from "$TEST_CONTRACT" \
    --unlocked --broadcast \
    --root "$ROOT/contracts" \
    src/token/Sigil.sol:Sigil \
    --constructor-args \
    "$TEST_CONTRACT" "$VERIFIER" "$POSEIDON2" 86400 100 1000000000000000000000000 \
    2>&1 | grep "Deployed to:" | awk '{print $3}')
  log "Sigil: $SIGIL"

  # Verify the address matches.
  SIGIL_LC=$(echo "$SIGIL" | tr '[:upper:]' '[:lower:]')
  TOKEN_LC=$(echo "$TOKEN" | tr '[:upper:]' '[:lower:]')
  if [ "$SIGIL_LC" != "$TOKEN_LC" ]; then
    echo "ERROR: deployed $SIGIL, expected $TOKEN" >&2
    exit 1
  fi
  log "Sigil address verified: $TOKEN"

  # Deploy MockWETH at the canonical WETH address.
  local WETH=0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2
  local MOCK_WETH
  MOCK_WETH=$(forge create \
    --rpc-url "$RPC" \
    --from "$TEST_CONTRACT" \
    --unlocked --broadcast \
    --root "$ROOT/contracts" \
    test/token/utils/MockWETH.sol:MockWETH \
    2>&1 | grep "Deployed to:" | awk '{print $3}')
  local WETH_CODE
  WETH_CODE=$(cast code "$MOCK_WETH" \
    --rpc-url "$RPC" 2>/dev/null)
  cast_rpc anvil_setCode \
    "$WETH" "$WETH_CODE" > /dev/null

  # Mint WETH to test contract and approve Sigil.
  cast_send_raw "$WETH" \
    "mint(address,uint256)" \
    "$TEST_CONTRACT" "1000000000" > /dev/null
  cast_send_raw "$WETH" \
    "approve(address,uint256)" \
    "$TOKEN" "1000000000" > /dev/null

  # Initialize Sigil (mints 1B tokens to TEST_CONTRACT).
  cast_send_raw "$TOKEN" \
    "initialize(address)" "$TEST_CONTRACT" \
    > /dev/null
  local supply
  supply=$(cast call "$TOKEN" \
    "totalSupply()(uint256)" \
    --rpc-url "$RPC" 2>/dev/null)
  log "Sigil initialized, total supply: $supply"
}

# Start a fresh anvil and deploy Sigil.
fresh_anvil() {
  if [ -n "${ANVIL_PID:-}" ]; then
    kill "$ANVIL_PID" 2>/dev/null
    wait "$ANVIL_PID" 2>/dev/null || true
  fi
  log "Starting anvil on port $ANVIL_PORT"
  anvil --port "$ANVIL_PORT" --silent &
  ANVIL_PID=$!
  sleep 1
  deploy_sigil
}

# The zkMint function signature.
PT_SIG="zkMint(uint256,address,"
PT_SIG+="(address,uint256,uint256,uint256),"
PT_SIG+="(uint256,uint256,bytes)[],"
PT_SIG+="uint256,bytes)"

# Fixture 1: self_relay
fresh_anvil

log "Setting up self_relay (key1 -> burn1)"
cast_send_raw "$TOKEN" \
  "transfer(address,uint256)" \
  "$BURN1" "$BURN_AMOUNT" > /dev/null

"$INPUTGEN" generate \
  --private-key "$KEY1" \
  --burn "$NONCE1 $MINT_AMOUNT" \
  --amount "$MINT_AMOUNT" \
  --recipient "$RECIPIENT" \
  --rpc-url "$RPC" \
  --token-address "$TOKEN" \
  --chain-id "$CHAIN_ID" \
  --domain-name "Sigil" \
  --domain-version "1" \
  -o "$CIRCUIT_DIR/Prover.toml"

gen_proof "self_relay"

# Fixture 2: second_mint
#
# Execute the self_relay proof on-chain to update the tree,
# then generate a second mint from the same burn address.

log "Executing self_relay on anvil for second_mint"

PROOF_HEX="0x$(od -v -An -tx1 \
  "$DATA_DIR/self_relay_proof" | tr -d ' \n')"
INPUTS_HEX=$(od -v -An -tx1 \
  "$DATA_DIR/self_relay_public_inputs" | tr -d ' \n')

# Public input layout (interleaved, 32 bytes each):
# [0]=amount [1]=sigHash [2..65]=hash/null pairs
# [66]=root.
AMOUNT_HEX="0x${INPUTS_HEX:0:64}"
ROOT_HEX="0x${INPUTS_HEX:$((66*64)):64}"

# First active burn (noteHash at field 2, null at field 3).
NOTE_HASH="0x${INPUTS_HEX:$((2*64)):64}"
NULLIFIER="0x${INPUTS_HEX:$((3*64)):64}"

# totalMintedEncrypted: abi.encode(new_total_minted).
# 50 ether = 0x...2b5e3af16b1880000.
TSE="0x000000000000000000000000000000000000000000000002b5e3af16b1880000"

# Zero reward data (self-relay).
ZERO_REWARD="(0x0000000000000000000000000000000000000000,0,0,0)"

# Execute the self_relay proof on anvil.
cast_send_raw "$TOKEN" \
  "$PT_SIG" \
  "$AMOUNT_HEX" "$RECIPIENT" \
  "$ZERO_REWARD" \
  "[($NOTE_HASH,$NULLIFIER,$TSE)]" \
  "$ROOT_HEX" "$PROOF_HEX" > /dev/null
log "self_relay executed on anvil"

# Generate second_mint: remaining 50 ether,
# prev_nonce=1, prev_total_minted=50e18.
"$INPUTGEN" generate \
  --private-key "$KEY1" \
  --burn "$NONCE1 $MINT_AMOUNT 1 $MINT_AMOUNT" \
  --amount "$MINT_AMOUNT" \
  --recipient "$RECIPIENT" \
  --rpc-url "$RPC" \
  --token-address "$TOKEN" \
  --chain-id "$CHAIN_ID" \
  --domain-name "Sigil" \
  --domain-version "1" \
  -o "$CIRCUIT_DIR/Prover.toml"

gen_proof "second_mint"

# Fixture 3: relayer
#
# relayer=address(1), priorityFee=1 gwei,
# conversionRate=385000, maxReward=1 ether.
fresh_anvil

cast_send_raw "$TOKEN" \
  "transfer(address,uint256)" \
  "$BURN2" "$BURN_AMOUNT" > /dev/null

"$INPUTGEN" generate \
  --private-key "$KEY2" \
  --burn "$NONCE2 $MINT_AMOUNT" \
  --amount "$MINT_AMOUNT" \
  --recipient "$RECIPIENT" \
  --rpc-url "$RPC" \
  --token-address "$TOKEN" \
  --chain-id "$CHAIN_ID" \
  --relayer 1 \
  --priority-fee 1000000000 \
  --conversion-rate 385000 \
  --max-reward "1000000000000000000" \
  --domain-name "Sigil" \
  --domain-version "1" \
  -o "$CIRCUIT_DIR/Prover.toml"

gen_proof "relayer"

# Fixture 4: specific_relayer
#
# Same parameters as relayer but with a specific address.
fresh_anvil

cast_send_raw "$TOKEN" \
  "transfer(address,uint256)" \
  "$BURN2" "$BURN_AMOUNT" > /dev/null

SPECIFIC_RELAYER=0xB435c60573DFD2dACf3472DCD47a8Aed400680a2

"$INPUTGEN" generate \
  --private-key "$KEY2" \
  --burn "$NONCE2 $MINT_AMOUNT" \
  --amount "$MINT_AMOUNT" \
  --recipient "$RECIPIENT" \
  --rpc-url "$RPC" \
  --token-address "$TOKEN" \
  --chain-id "$CHAIN_ID" \
  --relayer "$SPECIFIC_RELAYER" \
  --priority-fee 1000000000 \
  --conversion-rate 385000 \
  --max-reward "1000000000000000000" \
  --domain-name "Sigil" \
  --domain-version "1" \
  -o "$CIRCUIT_DIR/Prover.toml"

gen_proof "specific_relayer"

# Fixture 5: multi_burn (self-relay, 2 burns)
fresh_anvil

cast_send_raw "$TOKEN" \
  "transfer(address,uint256)" \
  "$BURN1" "$BURN_AMOUNT" > /dev/null
cast_send_raw "$TOKEN" \
  "transfer(address,uint256)" \
  "$BURN_STEALTH" "$BURN_AMOUNT" > /dev/null
log "Multi-burn: BURN1=$BURN1, STEALTH=$BURN_STEALTH"

"$INPUTGEN" generate \
  --private-key "$KEY1" \
  --burn "$NONCE1 $MB_MINT0" \
  --burn "$NONCE_STEALTH $MB_MINT1 0 0 0x42" \
  --amount "$MB_TOTAL" \
  --recipient "$RECIPIENT" \
  --rpc-url "$RPC" \
  --token-address "$TOKEN" \
  --chain-id "$CHAIN_ID" \
  --domain-name "Sigil" \
  --domain-version "1" \
  -o "$CIRCUIT_DIR/Prover.toml"

gen_proof "multi_burn"

# Fixture 6: multi_burn_relay (generic relay, 2 burns)
fresh_anvil

cast_send_raw "$TOKEN" \
  "transfer(address,uint256)" \
  "$BURN1" "$BURN_AMOUNT" > /dev/null
cast_send_raw "$TOKEN" \
  "transfer(address,uint256)" \
  "$BURN_STEALTH" "$BURN_AMOUNT" > /dev/null
log "Multi-burn relay: BURN1=$BURN1, STEALTH=$BURN_STEALTH"

"$INPUTGEN" generate \
  --private-key "$KEY1" \
  --burn "$NONCE1 $MB_MINT0" \
  --burn "$NONCE_STEALTH $MB_MINT1 0 0 0x42" \
  --amount "$MB_TOTAL" \
  --recipient "$RECIPIENT" \
  --rpc-url "$RPC" \
  --token-address "$TOKEN" \
  --chain-id "$CHAIN_ID" \
  --relayer 1 \
  --priority-fee 1000000000 \
  --conversion-rate 385000 \
  --max-reward "1000000000000000000" \
  --domain-name "Sigil" \
  --domain-version "1" \
  -o "$CIRCUIT_DIR/Prover.toml"

gen_proof "multi_burn_relay"

# Done
log "All fixtures generated:"
ls -la "$DATA_DIR"/*_proof "$DATA_DIR"/*_public_inputs
