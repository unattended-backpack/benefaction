# Configuration is loaded from `.env.maintainer` and can be overridden by
# environment variables.
#
# Usage:
#   make build                    # Build using `.env.maintainer`.

# Load configuration from `.env.maintainer` if it exists.
-include .env.maintainer

# Load configuration from `.env` if it exists.
-include .env

# Export all variables to child processes (e.g., forge scripts).
.EXPORT_ALL_VARIABLES:

# Allow environment variable overrides with defaults.
FOUNDRY_DISABLE_NIGHTLY_WARNING ?= 1
PRIVATE_KEY ?=
BURN_PRIVATE_KEY ?=
MNEMONIC ?= "faith faith faith faith faith faith faith grace grace grace grace grace"
MNEMONIC_INDEX ?= 0
RPC_URL ?= http://rpc.sacristy.local
VERIFIER ?= blockscout
VERIFIER_URL ?= http://api.blockscout.sacristy.local/api/

# Build wallet args: prefer PRIVATE_KEY if set, otherwise use MNEMONIC.
# Derive the sender address for forge script --sender.
ifneq ($(PRIVATE_KEY),)
WALLET_ARGS = --private-key $(PRIVATE_KEY)
SENDER = $(shell cast wallet address $(PRIVATE_KEY))
else
WALLET_ARGS = --mnemonics $(MNEMONIC) --mnemonic-indexes $(MNEMONIC_INDEX)
SENDER = $(shell cast wallet address --mnemonic $(MNEMONIC) --mnemonic-index $(MNEMONIC_INDEX))
endif

.PHONY: init
init:
	@echo "Initializing configuration files ..."
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "Created .env from .env.example - please review."; \
	else \
		echo ".env already exists."; \
	fi
	@echo "Initialization complete. Review configuration before running."

.PHONY: clean
clean:
	@bash -c 'echo -e "\033[33mWARNING: This will delete build artifacts.\033[0m"; \
	read -p "Are you sure you want to continue? [y/N]: " confirm; \
	if [[ "$$confirm" != "y" && "$$confirm" != "Y" ]]; then \
		echo "Operation cancelled."; \
		exit 1; \
	fi'
	cd ./contracts && forge clean && cd ../
	rm -rf out/
	rm -rf target/
	rm -rf ./circuits/target/
	rm -f result result-*

.PHONY: build
build:
	@echo "Building ..."
	cd ./contracts && forge soldeer install && forge build && cd ../
	@echo "... build complete."

.PHONY: test
test:
	@echo "Running tests ..."
	cd ./contracts && forge test && cd ../
	@echo "... tests completed."

.PHONY: test-cca
test-cca:
	@echo "Running CCA tests ..."
	cd ./contracts && forge test --match-path "test/cca/*" && cd ../
	@echo "... CCA tests completed."

.PHONY: test-token
test-token:
	@echo "Running token tests ..."
	cd ./contracts && forge test --match-path "test/token/*" && cd ../
	@echo "... token tests completed."

# Common deploy-and-verify logic. Requires CONTRACT to be set.
# CONTRACT_PATH defaults to src/$(CONTRACT).sol but can be overridden.
.PHONY: deploy-and-verify
deploy-and-verify:
ifndef CONTRACT
	$(error CONTRACT is required. Use a contract-specific target like deploy-sigil.)
endif
	$(eval CONTRACT_PATH ?= src/$(CONTRACT).sol)
	@echo "* Deploying $(CONTRACT) ..."
	@cd ./contracts && \
		OUTPUT=$$(forge script script/deploy/Deploy$(CONTRACT).s.sol --rpc-url $(RPC_URL) $(WALLET_ARGS) --sender $(SENDER) --broadcast --slow 2>&1); \
		STATUS=$$?; \
		echo "$$OUTPUT"; \
		if [ $$STATUS -ne 0 ]; then exit $$STATUS; fi && \
		ADDRESS=$$(echo "$$OUTPUT" | grep -oP '$(CONTRACT) \K0x[a-fA-F0-9]+') && \
		echo "* Verifying at $$ADDRESS ..." && \
		forge verify-contract $$ADDRESS $(CONTRACT_PATH):$(CONTRACT) --verifier $(VERIFIER) --verifier-url $(VERIFIER_URL)
	@echo "* ... deployed and verified."

.PHONY: deploy-sigil
deploy-sigil:
	@$(MAKE) deploy-and-verify CONTRACT=Sigil CONTRACT_PATH=src/token/Sigil.sol

.PHONY: deploy-cca
deploy-cca:
	@$(MAKE) deploy-and-verify CONTRACT=ContinuousClearingAuction CONTRACT_PATH=src/cca/ContinuousClearingAuction.sol

.PHONY: deploy-lens
deploy-lens:
	@$(MAKE) deploy-and-verify CONTRACT=AuctionStateLens CONTRACT_PATH=src/cca/lens/AuctionStateLens.sol

.PHONY: prepare-cca
prepare-cca:
	cd ./contracts && forge script script/deploy/PrepareCCA.s.sol --rpc-url $(RPC_URL) $(WALLET_ARGS) --broadcast && cd ../

.PHONY: deploy
deploy:
	$(MAKE) build
	$(MAKE) deploy-sigil
	$(MAKE) deploy-cca
	$(MAKE) deploy-lens
	$(MAKE) prepare-cca

.PHONY: submit-bid
submit-bid:
	cd ./contracts && forge script script/SubmitBid.s.sol --rpc-url $(RPC_URL) $(WALLET_ARGS) --broadcast && cd ../

.PHONY: random-bids
random-bids:
	cd ./contracts && forge script script/RandomBids.s.sol --rpc-url $(RPC_URL) $(WALLET_ARGS) --broadcast && cd ../

# Known Aztec Ignition ceremony G2 point (tau * G2_generator).
# These are the four 32-byte coordinates of the BN254 G2 point in EVM ecPairing
# order (x.c1, x.c0, y.c1, y.c0). Source: barretenberg bn254_crs_data.hpp.
IGNITION_G2_X_C1 := 0x260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c1
IGNITION_G2_X_C0 := 0x0118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b0
IGNITION_G2_Y_C1 := 0x04fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe4
IGNITION_G2_Y_C0 := 0x22febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e55

# Known first G1 point of the BN254 SRS: the generator (1, 2).
SRS_G1_FIRST_X := 0000000000000000000000000000000000000000000000000000000000000001
SRS_G1_FIRST_Y := 0000000000000000000000000000000000000000000000000000000000000002

.PHONY: verify-ceremony
verify-ceremony:
	@echo "Verifying Aztec Ignition ceremony artifacts ..."
	@echo ""
	@echo "1. Checking G2 ceremony point in ZKMintVerifier ..."
	@grep -q '$(IGNITION_G2_X_C1)' contracts/src/token/zk_mint/ZKMintVerifier.sol && \
	 grep -q '$(IGNITION_G2_X_C0)' contracts/src/token/zk_mint/ZKMintVerifier.sol && \
	 grep -q '$(IGNITION_G2_Y_C1)' contracts/src/token/zk_mint/ZKMintVerifier.sol && \
	 grep -q '$(IGNITION_G2_Y_C0)' contracts/src/token/zk_mint/ZKMintVerifier.sol && \
	 echo "   PASS: G2 point matches known Ignition ceremony output." || \
	 { echo "   FAIL: G2 point mismatch. The verifier may not be using the Ignition SRS."; exit 1; }
	@echo ""
	@CRS_FILE=$${CRS_PATH:-$$HOME/.bb-crs}/bn254_g1.dat; \
	 echo "2. Checking local CRS file ($$CRS_FILE) ..."; \
	 if [ ! -f "$$CRS_FILE" ]; then \
	   echo "   SKIP: CRS file not found. Run 'make proof' first to download it."; \
	 else \
	   FIRST_X=$$(od -A n -t x1 -N 32 "$$CRS_FILE" | tr -d ' \n'); \
	   FIRST_Y=$$(od -A n -t x1 -j 32 -N 32 "$$CRS_FILE" | tr -d ' \n'); \
	   if [ "$$FIRST_X" = "$(SRS_G1_FIRST_X)" ] && [ "$$FIRST_Y" = "$(SRS_G1_FIRST_Y)" ]; then \
	     echo "   PASS: First G1 point is the BN254 generator (1, 2)."; \
	   else \
	     echo "   FAIL: First G1 point does not match expected generator."; exit 1; \
	   fi; \
	 fi
	@echo ""
	@echo "Local checks passed. For full ceremony verification, see:"
	@echo "  https://github.com/AztecProtocol/ignition-verification"

# Goals for building the Noir ZK mint circuit.
.PHONY: circuit
circuit:
	@command -v nargo >/dev/null 2>&1 || { echo "nargo not found"; exit 1; }
	cd ./circuits && nargo compile

.PHONY: test-circuit
test-circuit:
	@command -v nargo >/dev/null 2>&1 || { echo "nargo not found"; exit 1; }
	@echo "Running circuit tests ..."
	cd ./circuits && nargo test
	@echo "Running circuit fuzz harnesses ..."
	cd ./circuits && nargo fuzz --timeout 10
	@echo "... circuit tests completed."

# Goals for the circuit input generator.
INPUTGEN := ./input_generator/target/release/zk-mint-input

.PHONY: $(INPUTGEN)
$(INPUTGEN):
	cd ./input_generator && cargo build --release

# Chain ID for address derivation and EIP-712 (default: Anvil).
CHAIN_ID ?= 31337

# Mine requires BURN_PRIVATE_KEY (viewing key is derived from it).
.PHONY: mine
mine: $(INPUTGEN)
ifndef BURN_PRIVATE_KEY
	$(error BURN_PRIVATE_KEY is required.)
endif
	$(INPUTGEN) mine --private-key $(BURN_PRIVATE_KEY) --chain-id $(CHAIN_ID)

# Required env vars for generate-input.
POW_NONCE ?=
MINT_AMOUNT ?=
MINT_RECIPIENT ?=
TOKEN_ADDRESS ?= $(TOKEN_EXPECTED_ADDRESS)
PREVIOUS_ACCOUNT_NONCE ?= 0
PREVIOUS_TOTAL_MINTED ?= 0

# Reward parameters for relayed ZK mints (all default to 0 = self-relay).
RELAYER_ADDRESS ?= 0
PRIORITY_FEE ?= 0
CONVERSION_RATE ?= 0
MAX_REWARD ?= 0

# Integration test harness parameters.
HARNESS_SEED ?=
HARNESS_ROUNDS ?= 50
HARNESS_ACCOUNTS ?= 4

.PHONY: generate-input
generate-input: $(INPUTGEN)
ifndef BURN_PRIVATE_KEY
	$(error BURN_PRIVATE_KEY is required.)
endif
ifndef POW_NONCE
	$(error POW_NONCE is required.)
endif
ifndef MINT_AMOUNT
	$(error MINT_AMOUNT is required.)
endif
ifndef MINT_RECIPIENT
	$(error MINT_RECIPIENT is required.)
endif
	$(INPUTGEN) generate \
		--private-key $(BURN_PRIVATE_KEY) \
		--burn "$(POW_NONCE) $(MINT_AMOUNT) $(PREVIOUS_ACCOUNT_NONCE) $(PREVIOUS_TOTAL_MINTED)" \
		--amount $(MINT_AMOUNT) \
		--recipient $(MINT_RECIPIENT) \
		--rpc-url $(RPC_URL) \
		--token-address $(TOKEN_ADDRESS) \
		--chain-id $(CHAIN_ID) \
		--relayer $(RELAYER_ADDRESS) \
		--priority-fee $(PRIORITY_FEE) \
		--conversion-rate $(CONVERSION_RATE) \
		--max-reward $(MAX_REWARD) \
		-o ./circuits/Prover.toml

.PHONY: verifier
verifier: circuit
	@command -v bb >/dev/null 2>&1 || { echo "bb not found"; exit 1; }
	cd ./circuits && \
		bb write_vk -b target/zk_mint.json -o out/ -t evm && \
		bb write_solidity_verifier -k out/vk -o target/verifier.sol -t evm
	sed -i \
		-e 's/pragma solidity \^0.8.27;/pragma solidity >=0.8.21;/' \
		-e 's/require(success, ShpleminiFailed());/if (!success) revert ShpleminiFailed();/' \
		./circuits/target/verifier.sol
	cp ./circuits/target/verifier.sol ./contracts/src/token/zk_mint/ZKMintVerifier.sol
	echo '' >> ./contracts/src/token/zk_mint/ZKMintVerifier.sol
	echo 'contract ZKMintVerifier is HonkVerifier {}' >> \
		./contracts/src/token/zk_mint/ZKMintVerifier.sol
	@echo "Verifier written to contracts/src/token/zk_mint/ZKMintVerifier.sol"

.PHONY: witness
witness:
	@command -v nargo >/dev/null 2>&1 || { echo "nargo not found"; exit 1; }
	cd ./circuits && nargo execute

.PHONY: proof
proof:
	@command -v bb >/dev/null 2>&1 || { echo "bb not found"; exit 1; }
	cd ./circuits && bb prove --verifier_target evm --write_vk -b target/zk_mint.json -w target/zk_mint.gz -o target/proof

.PHONY: zk-mint
zk-mint:
	cd ./contracts && forge script script/ZKMint.s.sol --rpc-url $(RPC_URL) $(WALLET_ARGS) --broadcast --slow && cd ../

.PHONY: harness
harness:
	cd ./harness && cargo run --release -- \
		$(if $(HARNESS_SEED),--seed $(HARNESS_SEED)) \
		--rounds $(HARNESS_ROUNDS) \
		--accounts $(HARNESS_ACCOUNTS)

.PHONY: help
help:
	@echo "Build System"
	@echo ""
	@echo "Targets:"
	@echo "  init              Initialize config from examples."
	@echo "  clean             Clean output directories."
	@echo "  build             Build contracts."
	@echo "  test              Run all tests."
	@echo "  test-cca          Run CCA tests only."
	@echo "  test-token        Run token tests only."
	@echo "  deploy-and-verify Deploy and verify a particular contract."
	@echo "  deploy-sigil      Deploy the Sigil token."
	@echo "  deploy-cca        Deploy the ContinuousClearingAuction."
	@echo "  deploy-lens       Deploy the AuctionStateLens."
	@echo "  prepare-cca       Prepare the CCA contract for auction start."
	@echo "  deploy            Deploy and prepare all required contracts."
	@echo "  submit-bid        Submit a bid to the CCA contract."
	@echo "  random-bids       Submit random bids."
	@echo "  verify-ceremony   Verify Aztec Ignition trusted setup artifacts."
	@echo "  circuit           Compile the Noir ZK mint circuit."
	@echo "  test-circuit      Run Noir circuit tests."
	@echo "  verifier          Regenerate the Solidity verifier from the circuit."
	@echo "  generate-input    Generate Prover.toml (fetches on-chain data via RPC)."
	@echo "  mine              Mine a PoW nonce for a private address."
	@echo "  witness           Generate witness from Prover.toml (nargo execute)."
	@echo "  proof             Generate UltraHonk proof and VK for EVM (bb)."
	@echo "  zk-mint           Submit a ZK mint with proof on-chain."
	@echo "  harness           Run the integration test harness on a local Anvil."
	@echo "  help              Show this help message."
	@echo ""
	@echo "Configuration:"
	@echo "  Variables are loaded from .env.maintainer, then .env."
	@echo "  See .env.example for available options:"
	@echo "    PRIVATE_KEY     Private key (takes precedence over MNEMONIC)"
	@echo "    MNEMONIC        Wallet mnemonic for deployment"
	@echo "    MNEMONIC_INDEX  Account derivation index"
	@echo "    RPC_URL         RPC endpoint URL"
	@echo "    VERIFIER        Verification service"
	@echo "    VERIFIER_URL    Verifier API URL"
	@echo "    CHAIN_ID        Chain ID for address derivation (default 31337)"
	@echo "    HARNESS_SEED    Harness RNG seed (random if unset)"
	@echo "    HARNESS_ROUNDS  Harness operation count (default 50)"
	@echo "    HARNESS_ACCOUNTS Harness test account count (default 4)"
	@echo ""
	@echo "Examples:"
	@echo "  make build"
	@echo "  make deploy"

.DEFAULT_GOAL := build
