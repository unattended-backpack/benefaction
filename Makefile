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
MNEMONIC ?= "faith faith faith faith faith faith faith grace grace grace grace grace"
MNEMONIC_INDEX ?= 0
RPC_URL ?= http://rpc.sacristy.local
VERIFIER ?= blockscout
VERIFIER_URL ?= http://api.blockscout.sacristy.local/api/

# Build wallet args: prefer PRIVATE_KEY if set, otherwise use MNEMONIC.
ifneq ($(PRIVATE_KEY),)
WALLET_ARGS = --private-key $(PRIVATE_KEY)
else
WALLET_ARGS = --mnemonics $(MNEMONIC) --mnemonic-indexes $(MNEMONIC_INDEX)
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
		OUTPUT=$$(forge script script/deploy/Deploy$(CONTRACT).s.sol --rpc-url $(RPC_URL) $(WALLET_ARGS) --broadcast 2>&1); \
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
	@echo ""
	@echo "Examples:"
	@echo "  make build"
	@echo "  make deploy"

.DEFAULT_GOAL := build
