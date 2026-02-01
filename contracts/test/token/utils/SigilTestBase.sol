// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { MockWETH } from "./MockWETH.sol";
import { Test } from "forge-std/Test.sol";
import { Sigil } from "token/Sigil.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title SigilTestBase
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A base test contract that sets up the Sigil token with its ERC-4626
  initialization requirements. This deploys a mock WETH at the mainnet
  WETH address, then deploys and initializes Sigil.

  @custom:date January 30th, 2026.
*/
abstract contract SigilTestBase is
  Test {

  /// The mainnet WETH address that Sigil expects.
  address internal constant WETH_ADDRESS =
    0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;

  /// The amount of WETH required for initialization (1 nanoEther).
  uint256 internal constant INIT_WETH_AMOUNT = 1e9;

  /// The total supply of SIGIL tokens.
  uint256 internal constant TOTAL_SUPPLY = 1000000000_000000000000000000;

  /// The mock WETH contract.
  MockWETH public weth;

  /// The Sigil token.
  Sigil public token;

  /// Deploy and set up WETH and Sigil for testing.
  function _setUpSigil () internal {

    // Deploy MockWETH at the expected mainnet address.
    weth = new MockWETH();
    vm.etch(WETH_ADDRESS, address(weth).code);
    weth = MockWETH(payable(WETH_ADDRESS));

    // Deploy Sigil with this contract as owner.
    token = new Sigil(address(this));

    // Mint WETH to this contract and approve Sigil to spend it.
    weth.mint(address(this), INIT_WETH_AMOUNT);
    weth.approve(address(token), INIT_WETH_AMOUNT);

    // Initialize Sigil, minting all tokens to this contract.
    token.initialize(address(this));
  }
}

