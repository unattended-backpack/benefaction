// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity ^0.8.0;

import { ITest20 } from "../../src/erc20/interfaces/ITest20.sol";
import { IContinuousClearingAuction } from
  "../../src/interfaces/IContinuousClearingAuction.sol";
import { console2 } from "forge-std/console2.sol";
import { Script } from "forge-std/Script.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Prepare the CCA
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A script to mint tokens to the CCA contract.

  @custom:date January 13th, 2026.
*/
contract DeployTest20 is
  Script {

  /// The address of the CCA auction contract.
  address constant AUCTION = 0xd829E17ce5f942365EeB589C0F59e0C104BC5cA4;

  /// The address of the token being sold in the auction.
  address constant TOKEN = 0x78E11d99b8f50C85b72bd4387a7D8f28C0CAbf2D;

  /// The total supply of the token being sold in the auction.
  uint128 constant AUCTION_SUPPLY = 500_000000_000000000000000000;

  /// Run the deploy script.
  function run () external {
    vm.startBroadcast();
    ITest20 _token = ITest20(TOKEN);
    IContinuousClearingAuction _auction = IContinuousClearingAuction(AUCTION);

    // Send tokens to the auction.
    _token.mint(AUCTION, AUCTION_SUPPLY);
    _auction.onTokensReceived();
    vm.stopBroadcast();
  }
}

