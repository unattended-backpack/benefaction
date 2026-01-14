// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity ^0.8.0;

import { ContinuousClearingAuction } from
  "../../src/ContinuousClearingAuction.sol";
import { AuctionParameters } from
  "../../src/interfaces/IContinuousClearingAuction.sol";
import { console2 } from "forge-std/console2.sol";
import { Script } from "forge-std/Script.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Deploy the ContinuousClearingAuction
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A script to deploy the `ContinuousClearingAuction`.

  @custom:date January 13th, 2026.
*/
contract DeployContinuousClearingAuction is
  Script {

  /// The address of the token being sold in the auction.
  address constant TOKEN = 0x78E11d99b8f50C85b72bd4387a7D8f28C0CAbf2D;

  /// The total supply of the token being sold in the auction.
  uint128 constant AUCTION_SUPPLY = 500_000000_000000000000000000;

  /// Run the deploy script.
  function run () external {

    // Prepare the auction parameters.
    // Each step is packed as: abi.encodePacked(uint24 mps, uint40 blockDelta)
    // Constraint: sum(mps * blockDelta) must equal 1e7
    bytes memory _auctionSteps = abi.encodePacked(
      uint24(333), uint40(300),       // 333 * 300 = 99,900
      uint24(3297), uint40(2699),     // 3297 * 2699 = 8,898,603
      uint24(1001497), uint40(1)      // 1001497 * 1 = 1,001,497  (total: 10,000,000)
    );
    AuctionParameters memory _parameters = AuctionParameters({
      currency: 0x0000000000000000000000000000000000000000,
      tokensRecipient: TOKEN,
      fundsRecipient: TOKEN,
      startBlock: 300,
      endBlock: 3300,
      claimBlock: 6000,
      tickSpacing: 7937103036892840872925,
      validationHook: 0x0000000000000000000000000000000000000000,
      floorPrice: 79371030368928408729250,
      requiredCurrencyRaised: 10_000000000000000000,
      auctionStepsData: _auctionSteps
    });

    // Create the CCA.
    vm.startBroadcast();
    ContinuousClearingAuction _auction =
      new ContinuousClearingAuction(TOKEN, AUCTION_SUPPLY, _parameters);
    vm.stopBroadcast();

    // Log the deployed addresses for Makefile parsing.
    console2.log("ContinuousClearingAuction", address(_auction));
  }
}

