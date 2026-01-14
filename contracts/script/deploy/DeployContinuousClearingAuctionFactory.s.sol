// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity ^0.8.0;

import { ContinuousClearingAuctionFactory } from
  "../../src/ContinuousClearingAuctionFactory.sol";
import { console2 } from "forge-std/console2.sol";
import { Script } from "forge-std/Script.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Deploy the ContinuousClearingAuctionFactory
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A script to deploy the `ContinuousClearingAuctionFactory`.

  @custom:date January 13th, 2026.
*/
contract DeployContinuousClearingAuctionFactory is
  Script {

  /// Run the deploy script.
  function run () external {
    vm.startBroadcast();
    ContinuousClearingAuctionFactory _factory =
      new ContinuousClearingAuctionFactory();
    vm.stopBroadcast();

    // Log the deployed addresses for Makefile parsing.
    console2.log("ContinuousClearingAuctionFactory", address(_factory));
  }
}

