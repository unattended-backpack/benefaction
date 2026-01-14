// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity ^0.8.0;

import { AuctionStateLens } from "../../src/lens/AuctionStateLens.sol";
import { console2 } from "forge-std/console2.sol";
import { Script } from "forge-std/Script.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Deploy the AuctionStateLens
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A script to deploy the `AuctionStateLens`.

  @custom:date January 14th, 2026.
*/
contract DeployAuctionStateLens is
  Script {

  /// Run the deploy script.
  function run () external {
    vm.startBroadcast();
    AuctionStateLens _lens = new AuctionStateLens();
    vm.stopBroadcast();

    // Log the deployed addresses for Makefile parsing.
    console2.log("AuctionStateLens", address(_lens));
  }
}

