// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity ^0.8.0;

import { Test20 } from "../../src/erc20/Test20.sol";
import { console2 } from "forge-std/console2.sol";
import { Script } from "forge-std/Script.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Deploy the ERC-20 token.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A script to deploy the ERC-20 token.

  @custom:date January 13th, 2026.
*/
contract DeployTest20 is
  Script {

  /// Run the deploy script.
  function run () external {
    vm.startBroadcast();
    Test20 _token = new Test20();
    vm.stopBroadcast();

    // Log the deployed addresses for Makefile parsing.
    console2.log("Test20", address(_token));
  }
}

