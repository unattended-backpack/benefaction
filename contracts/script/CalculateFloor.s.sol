// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity ^0.8.0;

import { console2 } from "forge-std/console2.sol";
import { Script } from "forge-std/Script.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Calculate a CCA floor price.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A script to calculate a CCA floor price based on a given Ether price and token price in dollars.

  @custom:date January 16th, 2026.
*/
contract CalculateFloor is
  Script {

  /// The price of Ether with six decimal places.
  uint256 private constant ETHER_PRICE = 3194_240000;

  /// The price of the token with six decimal places.
  uint256 private constant TOKEN_PRICE = 3200;

  /// Run the script.
  function run () external pure {
    uint256 _floorPrice = (2 ** 96) / (ETHER_PRICE / TOKEN_PRICE);
    console2.log("floor price", _floorPrice);
  }
}

