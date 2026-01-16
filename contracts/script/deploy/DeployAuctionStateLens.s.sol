// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity ^0.8.0;

import { AuctionStateLens } from "../../src/lens/AuctionStateLens.sol";
import { WithCreateX } from "./WithCreateX.s.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Deploy the AuctionStateLens
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A script to deploy the `AuctionStateLens`.

  @custom:date January 14th, 2026.
*/
contract DeployAuctionStateLens is
  WithCreateX {

  /// Run the deploy script.
  function run () external {
    bytes32 _salt = vm.envBytes32("LENS_SALT");
    address _expectedAddress = vm.envAddress("LENS_EXPECTED_ADDRESS");

    Deployment[] memory _deployments = new Deployment[](1);
    _deployments[0] = Deployment({
      salt: _salt,
      expectedAddress: _expectedAddress,
      contractName: "AuctionStateLens",
      initCode: type(AuctionStateLens).creationCode
    });
    deploy(_deployments);
  }
}
