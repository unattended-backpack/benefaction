// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity ^0.8.0;

import { ContinuousClearingAuctionFactory } from
  "../../src/ContinuousClearingAuctionFactory.sol";
import { WithCreateX } from "./WithCreateX.s.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Deploy the ContinuousClearingAuctionFactory
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A script to deploy the `ContinuousClearingAuctionFactory`.

  @custom:date January 13th, 2026.
*/
contract DeployContinuousClearingAuctionFactory is
  WithCreateX {

  /// Run the deploy script.
  function run () external {
    bytes32 _salt = vm.envBytes32("FACTORY_SALT");
    address _expectedAddress = vm.envAddress("FACTORY_EXPECTED_ADDRESS");

    Deployment[] memory _deployments = new Deployment[](1);
    _deployments[0] = Deployment({
      salt: _salt,
      expectedAddress: _expectedAddress,
      contractName: "ContinuousClearingAuctionFactory",
      initCode: type(ContinuousClearingAuctionFactory).creationCode
    });
    deploy(_deployments);
  }
}
