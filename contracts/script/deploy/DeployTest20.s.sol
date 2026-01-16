// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity ^0.8.0;

import { Test20 } from "../../src/erc20/Test20.sol";
import { WithCreateX } from "./WithCreateX.s.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Deploy the ERC-20 token.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A script to deploy the ERC-20 token.

  @custom:date January 13th, 2026.
*/
contract DeployTest20 is
  WithCreateX {

  /// Run the deploy script.
  function run () external {
    bytes32 _salt = vm.envBytes32("TOKEN_SALT");
    address _expectedAddress = vm.envAddress("TOKEN_EXPECTED_ADDRESS");

    Deployment[] memory _deployments = new Deployment[](1);
    _deployments[0] = Deployment({
      salt: _salt,
      expectedAddress: _expectedAddress,
      contractName: "Test20",
      initCode: type(Test20).creationCode
    });
    deploy(_deployments);
  }
}
