// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity ^0.8.0;

import { WithCreateX } from "../util/WithCreateX.sol";
import { Sigil } from "token/Sigil.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Deploy the Sigil token.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A script to deploy the Sigil ERC-20 token.

  @custom:date January 13th, 2026.
*/
contract DeploySigil is
  WithCreateX {

  /// Run the deploy script.
  function run () external {
    bytes32 _salt = vm.envBytes32("TOKEN_SALT");
    address _expectedAddress = vm.envAddress("TOKEN_EXPECTED_ADDRESS");
    address _recipient = vm.envAddress("TOKEN_RECIPIENT");
    Deployment[] memory _deployments = new Deployment[](1);
    _deployments[0] = Deployment({
      salt: _salt,
      expectedAddress: _expectedAddress,
      contractName: "Sigil",
      initCode: abi.encodePacked(
        type(Sigil).creationCode, abi.encode(_recipient)
      )
    });
    deploy(_deployments);
  }
}

