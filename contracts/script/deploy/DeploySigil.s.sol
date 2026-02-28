// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity ^0.8.0;

import { WithCreateX } from "../util/WithCreateX.sol";
import { IERC20 } from "forge-std/interfaces/IERC20.sol";
import { ZKMintVerifier } from
  "token/zk_mint/ZKMintVerifier.sol";
import { Poseidon2 } from
  "token/zk_mint/Poseidon2.sol";
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
  function run () external withSigner {
    bytes32 _poseidon2Salt = vm.envBytes32("POSEIDON2_SALT");
    address _poseidon2Expected = vm.envAddress("POSEIDON2_EXPECTED_ADDRESS");
    bytes32 _verifierSalt = vm.envBytes32("VERIFIER_SALT");
    address _verifierExpected = vm.envAddress("VERIFIER_EXPECTED_ADDRESS");
    bytes32 _tokenSalt = vm.envBytes32("TOKEN_SALT");
    address _tokenExpected = vm.envAddress("TOKEN_EXPECTED_ADDRESS");
    address _recipient = vm.envAddress("TOKEN_RECIPIENT");

    // Deploy the Poseidon hasher, the proof verifier, and the token.
    Deployment[] memory _deployments = new Deployment[](3);
    _deployments[0] = Deployment({
      salt: _poseidon2Salt,
      expectedAddress: _poseidon2Expected,
      contractName: "Poseidon2",
      initCode: type(Poseidon2).creationCode
    });
    _deployments[1] = Deployment({
      salt: _verifierSalt,
      expectedAddress: _verifierExpected,
      contractName: "ZKMintVerifier",
      initCode: type(ZKMintVerifier).creationCode
    });
    _deployments[2] = Deployment({
      salt: _tokenSalt,
      expectedAddress: _tokenExpected,
      contractName: "Sigil",
      initCode: abi.encodePacked(
        type(Sigil).creationCode,
        abi.encode(
          signer, _verifierExpected, _poseidon2Expected,
          1 days, uint256(100), 1_000_000e18
        )
      )
    });
    deployNaked(_deployments);

    // Approve the token's ERC-4626 asset and initialize.
    IERC20(Sigil(_tokenExpected).asset()).approve(
      _tokenExpected, type(uint256).max
    );
    Sigil(_tokenExpected).initialize(_recipient);
  }
}

