// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity ^0.8.0;

import { ICreateX } from "createx/ICreateX.sol";
import { WithSigner } from "./WithSigner.sol";
import { console2 } from "forge-std/console2.sol";

/**
  This error is emitted if an expected deployment address is incorrect.

  @param contractName The incorrect contract name.
  @param expected The expected address.
  @param actual The actual address.
*/
error UnexpectedAddress (
  string contractName,
  address expected,
  address actual
);

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title A forge helper script for CreateX deployment.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  This script supports easily specifying CreateX salts and output addresses for
  deploying contracts.

  @custom:date January 16th, 2026.
*/
contract WithCreateX is
  WithSigner {

  /**
    A struct encoding the details of a contract deployment via CreateX.

    @param salt The salt used to determine the contract address.
    @param expectedAddress The expected address of the deployed contract.
    @param contractName The name of the contract being deployed.
    @param initCode The contract creation bytecode.
  */
  struct Deployment {
    bytes32 salt;
    address expectedAddress;
    string contractName;
    bytes initCode;
  }

  /// The canonical CreateX factory address.
  address public constant CREATEX = 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed;

  /**
    Deploy one or more contracts via CreateX.

    @param _deployments An array of deployment configurations.
  */
  function _deploy (
    Deployment[] memory _deployments
  ) private {

    // Log environment details.
    console2.log("Environment ...");
    console2.log("  - CREATEX: %s", CREATEX);
    console2.log("  - DEPLOYER: %s", signer);
    for (uint256 i = 0; i < _deployments.length; i++) {
      console2.log("  - %s:", _deployments[i].contractName);
      console2.log("    - EXPECTED: %s", _deployments[i].expectedAddress);
      console2.log("    - SALT:");
      console2.logBytes32(_deployments[i].salt);
    }
    console2.log("--------------------------------");

    // Deploy the contracts.
    console2.log("Runtime ...");
    for (uint256 i = 0; i < _deployments.length; i++) {
      Deployment memory _d = _deployments[i];
      address _address = ICreateX(CREATEX).deployCreate3(_d.salt, _d.initCode);
      console2.log("  - %s: %s", _d.contractName, _address);
      if (_address != _d.expectedAddress) {
        revert UnexpectedAddress(_d.contractName, _d.expectedAddress, _address);
      }

      // Log the deployed address for Makefile parsing.
      console2.log(_d.contractName, _address);
    }
  }

  /**
    Deploy one or more contracts via CreateX using no signer. The caller is
    expected to bring its own broadcasting context.

    @param _deployments An array of deployment configurations.
  */
  function deployNaked (
    Deployment[] memory _deployments
  ) internal {
    _deploy(_deployments);
  }

  /**
    Deploy one or more contracts via CreateX using the environment signer.

    @param _deployments An array of deployment configurations.
  */
  function deploy (
    Deployment[] memory _deployments
  ) internal withSigner {
    _deploy(_deployments);
  }

  /**
    Deploy one or more contracts via CreateX using the environment signer with
    mnemonic account index.

    @param _index The mnemonic account index to deploy with.
    @param _deployments An array of deployment configurations.
  */
  function deploy (
    uint32 _index,
    Deployment[] memory _deployments
  ) internal withSignerIndex(_index) {
    _deploy(_deployments);
  }
}

