// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title A mock ERC-1271 signer for testing.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  This mock contract implements ERC-1271 signature validation. It has an owner
  EOA and validates signatures against that owner's key.

  @custom:date January 21st, 2026.
*/
contract MockERC1271Signer {

  /// The ERC-1271 magic value returned when a signature is valid.
  bytes4 public constant ERC1271_MAGIC_VALUE = 0x1626ba7e;

  /// The address of the owner whose signatures are considered valid.
  address public immutable owner;

  /**
    Construct a new mock ERC-1271 signer with a designated owner.

    @param _owner The address of the owner whose signatures will be validated.
  */
  constructor (
    address _owner
  ) {
    owner = _owner;
  }

  /**
    Validate a signature per ERC-1271. Returns the magic value if the signature
    is from the owner, otherwise returns an invalid value.

    @param _hash The hash that was signed.
    @param _signature The signature to validate.

    @return _ The ERC-1271 magic value if valid, otherwise `0xffffffff`.
  */
  function isValidSignature (
    bytes32 _hash,
    bytes memory _signature
  ) external view returns (bytes4) {
    if (SignatureCheckerLib.isValidSignatureNow(owner, _hash, _signature)) {
      return ERC1271_MAGIC_VALUE;
    }
    return 0xffffffff;
  }
}

