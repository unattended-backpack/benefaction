// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { ISignatureHelper } from "./interfaces/ISignatureHelper.sol";
import { EIP712 } from "solady/utils/EIP712.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title A simple signature verification helper.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  This is a simple signature helper which exposes a function to easily use the
  SignatureCheckerLib.

  @custom:date January 30th, 2026.
*/
abstract contract SignatureHelper is
  ISignatureHelper,
  EIP712 {

  /**
    Validate that a given `_signature` matches `_dataHash` as signed by
    `_signer`. This uses ERC-6492 signature validation to support counterfactual
    smart contract signers without persisting side effects. This function in the
    SignatureCheckerLib gracefully attempts to use other signature options as
    well; it is the closest to a universal signer.

    @param _signer The `_signer` address.
    @param _dataHash The EIP-712 encoded struct hash.
    @param _signature The signature from `_signer` to validate.
  */
  function _requireValidSignature (
    address _signer,
    bytes32 _dataHash,
    bytes memory _signature
  ) internal {
    if (
      !SignatureCheckerLib.isValidERC6492SignatureNow(
        _signer, _hashTypedData(_dataHash), _signature
      )
    ) {
      revert InvalidSignature();
    }
  }
}

