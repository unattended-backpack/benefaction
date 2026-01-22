// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { IERC3009 } from "./interfaces/IERC3009.sol";
import { ERC20 } from "solady/tokens/ERC20.sol";
import { EIP712 } from "solady/utils/EIP712.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title An implementation of ERC-3009.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  This is a simple extension of ERC-20 to support ERC-3009 signature-based
  transfers.

  @custom:date January 4th, 2026.
*/
abstract contract ERC3009 is
  IERC3009,
  ERC20,
  EIP712 {

  /**
    This is the EIP-712 typehash for transfers with authorization.

    keccak256("TransferWithAuthorization(address from,address to,uint256
    value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
  */
  bytes32 private constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH =
    0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267;

  /**
    This is the EIP-712 typehash for receiving authorized transfers.

    keccak256("ReceiveWithAuthorization(address from,address to,uint256
    value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
  */
  bytes32 private constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH =
    0xd099cc98ef71107a616c4f0f941f04c322d8e254fe26b3c6668db87aae413de8;

  /**
    This is the EIP-712 typehash for canceling an authorized transfer.

    keccak256("CancelAuthorization(address authorizer,bytes32 nonce)")
  */
  bytes32 private constant CANCEL_AUTHORIZATION_TYPEHASH =
    0x158b0a9edf7a828aad02f63cd515c68ef2f50ba807396f6d12842833a1597429;

  /**
    A double mapping from authorizer address to authorization nonce to whether
    or not the authorization nonce may still be used in a transfer.

    @custom:param _authorizer The address of an authorizer.
    @custom:param _nonce The nonce for a particular authorization.

    @custom:return _valid Whether or not the provided `_nonce` has been used for
      an authorized transfer or authorized cancel. If this is false, it means
      that `_nonce` can still be used for an authorized transfer.
  */
  mapping (
    address _authorizer => mapping (
      bytes32 _nonce => bool _valid
    )
  ) public authorizationState;

  /**
    Check that a given ERC-3009 authorization is valid.

    @param _authorizer The transfer authorizer's address.
    @param _nonce A unique nonce for this authorization.
    @param _validAfter The minimum timestamp after which the authorized transfer
      is valid.
    @param _validBefore The maximum timestamp before which the authorized
      transfer is valid.
  */
  function _requireValidAuthorization (
    address _authorizer,
    bytes32 _nonce,
    uint256 _validAfter,
    uint256 _validBefore
  ) private view {
    if (block.timestamp <= _validAfter) {
      revert AuthorizationNotYetValid();
    }

    if (block.timestamp >= _validBefore) {
      revert AuthorizationExpired();
    }

    if (authorizationState[_authorizer][_nonce]) {
      revert AuthorizationAlreadyUsed();
    }
  }

  /**
    Validate that a given `_signature` matches `_dataHash` as signed by
    `_signer`. This uses ERC-6492 signature validation to support counterfactual
    smart contract signers without persisting side effects.

    @param _signer The `_signer` address.
    @param _dataHash The EIP-712 encoded struct hash.
    @param _signature The signature from `_signer` to validate.
  */
  function _requireValidSignature (
    address _signer,
    bytes32 _dataHash,
    bytes memory _signature
  ) private {
    if (
      !SignatureCheckerLib.isValidERC6492SignatureNow(
        _signer, _hashTypedData(_dataHash), _signature
      )
    ) {
      revert InvalidSignature();
    }
  }

  /**
    Mark an authorization as used (or canceled).

    @param _authorizer The address of the authorizer.
    @param _nonce The authorization nonce.
  */
  function _markAuthorizationAsUsed (
    address _authorizer,
    bytes32 _nonce
  ) private {
    authorizationState[_authorizer][_nonce] = true;
    emit AuthorizationUsed(_authorizer, _nonce);
  }

  /**
    Execute a transfer with a signed authorization using a signature provided as
    combined bytes.

    @param _from The transfer authorizer's (payer's) address.
    @param _to The recipient's address.
    @param _amount The amount to be transferred.
    @param _validAfter The minimum timestamp after which the authorized transfer
      is valid.
    @param _validBefore The maximum timestamp before which the authorized
      transfer is valid.
    @param _nonce A unique nonce for this authorization.
    @param _signature The authorization signature.
  */
  function transferWithAuthorization (
    address _from,
    address _to,
    uint256 _amount,
    uint256 _validAfter,
    uint256 _validBefore,
    bytes32 _nonce,
    bytes memory _signature
  ) public {
    _requireValidAuthorization(_from, _nonce, _validAfter, _validBefore);
    _requireValidSignature(
      _from,
      keccak256(
        abi.encode(
          TRANSFER_WITH_AUTHORIZATION_TYPEHASH, _from, _to, _amount,
          _validAfter, _validBefore, _nonce
        )
      ), _signature
    );
    _markAuthorizationAsUsed(_from, _nonce);
    _transfer(_from, _to, _amount);
  }

  /**
    Execute a transfer with a signed authorization using a signature split into
    its three component parts.

    @param _from The transfer authorizer's (payer's) address.
    @param _to The recipient's address.
    @param _amount The amount to be transferred.
    @param _validAfter The minimum timestamp after which the authorized transfer
      is valid.
    @param _validBefore The maximum timestamp before which the authorized
      transfer is valid.
    @param _nonce A unique nonce for this authorization.
    @param _v The "v" component of the authorizer's signature.
    @param _r The "r" component of the authorizer's signature.
    @param _s The "s" component of the authorizer's signature.
  */
  function transferWithAuthorization (
    address _from,
    address _to,
    uint256 _amount,
    uint256 _validAfter,
    uint256 _validBefore,
    bytes32 _nonce,
    uint8 _v,
    bytes32 _r,
    bytes32 _s
  ) external {
    transferWithAuthorization(
      _from, _to, _amount, _validAfter, _validBefore, _nonce,
      abi.encodePacked(_r, _s, _v)
    );
  }

  /**
    Execute a transfer with a signed authorization using a signature provided as
    combined bytes. Only the `_to` recipient may be `msg.sender`.

    @param _from The transfer authorizer's (payer's) address.
    @param _to The recipient's address.
    @param _amount The amount to be transferred.
    @param _validAfter The minimum timestamp after which the authorized transfer
      is valid.
    @param _validBefore The maximum timestamp before which the authorized
      transfer is valid.
    @param _nonce A unique nonce for this authorization.
    @param _signature The authorization signature.
  */
  function receiveWithAuthorization (
    address _from,
    address _to,
    uint256 _amount,
    uint256 _validAfter,
    uint256 _validBefore,
    bytes32 _nonce,
    bytes memory _signature
  ) public {
    if (_to != msg.sender) {
      revert CallerMustBePayee();
    }
    _requireValidAuthorization(_from, _nonce, _validAfter, _validBefore);
    _requireValidSignature(
      _from,
      keccak256(
        abi.encode(
          RECEIVE_WITH_AUTHORIZATION_TYPEHASH, _from, _to, _amount, _validAfter,
          _validBefore, _nonce
        )
      ), _signature
    );
    _markAuthorizationAsUsed(_from, _nonce);
    _transfer(_from, _to, _amount);
  }

  /**
    Execute a transfer with a signed authorization using a signature split into
    its three component parts. Only the `_to` recipient may be `msg.sender`.

    @param _from The transfer authorizer's (payer's) address.
    @param _to The recipient's address.
    @param _amount The amount to be transferred.
    @param _validAfter The minimum timestamp after which the authorized transfer
      is valid.
    @param _validBefore The maximum timestamp before which the authorized
      transfer is valid.
    @param _nonce A unique nonce for this authorization.
    @param _v The "v" component of the authorizer's signature.
    @param _r The "r" component of the authorizer's signature.
    @param _s The "s" component of the authorizer's signature.
  */
  function receiveWithAuthorization (
    address _from,
    address _to,
    uint256 _amount,
    uint256 _validAfter,
    uint256 _validBefore,
    bytes32 _nonce,
    uint8 _v,
    bytes32 _r,
    bytes32 _s
  ) external {
    receiveWithAuthorization(
      _from, _to, _amount, _validAfter, _validBefore, _nonce,
      abi.encodePacked(_r, _s, _v)
    );
  }

  /**
    Attempt to cancel a signed authorization using a signature provided as
    combined bytes.

    @param _authorizer The transfer authorizer's (payer's) address.
    @param _nonce A unique nonce for this authorization.
    @param _signature The authorization signature.
  */
  function cancelAuthorization (
    address _authorizer,
    bytes32 _nonce,
    bytes memory _signature
  ) public {
    if (authorizationState[_authorizer][_nonce]) {
      revert AuthorizationAlreadyUsed();
    }
    _requireValidSignature(
      _authorizer,
      keccak256(abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, _authorizer, _nonce)),
      _signature
    );
    authorizationState[_authorizer][_nonce] = true;
    emit AuthorizationCanceled(_authorizer, _nonce);
  }

  /**
    Attempt to cancel a signed authorization using a signature split into its
    three component parts.

    @param _authorizer The transfer authorizer's (payer's) address.
    @param _nonce A unique nonce for this authorization.
    @param _v The "v" component of the authorizer's signature.
    @param _r The "r" component of the authorizer's signature.
    @param _s The "s" component of the authorizer's signature.
  */
  function cancelAuthorization (
    address _authorizer,
    bytes32 _nonce,
    uint8 _v,
    bytes32 _r,
    bytes32 _s
  ) external {
    cancelAuthorization(_authorizer, _nonce, abi.encodePacked(_r, _s, _v));
  }
}

