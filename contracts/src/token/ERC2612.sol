// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { IERC2612 } from "./interfaces/IERC2612.sol";
import { SignatureHelper } from "./SignatureHelper.sol";
import { ERC20 } from "solady/tokens/ERC20.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title An ERC-2612 implementation.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  This is an ERC-2612 implementation which extends the functionality of Solady
  to support smart contract signers for `permit` operations.

  @custom:date January 29th, 2026.
*/
abstract contract ERC2612 is
  IERC2612,
  ERC20,
  SignatureHelper {

  /**
    @custom:preserve

    The nonce slot of `owner` is given by:
    ```
    mstore(0x0c, _NONCES_SLOT_SEED)
    mstore(0x00, owner)
    let nonceSlot := keccak256(0x0c, 0x20)
    ```
  */
  uint256 private constant _NONCES_SLOT_SEED = 0x38377508;

  /**
    The EIP-712 typehash of the permit data.
    `keccak256("Permit(address owner,address spender,uint256 value,uint256
    nonce,uint256 deadline)")`.
  */
  bytes32 private constant _PERMIT_TYPEHASH =
    0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;

  /**
    @custom:preserve

    The allowance slot of (`owner`, `spender`) is given by:
    ```
    mstore(0x20, spender)
    mstore(0x0c, _ALLOWANCE_SLOT_SEED)
    mstore(0x00, owner)
    let allowanceSlot := keccak256(0x0c, 0x34)
    ```
  */
  uint256 private constant _ALLOWANCE_SLOT_SEED = 0x7f5e9f20;

  /**
    The ERC-20 approval event signature.
    `keccak256(bytes("Approval(address,address,uint256)"))`.
  */
  uint256 private constant _APPROVAL_EVENT_SIGNATURE =
    0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925;

  /**
    Returns the domain separator used in the encoding of the signature for
    `permit`, as defined by EIP-712.

    @return _ The EIP-712 domain separator.
  */
  function DOMAIN_SEPARATOR () public view virtual override(IERC2612, ERC20)
   returns (
    bytes32
  ) {
    return _domainSeparator();
  }

  /**
    Returns the current nonce for `_owner`. This value must be included whenever
    a signature is generated for `permit`.

    @param _owner The address to query the nonce for.

    @return _ The current nonce for `_owner`.
  */
  function nonces (
    address _owner
  ) public view virtual override(IERC2612, ERC20) returns (uint256) {
    return ERC20.nonces(_owner);
  }

  /**
    Use a valid signature by `_owner` to approve `_spender` to spend `_amount`
    tokens by `_deadline`.

    @param _owner The transfer authorizer's (payer's) address.
    @param _spender The approved spender.
    @param _amount The amount to be transferred.
    @param _deadline The maximum timestamp before which the authorized approval
      is valid.
    @param _signature The approval authorization signature.
  */
  function permit (
    address _owner,
    address _spender,
    uint256 _amount,
    uint256 _deadline,
    bytes memory _signature
  ) public {

    // Maintain the pre-existing allowance of Permit2.
    if (_givePermit2InfiniteAllowance()) {
      assembly ("memory-safe") {

        // If `spender == _PERMIT2 && value != type(uint256).max`.
        if iszero(or(xor(shr(96, shl(96, _spender)), _PERMIT2), iszero(not(
        _amount)))) {

          // `Permit2AllowanceIsFixedAtInfinity()`.
          mstore(0x00, 0x3f68539a)
          revert(0x1c, 0x04)
        }
      }
    }

    // Find the permit nonce storage slot and value.
    uint256 _nonceSlot;
    uint256 _nonce;
    assembly ("memory-safe") {

      /*
        Revert if the block timestamp is greater than `deadline`.
        `PermitExpired()`.
      */
      if gt(timestamp(), _deadline) {
        mstore(0x00, 0x1a15a3cc)
        revert(0x1c, 0x04)
      }

      // Clean the upper 96 bits of `_owner`.
      _owner := shr(96, shl(96, _owner))

      // Compute the owner's nonce slot and load its value.
      mstore(0x0c, _NONCES_SLOT_SEED)
      mstore(0x00, _owner)
      _nonceSlot := keccak256(0x0c, 0x20)
      _nonce := sload(_nonceSlot)

      // Increment and store the updated nonce.
      sstore(_nonceSlot, add(_nonce, 1))
    }

    /*
      Require a valid signature by `_owner` on the permit. This supports smart
      contract signers.
    */
    _requireValidSignature(
      _owner,
      keccak256(
        abi.encode(
          _PERMIT_TYPEHASH, _owner, _spender, _amount, _nonce, _deadline
        )
      ), _signature
    );

    // Since the signature has been verified as valid, we set the new allowance.
    assembly ("memory-safe") {

      // Clean the upper 96 bits of `_spender`.
      _spender := shr(96, shl(96, _spender))

      /*
        Compute the spender's allowance slot using scratch space only
        (0x00-0x3f) and store the spender's allowance.
      */
      mstore(0x20, _spender)
      mstore(0x0c, _ALLOWANCE_SLOT_SEED)
      mstore(0x00, _owner)
      sstore(keccak256(0x0c, 0x34), _amount)

      // Emit the approval event.
      mstore(0x00, _amount)
      log3(0x00, 0x20, _APPROVAL_EVENT_SIGNATURE, _owner, _spender)
    }
  }

  /**
    Use a valid signature by `_owner` to approve `_spender` to spend `_amount`
    tokens by `_deadline`. This function accepts an ECDSA signature split into
    its three component parts.

    @param _owner The transfer authorizer's (payer's) address.
    @param _spender The approved spender.
    @param _amount The amount to be transferred.
    @param _deadline The maximum timestamp before which the authorized approval
      is valid.
    @param _v The "v" component of the authorizer's signature.
    @param _r The "r" component of the authorizer's signature.
    @param _s The "s" component of the authorizer's signature.
  */
  function permit (
    address _owner,
    address _spender,
    uint256 _amount,
    uint256 _deadline,
    uint8 _v,
    bytes32 _r,
    bytes32 _s
  ) public virtual override(IERC2612, ERC20) {
    permit(_owner, _spender, _amount, _deadline, abi.encodePacked(_r, _s, _v));
  }
}

