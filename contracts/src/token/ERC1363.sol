// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { IERC1363 } from "./interfaces/IERC1363.sol";
import { IERC1363Receiver } from "./interfaces/IERC1363Receiver.sol";
import { IERC1363Spender } from "./interfaces/IERC1363Spender.sol";
import { ERC20 } from "solady/tokens/ERC20.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title An ERC-1363 implementation.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  An implementation of ERC-1363 that extends ERC-20 to add `transferAndCall`,
  `transferFromAndCall`, and `approveAndCall` functions which notify recipient
  contracts via hooks.

  @custom:date January 28th, 2026.
*/
abstract contract ERC1363 is
  ERC20,
  IERC1363 {

  /// The ERC-165 interface ID for ERC-165 itself.
  bytes4 private constant ERC165_INTERFACE_ID = 0x01ffc9a7;

  /// The ERC-165 interface ID for ERC-1363.
  bytes4 private constant ERC1363_INTERFACE_ID = 0xb0202a11;

  /**
    Return whether this contract supports a given interface.

    @param _interfaceId The interface identifier to check.

    @return _ Whether the interface is supported.
  */
  function supportsInterface (
    bytes4 _interfaceId
  ) public view virtual returns (bool) {
    return _interfaceId == ERC165_INTERFACE_ID
    || _interfaceId == ERC1363_INTERFACE_ID;
  }

  /**
    Call `onTransferReceived` on `_to` and verify it returns the expected
    selector.

    @param _operator The address that initiated the transfer.
    @param _from The address the tokens are transferred from.
    @param _to The address the tokens are transferred to.
    @param _value The amount of tokens transferred.
    @param _data Additional data to pass to the receiver.
  */
  function _checkOnTransferReceived (
    address _operator,
    address _from,
    address _to,
    uint256 _value,
    bytes memory _data
  ) private {
    if (_to.code.length == 0) {
      revert EmptyTarget();
    }

    // Revert if the target could not handle the transfer and bubble up errors.
    try IERC1363Receiver(_to).onTransferReceived(
      _operator, _from, _value, _data
    ) returns (bytes4 _retval) {
      if (_retval != IERC1363Receiver.onTransferReceived.selector) {
        revert InvalidReceiver();
      }
    } catch (bytes memory _reason) {
      if (_reason.length == 0) {
        revert InvalidReceiver();
      } else {
        assembly ("memory-safe") {
          revert(add(_reason, 0x20), mload(_reason))
        }
      }
    }
  }

  /**
    Transfer tokens to `_to` and then call `onTransferReceived` on `_to` with
    additional data.

    @param _to The recipient of the transfer.
    @param _value The amount of tokens to transfer.
    @param _data Additional data to pass to the receiver.

    @return _ Whether the operation succeeded.
  */
  function transferAndCall (
    address _to,
    uint256 _value,
    bytes memory _data
  ) public returns (bool) {
    transfer(_to, _value);
    _checkOnTransferReceived(msg.sender, msg.sender, _to, _value, _data);
    return true;
  }

  /**
    Transfer tokens to `_to` and then call `onTransferReceived` on `_to`.

    @param _to The recipient of the transfer.
    @param _value The amount of tokens to transfer.

    @return _ Whether the operation succeeded.
  */
  function transferAndCall (
    address _to,
    uint256 _value
  ) public returns (bool) {
    return transferAndCall(_to, _value, "");
  }

  /**
    Transfer tokens from `_from` to `_to` using the caller's allowance, then
    call `onTransferReceived` on `_to` with additional data.

    @param _from The sender of the tokens.
    @param _to The recipient of the transfer.
    @param _value The amount of tokens to transfer.
    @param _data Additional data to pass to the receiver.

    @return _ Whether the operation succeeded.
  */
  function transferFromAndCall (
    address _from,
    address _to,
    uint256 _value,
    bytes memory _data
  ) public returns (bool) {
    transferFrom(_from, _to, _value);
    _checkOnTransferReceived(msg.sender, _from, _to, _value, _data);
    return true;
  }

  /**
    Transfer tokens from `_from` to `_to` using the caller's allowance, then
    call `onTransferReceived` on `_to`.

    @param _from The sender of the tokens.
    @param _to The recipient of the transfer.
    @param _value The amount of tokens to transfer.

    @return _ Whether the operation succeeded.
  */
  function transferFromAndCall (
    address _from,
    address _to,
    uint256 _value
  ) public returns (bool) {
    return transferFromAndCall(_from, _to, _value, "");
  }

  /**
    Call `onApprovalReceived` on `_spender` and verify it returns the expected
    selector.

    @param _spender The address that was approved.
    @param _value The amount of tokens approved.
    @param _data Additional data to pass to the spender.
  */
  function _checkOnApprovalReceived (
    address _spender,
    uint256 _value,
    bytes memory _data
  ) private {
    if (_spender.code.length == 0) {
      revert EmptyTarget();
    }

    // Revert if the target could not handle the approval and bubble up errors.
    try IERC1363Spender(_spender).onApprovalReceived(
      msg.sender, _value, _data
    ) returns (bytes4 _retval) {
      if (_retval != IERC1363Spender.onApprovalReceived.selector) {
        revert InvalidSpender();
      }
    } catch (bytes memory _reason) {
      if (_reason.length == 0) {
        revert InvalidSpender();
      } else {
        assembly ("memory-safe") {
          revert(add(_reason, 0x20), mload(_reason))
        }
      }
    }
  }

  /**
    Approve `_spender` to spend `_value` tokens on behalf of the caller, then
    call `onApprovalReceived` on `_spender` with additional data.

    @param _spender The address to approve.
    @param _value The amount of tokens to approve.
    @param _data Additional data to pass to the spender.

    @return _ Whether the operation succeeded.
  */
  function approveAndCall (
    address _spender,
    uint256 _value,
    bytes memory _data
  ) public returns (bool) {
    approve(_spender, _value);
    _checkOnApprovalReceived(_spender, _value, _data);
    return true;
  }

  /**
    Approve `_spender` to spend `_value` tokens on behalf of the caller, then
    call `onApprovalReceived` on `_spender`.

    @param _spender The address to approve.
    @param _value The amount of tokens to approve.

    @return _ Whether the operation succeeded.
  */
  function approveAndCall (
    address _spender,
    uint256 _value
  ) public returns (bool) {
    return approveAndCall(_spender, _value, "");
  }
}

