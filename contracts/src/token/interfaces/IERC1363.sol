// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title An ERC-1363 Interface
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  An implementation of ERC-1363 that extends ERC-20 to add `transferAndCall`,
  `transferFromAndCall`, and `approveAndCall` functions which notify recipient
  contracts via hooks.

  @custom:date January 28th, 2026.
*/
interface IERC1363 {

  /// An error emitted if the target of a transfer or approval has no code.
  error EmptyTarget ();

  /// An error emitted if a receiver does not return the expected selector.
  error InvalidReceiver ();

  /// An error emitted if a spender does not return the expected selector.
  error InvalidSpender ();

  /**
    Return whether this contract supports a given interface.

    @param _interfaceId The interface identifier to check.

    @return _ Whether the interface is supported.
  */
  function supportsInterface (
    bytes4 _interfaceId
  ) external view returns (bool);

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
  ) external returns (bool);

  /**
    Transfer tokens to `_to` and then call `onTransferReceived` on `_to`.

    @param _to The recipient of the transfer.
    @param _value The amount of tokens to transfer.

    @return _ Whether the operation succeeded.
  */
  function transferAndCall (
    address _to,
    uint256 _value
  ) external returns (bool);

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
  ) external returns (bool);

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
  ) external returns (bool);

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
  ) external returns (bool);

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
  ) external returns (bool);
}

