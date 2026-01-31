// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title An ERC-1363 Receiver Interface
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  The interface for contracts that want to receive ERC-1363 `transferAndCall` or
  `transferFromAndCall` notifications.

  @custom:date January 28th, 2026.
*/
interface IERC1363Receiver {

  /**
    Handle the receipt of ERC-1363 tokens. This function is called when tokens
    are transferred to this contract via `transferAndCall` or
    `transferFromAndCall`. To accept the transfer, return the function selector
    `bytes4(keccak256("onTransferReceived(address,address,uint256,bytes)"))`.
    Any other return value or revert will cause the transfer to revert.

    @param _operator The address that initiated the transfer (the caller of
      `transferAndCall` or `transferFromAndCall`).
    @param _from The address the tokens are transferred from.
    @param _value The amount of tokens transferred.
    @param _data Additional data with no specified format.

    @return _ The function selector if the transfer is accepted.
  */
  function onTransferReceived (
    address _operator,
    address _from,
    uint256 _value,
    bytes calldata _data
  ) external returns (bytes4);
}

