// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title An ERC-1363 Spender Interface
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  The interface for contracts that want to receive ERC-1363 `approveAndCall`
  notifications.

  @custom:date January 28th, 2026.
*/
interface IERC1363Spender {

  /**
    Handle approval of ERC-1363 tokens. This function is called when this
    contract is approved to spend tokens via `approveAndCall`. To accept the
    approval, return the function selector
    `bytes4(keccak256("onApprovalReceived(address,uint256,bytes)"))`. Any other
    return value or revert will cause the approval to revert.

    @param _owner The address that approved the tokens.
    @param _value The amount of tokens approved.
    @param _data Additional data with no specified format.

    @return _ The function selector if the approval is accepted.
  */
  function onApprovalReceived (
    address _owner,
    uint256 _value,
    bytes calldata _data
  ) external returns (bytes4);
}

