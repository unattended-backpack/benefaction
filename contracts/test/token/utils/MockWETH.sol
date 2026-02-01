// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { ERC20 } from "solady/tokens/ERC20.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Mock Wrapped Ether
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A mock WETH contract for testing purposes.

  @custom:date January 30th, 2026.
*/
contract MockWETH is
  ERC20 {

  /**
    Return the name of the token.

    @return _ The name of the token.
  */
  function name () public pure override returns (string memory) {
    return "Wrapped Ether";
  }

  /**
    Returns the symbol of the token.

    @return _ The symbol of the token.
  */
  function symbol () public pure override returns (string memory) {
    return "WETH";
  }

  /**
    Mint WETH to an address.

    @param _to The address to mint to.
    @param _amount The amount to mint.
  */
  function mint (
    address _to,
    uint256 _amount
  ) external {
    _mint(_to, _amount);
  }

  /// Deposit ETH to receive WETH.
  function deposit () external payable {
    _mint(msg.sender, msg.value);
  }

  /**
    Withdraw WETH to receive ETH.

    @param _amount The amount to withdraw.
  */
  function withdraw (
    uint256 _amount
  ) external {
    _burn(msg.sender, _amount);
    payable(msg.sender).transfer(_amount);
  }

  /// Allow receiving ETH.
  receive () external payable {
    _mint(msg.sender, msg.value);
  }
}

