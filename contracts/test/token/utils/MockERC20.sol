// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { ERC20 } from "solady/tokens/ERC20.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Mock ERC-20
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A mock ERC-20 contract for testing purposes.

  @custom:date February 3rd, 2026.
*/
contract MockERC20 is
  ERC20 {

  /// The token name.
  string private _name;

  /// The token symbol.
  string private _symbol;

  /// The token decimals.
  uint8 private _decimals;

  /**
    Construct a new mock token.

    @param _name_ The token name.
    @param _symbol_ The token symbol.
    @param _decimals_ The token decimals.
  */
  constructor (
    string memory _name_,
    string memory _symbol_,
    uint8 _decimals_
  ) {
    _name = _name_;
    _symbol = _symbol_;
    _decimals = _decimals_;
  }

  /**
    Return the name of the token.

    @return _ The name of the token.
  */
  function name () public view override returns (string memory) {
    return _name;
  }

  /**
    Returns the symbol of the token.

    @return _ The symbol of the token.
  */
  function symbol () public view override returns (string memory) {
    return _symbol;
  }

  /**
    Returns the number of decimals of the token.

    @return _ The number of decimals.
  */
  function decimals () public view override returns (uint8) {
    return _decimals;
  }

  /**
    Mint tokens to an address.

    @param _to The address to mint to.
    @param _amount The amount to mint.
  */
  function mint (
    address _to,
    uint256 _amount
  ) external {
    _mint(_to, _amount);
  }
}

