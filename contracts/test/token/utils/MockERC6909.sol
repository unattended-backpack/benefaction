// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { ERC6909 } from "solady/tokens/ERC6909.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Mock ERC-6909
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A mock ERC-6909 contract for testing purposes.

  @custom:date February 3rd, 2026.
*/
contract MockERC6909 is
  ERC6909 {

  /**
    Returns the name for a given token ID.

    @return _ The token name.
  */
  function name (
    uint256
  ) public pure override returns (string memory) {
    return "Mock ERC6909";
  }

  /**
    Returns the symbol for a given token ID.

    @return _ The token symbol.
  */
  function symbol (
    uint256
  ) public pure override returns (string memory) {
    return "M6909";
  }

  /**
    Returns the URI for a given token ID.

    @return _ The token URI.
  */
  function tokenURI (
    uint256
  ) public pure override returns (string memory) {
    return "";
  }

  /**
    Mint tokens to an address.

    @param _to The address to mint to.
    @param _id The token ID to mint.
    @param _amount The amount to mint.
  */
  function mint (
    address _to,
    uint256 _id,
    uint256 _amount
  ) external {
    _mint(_to, _id, _amount);
  }
}

