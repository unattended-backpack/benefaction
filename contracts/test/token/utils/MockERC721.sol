// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { ERC721 } from "solady/tokens/ERC721.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Mock ERC-721
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A mock ERC-721 contract for testing purposes.

  @custom:date February 3rd, 2026.
*/
contract MockERC721 is
  ERC721 {

  /**
    Return the name of the token.

    @return _ The name of the token.
  */
  function name () public pure override returns (string memory) {
    return "Mock NFT";
  }

  /**
    Returns the symbol of the token.

    @return _ The symbol of the token.
  */
  function symbol () public pure override returns (string memory) {
    return "MNFT";
  }

  /**
    Returns the token URI for a given token ID.

    @return _ The token URI.
  */
  function tokenURI (
    uint256
  ) public pure override returns (string memory) {
    return "";
  }

  /**
    Mint an NFT to an address.

    @param _to The address to mint to.
    @param _tokenId The token ID to mint.
  */
  function mint (
    address _to,
    uint256 _tokenId
  ) external {
    _mint(_to, _tokenId);
  }
}

