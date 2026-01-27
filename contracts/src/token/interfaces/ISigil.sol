// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Sigil Interface
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  The interface for the Sigil ERC-20 contract.

  @custom:date January 4th, 2026.
*/
interface ISigil {

  /**
    Return the name of the token.

    @return _ The name of the token.
  */
  function name () external pure returns (string memory);

  /**
    Returns the symbol of the token.

    @return _ The symbol of the token.
  */
  function symbol () external pure returns (string memory);
}

