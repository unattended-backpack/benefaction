// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { ERC3009 } from "./ERC3009.sol";
import { ISigil } from "./interfaces/ISigil.sol";
import { ERC20 } from "solady/tokens/ERC20.sol";
import { ERC20Votes } from "solady/tokens/ERC20Votes.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title The Sigil ERC-20 token.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  The Sigil ERC-20 token.

  @custom:date January 4th, 2026.
*/
contract Sigil is
  ISigil,
  ERC20Votes,
  ERC3009 {

  /**
    Construct a new instance of the Sigil token, minting the entire supply to
    `_recipient`.

    @param _recipient The recipient of the total token supply.
  */
  constructor (
    address _recipient
  ) {
    _mint(_recipient, 1000000000_000000000000000000);
  }

  /**
    Return the name of the token.

    @return _ The name of the token.
  */
  function name () public pure override(ISigil, ERC20) returns (
    string memory
  ) {
    return "Sigil";
  }

  /**
    Returns the symbol of the token.

    @return _ The symbol of the token.
  */
  function symbol () public pure override(ISigil, ERC20) returns (
    string memory
  ) {
    return "SIGIL";
  }

  /**
    Return the EIP-712 domain name and version.

    @return _ A tuple consisting of (the EIP-712 domain name, the EIP-712 domain
      version).
  */
  function _domainNameAndVersion () internal pure override returns (
    string memory, string memory
  ) {
    return ("Sigil", "1");
  }

  /**
    This is a hook called after any transfer of tokens, including mint or burn.
    In this case, owing to our multiple inheritance, we explicitly opt for the
    ERC-5805 behavior of `ERC20Votes`.

    @param _from The address where tokens are transferring from.
    @param _to The address where tokens are transferring to.
    @param _amount The amount of tokens transferred.
  */
  function _afterTokenTransfer (
    address _from,
    address _to,
    uint256 _amount
  ) internal override(ERC20, ERC20Votes) {
    ERC20Votes._afterTokenTransfer(_from, _to, _amount);
  }
}

