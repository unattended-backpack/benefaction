// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { DelegateView } from "./DelegateView.sol";
import { ERC1363 } from "./ERC1363.sol";
import { ERC2612 } from "./ERC2612.sol";
import { ERC3009 } from "./ERC3009.sol";
import { ERC5805 } from "./ERC5805.sol";
import { EXTSLOAD } from "./EXTSLOAD.sol";
import { EXTTLOAD } from "./EXTTLOAD.sol";
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
  ERC1363,
  ERC2612,
  ERC3009,
  ERC5805,
  EXTSLOAD,
  EXTTLOAD,
  DelegateView {

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
    Return a constant hash of the token name to allow Solady to behave more
    optimally. This is set to `keccak256(bytes("Sigil"))`.

    @return _ The constant hash of the token name.
  */
  function _constantNameHash () internal pure override returns (bytes32) {
    return 0x186f3621aaa0f57aba0426c11019615813acda019a946a394416b38a82d50cdf;
  }

  /**
    Use a valid signature by `_owner` to approve `_spender` to spend `_amount`
    tokens by `_deadline`. This function accepts an ECDSA signature split into
    its three component parts. We are using our ERC-2612 implementation as
    override here in order to support a much wider range of acceptable
    signatures.

    @param _owner The transfer authorizer's (payer's) address.
    @param _spender The approved spender.
    @param _amount The amount to be transferred.
    @param _deadline The maximum timestamp before which the authorized approval
      is valid.
    @param _v The "v" component of the authorizer's signature.
    @param _r The "r" component of the authorizer's signature.
    @param _s The "s" component of the authorizer's signature.
  */
  function permit (
    address _owner,
    address _spender,
    uint256 _amount,
    uint256 _deadline,
    uint8 _v,
    bytes32 _r,
    bytes32 _s
  ) public override(ERC20, ERC2612) {
    ERC2612.permit(
      _owner, _spender, _amount, _deadline, abi.encodePacked(_r, _s, _v)
    );
  }

  /**
    Returns the current nonce for `_owner`. This value must be included whenever
    a signature is generated for `permit` or `delegateBySig`.

    @param _owner The address to query the nonce for.

    @return _ The current nonce for `_owner`.
  */
  function nonces (
    address _owner
  ) public view override(ERC20, ERC2612, ERC5805) returns (uint256) {
    return ERC20.nonces(_owner);
  }

  /**
    Returns the domain separator used in the encoding of the signature for
    `permit`, as defined by EIP-712.

    @return _ The EIP-712 domain separator.
  */
  function DOMAIN_SEPARATOR () public view override(ERC20, ERC2612) returns (
    bytes32
  ) {
    return _domainSeparator();
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

