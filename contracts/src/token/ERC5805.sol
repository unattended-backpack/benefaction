// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { IERC5805 } from "./interfaces/IERC5805.sol";
import { SignatureHelper } from "./SignatureHelper.sol";
import { ERC20 } from "solady/tokens/ERC20.sol";
import { ERC20Votes } from "solady/tokens/ERC20Votes.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title An ERC-5805 implementation.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  This is an ERC-5805 implementation which extends the functionality of Solady
  to support smart contract signers for `delegateBySig` operations.

  @custom:date January 30th, 2026.
*/
abstract contract ERC5805 is
  IERC5805,
  ERC20Votes,
  SignatureHelper {

  /// `keccak256("Delegation(address delegatee,uint256 nonce,uint256 expiry)")`.
  bytes32 private constant _ERC5805_DELEGATION_TYPEHASH =
    0xe48329057bfd03d55e49b547132e39cffd9c1820ad7b9d4c5307691425d15adf;

  /**
    Use a valid signature by `_delegator` to set the voting delegate of
    `_delegator` to `_delegatee`. This function supports smart contract signers.

    @param _delegator The delegator who has signed away voting power.
    @param _delegatee The delegatee receiving voting power.
    @param _nonce The signing delegator's nonce.
    @param _expiry The maximum timestamp before which the signatue is valid.
    @param _signature The delegation authorization signature.
  */
  function delegateBySig (
    address _delegator,
    address _delegatee,
    uint256 _nonce,
    uint256 _expiry,
    bytes memory _signature
  ) public {

    // Revert on expired signatures with `ERC5805DelegateSignatureExpired()`.
    assembly ("memory-safe") {
      if gt(timestamp(), _expiry) {
        mstore(0x00, 0x3480e9e1)
        revert(0x1c, 0x04)
      }
    }

    /*
      Validate then increment the signer's nonce.
      Revert with `ERC5805DelegateInvalidSignature()` if a nonce mismatches.
    */
    if (nonces(_delegator) != _nonce) {
      assembly ("memory-safe") {
        mstore(0x00, 0x1838d95c)
        revert(0x1c, 0x04)
      }
    }
    _incrementNonce(_delegator);

    /*
      Require a valid signature by `_delegator` on the permit. This supports
      smart contract signers.
    */
    _requireValidSignature(
      _delegator,
      keccak256(
        abi.encode(_ERC5805_DELEGATION_TYPEHASH, _delegatee, _nonce, _expiry)
      ), _signature
    );

    // Perform vote delegation.
    _delegate(_delegator, _delegatee);
  }

  /**
    Use a valid signature to set the voting delegate of `msg.sender` to
    `_delegatee`. This function accepts an ECDSA signature split into its three
    component parts.

    @param _delegatee The delegatee receiving voting power.
    @param _nonce The signing delegator's nonce.
    @param _expiry The maximum timestamp before which the signature is valid.
    @param _v The "v" component of the delegator's signature.
    @param _r The "r" component of the delegator's signature.
    @param _s The "s" component of the delegator's signature.
  */
  function delegateBySig (
    address _delegatee,
    uint256 _nonce,
    uint256 _expiry,
    uint8 _v,
    bytes32 _r,
    bytes32 _s
  ) public virtual override(IERC5805, ERC20Votes) {
    ERC20Votes.delegateBySig(_delegatee, _nonce, _expiry, _v, _r, _s);
  }

  /**
    Returns the machine-readable description of the clock mode.

    @return _ The clock mode description string.
  */
  function CLOCK_MODE ()
    public view virtual override(IERC5805, ERC20Votes) returns (string memory)
  {
    return ERC20Votes.CLOCK_MODE();
  }

  /**
    Returns the clock used for voting checkpoints.

    @return _ The current clock value.
  */
  function clock ()
    public view virtual override(IERC5805, ERC20Votes) returns (uint48)
  {
    return ERC20Votes.clock();
  }

  /**
    Returns the current voting power of `_account`.

    @param _account The address to query voting power for.

    @return _ The current voting power of `_account`.
  */
  function getVotes (
    address _account
  ) public view virtual override(IERC5805, ERC20Votes) returns (uint256) {
    return ERC20Votes.getVotes(_account);
  }

  /**
    Returns the total supply of votes available at the current timepoint.

    @return _ The total supply of votes.
  */
  function getVotesTotalSupply ()
    public view virtual override(IERC5805, ERC20Votes) returns (uint256)
  {
    return ERC20Votes.getVotesTotalSupply();
  }

  /**
    Returns the voting power of `_account` at a specific `_timepoint`.

    @param _account The address to query voting power for.
    @param _timepoint The historical timepoint to query.

    @return _ The voting power of `_account` at `_timepoint`.
  */
  function getPastVotes (
    address _account,
    uint256 _timepoint
  ) public view virtual override(IERC5805, ERC20Votes) returns (uint256) {
    return ERC20Votes.getPastVotes(_account, _timepoint);
  }

  /**
    Returns the total supply of votes available at a specific `_timepoint`.

    @param _timepoint The historical timepoint to query.

    @return _ The total supply of votes at `_timepoint`.
  */
  function getPastVotesTotalSupply (
    uint256 _timepoint
  ) public view virtual override(IERC5805, ERC20Votes) returns (uint256) {
    return ERC20Votes.getPastVotesTotalSupply(_timepoint);
  }

  /**
    Returns the delegate that `_account` has chosen.

    @param _account The address to query the delegate for.

    @return _ The address of the delegate for `_account`.
  */
  function delegates (
    address _account
  ) public view virtual override(IERC5805, ERC20Votes) returns (address) {
    return ERC20Votes.delegates(_account);
  }

  /**
    Returns the current nonce for `_owner`.

    @param _owner The address to query the nonce for.

    @return _ The current nonce for `_owner`.
  */
  function nonces (
    address _owner
  ) public view virtual override(IERC5805, ERC20) returns (uint256) {
    return ERC20.nonces(_owner);
  }

  /**
    Delegates the caller's voting power to `_delegatee`.

    @param _delegatee The address to delegate voting power to.
  */
  function delegate (
    address _delegatee
  ) public virtual override(IERC5805, ERC20Votes) {
    ERC20Votes.delegate(_delegatee);
  }
}

