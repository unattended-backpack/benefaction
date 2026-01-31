// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title An ERC-5805 Interface
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  This is an ERC-5805 implementation which extends the functionality of Solady
  to support smart contract signers for `delegateBySig` operations.

  @custom:date January 30th, 2026.
*/
interface IERC5805 {

  /**
    Returns the machine-readable description of the clock mode, as specified in
    EIP-6372.

    @return _ The clock mode description string.
  */
  function CLOCK_MODE () external view returns (string memory);

  /**
    Returns the clock used for voting checkpoints. This is used to determine the
    timepoint at which voting power is queried.

    @return _ The current clock value (block number or timestamp).
  */
  function clock () external view returns (uint48);

  /**
    Returns the current voting power of `_account`.

    @param _account The address to query voting power for.

    @return _ The current voting power of `_account`.
  */
  function getVotes (
    address _account
  ) external view returns (uint256);

  /**
    Returns the total supply of votes available at the current timepoint.

    @return _ The total supply of votes.
  */
  function getVotesTotalSupply () external view returns (uint256);

  /**
    Returns the voting power of `_account` at a specific `_timepoint` in the
    past. The `_timepoint` must be in the past according to the token's clock.

    @param _account The address to query voting power for.
    @param _timepoint The historical timepoint to query.

    @return _ The voting power of `_account` at `_timepoint`.
  */
  function getPastVotes (
    address _account,
    uint256 _timepoint
  ) external view returns (uint256);

  /**
    Returns the total supply of votes available at a specific `_timepoint` in
    the past. The `_timepoint` must be in the past according to the token's
    clock.

    @param _timepoint The historical timepoint to query.

    @return _ The total supply of votes at `_timepoint`.
  */
  function getPastVotesTotalSupply (
    uint256 _timepoint
  ) external view returns (uint256);

  /**
    Returns the delegate that `_account` has chosen.

    @param _account The address to query the delegate for.

    @return _ The address of the delegate for `_account`.
  */
  function delegates (
    address _account
  ) external view returns (address);

  /**
    Returns the current nonce for `_owner`. This value must be included whenever
    a signature is generated for `delegateBySig`.

    @param _owner The address to query the nonce for.

    @return _ The current nonce for `_owner`.
  */
  function nonces (
    address _owner
  ) external view returns (uint256);

  /**
    Delegates the caller's voting power to `_delegatee`.

    @param _delegatee The address to delegate voting power to.
  */
  function delegate (
    address _delegatee
  ) external;

  /**
    Use a valid signature by `_delegator` to set the voting delegate of
    `_delegator` to `_delegatee`. This function supports smart contract signers.

    @param _delegator The delegator who has signed away voting power.
    @param _delegatee The delegatee receiving voting power.
    @param _nonce The signing delegator's nonce.
    @param _expiry The maximum timestamp before which the signature is valid.
    @param _signature The delegation authorization signature.
  */
  function delegateBySig (
    address _delegator,
    address _delegatee,
    uint256 _nonce,
    uint256 _expiry,
    bytes memory _signature
  ) external;

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
  ) external;
}

