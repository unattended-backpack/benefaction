// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title DelegateView Interface
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  This is a base contract whose functions allow external callers to craft their
  own contracts for querying state via reverting DELEGATECALLs.

  @custom:date January 28th, 2026.
*/
interface IDelegateView {

  /**
    Allow external callers to craft their own views into this contract by
    providing raw query contract bytecode. The bytecode is deployed via CREATE,
    called, and then the entire execution reverts so that nothing persists.

    @param _code The creation bytecode of the query contract.
    @param _data The calldata for the reverting DELEGATECALL on the query.
  */
  function delegateviewRevert (
    bytes calldata _code,
    bytes calldata _data
  ) external;

  /**
    Allow external callers to craft their own views into this contract by
    providing raw query contract bytecode. This function uses the underlying
    bytecode `delegateviewRevert` function but decodes the view data for easier
    consumption.

    @param _code The creation bytecode of the query contract.
    @param _data The calldata for the DELEGATECALL on the deployed query.

    @return _ A tuple consisting of (whether or not the DELEGATECALL succeeded,
      and the result of the call).
  */
  function delegateview (
    bytes calldata _code,
    bytes calldata _data
  ) external returns (bool, bytes memory);

  /**
    Allow external callers to craft their own views into this contract. This
    function is guaranteed to revert, which is why the use of DELEGATECALL is
    safe.

    @param _query The address of a view query contract.
    @param _data The calldata for the reverting DELEGATECALL on the query.
  */
  function delegateviewRevert (
    address _query,
    bytes calldata _data
  ) external;

  /**
    Allow external callers to craft their own views into this contract. This
    function uses the underlying `delegateviewRevert` function but decodes the
    view data for easier consumption.

    @param _query The address of a view query contract.
    @param _data The calldata for the reverting DELEGATECALL on the query.

    @return _ A tuple consisting of (whether or not the DELEGATECALL succeeded,
      and the result of the call).
  */
  function delegateview (
    address _query,
    bytes calldata _data
  ) external returns (bool, bytes memory);

  /*
    @custom:preserve

    This fallback routes unrecognized calls to a query contract specified as
    the first argument in the calldata. This allows external callers to interact
    with query contracts as if their view functions lived directly on this
    contract.

    The query contract address is extracted from the first ABI-encoded argument.
    Query contract functions should accept the query contract address as their
    first parameter and ignore it, since it is only used for routing.

    function myQuery (
      address,
      address _user
    ) external view returns (uint256);

    Callers can then invoke their queries like so.
 
    IMyQuery(address(this)).myQuery(queryAddr, user);
  */
  fallback () external;
}
