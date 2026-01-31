// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { IDelegateView } from "./interfaces/IDelegateView.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title DelegateView
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  This is a base contract whose functions allow external callers to craft their
  own contracts for querying state via reverting DELEGATECALLs.

  @custom:date January 28th, 2026.
*/
contract DelegateView is
  IDelegateView {

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
  ) public {
    address _query;
    bytes memory _codeMemory = _code;
    assembly ("memory-safe") {
      _query := create(0, add(_codeMemory, 0x20), mload(_codeMemory))
    }
    (bool _success, bytes memory _result) = _query.delegatecall(_data);
    bytes memory _encoded = abi.encode(_success, _result);
    assembly ("memory-safe") {
      revert(add(_encoded, 0x20), mload(_encoded))
    }
  }

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
  ) public returns (bool, bytes memory) {
    (bool _success, bytes memory _result) = address(this).call(
      abi.encodeWithSignature("delegateviewRevert(bytes,bytes)", _code, _data)
    );
    assert(!_success);
    return abi.decode(_result, (bool, bytes));
  }

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
  ) public {
    (bool _success, bytes memory _result) = _query.delegatecall(_data);
    bytes memory _encoded = abi.encode(_success, _result);
    assembly ("memory-safe") {
      revert(add(_encoded, 0x20), mload(_encoded))
    }
  }

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
  ) public returns (bool, bytes memory) {
    (bool _success, bytes memory _result) = address(this).call(
      abi.encodeWithSignature(
        "delegateviewRevert(address,bytes)", _query, _data
      )
    );
    assert(!_success);
    return abi.decode(_result, (bool, bytes));
  }

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
  fallback () external {
    address _query = abi.decode(msg.data[4:], (address));
    (bool _innerSuccess, bytes memory _innerResult) = delegateview(
      _query, msg.data
    );
    assembly ("memory-safe") {
      let _ptr := add(_innerResult, 0x20)
      let _len := mload(_innerResult)
      if iszero(_innerSuccess) {
        revert(_ptr, _len)
      }
      return(_ptr, _len)
    }
  }
}

