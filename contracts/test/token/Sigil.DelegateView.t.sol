// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { SigilTestBase } from "./utils/SigilTestBase.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title ISigilQuery
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  An interface for calling SigilQuery functions through Sigil's fallback. These
  are intentionally not `view` because the fallback uses CALL internally.

  @custom:date January 28th, 2026.
*/
interface ISigilQuery {

  /**
    Return the balance of `_account`.

    @param _query The query contract address (used for fallback routing).
    @param _account The account whose balance to read.

    @return _ The balance of `_account`.
  */
  function getBalance (
    address _query,
    address _account
  ) external returns (uint256);

  /**
    Return the total supply.

    @param _query The query contract address (used for fallback routing).

    @return _ The total supply.
  */
  function getTotalSupply (
    address _query
  ) external returns (uint256);

  /**
    Return the balances of two accounts.

    @param _query The query contract address (used for fallback routing).
    @param _a The first account.
    @param _b The second account.

    @return _ A tuple consisting of (the balance of `_a`, the balance of `_b`).
  */
  function getBalances (
    address _query,
    address _a,
    address _b
  ) external returns (uint256, uint256);
}

/// An interface for calling the reverting query through Sigil's fallback.
interface IRevertingQuery {

  /**
    Always revert with a custom error message.

    @param _query The query contract address (used for fallback routing).
  */
  function willRevert (
    address _query
  ) external;
}

/// An interface for calling the state-writing query through Sigil's fallback.
interface IStateWritingQuery {

  /**
    Attempt to write to a balance slot and return the value written.

    @param _query The query contract address (used for fallback routing).
    @param _account The account whose balance slot to write.
    @param _newBalance The balance to write.

    @return _ The balance that was written (before rollback).
  */
  function writeBalance (
    address _query,
    address _account,
    uint256 _newBalance
  ) external returns (uint256);
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title SigilQuery
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A query contract whose functions run in Sigil's storage context via the
  delegateview mechanism. Each function accepts the query contract address as
  its first parameter per the fallback routing convention; this parameter is
  ignored.

  @custom:date January 27th, 2026.
*/
contract SigilQuery {

  /// The Solady ERC-20 balance slot seed.
  uint256 private constant BALANCE_SLOT_SEED = 0x87a211a2;

  /**
    Return the balance of `_account`.

    @param _account The account whose balance to read.

    @return _ The balance of `_account`.
  */
  function getBalance (
    address,
    address _account
  ) external view returns (uint256) {
    uint256 _balance;
    assembly {
      mstore(0x0c, BALANCE_SLOT_SEED)
      mstore(0x00, _account)
      _balance := sload(keccak256(0x0c, 0x20))
    }
    return _balance;
  }

  /**
    Return the total supply.

    @return _ The total supply.
  */
  function getTotalSupply (
    address
  ) external view returns (uint256) {
    uint256 _supply;
    assembly {
      _supply := sload(0x05345cdf77eb68f44c)
    }
    return _supply;
  }

  /**
    Return the balances of two accounts.

    @param _a The first account.
    @param _b The second account.

    @return _ A tuple consisting of (the balance of `_a`, the balance of `_b`).
  */
  function getBalances (
    address,
    address _a,
    address _b
  ) external view returns (uint256, uint256) {
    uint256 _balA;
    uint256 _balB;
    assembly {
      mstore(0x0c, BALANCE_SLOT_SEED)
      mstore(0x00, _a)
      _balA := sload(keccak256(0x0c, 0x20))
      mstore(0x00, _b)
      _balB := sload(keccak256(0x0c, 0x20))
    }
    return (_balA, _balB);
  }
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title RevertingQuery
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A query contract that always reverts, for testing error propagation through
  the delegateview mechanism.

  @custom:date January 27th, 2026.
*/
contract RevertingQuery {

  /**
    Always revert with a custom error message.
  */
  function willRevert (
    address
  ) external pure {
    revert("query failed");
  }
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title StateWritingQuery
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A query contract that attempts to write state, for verifying that delegateview
  rolls back all state changes.

  @custom:date January 28th, 2026.
*/
contract StateWritingQuery {

  /// The Solady ERC-20 balance slot seed.
  uint256 private constant BALANCE_SLOT_SEED = 0x87a211a2;

  /**
    Attempt to write to a balance slot and return the value written. Since this
    runs via delegateview, the write should be rolled back.

    @param _account The account whose balance slot to write.
    @param _newBalance The balance to write.

    @return _ The balance that was written (before rollback).
  */
  function writeBalance (
    address,
    address _account,
    uint256 _newBalance
  ) external returns (uint256) {
    assembly {
      mstore(0x0c, BALANCE_SLOT_SEED)
      mstore(0x00, _account)
      sstore(keccak256(0x0c, 0x20), _newBalance)
    }
    return _newBalance;
  }
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title RevertingConstructor
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A contract whose constructor always reverts, for testing CREATE failure in
  the bytecode delegateview variant.

  @custom:date January 28th, 2026.
*/
contract RevertingConstructor {

  /**
    This constructor always reverts to test CREATE failure in bytecode variant.
  */
  constructor () {
    revert("constructor failed");
  }

  /**
    A dummy function that would be called if the constructor succeeded. Since
    the constructor always reverts, this function is never reachable.

    @return _ A dummy value.
  */
  function dummy (
    address
  ) external pure returns (uint256) {
    return 42;
  }
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Tests for delegateview and fallback functionality in the Sigil token.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  Test that Sigil's delegateview and fallback query routing work correctly.

  @custom:date January 27th, 2026.
*/
contract SigilDelegateViewTest is
  SigilTestBase {

  /// Store the address of the query contract.
  SigilQuery public query;

  /// Store the address of the reverting query contract.
  RevertingQuery public reverter;

  /// Store the address of the state-writing query contract.
  StateWritingQuery public stateWriter;

  /// Store Alice's address.
  address internal alice;

  /// Store Bob's address.
  address internal bob;

  /// Set up the test.
  function setUp () public {
    _setUpSigil();
    query = new SigilQuery();
    reverter = new RevertingQuery();
    stateWriter = new StateWritingQuery();
    alice = makeAddr("alice");
    bob = makeAddr("bob");
    token.transfer(alice, 500 ether);
    token.transfer(bob, 300 ether);
  }

  /// delegateview returns the correct balance via a query contract.
  function test_delegateview_balance () public {
    bytes memory _data =
      abi.encodeCall(query.getBalance, (address(query), alice));
    (bool _success, bytes memory _result) = token.delegateview(
      address(query), _data
    );
    assertTrue(_success);
    uint256 _balance = abi.decode(_result, (uint256));
    assertEq(_balance, token.balanceOf(alice));
  }

  /// delegateview returns the correct total supply via a query contract.
  function test_delegateview_totalSupply () public {
    bytes memory _data =
      abi.encodeCall(query.getTotalSupply, (address(query)));
    (bool _success, bytes memory _result) = token.delegateview(
      address(query), _data
    );
    assertTrue(_success);
    uint256 _supply = abi.decode(_result, (uint256));
    assertEq(_supply, token.totalSupply());
  }

  /// delegateview returns multiple values from a query contract.
  function test_delegateview_multipleReturnValues () public {
    bytes memory _data =
      abi.encodeCall(query.getBalances, (address(query), alice, bob));
    (bool _success, bytes memory _result) = token.delegateview(
      address(query), _data
    );
    assertTrue(_success);
    (uint256 _balA, uint256 _balB) = abi.decode(_result, (uint256, uint256));
    assertEq(_balA, token.balanceOf(alice));
    assertEq(_balB, token.balanceOf(bob));
  }

  /// delegateview reports failure when the query contract reverts.
  function test_delegateview_queryReverts () public {
    bytes memory _data =
      abi.encodeCall(reverter.willRevert, (address(reverter)));
    (bool _success, bytes memory _result) = token.delegateview(
      address(reverter), _data
    );
    assertFalse(_success);
    assertGt(_result.length, 0);
  }

  /// delegateviewRevert always reverts when called directly.
  function test_delegateviewRevert_alwaysReverts () public {
    bytes memory _data =
      abi.encodeCall(query.getTotalSupply, (address(query)));
    (bool _success, ) = address(token).call(
      abi.encodeWithSignature(
        "delegateviewRevert(address,bytes)", address(query), _data
      )
    );
    assertFalse(_success);
  }

  /// The fallback returns the correct balance via the query contract.
  function test_fallback_balance () public {
    uint256 _balance =
      ISigilQuery(address(token)).getBalance(address(query), alice);
    assertEq(_balance, token.balanceOf(alice));
  }

  /// The fallback returns the correct total supply via the query contract.
  function test_fallback_totalSupply () public {
    uint256 _supply =
      ISigilQuery(address(token)).getTotalSupply(address(query));
    assertEq(_supply, token.totalSupply());
  }

  /// The fallback returns multiple values via the query contract.
  function test_fallback_multipleReturnValues () public {
    (uint256 _balA, uint256 _balB) = ISigilQuery(address(token)).getBalances(
      address(query), alice, bob
    );
    assertEq(_balA, token.balanceOf(alice));
    assertEq(_balB, token.balanceOf(bob));
  }

  /// The fallback reverts when the query contract reverts.
  function test_fallback_queryReverts () public {
    vm.expectRevert("query failed");
    IRevertingQuery(address(token)).willRevert(address(reverter));
  }

  /// The fallback reflects balance changes after a transfer.
  function test_fallback_reflectsStateChanges () public {
    uint256 _before =
      ISigilQuery(address(token)).getBalance(address(query), alice);
    vm.prank(alice);
    token.transfer(bob, 100 ether);
    uint256 _after =
      ISigilQuery(address(token)).getBalance(address(query), alice);
    assertEq(_before - _after, 100 ether);
  }

  /**
    Bytecode delegateview returns the correct balance without a deployed query.
  */
  function test_delegateviewBytecode_balance () public {
    bytes memory _code = type(SigilQuery).creationCode;
    bytes memory _data = abi.encodeCall(query.getBalance, (address(0), alice));
    (bool _success, bytes memory _result) = token.delegateview(_code, _data);
    assertTrue(_success);
    uint256 _balance = abi.decode(_result, (uint256));
    assertEq(_balance, token.balanceOf(alice));
  }

  /// Bytecode delegateview returns the correct total supply.
  function test_delegateviewBytecode_totalSupply () public {
    bytes memory _code = type(SigilQuery).creationCode;
    bytes memory _data = abi.encodeCall(query.getTotalSupply, (address(0)));
    (bool _success, bytes memory _result) = token.delegateview(_code, _data);
    assertTrue(_success);
    uint256 _supply = abi.decode(_result, (uint256));
    assertEq(_supply, token.totalSupply());
  }

  /// Bytecode delegateview returns multiple values.
  function test_delegateviewBytecode_multipleReturnValues () public {
    bytes memory _code = type(SigilQuery).creationCode;
    bytes memory _data =
      abi.encodeCall(query.getBalances, (address(0), alice, bob));
    (bool _success, bytes memory _result) = token.delegateview(_code, _data);
    assertTrue(_success);
    (uint256 _balA, uint256 _balB) = abi.decode(_result, (uint256, uint256));
    assertEq(_balA, token.balanceOf(alice));
    assertEq(_balB, token.balanceOf(bob));
  }

  /// Bytecode delegateview reports failure when the query reverts.
  function test_delegateviewBytecode_queryReverts () public {
    bytes memory _code = type(RevertingQuery).creationCode;
    bytes memory _data = abi.encodeCall(reverter.willRevert, (address(0)));
    (bool _success, bytes memory _result) = token.delegateview(_code, _data);
    assertFalse(_success);
    assertGt(_result.length, 0);
  }

  /// Bytecode delegateviewRevert always reverts when called directly.
  function test_delegateviewRevertBytecode_alwaysReverts () public {
    bytes memory _code = type(SigilQuery).creationCode;
    bytes memory _data = abi.encodeCall(query.getTotalSupply, (address(0)));
    (bool _success, ) = address(token).call(
      abi.encodeWithSignature("delegateviewRevert(bytes,bytes)", _code, _data)
    );
    assertFalse(_success);
  }

  /// delegateview to an EOA (no code) returns success with empty data.
  function test_delegateview_noCodeTarget_eoa () public {
    address _eoa = makeAddr("eoa");
    bytes memory _data = abi.encodeWithSignature("anything()");
    (bool _success, bytes memory _result) = token.delegateview(_eoa, _data);
    assertTrue(_success);
    assertEq(_result.length, 0);
  }

  /// delegateview to address(0) returns success with empty data.
  function test_delegateview_noCodeTarget_addressZero () public {
    bytes memory _data = abi.encodeWithSignature("anything()");
    (bool _success, bytes memory _result) = token.delegateview(
      address(0), _data
    );
    assertTrue(_success);
    assertEq(_result.length, 0);
  }

  /// Bytecode delegateview with empty bytecode returns success with empty data.
  function test_delegateviewBytecode_emptyBytecode () public {
    bytes memory _code = "";
    bytes memory _data = abi.encodeWithSignature("anything()");
    (bool _success, bytes memory _result) = token.delegateview(_code, _data);
    assertTrue(_success);
    assertEq(_result.length, 0);
  }

  /**
    Bytecode delegateview with reverting constructor returns success with empty
    data (CREATE fails, delegatecall to address(0) succeeds vacuously).
  */
  function test_delegateviewBytecode_revertingConstructor () public {
    bytes memory _code = type(RevertingConstructor).creationCode;
    bytes memory _data = abi.encodeWithSignature("dummy(address)", address(0));
    (bool _success, bytes memory _result) = token.delegateview(_code, _data);
    assertTrue(_success);
    assertEq(_result.length, 0);
  }

  /// State changes made by a query are rolled back after delegateview returns.
  function test_delegateview_stateRollback () public {
    uint256 _balanceBefore = token.balanceOf(alice);
    uint256 _newBalance = 999 ether;

    // Call the state-writing query that attempts to overwrite Alice's balance.
    bytes memory _data =
      abi.encodeCall(
        stateWriter.writeBalance, (address(stateWriter), alice, _newBalance)
      );
    (bool _success, bytes memory _result) = token.delegateview(
      address(stateWriter), _data
    );

    // The query should report success and return the value it wrote.
    assertTrue(_success);
    uint256 _returnedBalance = abi.decode(_result, (uint256));
    assertEq(_returnedBalance, _newBalance);

    // But Alice's actual balance should be unchanged.
    assertEq(token.balanceOf(alice), _balanceBefore);
  }

  /// State changes via fallback are also rolled back.
  function test_fallback_stateRollback () public {
    uint256 _balanceBefore = token.balanceOf(alice);
    uint256 _newBalance = 999 ether;

    // Call through the fallback.
    uint256 _returnedBalance =
      IStateWritingQuery(address(token)).writeBalance(
        address(stateWriter), alice, _newBalance
      );

    // The query reports the value it wrote.
    assertEq(_returnedBalance, _newBalance);

    // But Alice's actual balance should be unchanged.
    assertEq(token.balanceOf(alice), _balanceBefore);
  }

  /// State changes via bytecode delegateview are also rolled back.
  function test_delegateviewBytecode_stateRollback () public {
    uint256 _balanceBefore = token.balanceOf(alice);
    uint256 _newBalance = 999 ether;
    bytes memory _code = type(StateWritingQuery).creationCode;
    bytes memory _data =
      abi.encodeCall(
        stateWriter.writeBalance, (address(0), alice, _newBalance)
      );
    (bool _success, bytes memory _result) = token.delegateview(_code, _data);
    assertTrue(_success);
    uint256 _returnedBalance = abi.decode(_result, (uint256));
    assertEq(_returnedBalance, _newBalance);

    // Alice's actual balance should be unchanged.
    assertEq(token.balanceOf(alice), _balanceBefore);
  }

  /// Fallback with calldata too short to contain an address reverts.
  function test_fallback_malformedCalldata_tooShort () public {

    // Send only a 4-byte selector with no address argument.
    bytes memory _calldata = abi.encodeWithSignature("foo()");
    (bool _success, ) = address(token).call(_calldata);
    assertFalse(_success);
  }

  /// Fallback with partial address data reverts.
  function test_fallback_malformedCalldata_partialAddress () public {

    // Send selector + only 16 bytes (not enough for a full address).
    bytes memory _calldata =
      abi.encodePacked(bytes4(keccak256("foo(address)")), bytes16(0));
    (bool _success, ) = address(token).call(_calldata);
    assertFalse(_success);
  }
}

