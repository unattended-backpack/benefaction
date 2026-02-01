// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { SigilTestBase } from "./utils/SigilTestBase.sol";
import { EXTTLOAD } from "token/EXTTLOAD.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title TransientWriter
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A transient storage writing contract for simple tests.

  @custom:date January 29th, 2026.
*/
contract TransientWriter is
  EXTTLOAD {

  /**
    Write to a transient storage slot and immediately read it back via
    `exttload`.

    @param _slot The transient storage slot to write to.
    @param _value The value to write.

    @return _ The value read back from `exttload`.
  */
  function writeAndReadSingle (
    bytes32 _slot,
    bytes32 _value
  ) external returns (bytes32) {
    assembly {
      tstore(_slot, _value)
    }
    return this.exttload(_slot);
  }

  /**
    Write to multiple transient storage slots and immediately read them back via
    `exttload`.

    @param _slots The transient storage slots to write to.
    @param _values The values to write.

    @return _ The values read back from `exttload`.
  */
  function writeAndReadMultiple (
    bytes32[] calldata _slots,
    bytes32[] calldata _values
  ) external returns (bytes32[] memory) {
    for (uint256 i = 0; i < _slots.length; i++) {
      bytes32 _s = _slots[i];
      bytes32 _v = _values[i];
      assembly {
        tstore(_s, _v)
      }
    }
    return this.exttload(_slots);
  }

  /**
    Write to consecutive transient storage slots and immediately read them back
    via `exttload`.

    @param _startSlot The first transient storage slot to write to.
    @param _values The values to write to consecutive slots.

    @return _ The values read back from `exttload`.
  */
  function writeConsecutiveAndRead (
    bytes32 _startSlot,
    bytes32[] calldata _values
  ) external returns (bytes32[] memory) {
    for (uint256 i = 0; i < _values.length; i++) {
      bytes32 _slot = bytes32(uint256(_startSlot) + i);
      bytes32 _v = _values[i];
      assembly {
        tstore(_slot, _v)
      }
    }
    return this.exttload(_startSlot, _values.length);
  }
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Tests for EXTSLOAD and EXTTLOAD functionality in the Sigil token.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  Test that Sigil has implemented EXTSLOAD and EXTTLOAD correctly.

  @custom:date January 27th, 2026.
*/
contract SigilEXTLOADTest is
  SigilTestBase {

  /// The Solady ERC-20 balance slot seed.
  uint256 private constant BALANCE_SLOT_SEED = 0x87a211a2;

  /// The Solady ERC-20 allowance slot seed.
  uint256 private constant ALLOWANCE_SLOT_SEED = 0x7f5e9f20;

  /// The Solady ERC-20 total supply slot.
  bytes32 private constant TOTAL_SUPPLY_SLOT =
    bytes32(uint256(0x05345cdf77eb68f44c));

  /// Store the address of the TransientWriter helper for testing.
  TransientWriter public writer;

  /// Store Alice's address.
  address internal alice;

  /// Store Bob's address.
  address internal bob;

  /// Set up the test.
  function setUp () public {
    _setUpSigil();
    writer = new TransientWriter();
    alice = makeAddr("alice");
    bob = makeAddr("bob");

    // Give tokens to Alice and Bob for testing.
    token.transfer(alice, 500 ether);
    token.transfer(bob, 300 ether);
  }

  /**
    Compute the Solady balance storage slot for a given account.

    @param _account The account to compute the balance slot for.

    @return _ The storage slot.
  */
  function _balanceSlot (
    address _account
  ) internal pure returns (bytes32) {
    bytes32 _slotOutput;
    assembly {
      mstore(0x0c, BALANCE_SLOT_SEED)
      mstore(0x00, _account)
      _slotOutput := keccak256(0x0c, 0x20)
    }
    return _slotOutput;
  }

  /**
    Compute the Solady allowance storage slot for a given owner and spender.

    @param _owner The token owner.
    @param _spender The spender.

    @return _ The storage slot.
  */
  function _allowanceSlot (
    address _owner,
    address _spender
  ) internal pure returns (bytes32) {
    bytes32 _slotOutput;
    assembly {
      mstore(0x20, _spender)
      mstore(0x0c, ALLOWANCE_SLOT_SEED)
      mstore(0x00, _owner)
      _slotOutput := keccak256(0x0c, 0x34)
    }
    return _slotOutput;
  }

  /**
    Compute the Solidity storage slot for a nested mapping `mapping(address =>
    mapping(bytes32 => bool))` at base slot 0.

    @param _authorizer The outer mapping key.
    @param _nonce The inner mapping key.

    @return _ The storage slot.
  */
  function _authorizationStateSlot (
    address _authorizer,
    bytes32 _nonce
  ) internal pure returns (bytes32) {
    bytes32 _innerSlot = keccak256(abi.encode(_authorizer, uint256(0)));
    return keccak256(abi.encode(_nonce, _innerSlot));
  }

  /// Reading the total supply slot returns the correct total supply.
  function test_extsload_totalSupply () public view {
    bytes32 _value = token.extsload(TOTAL_SUPPLY_SLOT);
    assertEq(uint256(_value), token.totalSupply());
  }

  /// Reading a balance slot returns the correct balance.
  function test_extsload_balance () public view {
    bytes32 _slot = _balanceSlot(alice);
    bytes32 _value = token.extsload(_slot);
    assertEq(uint256(_value), token.balanceOf(alice));
  }

  /// Reading an allowance slot returns the correct allowance.
  function test_extsload_allowance () public {
    vm.prank(alice);
    token.approve(bob, 42 ether);
    bytes32 _slot = _allowanceSlot(alice, bob);
    bytes32 _value = token.extsload(_slot);
    assertEq(uint256(_value), token.allowance(alice, bob));
  }

  /// Reading the authorizationState mapping after a cancel returns true.
  function test_extsload_authorizationState () public {

    // Set authorizationState[alice][nonce] to true via cancelAuthorization.
    uint256 _alicePk = 0xA11CE;
    address _aliceAddr = vm.addr(_alicePk);
    token.transfer(_aliceAddr, 1 ether);
    bytes32 _nonce = bytes32(uint256(99));
    bytes32 _cancelTypehash =
      0x158b0a9edf7a828aad02f63cd515c68ef2f50ba807396f6d12842833a1597429;
    bytes32 _structHash =
      keccak256(abi.encode(_cancelTypehash, _aliceAddr, _nonce));
    bytes32 _digest =
      keccak256(
        abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), _structHash)
      );
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(_alicePk, _digest);
    token.cancelAuthorization(_aliceAddr, _nonce, abi.encodePacked(_r, _s, _v));

    // Now read the slot via extsload.
    bytes32 _slot = _authorizationStateSlot(_aliceAddr, _nonce);
    bytes32 _value = token.extsload(_slot);
    assertEq(uint256(_value), 1);
  }

  /// Reading an uninitialized slot returns zero.
  function test_extsload_emptySlot () public view {
    bytes32 _slot = bytes32(uint256(0xdeadbeef));
    bytes32 _value = token.extsload(_slot);
    assertEq(uint256(_value), 0);
  }

  /// Reading multiple balance slots returns the correct balances.
  function test_extsload_multipleSlots () public view {
    bytes32[] memory _slots = new bytes32[](3);
    _slots[0] = _balanceSlot(alice);
    _slots[1] = _balanceSlot(bob);
    _slots[2] = _balanceSlot(address(this));
    bytes32[] memory _values = token.extsload(_slots);
    assertEq(_values.length, 3);
    assertEq(uint256(_values[0]), token.balanceOf(alice));
    assertEq(uint256(_values[1]), token.balanceOf(bob));
    assertEq(uint256(_values[2]), token.balanceOf(address(this)));
  }

  /// Reading a mix of populated and empty slots returns correct values.
  function test_extsload_multipleSlots_mixedPopulatedAndEmpty () public view {
    bytes32[] memory _slots = new bytes32[](3);
    _slots[0] = _balanceSlot(alice);
    _slots[1] = bytes32(uint256(0xdeadbeef));
    _slots[2] = TOTAL_SUPPLY_SLOT;
    bytes32[] memory _values = token.extsload(_slots);
    assertEq(uint256(_values[0]), token.balanceOf(alice));
    assertEq(uint256(_values[1]), 0);
    assertEq(uint256(_values[2]), token.totalSupply());
  }

  /// Reading consecutive slots starting from the total supply slot.
  function test_extsload_consecutiveSlots () public view {
    bytes32[] memory _values = token.extsload(TOTAL_SUPPLY_SLOT, 3);
    assertEq(_values.length, 3);

    /*
      The first slot is the total supply; subsequent slots are whatever happens
      to follow in storage.
    */
    assertEq(uint256(_values[0]), token.totalSupply());
  }

  /// Reading a single consecutive slot returns a one-element array.
  function test_extsload_consecutiveSlots_single () public view {
    bytes32[] memory _values = token.extsload(TOTAL_SUPPLY_SLOT, 1);
    assertEq(_values.length, 1);
    assertEq(uint256(_values[0]), token.totalSupply());
  }

  /// Reading an unwritten transient slot on Sigil returns zero.
  function test_exttload_emptySlot () public view {
    bytes32 _value = token.exttload(bytes32(uint256(1)));
    assertEq(uint256(_value), 0);
  }

  /// Writing and reading a single transient slot returns the written value.
  function test_exttload_singleSlot_roundTrip () public {
    bytes32 _slot = bytes32(uint256(42));
    bytes32 _expected = bytes32(uint256(0x1234));
    bytes32 _value = writer.writeAndReadSingle(_slot, _expected);
    assertEq(_value, _expected);
  }

  /// Writing and reading multiple transient slots returns the written values.
  function test_exttload_multipleSlots_roundTrip () public {
    bytes32[] memory _slots = new bytes32[](3);
    _slots[0] = bytes32(uint256(10));
    _slots[1] = bytes32(uint256(20));
    _slots[2] = bytes32(uint256(30));
    bytes32[] memory _expected = new bytes32[](3);
    _expected[0] = bytes32(uint256(0xAAAA));
    _expected[1] = bytes32(uint256(0xBBBB));
    _expected[2] = bytes32(uint256(0xCCCC));
    bytes32[] memory _values = writer.writeAndReadMultiple(_slots, _expected);
    assertEq(_values.length, 3);
    assertEq(_values[0], _expected[0]);
    assertEq(_values[1], _expected[1]);
    assertEq(_values[2], _expected[2]);
  }

  /// Reading multiple unwritten transient slots on Sigil returns zeros.
  function test_exttload_multipleSlots_empty () public view {
    bytes32[] memory _slots = new bytes32[](2);
    _slots[0] = bytes32(uint256(100));
    _slots[1] = bytes32(uint256(200));
    bytes32[] memory _values = token.exttload(_slots);
    assertEq(_values.length, 2);
    assertEq(uint256(_values[0]), 0);
    assertEq(uint256(_values[1]), 0);
  }

  /**
    Writing and reading consecutive transient slots returns the written values.
  */
  function test_exttload_consecutiveSlots_roundTrip () public {
    bytes32 _startSlot = bytes32(uint256(50));
    bytes32[] memory _expected = new bytes32[](3);
    _expected[0] = bytes32(uint256(0x111));
    _expected[1] = bytes32(uint256(0x222));
    _expected[2] = bytes32(uint256(0x333));
    bytes32[] memory _values =
      writer.writeConsecutiveAndRead(_startSlot, _expected);
    assertEq(_values.length, 3);
    assertEq(_values[0], _expected[0]);
    assertEq(_values[1], _expected[1]);
    assertEq(_values[2], _expected[2]);
  }

  /// Reading consecutive unwritten transient slots on Sigil returns zeros.
  function test_exttload_consecutiveSlots_empty () public view {
    bytes32[] memory _values = token.exttload(bytes32(uint256(500)), 3);
    assertEq(_values.length, 3);
    assertEq(uint256(_values[0]), 0);
    assertEq(uint256(_values[1]), 0);
    assertEq(uint256(_values[2]), 0);
  }

  /// Reading zero storage slots via the array variant returns an empty array.
  function test_extsload_zeroLengthArray () public view {
    bytes32[] memory _slots = new bytes32[](0);
    bytes32[] memory _values = token.extsload(_slots);
    assertEq(_values.length, 0);
  }

  /// Reading zero consecutive storage slots returns an empty array.
  function test_extsload_zeroConsecutiveSlots () public view {
    bytes32[] memory _values = token.extsload(TOTAL_SUPPLY_SLOT, 0);
    assertEq(_values.length, 0);
  }

  /// Reading zero transient slots via the array variant returns an empty array.
  function test_exttload_zeroLengthArray () public view {
    bytes32[] memory _slots = new bytes32[](0);
    bytes32[] memory _values = token.exttload(_slots);
    assertEq(_values.length, 0);
  }

  /// Reading zero consecutive transient slots returns an empty array.
  function test_exttload_zeroConsecutiveSlots () public view {
    bytes32[] memory _values = token.exttload(bytes32(uint256(1)), 0);
    assertEq(_values.length, 0);
  }

  /// A full-width bytes32 value is read back without truncation via extsload.
  function test_extsload_fullWidthValue () public {
    bytes32 _slot = bytes32(uint256(0xCAFE));
    bytes32 _fullWidth = bytes32(type(uint256).max);
    vm.store(address(token), _slot, _fullWidth);
    assertEq(token.extsload(_slot), _fullWidth);
  }

  /// A full-width bytes32 value round-trips without truncation via exttload.
  function test_exttload_fullWidthValue () public {
    bytes32 _slot = bytes32(uint256(0xCAFE));
    bytes32 _fullWidth = bytes32(type(uint256).max);
    bytes32 _value = writer.writeAndReadSingle(_slot, _fullWidth);
    assertEq(_value, _fullWidth);
  }

  /**
    All elements of a consecutive storage read match individually-stored values.
  */
  function test_extsload_consecutiveSlots_allVerified () public {
    bytes32 _startSlot = bytes32(uint256(0xF000));
    bytes32[4] memory _expected =
      [bytes32(uint256(0xAA)), bytes32(uint256(0xBB)),
      bytes32(type(uint256).max), bytes32(uint256(0))];
    for (uint256 i = 0; i < _expected.length; i++) {
      vm.store(address(token), bytes32(uint256(_startSlot) + i), _expected[i]);
    }
    bytes32[] memory _values = token.extsload(_startSlot, 4);
    assertEq(_values.length, 4);
    for (uint256 i = 0; i < _expected.length; i++) {
      assertEq(_values[i], _expected[i]);
    }
  }

  /**
    All elements of a consecutive transient storage read match
    individually-stored values.
  */
  function test_exttload_consecutiveSlots_allVerified () public {
    bytes32 _startSlot = bytes32(uint256(0xF000));
    bytes32[] memory _expected = new bytes32[](4);
    _expected[0] = bytes32(uint256(0xAA));
    _expected[1] = bytes32(uint256(0xBB));
    _expected[2] = bytes32(type(uint256).max);
    _expected[3] = bytes32(uint256(0));
    bytes32[] memory _values =
      writer.writeConsecutiveAndRead(_startSlot, _expected);
    assertEq(_values.length, 4);
    for (uint256 i = 0; i < _expected.length; i++) {
      assertEq(_values[i], _expected[i]);
    }
  }
}

