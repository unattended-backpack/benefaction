// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { SigilTestBase } from "./utils/SigilTestBase.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Tests for ERC-165 functionality.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  Test that the ERC-165 implementation works correctly and that all supported
  interfaces are properly declared.

  @custom:date January 30th, 2026.
*/
contract SigilERC165Test is
  SigilTestBase {

  /// The ERC-165 interface ID for ERC-165 itself.
  bytes4 private constant ERC165_INTERFACE_ID = 0x01ffc9a7;

  /// The ERC-165 interface ID for ERC-20.
  bytes4 private constant ERC20_INTERFACE_ID = 0x36372b07;

  /// The ERC-165 interface ID for ERC-1363.
  bytes4 private constant ERC1363_INTERFACE_ID = 0xb0202a11;

  /// The ERC-165 interface ID for ERC-2612.
  bytes4 private constant ERC2612_INTERFACE_ID = 0x9d8ff7da;

  /// The ERC-165 interface ID for ERC-3009.
  bytes4 private constant ERC3009_INTERFACE_ID = 0xbff533ba;

  /// The ERC-165 interface ID for ERC-5805.
  bytes4 private constant ERC5805_INTERFACE_ID = 0xbd745767;

  /// Set up the test.
  function setUp () public {
    _setUpSigil();
  }

  /// supportsInterface returns true for ERC-165.
  function test_supportsInterface_erc165 () public view {
    assertTrue(token.supportsInterface(ERC165_INTERFACE_ID));
  }

  /// supportsInterface returns true for ERC-20.
  function test_supportsInterface_erc20 () public view {
    assertTrue(token.supportsInterface(ERC20_INTERFACE_ID));
  }

  /// supportsInterface returns true for ERC-1363.
  function test_supportsInterface_erc1363 () public view {
    assertTrue(token.supportsInterface(ERC1363_INTERFACE_ID));
  }

  /// supportsInterface returns true for ERC-2612.
  function test_supportsInterface_erc2612 () public view {
    assertTrue(token.supportsInterface(ERC2612_INTERFACE_ID));
  }

  /// supportsInterface returns true for ERC-3009.
  function test_supportsInterface_erc3009 () public view {
    assertTrue(token.supportsInterface(ERC3009_INTERFACE_ID));
  }

  /// supportsInterface returns true for ERC-5805.
  function test_supportsInterface_erc5805 () public view {
    assertTrue(token.supportsInterface(ERC5805_INTERFACE_ID));
  }

  /// supportsInterface returns false for unknown interface.
  function test_supportsInterface_unknown () public view {
    assertFalse(token.supportsInterface(0xdeadbeef));
  }

  /// supportsInterface returns false for zero interface.
  function test_supportsInterface_zero () public view {
    assertFalse(token.supportsInterface(0x00000000));
  }

  /// supportsInterface returns false for 0xffffffff (reserved invalid).
  function test_supportsInterface_invalidReserved () public view {
    assertFalse(token.supportsInterface(0xffffffff));
  }

  /// Verify that all interface IDs are distinct.
  function test_interfaceIds_areDistinct () public pure {
    assertTrue(ERC165_INTERFACE_ID != ERC20_INTERFACE_ID);
    assertTrue(ERC165_INTERFACE_ID != ERC1363_INTERFACE_ID);
    assertTrue(ERC165_INTERFACE_ID != ERC2612_INTERFACE_ID);
    assertTrue(ERC165_INTERFACE_ID != ERC3009_INTERFACE_ID);
    assertTrue(ERC165_INTERFACE_ID != ERC5805_INTERFACE_ID);
    assertTrue(ERC20_INTERFACE_ID != ERC1363_INTERFACE_ID);
    assertTrue(ERC20_INTERFACE_ID != ERC2612_INTERFACE_ID);
    assertTrue(ERC20_INTERFACE_ID != ERC3009_INTERFACE_ID);
    assertTrue(ERC20_INTERFACE_ID != ERC5805_INTERFACE_ID);
    assertTrue(ERC1363_INTERFACE_ID != ERC2612_INTERFACE_ID);
    assertTrue(ERC1363_INTERFACE_ID != ERC3009_INTERFACE_ID);
    assertTrue(ERC1363_INTERFACE_ID != ERC5805_INTERFACE_ID);
    assertTrue(ERC2612_INTERFACE_ID != ERC3009_INTERFACE_ID);
    assertTrue(ERC2612_INTERFACE_ID != ERC5805_INTERFACE_ID);
    assertTrue(ERC3009_INTERFACE_ID != ERC5805_INTERFACE_ID);
  }

  /**
    Fuzz test that random interface IDs return false.

    @param _interfaceId TODO
  */
  function testFuzz_supportsInterface_randomIds (
    bytes4 _interfaceId
  ) public view {

    // Skip known supported interfaces.
    vm.assume(_interfaceId != ERC165_INTERFACE_ID);
    vm.assume(_interfaceId != ERC20_INTERFACE_ID);
    vm.assume(_interfaceId != ERC1363_INTERFACE_ID);
    vm.assume(_interfaceId != ERC2612_INTERFACE_ID);
    vm.assume(_interfaceId != ERC3009_INTERFACE_ID);
    vm.assume(_interfaceId != ERC5805_INTERFACE_ID);
    assertFalse(token.supportsInterface(_interfaceId));
  }
}

