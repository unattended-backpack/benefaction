// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title EXTSLOAD Interface
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  An implementation of storage read options supporting mimicry of an EIP-2330
  EXTSLOAD opcode. This allows external contracts to read any storage slots of
  the inheritor.

  This is adapted from a Uniswap implementation.

  @custom:date January 27th, 2026.
*/
interface IEXTSLOAD {

  /**
    Read the storage value at a particular storage slot.

    @param _slot The storage slot to read.

    @return _ The storage value.
  */
  function extsload (
    bytes32 _slot
  ) external view returns (bytes32);

  /**
    Read the storage values at potentially multiple storage slots.

    @param _slots The storage slots to read.

    @return _ The storage value for each slot in `_slots`.
  */
  function extsload (
    bytes32[] calldata _slots
  ) external view returns (bytes32[] memory);

  /**
    Read the storage values at potentially multiple consecutive storage slots.

    @param _slot The storage slot to start reading from.
    @param _n The number of consecutive slots to read.

    @return _ The storage value for each of the consecutive slots.
  */
  function extsload (
    bytes32 _slot,
    uint256 _n
  ) external view returns (bytes32[] memory);
}

