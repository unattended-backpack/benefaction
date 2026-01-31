// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title EXTTLOAD Interface
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  An implementation of storage read options supporting an EXTTLOAD opcode, for
  which there is no current EIP proposed. This allows external contracts to read
  any transient storage slots of the inheritor.

  This is adapted from a Uniswap implementation.

  @custom:date January 27th, 2026.
*/
interface IEXTTLOAD {

  /**
    Read the transient storage value at a particular transient storage slot.

    @param _slot The storage slot to read.

    @return _ The storage value.
  */
  function exttload (
    bytes32 _slot
  ) external view returns (bytes32);

  /**
    Read the transient storage values at potentially multiple storage slots.

    @param _slots The storage slots to read.

    @return _ The storage value for each slot in `_slots`.
  */
  function exttload (
    bytes32[] calldata _slots
  ) external view returns (bytes32[] memory);

  /**
    Read the storage values at potentially multiple consecutive transient
    storage slots.

    @param _slot The storage slot to start reading from.
    @param _n The number of consecutive slots to read.

    @return _ The storage value for each of the consecutive slots.
  */
  function exttload (
    bytes32 _slot,
    uint256 _n
  ) external view returns (bytes32[] memory);
}

