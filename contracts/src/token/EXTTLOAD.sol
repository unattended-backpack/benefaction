// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { IEXTTLOAD } from "./interfaces/IEXTTLOAD.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title EXTTLOAD
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  An implementation of storage read options supporting an EXTTLOAD opcode, for
  which there is no current EIP proposed. This allows external contracts to read
  any transient storage slots of the inheritor.

  This is adapted from a Uniswap implementation.

  @custom:date January 27th, 2026.
*/
contract EXTTLOAD is
  IEXTTLOAD {

  /**
    Read the transient storage value at a particular transient storage slot.

    @param _slot The storage slot to read.

    @return _ The storage value.
  */
  function exttload (
    bytes32 _slot
  ) external view returns (bytes32) {
    assembly ("memory-safe") {
      mstore(0, tload(_slot))
      return(0, 0x20)
    }
  }

  /**
    Read the transient storage values at potentially multiple storage slots.

    @param _slots The storage slots to read.

    @return _ The storage value for each slot in `_slots`.
  */
  function exttload (
    bytes32[] calldata _slots
  ) external view returns (bytes32[] memory) {

    // Construct our return array with assembly.
    assembly ("memory-safe") {

      // Track Solidity's free memory pointer for starting our return data.
      let _start := mload(0x40)

      /*
        Construct the bytes32[] return data in memory. Contract ABI encoding
        dictates that the first word for a dynamic type like this be the offset
        to where the array data is defined. The array data will be immediately
        after this offset because there are no other types being returned. The
        data will start at the second word, so the offset in the first word is
        0x20.
      */
      mstore(_start, 0x20)

      // In the next word after the offset, we store the dynamic data length.
      mstore(add(_start, 0x20), _slots.length)

      /*
        Use the next word after the array length to begin tracking where the
        return data is stored.
      */
      let _data := add(_start, 0x40)

      /*
        Find the end of the return data by adding one word per returned array
        element to the two words (offset and length) that we already have. A
        left bit-shift of five is equivalent to multiplying by 32 but costs less
        gas.
      */
      let _end := add(_data, shl(5, _slots.length))

      // Track the pointer to the data section of our `_slots` parameter.
      let _calldataptr := _slots.offset
      for {} 1 {} {

        /*
          1. Load the word from calldata at our `_slots` pointer. This is a
          specific storage slot from `_slots`.
          2. Load the value of that storage slot.
          3. Store the value of that storage slot in our return data.
        */
        mstore(_data, tload(calldataload(_calldataptr)))

        // Increment our return data and calldata pointers by one word.
        _data := add(_data, 0x20)
        _calldataptr := add(_calldataptr, 0x20)

        // Continue looping until we have populated return data with all slots.
        if iszero(lt(_data, _end)) {
          break
        }
      }

      // Finally, return.
      return(_start, sub(_end, _start))
    }
  }

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
  ) external view returns (bytes32[] memory) {

    // Construct our return array with assembly.
    assembly ("memory-safe") {

      // Track Solidity's free memory pointer for starting our return data.
      let _start := mload(0x40)

      /*
        Construct the bytes32[] return data in memory. Contract ABI encoding
        dictates that the first word for a dynamic type like this be the offset
        to where the array data is defined. The array data will be immediately
        after this offset because there are no other types being returned. The
        data will start at the second word, so the offset in the first word is
        0x20.
      */
      mstore(_start, 0x20)

      // In the next word after the offset, we store the dynamic data length.
      mstore(add(_start, 0x20), _n)

      /*
        Use the next word after the array length to begin tracking where the
        return data is stored.
      */
      let _data := add(_start, 0x40)

      /*
        Find the end of the return data by adding one word per returned array
        element to the two words (offset and length) that we already have. A
        left bit-shift of five is equivalent to multiplying by 32 but costs less
        gas.
      */
      let _end := add(_data, shl(5, _n))
      for {} 1 {} {

        /*
          1. Load the value of our starting storage slot.
          2. Store the value of that storage slot in our return data.
        */
        mstore(_data, tload(_slot))

        // Increment our return data and starting slot pointers.
        _data := add(_data, 0x20)
        _slot := add(_slot, 1)

        // Continue looping until we have populated return data with all slots.
        if iszero(lt(_data, _end)) {
          break
        }
      }

      // Finally, return.
      return(_start, sub(_end, _start))
    }
  }
}

