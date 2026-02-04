// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { ERC1155 } from "solady/tokens/ERC1155.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Mock ERC-1155
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A mock ERC-1155 contract for testing purposes.

  @custom:date February 3rd, 2026.
*/
contract MockERC1155 is
  ERC1155 {

  /// The ERC1155 master slot seed from Solady.
  uint256 private constant _ERC1155_MASTER_SLOT_SEED = 0x9a31110384e0b0c9;

  /**
    Returns the URI for a given token ID.

    @return _ The token URI.
  */
  function uri (
    uint256
  ) public pure override returns (string memory) {
    return "";
  }

  /**
    Mint tokens to an address without safe transfer check. This is useful for
    testing rescue functionality where the recipient contract doesn't implement
    ERC1155Receiver.

    @param _to The address to mint to.
    @param _id The token ID to mint.
    @param _amount The amount to mint.
  */
  function mint (
    address _to,
    uint256 _id,
    uint256 _amount
  ) external {

    /*
      Use assembly to directly set the balance, bypassing safe transfer checks.
      This mimics tokens being "stuck" in a contract that can't receive them.
    */
    /// @solidity memory-safe-assembly
    assembly {

      // Storage slot matches Solady's ERC1155 balanceOf layout.
      mstore(0x20, _ERC1155_MASTER_SLOT_SEED)
      mstore(0x14, _to)
      mstore(0x00, _id)
      let _balanceSlot := keccak256(0x00, 0x40)
      sstore(_balanceSlot, add(sload(_balanceSlot), _amount))
    }
    emit TransferSingle(msg.sender, address(0), _to, _id, _amount);
  }
}

