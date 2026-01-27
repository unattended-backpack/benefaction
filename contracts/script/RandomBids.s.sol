// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity ^0.8.0;

import { WithSigner } from "./util/WithSigner.sol";
import { IContinuousClearingAuction } from
  "cca/interfaces/IContinuousClearingAuction.sol";
import { console2 } from "forge-std/console2.sol";
import { Script } from "forge-std/Script.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Random Bids
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A script to submit random bids to the CCA contract from multiple signers
  derived from a mnemonic at indices 0 through 13.

  @custom:date January 27th, 2026.
*/
contract RandomBids is
  Script,
  WithSigner {

  /// The number of random bids to submit.
  uint256 constant BID_COUNT = 16;

  /// The maximum tick offset above the floor price.
  uint256 constant MAX_TICK_OFFSET = 50;

  /// The minimum amount to bid.
  uint128 constant MIN_AMOUNT = 1_0000000000000000;

  /// The maximum amount to bid.
  uint128 constant MAX_AMOUNT = 10_000000000000000000;

  /**
    Create a random bid with a particular signer.

    @param _index The index of the environment-derived mnemonic to sign with.
    @param _seed A random seed.
  */
  function _bid (
    uint32 _index,
    bytes32 _seed
  ) private withSignerIndex(_index) {
    address _auctionAddress = vm.envAddress("CCA_ADDRESS");
    IContinuousClearingAuction _auction =
      IContinuousClearingAuction(_auctionAddress);
    uint256 _floorPrice = _auction.floorPrice();
    uint256 _tickSpacing = _auction.tickSpacing();

    // Pick a random bid amount.
    uint128 _amount =
      MIN_AMOUNT + uint128(
        uint256(keccak256(abi.encodePacked(_seed, "amount"))) % (
          MAX_AMOUNT - MIN_AMOUNT
        )
      );

    // Pick a random tick offset.
    uint256 _tickOffset =
      1 + (
        uint256(keccak256(abi.encodePacked(_seed, "price"))) % MAX_TICK_OFFSET
      );
    uint256 _maxPrice = _floorPrice + (_tickSpacing * _tickOffset);

    // Submit the bid.
    _auction.submitBid{ value: _amount, gas: 350000 }(
      _maxPrice, _amount, signer, bytes("")
    );
  }

  /// Run the script.
  function run () external {

    // Submit each random bid on a mnemonic index from 0 to 13.
    for (uint256 i = 0; i < BID_COUNT; i++) {
      bytes32 _seed = keccak256(abi.encodePacked(i, block.timestamp));
      uint32 _index = uint32(uint256(_seed) % 14);
      _bid(_index, _seed);
    }
  }
}

