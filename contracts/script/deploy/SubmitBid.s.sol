// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity ^0.8.0;

import { IContinuousClearingAuction } from
  "../../src/interfaces/IContinuousClearingAuction.sol";
import { WithSigner } from "./WithSigner.s.sol";
import { console2 } from "forge-std/console2.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Submit CCA Bids
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A script to submit bids to the CCA contract.

  @custom:date January 13th, 2026.
*/
contract SubmitBid is
  WithSigner {

  /// Run the script.
  function run () external withSigner {
    address _auctionAddress = vm.envAddress("CCA_ADDRESS");
    uint256 _bidValue = vm.envUint("BID_VALUE");
    uint256 _bidTickOffset = vm.envOr("BID_TICK_OFFSET", uint256(1));

    // Submit a bid.
    IContinuousClearingAuction _auction =
      IContinuousClearingAuction(_auctionAddress);
    uint256 _maxBidPrice =
      _auction.floorPrice() + (_auction.tickSpacing() * _bidTickOffset);
    uint256 _bidId =
      _auction.submitBid{ value: _bidValue }(
        _maxBidPrice, uint128(_bidValue), signer, bytes("")
      );
    console2.log("Bid submitted with ID:", _bidId);
    console2.log("- Max bid price:", _maxBidPrice);
    console2.log("- Bid value:", _bidValue);
  }
}

