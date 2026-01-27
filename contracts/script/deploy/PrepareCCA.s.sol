// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity ^0.8.0;

import { IContinuousClearingAuction } from
  "cca/interfaces/IContinuousClearingAuction.sol";
import { IERC20 } from "@openzeppelin/contracts/interfaces/IERC20.sol";
import { WithSigner } from "../util/WithSigner.sol";
import { console2 } from "forge-std/console2.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Prepare the CCA
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A script to transfer tokens to the CCA contract.

  @custom:date January 13th, 2026.
*/
contract PrepareCCA is
  WithSigner {

  /// Run the deploy script.
  function run () external withSigner {
    address _tokenAddress = vm.envAddress("CCA_TOKEN");
    address _auctionAddress = vm.envAddress("CCA_ADDRESS");
    uint128 _auctionSupply = uint128(vm.envUint("CCA_AUCTION_SUPPLY"));

    // Send tokens to the auction.
    IERC20 _token = IERC20(_tokenAddress);
    IContinuousClearingAuction _auction =
      IContinuousClearingAuction(_auctionAddress);
    _token.transfer(_auctionAddress, _auctionSupply);
    _auction.onTokensReceived();
    console2.log(
      "Transferred", _auctionSupply, "tokens to auction at", _auctionAddress
    );
  }
}

