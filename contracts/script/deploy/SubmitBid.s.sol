// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity ^0.8.0;

import { ITest20 } from "../../src/erc20/interfaces/ITest20.sol";
import { IContinuousClearingAuction } from
  "../../src/interfaces/IContinuousClearingAuction.sol";
import { console2 } from "forge-std/console2.sol";
import { Script } from "forge-std/Script.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Submit CCA Bids
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A script to submit bids to the CCA contract.

  @custom:date January 13th, 2026.
*/
contract SubmitBid is
  Script {

  /// The address of the CCA contract.
  address constant AUCTION = 0xd829E17ce5f942365EeB589C0F59e0C104BC5cA4;

  /// Run the script.
  function run () external {

    // Retrieve the bid submitter based on the configured signer.
    uint256 _privateKey = vm.envOr("PRIVATE_KEY", uint256(0));
    if (_privateKey == 0) {
      string memory _mnemonic = vm.envString("MNEMONIC");
      uint32 _index = uint32(vm.envUint("MNEMONIC_INDEX"));
      _privateKey = vm.deriveKey(_mnemonic, _index);
    }
    address _signer = vm.addr(_privateKey);

    // Submit a bid.
    vm.startBroadcast(_privateKey);
    IContinuousClearingAuction _auction = IContinuousClearingAuction(AUCTION);
    uint256 _maxBidPrice = _auction.floorPrice() + _auction.tickSpacing();
    uint256 _bidId =
      _auction.submitBid{ value: 1 ether }(
        _maxBidPrice, 1 ether, _signer, bytes("")
      );
    console2.log("Bid submitted with ID:", _bidId);
    console2.log("Signer:", _signer);
    vm.stopBroadcast();
  }
}

