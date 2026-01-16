// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity ^0.8.0;

import { ContinuousClearingAuction } from
  "../../src/ContinuousClearingAuction.sol";
import { AuctionParameters } from
  "../../src/interfaces/IContinuousClearingAuction.sol";
import { WithCreateX } from "./WithCreateX.s.sol";

/// This error is thrown when the auction steps arrays have mismatched lengths.
error AuctionStepsLengthMismatch (
  uint256 mpsLength,
  uint256 blocksLength
);

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Deploy the ContinuousClearingAuction
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A script to deploy the `ContinuousClearingAuction`.

  @custom:date January 13th, 2026.
*/
contract DeployContinuousClearingAuction is
  WithCreateX {

  /**
    Pack auction steps from parallel MPS and block delta arrays.

    @param _mpsValues The MPS (millipercent of supply) values for each step.
    @param _blockDeltas The block delta values for each step.

    @return _auctionSteps The packed auction steps data.
  */
  function _packAuctionSteps (
    uint256[] memory _mpsValues,
    uint256[] memory _blockDeltas
  ) internal pure returns (bytes memory _auctionSteps) {
    if (_mpsValues.length != _blockDeltas.length) {
      revert AuctionStepsLengthMismatch(_mpsValues.length, _blockDeltas.length);
    }
    for (uint256 i = 0; i < _mpsValues.length; i++) {
      _auctionSteps = abi.encodePacked(
        _auctionSteps,
        uint24(_mpsValues[i]),
        uint40(_blockDeltas[i])
      );
    }
  }

  /// Run the deploy script.
  function run () external {

    // Load auction configuration from environment.
    address _token = vm.envAddress("CCA_TOKEN");
    uint128 _auctionSupply = uint128(vm.envUint("CCA_AUCTION_SUPPLY"));

    // Load and pack auction steps from environment.
    uint256[] memory _mpsValues = vm.envUint("CCA_AUCTION_STEPS_MPS", ",");
    uint256[] memory _blockDeltas = vm.envUint("CCA_AUCTION_STEPS_BLOCKS", ",");
    bytes memory _auctionSteps = _packAuctionSteps(_mpsValues, _blockDeltas);

    // Prepare the auction parameters.
    AuctionParameters memory _parameters = AuctionParameters({
      currency: vm.envAddress("CCA_CURRENCY"),
      tokensRecipient: vm.envAddress("CCA_TOKENS_RECIPIENT"),
      fundsRecipient: vm.envAddress("CCA_FUNDS_RECIPIENT"),
      startBlock: uint64(vm.envUint("CCA_START_BLOCK")),
      endBlock: uint64(vm.envUint("CCA_END_BLOCK")),
      claimBlock: uint64(vm.envUint("CCA_CLAIM_BLOCK")),
      tickSpacing: vm.envUint("CCA_TICK_SPACING"),
      validationHook: vm.envAddress("CCA_VALIDATION_HOOK"),
      floorPrice: vm.envUint("CCA_FLOOR_PRICE"),
      requiredCurrencyRaised: uint128(vm.envUint("CCA_REQUIRED_CURRENCY_RAISED")),
      auctionStepsData: _auctionSteps
    });

    // Deploy the auction.
    Deployment[] memory _deployments = new Deployment[](1);
    _deployments[0] = Deployment({
      salt: vm.envBytes32("CCA_SALT"),
      expectedAddress: vm.envAddress("CCA_EXPECTED_ADDRESS"),
      contractName: "ContinuousClearingAuction",
      initCode: abi.encodePacked(
        type(ContinuousClearingAuction).creationCode,
        abi.encode(_token, _auctionSupply, _parameters)
      )
    });
    deploy(_deployments);
  }
}
