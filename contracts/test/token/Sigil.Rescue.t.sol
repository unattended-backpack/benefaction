// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { MockERC1155 } from "./utils/MockERC1155.sol";
import { MockERC20 } from "./utils/MockERC20.sol";
import { MockERC6909 } from "./utils/MockERC6909.sol";
import { MockERC721 } from "./utils/MockERC721.sol";
import { SigilTestBase } from "./utils/SigilTestBase.sol";
import { Lifebuoy } from "solady/utils/Lifebuoy.sol";
import { Sigil } from "token/Sigil.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Tests for rescue functionality in the Sigil token.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  Test that Sigil has implemented Lifebuoy rescue functionality correctly,
  including the restriction on rescuing the ERC-4626 vault asset (WETH).

  @custom:date February 3rd, 2026.
*/
contract SigilRescueTest is
  SigilTestBase {

  /// A mock ERC-20 token for testing rescue.
  MockERC20 public mockToken;

  /// A mock ERC-721 token for testing rescue.
  MockERC721 public mockNFT;

  /// A mock ERC-1155 token for testing rescue.
  MockERC1155 public mockERC1155;

  /// A mock ERC-6909 token for testing rescue.
  MockERC6909 public mockERC6909;

  /// A random recipient address.
  address internal recipient;

  /// Set up the test.
  function setUp () public {
    _setUpSigil();
    recipient = makeAddr("recipient");

    // Deploy mock tokens.
    mockToken = new MockERC20("Mock Token", "MOCK", 18);
    mockNFT = new MockERC721();
    mockERC1155 = new MockERC1155();
    mockERC6909 = new MockERC6909();
  }

  /// The owner can rescue ETH accidentally sent to the contract.
  function test_rescueETH_asOwner_succeeds () public {

    // Send ETH to the token contract.
    uint256 _amount = 1 ether;
    vm.deal(address(token), _amount);
    assertEq(address(token).balance, _amount);
    uint256 _recipientBalanceBefore = recipient.balance;

    // Owner rescues the ETH.
    token.rescueETH(recipient, _amount);
    assertEq(address(token).balance, 0);
    assertEq(recipient.balance, _recipientBalanceBefore + _amount);
  }

  /// A non-owner cannot rescue ETH.
  function test_rescueETH_asNonOwner_reverts () public {

    // Send ETH to the token contract.
    uint256 _amount = 1 ether;
    vm.deal(address(token), _amount);

    // Non-owner tries to rescue ETH.
    vm.prank(recipient);
    vm.expectRevert(Lifebuoy.RescueUnauthorizedOrLocked.selector);
    token.rescueETH(recipient, _amount);
  }

  /// The owner can rescue partial ETH.
  function test_rescueETH_partialAmount_succeeds () public {

    // Send ETH to the token contract.
    uint256 _totalAmount = 2 ether;
    uint256 _rescueAmount = 1 ether;
    vm.deal(address(token), _totalAmount);

    // Owner rescues partial ETH.
    token.rescueETH(recipient, _rescueAmount);
    assertEq(address(token).balance, _totalAmount - _rescueAmount);
    assertEq(recipient.balance, _rescueAmount);
  }

  /// The owner can rescue ERC-20 tokens accidentally sent to the contract.
  function test_rescueERC20_asOwner_succeeds () public {

    // Send mock tokens to the token contract.
    uint256 _amount = 1000 ether;
    mockToken.mint(address(token), _amount);
    assertEq(mockToken.balanceOf(address(token)), _amount);

    // Owner rescues the tokens.
    token.rescueERC20(address(mockToken), recipient, _amount);
    assertEq(mockToken.balanceOf(address(token)), 0);
    assertEq(mockToken.balanceOf(recipient), _amount);
  }

  /// A non-owner cannot rescue ERC-20 tokens.
  function test_rescueERC20_asNonOwner_reverts () public {

    // Send mock tokens to the token contract.
    uint256 _amount = 1000 ether;
    mockToken.mint(address(token), _amount);

    // Non-owner tries to rescue tokens.
    vm.prank(recipient);
    vm.expectRevert(Lifebuoy.RescueUnauthorizedOrLocked.selector);
    token.rescueERC20(address(mockToken), recipient, _amount);
  }

  /// The owner cannot rescue the ERC-4626 vault asset (WETH).
  function test_rescueERC20_vaultAsset_reverts () public {

    // Mint additional WETH to the token contract (simulating accidental send).
    uint256 _amount = 1 ether;
    weth.mint(address(token), _amount);

    // Owner tries to rescue WETH but is blocked.
    vm.expectRevert(Sigil.CannotRescueVaultAsset.selector);
    token.rescueERC20(address(weth), recipient, _amount);
  }

  /// The vault asset restriction applies to the exact asset address.
  function test_rescueERC20_notVaultAsset_succeeds () public {

    // Create a different token that is NOT WETH.
    MockERC20 _otherToken = new MockERC20("Other", "OTH", 18);
    uint256 _amount = 1000 ether;
    _otherToken.mint(address(token), _amount);

    // Owner can rescue this token.
    token.rescueERC20(address(_otherToken), recipient, _amount);
    assertEq(_otherToken.balanceOf(recipient), _amount);
  }

  /// The owner can rescue partial ERC-20 tokens.
  function test_rescueERC20_partialAmount_succeeds () public {

    // Send mock tokens to the token contract.
    uint256 _totalAmount = 1000 ether;
    uint256 _rescueAmount = 400 ether;
    mockToken.mint(address(token), _totalAmount);

    // Owner rescues partial tokens.
    token.rescueERC20(address(mockToken), recipient, _rescueAmount);
    assertEq(mockToken.balanceOf(address(token)), _totalAmount - _rescueAmount);
    assertEq(mockToken.balanceOf(recipient), _rescueAmount);
  }

  /// The owner can rescue ERC-721 tokens accidentally sent to the contract.
  function test_rescueERC721_asOwner_succeeds () public {

    // Mint an NFT to the token contract.
    uint256 _tokenId = 42;
    mockNFT.mint(address(token), _tokenId);
    assertEq(mockNFT.ownerOf(_tokenId), address(token));

    // Owner rescues the NFT.
    token.rescueERC721(address(mockNFT), recipient, _tokenId);
    assertEq(mockNFT.ownerOf(_tokenId), recipient);
  }

  /// A non-owner cannot rescue ERC-721 tokens.
  function test_rescueERC721_asNonOwner_reverts () public {

    // Mint an NFT to the token contract.
    uint256 _tokenId = 42;
    mockNFT.mint(address(token), _tokenId);

    // Non-owner tries to rescue NFT.
    vm.prank(recipient);
    vm.expectRevert(Lifebuoy.RescueUnauthorizedOrLocked.selector);
    token.rescueERC721(address(mockNFT), recipient, _tokenId);
  }

  /// The owner can lock rescue functions.
  function test_lockRescue_asOwner_succeeds () public {

    // Lock ETH rescue. _LIFEBUOY_RESCUE_ETH_LOCK
    uint256 _ethLock = 1 << 3;
    token.lockRescue(_ethLock);
    assertTrue(token.rescueLocked() & _ethLock != 0);
  }

  /// After locking, the rescue function reverts.
  function test_rescueETH_afterLock_reverts () public {

    // Send ETH to the token contract.
    uint256 _amount = 1 ether;
    vm.deal(address(token), _amount);

    // Lock ETH rescue. _LIFEBUOY_RESCUE_ETH_LOCK
    uint256 _ethLock = 1 << 3;
    token.lockRescue(_ethLock);

    // Owner tries to rescue ETH but is locked out.
    vm.expectRevert(Lifebuoy.RescueUnauthorizedOrLocked.selector);
    token.rescueETH(recipient, _amount);
  }

  /// After locking ERC20 rescue, it still blocks WETH with the custom error.
  function test_rescueERC20_vaultAsset_afterLock_reverts () public {

    // Lock ERC20 rescue. _LIFEBUOY_RESCUE_ERC20_LOCK
    uint256 _erc20Lock = 1 << 4;
    token.lockRescue(_erc20Lock);

    // Mint WETH to the token contract.
    weth.mint(address(token), 1 ether);

    // Even without lock, WETH rescue would fail. With lock, generic error.
    vm.expectRevert(Lifebuoy.RescueUnauthorizedOrLocked.selector);
    token.rescueERC20(address(weth), recipient, 1 ether);
  }

  /// Locks are permanent and additive.
  function test_lockRescue_permanent () public {

    // Lock ETH rescue.
    uint256 _ethLock = 1 << 3;
    token.lockRescue(_ethLock);

    // Lock ERC20 rescue.
    uint256 _erc20Lock = 1 << 4;
    token.lockRescue(_erc20Lock);

    // Both are locked.
    uint256 _locks = token.rescueLocked();
    assertTrue(_locks & _ethLock != 0);
    assertTrue(_locks & _erc20Lock != 0);
  }

  /**
    WETH sent to the contract increases the redemption value for token holders.
  */
  function test_wethSentToContract_increasesRedemptionValue () public {

    // Get initial total assets.
    uint256 _initialAssets = token.totalAssets();

    // Someone accidentally sends WETH to the contract.
    uint256 _accidentalAmount = 10 ether;
    weth.mint(address(token), _accidentalAmount);

    // Total assets increases (benefiting all token holders).
    assertEq(token.totalAssets(), _initialAssets + _accidentalAmount);

    // Owner cannot steal this WETH.
    vm.expectRevert(Sigil.CannotRescueVaultAsset.selector);
    token.rescueERC20(address(weth), recipient, _accidentalAmount);
  }

  /// The WETH protection is hardcoded and cannot be bypassed.
  function test_wethProtection_cannotBeBypassed () public {

    /*
      Even if owner locks then unlocks (impossible), the check is in code. This
      test verifies the check exists regardless of lock state. Nothing locked
      initially.
    */
    assertEq(token.rescueLocked(), 0);

    // WETH rescue still fails.
    weth.mint(address(token), 1 ether);
    vm.expectRevert(Sigil.CannotRescueVaultAsset.selector);
    token.rescueERC20(address(weth), recipient, 1 ether);
  }

  /// The owner can rescue SIGIL tokens accidentally sent to the contract.
  function test_rescueERC20_sigilTokens_succeeds () public {

    // Someone accidentally sends SIGIL tokens to the SIGIL contract.
    uint256 _amount = 100 ether;
    token.transfer(address(token), _amount);
    assertEq(token.balanceOf(address(token)), _amount);

    // Owner can rescue these tokens (SIGIL != WETH).
    token.rescueERC20(address(token), recipient, _amount);
    assertEq(token.balanceOf(address(token)), 0);
    assertEq(token.balanceOf(recipient), _amount);
  }

  /// The owner can rescue ERC-1155 tokens accidentally sent to the contract.
  function test_rescueERC1155_asOwner_succeeds () public {

    // Mint ERC-1155 tokens to the token contract.
    uint256 _id = 1;
    uint256 _amount = 100;
    mockERC1155.mint(address(token), _id, _amount);
    assertEq(mockERC1155.balanceOf(address(token), _id), _amount);

    // Owner rescues the tokens.
    token.rescueERC1155(address(mockERC1155), recipient, _id, _amount, "");
    assertEq(mockERC1155.balanceOf(address(token), _id), 0);
    assertEq(mockERC1155.balanceOf(recipient, _id), _amount);
  }

  /// A non-owner cannot rescue ERC-1155 tokens.
  function test_rescueERC1155_asNonOwner_reverts () public {

    // Mint ERC-1155 tokens to the token contract.
    uint256 _id = 1;
    uint256 _amount = 100;
    mockERC1155.mint(address(token), _id, _amount);

    // Non-owner tries to rescue tokens.
    vm.prank(recipient);
    vm.expectRevert(Lifebuoy.RescueUnauthorizedOrLocked.selector);
    token.rescueERC1155(address(mockERC1155), recipient, _id, _amount, "");
  }

  /// The owner can rescue ERC-6909 tokens accidentally sent to the contract.
  function test_rescueERC6909_asOwner_succeeds () public {

    // Mint ERC-6909 tokens to the token contract.
    uint256 _id = 42;
    uint256 _amount = 500;
    mockERC6909.mint(address(token), _id, _amount);
    assertEq(mockERC6909.balanceOf(address(token), _id), _amount);

    // Owner rescues the tokens.
    token.rescueERC6909(address(mockERC6909), recipient, _id, _amount);
    assertEq(mockERC6909.balanceOf(address(token), _id), 0);
    assertEq(mockERC6909.balanceOf(recipient, _id), _amount);
  }

  /// A non-owner cannot rescue ERC-6909 tokens.
  function test_rescueERC6909_asNonOwner_reverts () public {

    // Mint ERC-6909 tokens to the token contract.
    uint256 _id = 42;
    uint256 _amount = 500;
    mockERC6909.mint(address(token), _id, _amount);

    // Non-owner tries to rescue tokens.
    vm.prank(recipient);
    vm.expectRevert(Lifebuoy.RescueUnauthorizedOrLocked.selector);
    token.rescueERC6909(address(mockERC6909), recipient, _id, _amount);
  }

  /// Rescuing zero ETH succeeds (no-op).
  function test_rescueETH_zeroAmount_succeeds () public {
    uint256 _recipientBalanceBefore = recipient.balance;
    token.rescueETH(recipient, 0);
    assertEq(recipient.balance, _recipientBalanceBefore);
  }

  /// Rescuing zero ERC-20 tokens succeeds (no-op).
  function test_rescueERC20_zeroAmount_succeeds () public {
    token.rescueERC20(address(mockToken), recipient, 0);
    assertEq(mockToken.balanceOf(recipient), 0);
  }

  /// Rescuing more ETH than available reverts.
  function test_rescueETH_moreThanBalance_reverts () public {

    // Send 1 ETH to the token contract.
    vm.deal(address(token), 1 ether);

    // Try to rescue 2 ETH.
    vm.expectRevert(Lifebuoy.RescueTransferFailed.selector);
    token.rescueETH(recipient, 2 ether);
  }

  /// Rescuing more ERC-20 tokens than available reverts.
  function test_rescueERC20_moreThanBalance_reverts () public {

    // Mint 100 tokens to the token contract.
    mockToken.mint(address(token), 100 ether);

    // Try to rescue 200 tokens.
    vm.expectRevert(Lifebuoy.RescueTransferFailed.selector);
    token.rescueERC20(address(mockToken), recipient, 200 ether);
  }

  /// Locking owner access prevents owner from rescuing.
  function test_lockRescue_ownerAccess_preventsRescue () public {

    // Send ETH to the token contract.
    vm.deal(address(token), 1 ether);

    // Lock owner access. _LIFEBUOY_OWNER_ACCESS_LOCK
    uint256 _ownerLock = 1 << 1;
    token.lockRescue(_ownerLock);

    // Owner can no longer rescue.
    vm.expectRevert(Lifebuoy.RescueUnauthorizedOrLocked.selector);
    token.rescueETH(recipient, 1 ether);
  }

  /// Locking deployer access still allows owner to rescue.
  function test_lockRescue_deployerAccess_ownerCanStillRescue () public {

    // Send ETH to the token contract.
    vm.deal(address(token), 1 ether);

    // Lock deployer access. _LIFEBUOY_DEPLOYER_ACCESS_LOCK
    uint256 _deployerLock = 1 << 0;
    token.lockRescue(_deployerLock);

    // Owner can still rescue (owner access not locked).
    token.rescueETH(recipient, 1 ether);
    assertEq(recipient.balance, 1 ether);
  }

  /// Locking the lock function prevents further locks.
  function test_lockRescue_lockFunction_preventsMoreLocks () public {

    // Lock the lock function. _LIFEBUOY_LOCK_RESCUE_LOCK
    uint256 _lockLock = 1 << 2;
    token.lockRescue(_lockLock);

    // Try to lock ETH rescue.
    uint256 _ethLock = 1 << 3;
    vm.expectRevert(Lifebuoy.RescueUnauthorizedOrLocked.selector);
    token.lockRescue(_ethLock);
  }

  /// Locking ERC1155 rescue prevents rescuing ERC1155.
  function test_rescueERC1155_afterLock_reverts () public {

    // Mint ERC-1155 tokens to the token contract.
    mockERC1155.mint(address(token), 1, 100);

    // Lock ERC1155 rescue. _LIFEBUOY_RESCUE_ERC1155_LOCK
    uint256 _erc1155Lock = 1 << 6;
    token.lockRescue(_erc1155Lock);

    // Owner cannot rescue.
    vm.expectRevert(Lifebuoy.RescueUnauthorizedOrLocked.selector);
    token.rescueERC1155(address(mockERC1155), recipient, 1, 100, "");
  }

  /// Locking ERC6909 rescue prevents rescuing ERC6909.
  function test_rescueERC6909_afterLock_reverts () public {

    // Mint ERC-6909 tokens to the token contract.
    mockERC6909.mint(address(token), 42, 500);

    // Lock ERC6909 rescue. _LIFEBUOY_RESCUE_ERC6909_LOCK
    uint256 _erc6909Lock = 1 << 7;
    token.lockRescue(_erc6909Lock);

    // Owner cannot rescue.
    vm.expectRevert(Lifebuoy.RescueUnauthorizedOrLocked.selector);
    token.rescueERC6909(address(mockERC6909), recipient, 42, 500);
  }

  /// Locking ERC721 rescue prevents rescuing ERC721.
  function test_rescueERC721_afterLock_reverts () public {

    // Mint an NFT to the token contract.
    mockNFT.mint(address(token), 99);

    // Lock ERC721 rescue. _LIFEBUOY_RESCUE_ERC721_LOCK
    uint256 _erc721Lock = 1 << 5;
    token.lockRescue(_erc721Lock);

    // Owner cannot rescue.
    vm.expectRevert(Lifebuoy.RescueUnauthorizedOrLocked.selector);
    token.rescueERC721(address(mockNFT), recipient, 99);
  }
}

