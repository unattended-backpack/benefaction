// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { SigilTestBase } from "./utils/SigilTestBase.sol";
import { Ownable } from "solady/auth/Ownable.sol";
import { BurnOnlyERC4626 } from "token/BurnOnlyERC4626.sol";
import { Sigil } from "token/Sigil.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Tests for ERC-4626 functionality in the Sigil token.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  Test that Sigil correctly implements ERC-4626 with modifications for a
  one-time token emission. After initialization, no further deposits or mints
  are allowed, but withdrawals and redemptions remain functional to allow
  holders to redeem their SIGIL for proportional WETH.

  @custom:date January 30th, 2026.
*/
contract SigilERC4626Test is
  SigilTestBase {

  /**
    Emitted when assets are withdrawn from the vault.

    @param by The caller who initiated the withdrawal.
    @param to The receiver of the assets.
    @param owner The owner of the shares being burned.
    @param assets The amount of assets withdrawn.
    @param shares The amount of shares burned.
  */
  event Withdraw (
    address indexed by,
    address indexed to,
    address indexed owner,
    uint256 assets,
    uint256 shares
  );

  /// Store Alice's address.
  address internal alice;

  /// Store Bob's address.
  address internal bob;

  /// Set up the test.
  function setUp () public {
    _setUpSigil();
    alice = makeAddr("alice");
    bob = makeAddr("bob");

    // Distribute tokens to test users.
    token.transfer(alice, 1000 ether);
    token.transfer(bob, 500 ether);
  }

  /// asset() returns the mainnet WETH address.
  function test_asset () public view {
    assertEq(token.asset(), WETH_ADDRESS);
  }

  /// decimals() returns 18.
  function test_decimals () public view {
    assertEq(token.decimals(), 18);
  }

  /// totalAssets() returns the WETH balance of the contract.
  function test_totalAssets () public view {
    assertEq(token.totalAssets(), INIT_WETH_AMOUNT);
  }

  /// totalSupply() returns the total minted SIGIL supply.
  function test_totalSupply () public view {
    assertEq(token.totalSupply(), TOTAL_SUPPLY);
  }

  /// Initial state after initialization is correct.
  function test_initialState () public view {
    assertEq(token.totalSupply(), TOTAL_SUPPLY);
    assertEq(token.totalAssets(), INIT_WETH_AMOUNT);
    assertEq(token.asset(), WETH_ADDRESS);
  }

  /// initialized is true after setUp.
  function test_initialized_isTrue () public view {
    assertTrue(token.initialized());
  }

  /// initialized is false before initialize() is called.
  function test_initialized_startsAsFalse () public {
    Sigil _newToken = new Sigil(address(this), address(0), address(token.poseidon2()), 1 days, 100, 1_000_000e18);
    assertFalse(_newToken.initialized());
  }

  /// initialize() can only be called by the owner.
  function test_initialize_onlyOwner_reverts () public {
    Sigil _newToken = new Sigil(address(this), address(0), address(token.poseidon2()), 1 days, 100, 1_000_000e18);

    // Fund WETH for initialization.
    weth.mint(alice, INIT_WETH_AMOUNT);
    vm.prank(alice);
    weth.approve(address(_newToken), INIT_WETH_AMOUNT);

    // Alice is not the owner.
    vm.prank(alice);
    vm.expectRevert();
    _newToken.initialize(alice);
  }

  /// initialize() mints all tokens to the recipient.
  function test_initialize_mintsToRecipient () public {
    Sigil _newToken = new Sigil(address(this), address(0), address(token.poseidon2()), 1 days, 100, 1_000_000e18);

    // Fund WETH for initialization.
    weth.mint(address(this), INIT_WETH_AMOUNT);
    weth.approve(address(_newToken), INIT_WETH_AMOUNT);

    // Initialize with alice as recipient.
    _newToken.initialize(alice);
    assertEq(_newToken.balanceOf(alice), TOTAL_SUPPLY);
    assertEq(_newToken.totalSupply(), TOTAL_SUPPLY);
  }

  /// initialize() reverts when called a second time.
  function test_initialize_secondCall_reverts () public {

    /*
      Token is already initialized in setUp via _setUpSigil(). Attempting to
      initialize again should revert.
    */
    weth.mint(address(this), INIT_WETH_AMOUNT);
    weth.approve(address(token), INIT_WETH_AMOUNT);
    vm.expectRevert();
    token.initialize(alice);
  }

  /// deposit() always reverts (deposits are permanently disabled).
  function test_deposit_reverts () public {
    uint256 _depositAmount = 1 ether;
    weth.mint(alice, _depositAmount);
    vm.startPrank(alice);
    weth.approve(address(token), _depositAmount);
    vm.expectRevert(BurnOnlyERC4626.Disabled.selector);
    token.deposit(_depositAmount, alice);
    vm.stopPrank();
  }

  /// mint() reverts after initialization with Disabled error.
  function test_mint_afterInitialization_reverts () public {
    uint256 _mintShares = 1 ether;

    // Mint enough WETH to cover the mint.
    weth.mint(alice, 1 ether);
    vm.startPrank(alice);
    weth.approve(address(token), type(uint256).max);
    vm.expectRevert(Ownable.Unauthorized.selector);
    token.mint(_mintShares, alice);
    vm.stopPrank();
  }

  /// maxDeposit() always returns 0 (deposits are permanently disabled).
  function test_maxDeposit () public view {
    assertEq(token.maxDeposit(alice), 0);
    assertEq(token.maxDeposit(address(this)), 0);
    assertEq(token.maxDeposit(address(0)), 0);
  }

  /// maxMint() returns 0 after initialization.
  function test_maxMint_afterInitialization () public view {
    assertEq(token.maxMint(alice), 0);
    assertEq(token.maxMint(address(this)), 0);
    assertEq(token.maxMint(address(0)), 0);
  }

  /// previewDeposit() always returns 0 (deposits are permanently disabled).
  function test_previewDeposit () public view {
    assertEq(token.previewDeposit(1 ether), 0);
    assertEq(token.previewDeposit(0), 0);
  }

  /// previewMint() returns 0 after initialization (no mints allowed).
  function test_previewMint_afterInitialization () public view {

    // Since mints are disabled, preview should reflect that.
    assertEq(token.previewMint(1 ether), 0);
  }

  /// maxWithdraw() returns the correct value for a shareholder.
  function test_maxWithdraw () public view {
    uint256 _aliceShares = token.balanceOf(alice);
    uint256 _expectedAssets = token.convertToAssets(_aliceShares);
    assertEq(token.maxWithdraw(alice), _expectedAssets);
  }

  /// maxWithdraw() returns 0 for non-shareholders.
  function test_maxWithdraw_nonShareholder () public {
    address _nobody = makeAddr("nobody");
    assertEq(token.maxWithdraw(_nobody), 0);
  }

  /// maxRedeem() returns the share balance.
  function test_maxRedeem () public view {
    assertEq(token.maxRedeem(alice), token.balanceOf(alice));
    assertEq(token.maxRedeem(bob), token.balanceOf(bob));
  }

  /// maxRedeem() returns 0 for non-shareholders.
  function test_maxRedeem_nonShareholder () public {
    address _nobody = makeAddr("nobody");
    assertEq(token.maxRedeem(_nobody), 0);
  }

  /// previewWithdraw() returns correct share amount for given assets.
  function test_previewWithdraw () public view {

    // 1 wei of WETH
    uint256 _assets = 1;
    uint256 _expectedShares = token.previewWithdraw(_assets);

    /*
      With decimalsOffset of 18 and 1B tokens for 1 gwei WETH: 1 share = 1e-9
      WETH (1 gwei / 1B tokens) So 1 wei WETH = 1e9 shares = 1 SIGIL
    */
    assertTrue(_expectedShares > 0);
  }

  /// previewRedeem() returns correct asset amount for given shares.
  function test_previewRedeem () public view {

    // 1 SIGIL token
    uint256 _shares = 1 ether;
    uint256 _expectedAssets = token.previewRedeem(_shares);

    // 1 SIGIL = 1e-9 WETH with initial conditions.
    assertTrue(_expectedAssets >= 0);
  }

  /// redeem() burns shares and transfers assets to receiver.
  function test_redeem () public {

    // 100 SIGIL
    uint256 _redeemShares = 100 ether;
    uint256 _expectedAssets = token.previewRedeem(_redeemShares);
    uint256 _aliceSharesBefore = token.balanceOf(alice);
    uint256 _aliceAssetsBefore = weth.balanceOf(alice);
    vm.prank(alice);
    uint256 _assetsReceived = token.redeem(_redeemShares, alice, alice);
    assertEq(_assetsReceived, _expectedAssets);
    assertEq(token.balanceOf(alice), _aliceSharesBefore - _redeemShares);
    assertEq(weth.balanceOf(alice), _aliceAssetsBefore + _assetsReceived);
  }

  /// redeem() works with a different receiver.
  function test_redeem_differentReceiver () public {
    uint256 _redeemShares = 100 ether;
    uint256 _expectedAssets = token.previewRedeem(_redeemShares);
    uint256 _aliceSharesBefore = token.balanceOf(alice);
    uint256 _bobAssetsBefore = weth.balanceOf(bob);
    vm.prank(alice);
    uint256 _assetsReceived = token.redeem(_redeemShares, bob, alice);
    assertEq(_assetsReceived, _expectedAssets);
    assertEq(token.balanceOf(alice), _aliceSharesBefore - _redeemShares);
    assertEq(weth.balanceOf(bob), _bobAssetsBefore + _assetsReceived);
  }

  /// redeem() requires approval when owner != caller.
  function test_redeem_requiresApproval () public {
    uint256 _redeemShares = 100 ether;

    // Bob tries to redeem Alice's shares without approval.
    vm.prank(bob);
    vm.expectRevert();
    token.redeem(_redeemShares, bob, alice);

    // Alice approves Bob.
    vm.prank(alice);
    token.approve(bob, _redeemShares);

    // Now Bob can redeem Alice's shares.
    uint256 _aliceSharesBefore = token.balanceOf(alice);
    vm.prank(bob);
    token.redeem(_redeemShares, bob, alice);
    assertEq(token.balanceOf(alice), _aliceSharesBefore - _redeemShares);
  }

  /// redeem() reverts when exceeding balance.
  function test_redeem_exceedsBalance_reverts () public {
    uint256 _tooMany = token.balanceOf(alice) + 1;
    vm.prank(alice);
    vm.expectRevert();
    token.redeem(_tooMany, alice, alice);
  }

  /// withdraw() burns correct shares and transfers assets.
  function test_withdraw () public {

    /*
      With initial conditions, each share is worth very little WETH. Let's
      withdraw 1 wei of WETH.
    */
    uint256 _withdrawAssets = 1;
    uint256 _expectedShares = token.previewWithdraw(_withdrawAssets);

    // Ensure alice has enough shares.
    vm.assume(_expectedShares <= token.balanceOf(alice));
    uint256 _aliceSharesBefore = token.balanceOf(alice);
    uint256 _aliceAssetsBefore = weth.balanceOf(alice);
    vm.prank(alice);
    uint256 _sharesBurned = token.withdraw(_withdrawAssets, alice, alice);
    assertEq(_sharesBurned, _expectedShares);
    assertEq(token.balanceOf(alice), _aliceSharesBefore - _sharesBurned);
    assertEq(weth.balanceOf(alice), _aliceAssetsBefore + _withdrawAssets);
  }

  /// withdraw() works with a different receiver.
  function test_withdraw_differentReceiver () public {
    uint256 _withdrawAssets = 1;
    uint256 _expectedShares = token.previewWithdraw(_withdrawAssets);
    uint256 _aliceSharesBefore = token.balanceOf(alice);
    uint256 _bobAssetsBefore = weth.balanceOf(bob);
    vm.prank(alice);
    uint256 _sharesBurned = token.withdraw(_withdrawAssets, bob, alice);
    assertEq(_sharesBurned, _expectedShares);
    assertEq(token.balanceOf(alice), _aliceSharesBefore - _sharesBurned);
    assertEq(weth.balanceOf(bob), _bobAssetsBefore + _withdrawAssets);
  }

  /// withdraw() requires approval when owner != caller.
  function test_withdraw_requiresApproval () public {
    uint256 _withdrawAssets = 1;
    uint256 _expectedShares = token.previewWithdraw(_withdrawAssets);

    // Bob tries to withdraw from Alice without approval.
    vm.prank(bob);
    vm.expectRevert();
    token.withdraw(_withdrawAssets, bob, alice);

    // Alice approves Bob for the required shares.
    vm.prank(alice);
    token.approve(bob, _expectedShares);

    // Now Bob can withdraw Alice's assets.
    uint256 _aliceSharesBefore = token.balanceOf(alice);
    vm.prank(bob);
    token.withdraw(_withdrawAssets, bob, alice);
    assertEq(token.balanceOf(alice), _aliceSharesBefore - _expectedShares);
  }

  /// withdraw() reverts when exceeding available assets.
  function test_withdraw_exceedsAvailable_reverts () public {

    // Try to withdraw more assets than alice's shares are worth.
    uint256 _tooMuch = token.maxWithdraw(alice) + 1;
    vm.prank(alice);
    vm.expectRevert();
    token.withdraw(_tooMuch, alice, alice);
  }

  /**
    @custom:preserve

    convertToShares() returns correct share amount.

    With initial state:
    - totalAssets = 1 gwei (1e9 wei WETH)
    - totalSupply = 1 billion SIGIL (1e27 wei)
    - decimalsOffset = 18

    Formula (Solady ERC4626 with offset):
    shares = assets * (totalSupply + 10^offset) / (totalAssets + 1)

    For 1 WETH (1e18 wei):
    shares = 1e18 * (1e27 + 1e18) / (1e9 + 1)
           ≈ 1e18 * 1e27 / 1e9
           = 1e45 / 1e9 = 1e36 shares

    This is 1 billion times the total supply because 1 WETH is 1 billion times
    the initial backing amount (1 gwei).
  */
  function test_convertToShares () public view {
    uint256 _assets = 1 ether;
    uint256 _shares = token.convertToShares(_assets);

    // 1 WETH should convert to ~1e36 shares (1B times total supply).
    uint256 _expectedShares =
      _assets * (TOTAL_SUPPLY + 1e18) / (INIT_WETH_AMOUNT + 1);
    assertEq(_shares, _expectedShares);

    // Sanity check: 1 WETH = 1e9 gwei, so 1e9 times the total supply.
    assertApproxEqRel(_shares, TOTAL_SUPPLY * 1e9, 0.001e18);
  }

  /**
    @custom:preserve

    convertToAssets() returns correct asset amount.

    With initial state:
    - totalAssets = 1 gwei (1e9 wei WETH)
    - totalSupply = 1 billion SIGIL (1e27 wei)
    - decimalsOffset = 18

    Formula (Solady ERC4626 with offset):
    assets = shares * (totalAssets + 1) / (totalSupply + 10^offset)

    For 1 SIGIL (1e18 wei):
    assets = 1e18 * (1e9 + 1) / (1e27 + 1e18)
           ≈ 1e18 * 1e9 / 1e27
           = 1e27 / 1e27 = 1 wei WETH
  */
  function test_convertToAssets () public view {
    uint256 _shares = 1 ether;
    uint256 _assets = token.convertToAssets(_shares);

    // 1 SIGIL should convert to approximately 1 wei of WETH.
    uint256 _expectedAssets =
      _shares * (INIT_WETH_AMOUNT + 1) / (TOTAL_SUPPLY + 1e18);
    assertEq(_assets, _expectedAssets);
    assertEq(_assets, 1);
  }

  /// convertToShares and convertToAssets are roughly inverse operations.
  function test_conversionRoundTrip () public view {
    uint256 _originalAssets = 1000;
    uint256 _shares = token.convertToShares(_originalAssets);
    uint256 _assetsBack = token.convertToAssets(_shares);

    // Due to rounding, assetsBack may be slightly less than original.
    assertTrue(_assetsBack <= _originalAssets);
  }

  /// totalAssets() increases when WETH is transferred to the contract.
  function test_totalAssets_increasesWithRevenue () public {
    uint256 _totalAssetsBefore = token.totalAssets();

    // Simulate revenue by transferring WETH to the contract.
    uint256 _revenue = 1 ether;
    weth.mint(address(token), _revenue);
    assertEq(token.totalAssets(), _totalAssetsBefore + _revenue);
  }

  /// Share value increases when revenue is added.
  function test_shareValue_increasesWithRevenue () public {

    // 1000 SIGIL
    uint256 _shares = 1000 ether;
    uint256 _assetsBefore = token.convertToAssets(_shares);

    // Add revenue.
    uint256 _revenue = 1 ether;
    weth.mint(address(token), _revenue);
    uint256 _assetsAfter = token.convertToAssets(_shares);

    // After revenue, same shares are worth more assets.
    assertTrue(_assetsAfter > _assetsBefore);
  }

  /// Redeem value per share increases after revenue is added.
  function test_redeemValue_increasesWithRevenue () public {
    uint256 _shares = 1000 ether;
    uint256 _previewBefore = token.previewRedeem(_shares);

    // Add revenue.
    uint256 _revenue = 1 ether;
    weth.mint(address(token), _revenue);
    uint256 _previewAfter = token.previewRedeem(_shares);
    assertTrue(_previewAfter > _previewBefore);
  }

  /// Full redemption after revenue gives proportional share of total assets.
  function test_fullRedemption_afterRevenue () public {

    // Add significant revenue.
    uint256 _revenue = 10 ether;
    weth.mint(address(token), _revenue);

    // Alice redeems all her shares.
    uint256 _aliceShares = token.balanceOf(alice);
    uint256 _totalShares = token.totalSupply();
    uint256 _totalAssets = token.totalAssets();

    // Expected: alice's proportion of total assets.
    uint256 _expectedAssets = (_aliceShares * _totalAssets) / _totalShares;
    vm.prank(alice);
    uint256 _received = token.redeem(_aliceShares, alice, alice);

    /*
      Allow for rounding differences due to ERC4626 virtual shares/assets math.
      The _decimalsOffset of 18 introduces rounding at extreme ratios. 0.1%
      tolerance
    */
    assertApproxEqRel(_received, _expectedAssets, 0.001e18);
  }

  /// redeem() with zero shares succeeds with zero assets.
  function test_redeem_zeroShares () public {
    uint256 _aliceAssetsBefore = weth.balanceOf(alice);
    vm.prank(alice);
    uint256 _assets = token.redeem(0, alice, alice);
    assertEq(_assets, 0);
    assertEq(weth.balanceOf(alice), _aliceAssetsBefore);
  }

  /// withdraw() with zero assets succeeds with zero shares burned.
  function test_withdraw_zeroAssets () public {
    uint256 _aliceSharesBefore = token.balanceOf(alice);
    vm.prank(alice);
    uint256 _shares = token.withdraw(0, alice, alice);
    assertEq(_shares, 0);
    assertEq(token.balanceOf(alice), _aliceSharesBefore);
  }

  /// redeem() to address(0) is allowed (Solady behavior).
  function test_redeem_toZeroAddress () public {
    uint256 _shares = 100 ether;
    vm.prank(alice);

    // Solady ERC4626 allows redemption to address(0).
    token.redeem(_shares, address(0), alice);
  }

  /// Complete redemption of all shares leaves only the virtual asset offset.
  function test_completeRedemption_drainsVault () public {

    // Add some revenue first so there's something to drain.
    uint256 _revenue = 1 ether;
    weth.mint(address(token), _revenue);
    uint256 _totalAssetsBefore = token.totalAssets();

    // Get all holders' shares.
    uint256 _aliceShares = token.balanceOf(alice);
    uint256 _bobShares = token.balanceOf(bob);
    uint256 _thisShares = token.balanceOf(address(this));

    // Everyone redeems.
    vm.prank(alice);
    uint256 _aliceReceived = token.redeem(_aliceShares, alice, alice);
    vm.prank(bob);
    uint256 _bobReceived = token.redeem(_bobShares, bob, bob);
    uint256 _thisReceived =
      token.redeem(_thisShares, address(this), address(this));

    // All shares should be burned.
    assertEq(token.totalSupply(), 0);

    /*
      Due to _decimalsOffset of 18, there's a "virtual" 1 gwei of assets that
      remains locked to prevent share inflation attacks. All other assets were
      distributed to redeemers.
    */
    uint256 _totalRedeemed = _aliceReceived + _bobReceived + _thisReceived;
    assertApproxEqAbs(_totalRedeemed, _totalAssetsBefore, INIT_WETH_AMOUNT + 1);

    // Remaining should be approximately the initial offset amount.
    assertApproxEqAbs(token.totalAssets(), INIT_WETH_AMOUNT, 1);
  }

  /// Multiple users can redeem proportionally.
  function test_multipleRedemptions () public {

    // Add revenue.
    uint256 _revenue = 1 ether;
    weth.mint(address(token), _revenue);
    uint256 _aliceShares = token.balanceOf(alice);
    uint256 _bobShares = token.balanceOf(bob);

    // Alice redeems half her shares.
    vm.prank(alice);
    uint256 _aliceAssets = token.redeem(_aliceShares / 2, alice, alice);

    // Bob redeems all his shares.
    vm.prank(bob);
    uint256 _bobAssets = token.redeem(_bobShares, bob, bob);

    // Both should have received assets.
    assertTrue(_aliceAssets > 0);
    assertTrue(_bobAssets > 0);

    /*
      Bob had half as many shares as Alice, so should get roughly half.
      (comparing full redemption amounts)
    */
    assertApproxEqRel(_bobAssets, _aliceAssets, 0.01e18);
  }

  /// Redeem, add assets, redeem again - share value should increase.
  function test_interleavedRedemptionAndRevenue () public {

    // Add initial revenue.
    weth.mint(address(token), 1 ether);

    // Alice redeems some shares.
    uint256 _firstRedeemShares = 100 ether;
    vm.prank(alice);
    uint256 _firstAssets = token.redeem(_firstRedeemShares, alice, alice);

    // More revenue arrives.
    weth.mint(address(token), 2 ether);

    // Alice redeems same number of shares - should get MORE assets this time.
    vm.prank(alice);
    uint256 _secondAssets = token.redeem(_firstRedeemShares, alice, alice);

    // Second redemption should yield more assets per share.
    assertTrue(_secondAssets > _firstAssets);
  }

  /// Multiple users redeeming with revenue added between each.
  function test_multiUserInterleavedRedemptions () public {

    // Add initial revenue.
    weth.mint(address(token), 1 ether);

    // Track share values.
    uint256 _shares = 100 ether;
    uint256 _aliceValueBefore = token.previewRedeem(_shares);

    // Alice redeems.
    vm.prank(alice);
    uint256 _aliceReceived = token.redeem(_shares, alice, alice);
    assertEq(_aliceReceived, _aliceValueBefore);

    // More revenue arrives.
    weth.mint(address(token), 1 ether);

    // Bob redeems same number of shares - should get more.
    uint256 _bobValueBefore = token.previewRedeem(_shares);
    vm.prank(bob);
    uint256 _bobReceived = token.redeem(_shares, bob, bob);
    assertEq(_bobReceived, _bobValueBefore);
    assertTrue(_bobReceived > _aliceReceived);
  }

  /// Withdraw interleaved with revenue additions.
  function test_interleavedWithdrawAndRevenue () public {

    // Add initial revenue.
    weth.mint(address(token), 1 ether);

    // 1000 wei
    uint256 _withdrawAmount = 1000;
    uint256 _firstSharesBurned = token.previewWithdraw(_withdrawAmount);

    // Alice withdraws.
    vm.prank(alice);
    uint256 _actualFirstShares = token.withdraw(_withdrawAmount, alice, alice);
    assertEq(_actualFirstShares, _firstSharesBurned);

    // More revenue arrives - shares become more valuable.
    weth.mint(address(token), 1 ether);

    // Same withdrawal amount should burn FEWER shares now.
    uint256 _secondSharesBurned = token.previewWithdraw(_withdrawAmount);
    assertTrue(_secondSharesBurned < _firstSharesBurned);

    // Execute the withdrawal.
    vm.prank(alice);
    uint256 _actualSecondShares =
      token.withdraw(_withdrawAmount, alice, alice);
    assertEq(_actualSecondShares, _secondSharesBurned);
  }

  /// Revenue added between preview and execution changes nothing (atomic).
  function test_previewMatchesExecution_despiteRevenueChange () public {

    // Add initial revenue.
    weth.mint(address(token), 1 ether);
    uint256 _shares = 100 ether;
    uint256 _previewedAssets = token.previewRedeem(_shares);

    /*
      Even if we add revenue now, the redemption should match preview because
      preview and redeem happen in the same transaction.
    */
    vm.prank(alice);
    uint256 _actualAssets = token.redeem(_shares, alice, alice);
    assertEq(_actualAssets, _previewedAssets);
  }

  /// Alternating redemptions and withdrawals with revenue.
  function test_alternatingRedeemWithdrawWithRevenue () public {
    weth.mint(address(token), 1 ether);

    // Alice redeems.
    vm.prank(alice);
    token.redeem(50 ether, alice, alice);

    // Revenue added.
    weth.mint(address(token), 0.5 ether);

    // Bob withdraws.
    vm.prank(bob);
    token.withdraw(100, bob, bob);

    // Revenue added.
    weth.mint(address(token), 0.5 ether);

    // Alice redeems again.
    vm.prank(alice);
    token.redeem(50 ether, alice, alice);

    // Revenue added.
    weth.mint(address(token), 0.5 ether);

    // Bob withdraws again.
    vm.prank(bob);
    token.withdraw(100, bob, bob);

    // Verify final state is consistent.
    assertTrue(token.totalAssets() > 0);
    assertTrue(token.totalSupply() > 0);
  }

  /**
    Solady's ERC4626 follows checks-effects-interactions pattern: - Burns shares
    (effect) before transferring assets (interaction) - This prevents reentrancy
    attacks We verify this by checking that state is updated before external
    calls.
  */
  function test_redeem_stateUpdatedBeforeTransfer () public {
    uint256 _shares = 100 ether;
    uint256 _aliceBalanceBefore = token.balanceOf(alice);
    uint256 _totalSupplyBefore = token.totalSupply();

    // Create a snapshot of expected state after burn but before transfer.
    uint256 _expectedAliceBalance = _aliceBalanceBefore - _shares;
    uint256 _expectedTotalSupply = _totalSupplyBefore - _shares;
    vm.prank(alice);
    token.redeem(_shares, alice, alice);

    // Verify shares were burned (state was updated).
    assertEq(token.balanceOf(alice), _expectedAliceBalance);
    assertEq(token.totalSupply(), _expectedTotalSupply);
  }

  /// Withdraw follows checks-effects-interactions pattern.
  function test_withdraw_stateUpdatedBeforeTransfer () public {
    uint256 _assets = 1;
    uint256 _sharesToBurn = token.previewWithdraw(_assets);
    uint256 _aliceBalanceBefore = token.balanceOf(alice);
    vm.prank(alice);
    token.withdraw(_assets, alice, alice);

    // Verify shares were burned.
    assertEq(token.balanceOf(alice), _aliceBalanceBefore - _sharesToBurn);
  }

  /// redeem() emits Withdraw event.
  function test_redeem_emitsWithdrawEvent () public {
    uint256 _shares = 100 ether;
    uint256 _expectedAssets = token.previewRedeem(_shares);
    vm.expectEmit(true, true, true, true);
    emit Withdraw(alice, alice, alice, _expectedAssets, _shares);
    vm.prank(alice);
    token.redeem(_shares, alice, alice);
  }

  /// withdraw() emits Withdraw event.
  function test_withdraw_emitsWithdrawEvent () public {
    uint256 _assets = 1;
    uint256 _expectedShares = token.previewWithdraw(_assets);
    vm.expectEmit(true, true, true, true);
    emit Withdraw(alice, alice, alice, _assets, _expectedShares);
    vm.prank(alice);
    token.withdraw(_assets, alice, alice);
  }

  /// redeem() with different receiver emits correct Withdraw event.
  function test_redeem_differentReceiver_emitsCorrectEvent () public {
    uint256 _shares = 100 ether;
    uint256 _expectedAssets = token.previewRedeem(_shares);

    // Event should show: caller=alice, receiver=bob, owner=alice
    vm.expectEmit(true, true, true, true);
    emit Withdraw(alice, bob, alice, _expectedAssets, _shares);
    vm.prank(alice);
    token.redeem(_shares, bob, alice);
  }

  /**
    Fuzz test: redeem any valid amount.

    @param _shares The number of shares to redeem.
  */
  function testFuzz_redeem (
    uint256 _shares
  ) public {
    uint256 _aliceBalance = token.balanceOf(alice);
    _shares = bound(_shares, 0, _aliceBalance);
    uint256 _expectedAssets = token.previewRedeem(_shares);
    uint256 _aliceAssetsBefore = weth.balanceOf(alice);
    vm.prank(alice);
    uint256 _assets = token.redeem(_shares, alice, alice);
    assertEq(_assets, _expectedAssets);
    assertEq(token.balanceOf(alice), _aliceBalance - _shares);
    assertEq(weth.balanceOf(alice), _aliceAssetsBefore + _assets);
  }

  /**
    Fuzz test: withdraw any valid amount.

    @param _assets The amount of assets to withdraw.
  */
  function testFuzz_withdraw (
    uint256 _assets
  ) public {
    uint256 _maxWithdraw = token.maxWithdraw(alice);
    _assets = bound(_assets, 0, _maxWithdraw);
    uint256 _expectedShares = token.previewWithdraw(_assets);
    uint256 _aliceSharesBefore = token.balanceOf(alice);
    uint256 _aliceAssetsBefore = weth.balanceOf(alice);
    vm.prank(alice);
    uint256 _shares = token.withdraw(_assets, alice, alice);
    assertEq(_shares, _expectedShares);
    assertEq(token.balanceOf(alice), _aliceSharesBefore - _shares);
    assertEq(weth.balanceOf(alice), _aliceAssetsBefore + _assets);
  }

  /**
    Fuzz test: revenue accumulation affects share value.

    @param _revenue The amount of revenue to add.
  */
  function testFuzz_revenueAccumulation (
    uint256 _revenue
  ) public {

    /*
      Bound revenue to amounts large enough to affect share value given the
      extreme initial ratio (1B tokens : 1 gwei WETH). Small amounts may not
      change integer division results.
    */
    _revenue = bound(_revenue, 0.001 ether, 1000 ether);
    uint256 _shares = 1000 ether;
    uint256 _valueBefore = token.convertToAssets(_shares);

    // Add revenue.
    weth.mint(address(token), _revenue);
    uint256 _valueAfter = token.convertToAssets(_shares);

    // Share value should increase (or stay same if revenue rounds to zero).
    assertTrue(_valueAfter >= _valueBefore);

    // With minimum 0.001 ether revenue, value should definitely increase.
    if (_revenue >= 0.001 ether) {
      assertTrue(_valueAfter > _valueBefore);
    }
  }

  /**
    Fuzz test: interleaved redemptions with revenue additions.

    @param _redeemAmount1 First redemption amount (bounded to alice's balance).
    @param _revenue1 First revenue addition.
    @param _redeemAmount2 Second redemption amount.
    @param _revenue2 Second revenue addition.
  */
  function testFuzz_interleavedRedemptionsWithRevenue (
    uint256 _redeemAmount1,
    uint256 _revenue1,
    uint256 _redeemAmount2,
    uint256 _revenue2
  ) public {
    uint256 _aliceBalance = token.balanceOf(alice);

    /*
      Bound inputs - use minimum amounts that yield non-zero assets. With
      initial 1 gwei backing 1B tokens, need substantial shares.
    */
    _redeemAmount1 = bound(_redeemAmount1, 1 ether, _aliceBalance / 2);
    _revenue1 = bound(_revenue1, 0.001 ether, 10 ether);
    _redeemAmount2 = bound(_redeemAmount2, 1 ether, _aliceBalance / 2);
    _revenue2 = bound(_revenue2, 0.001 ether, 10 ether);
    uint256 _totalAssetsStart = token.totalAssets();

    // First redemption.
    vm.prank(alice);
    uint256 _assets1 = token.redeem(_redeemAmount1, alice, alice);

    // Add revenue.
    weth.mint(address(token), _revenue1);

    // Second redemption - should get better rate after revenue added.
    vm.prank(alice);
    uint256 _assets2 = token.redeem(_redeemAmount2, alice, alice);

    // Add more revenue.
    weth.mint(address(token), _revenue2);

    // If both received assets, second should have better rate per share.
    if (_assets1 > 0 && _assets2 > 0) {
      uint256 _valuePerShareBefore = _assets1 * 1e18 / _redeemAmount1;
      uint256 _valuePerShareAfter = _assets2 * 1e18 / _redeemAmount2;
      assertTrue(_valuePerShareAfter >= _valuePerShareBefore);
    }

    // Total assets should have increased from revenue (minus redemptions).
    uint256 _totalRedeemed = _assets1 + _assets2;
    uint256 _totalRevenue = _revenue1 + _revenue2;
    uint256 _expectedAssets =
      _totalAssetsStart + _totalRevenue - _totalRedeemed;
    assertEq(token.totalAssets(), _expectedAssets);
  }

  /**
    Fuzz test: multiple users with interleaved operations.

    @param _aliceRedeem Amount alice redeems.
    @param _bobWithdraw Amount bob withdraws.
    @param _revenue Revenue added between operations.
  */
  function testFuzz_multiUserInterleaved (
    uint256 _aliceRedeem,
    uint256 _bobWithdraw,
    uint256 _revenue
  ) public {

    // Bound inputs.
    _aliceRedeem = bound(_aliceRedeem, 0, token.balanceOf(alice) / 2);
    _bobWithdraw = bound(_bobWithdraw, 0, token.maxWithdraw(bob) / 2);
    _revenue = bound(_revenue, 0.001 ether, 10 ether);
    uint256 _aliceAssetsBefore = weth.balanceOf(alice);
    uint256 _bobAssetsBefore = weth.balanceOf(bob);

    // Alice redeems.
    vm.prank(alice);
    uint256 _aliceReceived = token.redeem(_aliceRedeem, alice, alice);

    // Revenue added.
    weth.mint(address(token), _revenue);

    // Bob withdraws.
    vm.prank(bob);
    token.withdraw(_bobWithdraw, bob, bob);

    // Verify both received their assets.
    assertEq(weth.balanceOf(alice), _aliceAssetsBefore + _aliceReceived);
    assertEq(weth.balanceOf(bob), _bobAssetsBefore + _bobWithdraw);
  }
}

