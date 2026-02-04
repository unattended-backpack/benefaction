// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { MockERC1271Signer } from "./signers/MockERC1271Signer.sol";
import { SigilTestBase } from "./utils/SigilTestBase.sol";
import { IERC1363Receiver } from "token/interfaces/IERC1363Receiver.sol";
import { IERC3009 } from "token/interfaces/IERC3009.sol";
import { Sigil } from "token/Sigil.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Integration tests for complex ERC interplay in Sigil.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  Adversarial integration tests exploring potentially dangerous interactions
  between ERC-20, ERC-1363, ERC-2612, ERC-3009, ERC-5805, ERC-4626, and the
  burn extension. Written from the perspective of a security auditor looking
  for edge cases and attack vectors.

  @custom:date February 3rd, 2026.
*/
contract SigilIntegrationTest is
  SigilTestBase {

  /// Private key for Alice.
  uint256 internal constant ALICE_PK = 0xA11CE;

  /// Private key for Bob.
  uint256 internal constant BOB_PK = 0xB0B;

  /// Private key for attacker.
  uint256 internal constant ATTACKER_PK = 0xBAD;

  /// ERC-3009 transfer typehash.
  bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH =
    0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267;

  /// Burn authorization typehash.
  bytes32 public constant BURN_WITH_AUTHORIZATION_TYPEHASH =
    0x2808d214735158921f7f8a6ca28e887d7f781959759f5c1cd6645228bdfe6386;

  /// ERC-2612 permit typehash.
  bytes32 public constant PERMIT_TYPEHASH =
    0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;

  /// ERC-5805 delegation typehash.
  bytes32 public constant DELEGATION_TYPEHASH =
    0xe48329057bfd03d55e49b547132e39cffd9c1820ad7b9d4c5307691425d15adf;

  /// ERC-6492 universal signature validator.
  address internal constant EIP6492_UNIVERSAL_VALIDATOR =
    0x00007bd799e4A591FeA53f8A8a3E9f931626Ba7e;

  /// Alice's address.
  address internal alice;

  /// Bob's address.
  address internal bob;

  /// Attacker's address.
  address internal attacker;

  /// Domain separator.
  bytes32 internal DOMAIN_SEPARATOR;

  /// Set up the test environment.
  function setUp () public {
    _setUpSigil();
    alice = vm.addr(ALICE_PK);
    bob = vm.addr(BOB_PK);
    attacker = vm.addr(ATTACKER_PK);

    // Distribute tokens.
    token.transfer(alice, 10000 ether);
    token.transfer(bob, 5000 ether);

    // Cache domain separator.
    DOMAIN_SEPARATOR = token.DOMAIN_SEPARATOR();

    // Deploy ERC-6492 validator.
    vm.etch(
      EIP6492_UNIVERSAL_VALIDATOR,
      hex"36383d373d3d6020515160208051013d3d515af160203851516084018038385101606037303452813582523838523490601c34355afa34513060e01b141634fd"
    );
  }

  /**
    Verify that signing both a permit and transferWithAuthorization for the same
    tokens does not allow double-draining. Only one can succeed.
  */
  function test_integration_permitAndTransferAuth_noDoubleDrain () public {

    /*
      Alice has 10000 tokens. She signs a permit for 10000 AND a transfer
      authorization for 10000. If both could execute, 20000 would be extracted.
    */
    uint256 _aliceBalance = token.balanceOf(alice);

    // Full balance.
    uint256 _amount = _aliceBalance;

    // Alice signs a permit allowing attacker to spend ALL her tokens.
    uint256 _permitNonce = token.nonces(alice);
    uint256 _permitDeadline = block.timestamp + 1 hours;
    bytes memory _permitSig =
      _signPermit(
        ALICE_PK, alice, attacker, _amount, _permitNonce, _permitDeadline
      );

    // Alice also signs a transferWithAuthorization for ALL her tokens to Bob.
    bytes32 _transferNonce = bytes32(uint256(999));
    bytes memory _transferSig =
      _signTransferAuthorization(
        ALICE_PK, alice, bob, _amount, block.timestamp - 1,
        block.timestamp + 1 hours, _transferNonce
      );

    // Attacker executes permit first.
    vm.prank(attacker);
    token.permit(alice, attacker, _amount, _permitDeadline, _permitSig);

    // Attacker drains via transferFrom.
    vm.prank(attacker);
    token.transferFrom(alice, attacker, _amount);

    // Now the transferWithAuthorization fails - Alice has no tokens left.
    vm.expectRevert();
    token.transferWithAuthorization(
      alice, bob, _amount, block.timestamp - 1, block.timestamp + 1 hours,
      _transferNonce, _transferSig
    );

    // Alice lost exactly her full balance, not double.
    assertEq(token.balanceOf(alice), 0);
    assertEq(token.balanceOf(attacker), _aliceBalance);

    // Bob's original balance.
    assertEq(token.balanceOf(bob), 5000 ether);
  }

  /**
    Verify that delegation checkpoints remain accurate after token burns.
    Historical voting power should be preserved while current power decreases.
  */
  function test_integration_delegationAndBurn_checkpointsAccurate () public {
    uint256 _aliceBalance = token.balanceOf(alice);

    // Alice delegates to Bob.
    vm.prank(alice);
    token.delegate(bob);

    // Verify Bob has Alice's voting power.
    assertEq(token.getVotes(bob), _aliceBalance);
    assertEq(token.getVotes(alice), 0);

    // Record checkpoint.
    uint256 _checkpointBlock = block.number;
    vm.roll(block.number + 1);

    // Alice burns half her tokens.
    uint256 _burnAmount = _aliceBalance / 2;
    vm.prank(alice);
    token.burn(_burnAmount);

    // Bob's voting power should be reduced.
    assertEq(token.getVotes(bob), _aliceBalance - _burnAmount);

    // Historical checkpoint should still show original voting power.
    assertEq(token.getPastVotes(bob, _checkpointBlock), _aliceBalance);

    // Alice's balance is reduced.
    assertEq(token.balanceOf(alice), _aliceBalance - _burnAmount);
  }

  /**
    Verify that the shared nonce space between transfer and burn authorizations
    prevents both from executing with the same nonce.
  */
  function test_integration_sharedNonce_onlyOneSucceeds () public {
    uint256 _amount = 500 ether;
    bytes32 _sharedNonce = bytes32(uint256(12345));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;

    // Alice signs a transfer authorization.
    bytes memory _transferSig =
      _signTransferAuthorization(
        ALICE_PK, alice, bob, _amount, _validAfter, _validBefore, _sharedNonce
      );

    // Alice also signs a burn authorization with the SAME nonce.
    bytes memory _burnSig =
      _signBurnAuthorization(
        ALICE_PK, alice, _amount, _validAfter, _validBefore, _sharedNonce
      );
    uint256 _aliceBalanceBefore = token.balanceOf(alice);

    // Execute the transfer first.
    token.transferWithAuthorization(
      alice, bob, _amount, _validAfter, _validBefore, _sharedNonce, _transferSig
    );

    // Nonce is now used.
    assertTrue(token.authorizationState(alice, _sharedNonce));

    // Burn authorization with same nonce should fail.
    vm.expectRevert(IERC3009.AuthorizationAlreadyUsed.selector);
    token.burnWithAuthorization(
      alice, _amount, _validAfter, _validBefore, _sharedNonce, _burnSig
    );

    // Only transfer happened, not burn.
    assertEq(token.balanceOf(alice), _aliceBalanceBefore - _amount);
    assertEq(token.balanceOf(bob), 5000 ether + _amount);
  }

  /**
    Verify that nested transfers during ERC-1363 callbacks result in
    mathematically consistent balances with no tokens created or destroyed.
  */
  function test_integration_erc1363_callbackTransfer_balancesConsistent ()
    public {

    // Deploy receiver that transfers tokens back during callback.
    ReentrantReceiver _receiver = new ReentrantReceiver(address(token));
    uint256 _amount = 100 ether;

    // Give attacker some tokens.
    token.transfer(attacker, _amount);
    uint256 _totalSupplyBefore = token.totalSupply();
    uint256 _attackerBalanceBefore = token.balanceOf(attacker);
    uint256 _receiverBalanceBefore = token.balanceOf(address(_receiver));

    // Attacker calls transferAndCall to receiver.
    vm.prank(attacker);
    token.transferAndCall(address(_receiver), _amount, "");

    /*
      The receiver transferred half the tokens back during callback.
      Flow: attacker -> receiver (100), then receiver -> attacker (50).
      Net: attacker loses 50, receiver gains 50.
    */
    uint256 _callbackReturn = _amount / 2;
    assertEq(
      token.balanceOf(attacker),
      _attackerBalanceBefore - _amount + _callbackReturn,
      "Attacker balance: -100 + 50 callback return"
    );
    assertEq(
      token.balanceOf(address(_receiver)),
      _receiverBalanceBefore + _amount - _callbackReturn,
      "Receiver balance: +100 - 50 callback return"
    );

    // Total supply unchanged (no tokens created or destroyed).
    assertEq(token.totalSupply(), _totalSupplyBefore);
  }

  /**
    Verify that permit front-running by a third party does not allow them to
    steal tokens; the permit still grants approval to the intended spender.
  */
  function test_integration_permitFrontRunning_noImpact () public {
    uint256 _amount = 1000 ether;
    uint256 _nonce = token.nonces(alice);
    uint256 _deadline = block.timestamp + 1 hours;

    // Alice signs permit for Bob (not attacker).
    bytes memory _sig =
      _signPermit(ALICE_PK, alice, bob, _amount, _nonce, _deadline);

    // Attacker front-runs by submitting the permit themselves.
    vm.prank(attacker);
    token.permit(alice, bob, _amount, _deadline, _sig);

    // The permit was set correctly - Bob is approved, not attacker.
    assertEq(token.allowance(alice, bob), _amount);
    assertEq(token.allowance(alice, attacker), 0);

    // Attacker cannot steal tokens because they're not the approved spender.
    vm.prank(attacker);
    vm.expectRevert();
    token.transferFrom(alice, attacker, _amount);

    // Bob can still use the approval.
    vm.prank(bob);
    token.transferFrom(alice, bob, _amount);
    assertEq(token.balanceOf(bob), 5000 ether + _amount);
  }

  /**
    Verify that flash-loan style voting manipulation is prevented by the
    checkpoint system. Votes at snapshot blocks cannot be manipulated.
  */
  function test_integration_flashLoanVoting_noManipulation () public {

    // Attacker starts with no tokens.
    assertEq(token.balanceOf(attacker), 0);
    assertEq(token.getVotes(attacker), 0);

    // Record the current block as the "snapshot" block for governance.
    uint256 _snapshotBlock = block.number;

    // Move to next block (simulates time passing before attack).
    vm.roll(block.number + 1);

    // In a single transaction context: 1. Alice transfers tokens to attacker.
    vm.prank(alice);
    token.transfer(attacker, 5000 ether);

    // 2. Attacker self-delegates.
    vm.prank(attacker);
    token.delegate(attacker);

    // 3. Attacker has current voting power but...
    assertEq(token.getVotes(attacker), 5000 ether);

    // 4. ...getPastVotes for the snapshot block shows ZERO.
    assertEq(token.getPastVotes(attacker, _snapshotBlock), 0);

    // 5. Attacker transfers tokens back.
    vm.prank(attacker);
    token.transfer(alice, 5000 ether);

    // Attacker ends with no tokens and no voting power.
    assertEq(token.balanceOf(attacker), 0);
    assertEq(token.getVotes(attacker), 0);
  }

  /**
    Verify that redeeming tokens via ERC-4626 invalidates pending transfer
    authorizations by leaving insufficient balance.
  */
  function test_integration_redeemThenTransferAuth_failsCleanly () public {
    uint256 _aliceBalance = token.balanceOf(alice);

    // Alice signs a transfer authorization.
    bytes32 _nonce = bytes32(uint256(7777));
    bytes memory _sig =
      _signTransferAuthorization(
        ALICE_PK, alice, bob, _aliceBalance, block.timestamp - 1,
        block.timestamp + 1 hours, _nonce
      );

    // Before authorization is used, Alice redeems ALL her tokens for WETH.
    vm.prank(alice);
    token.redeem(_aliceBalance, alice, alice);

    // Alice now has 0 SIGIL but has WETH.
    assertEq(token.balanceOf(alice), 0);
    assertTrue(weth.balanceOf(alice) > 0);

    // The pending authorization should now fail.
    vm.expectRevert();
    token.transferWithAuthorization(
      alice, bob, _aliceBalance, block.timestamp - 1, block.timestamp + 1 hours,
      _nonce, _sig
    );

    // Bob's balance unchanged.
    assertEq(token.balanceOf(bob), 5000 ether);
  }

  /**
    Verify that approvals are shared between burnFrom and transferFrom; the
    total amount extracted via both methods cannot exceed the approval.
  */
  function test_integration_approvalSharedBetweenBurnAndTransfer () public {
    uint256 _approval = 1000 ether;
    uint256 _aliceBalanceBefore = token.balanceOf(alice);

    // Alice approves Bob.
    vm.prank(alice);
    token.approve(bob, _approval);

    // Bob burns 600 tokens from Alice.
    vm.prank(bob);
    token.burnFrom(alice, 600 ether);

    // Allowance reduced.
    assertEq(token.allowance(alice, bob), 400 ether);

    // Bob tries to transfer 500 (more than remaining allowance).
    vm.prank(bob);
    vm.expectRevert();
    token.transferFrom(alice, bob, 500 ether);

    // Bob transfers the remaining 400.
    vm.prank(bob);
    token.transferFrom(alice, bob, 400 ether);

    // Allowance exhausted.
    assertEq(token.allowance(alice, bob), 0);

    // Total extracted: 600 burned + 400 transferred = 1000 (matches approval).
    assertEq(token.balanceOf(alice), _aliceBalanceBefore - _approval);
  }

  /**
    Verify that signatures for one authorization type cannot be replayed for a
    different type due to distinct typehashes.
  */
  function test_integration_smartWalletSignature_noCrossReplay () public {

    // Deploy a smart wallet owned by Alice.
    MockERC1271Signer _wallet = new MockERC1271Signer(alice);
    address _walletAddr = address(_wallet);

    // Give the wallet some tokens.
    token.transfer(_walletAddr, 1000 ether);
    bytes32 _nonce = bytes32(uint256(8888));
    uint256 _amount = 500 ether;
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;

    // Sign a TRANSFER authorization from the wallet.
    bytes memory _transferSig =
      _signTransferAuthorization(
        ALICE_PK, _walletAddr, bob, _amount, _validAfter, _validBefore, _nonce
      );

    // Try to use this transfer signature for a BURN - should fail.
    vm.expectRevert();
    token.burnWithAuthorization(
      _walletAddr, _amount, _validAfter, _validBefore, _nonce, _transferSig
    );

    // The transfer signature works for its intended purpose.
    token.transferWithAuthorization(
      _walletAddr, bob, _amount, _validAfter, _validBefore, _nonce, _transferSig
    );
    assertEq(token.balanceOf(_walletAddr), 500 ether);
    assertEq(token.balanceOf(bob), 5000 ether + _amount);
  }

  /**
    Verify that delegation during an ERC-1363 callback correctly updates voting
    power for the received tokens.
  */
  function test_integration_erc1363Callback_delegationCorrect () public {

    // Deploy a receiver that self-delegates on receive.
    DelegatingReceiver _receiver = new DelegatingReceiver(address(token));
    uint256 _amount = 1000 ether;

    // Before transfer, receiver has no votes.
    assertEq(token.getVotes(address(_receiver)), 0);

    // Alice transfers via transferAndCall.
    vm.prank(alice);
    token.transferAndCall(address(_receiver), _amount, "");

    /*
      The receiver self-delegated during the callback. Verify voting power is
      correct.
    */
    assertEq(token.balanceOf(address(_receiver)), _amount);
    assertEq(token.getVotes(address(_receiver)), _amount);
  }

  /**
    Verify that race conditions between authorization execution and cancellation
    result in consistent state regardless of ordering.
  */
  function test_integration_cancelRace_stateConsistent () public {
    uint256 _amount = 1000 ether;
    bytes32 _nonce = bytes32(uint256(11111));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;

    // Alice signs a transfer authorization.
    bytes memory _transferSig =
      _signTransferAuthorization(
        ALICE_PK, alice, attacker, _amount, _validAfter, _validBefore, _nonce
      );

    // Alice also signs a cancellation.
    bytes memory _cancelSig =
      _signCancelAuthorization(ALICE_PK, alice, _nonce);

    // Scenario A: Cancellation wins the race.
    token.cancelAuthorization(alice, _nonce, _cancelSig);
    assertTrue(token.authorizationState(alice, _nonce));

    // Transfer authorization now fails.
    vm.expectRevert(IERC3009.AuthorizationAlreadyUsed.selector);
    token.transferWithAuthorization(
      alice, attacker, _amount, _validAfter, _validBefore, _nonce, _transferSig
    );

    // Scenario B: What if transfer wins? (Use different nonce)
    bytes32 _nonce2 = bytes32(uint256(11112));
    bytes memory _transferSig2 =
      _signTransferAuthorization(
        ALICE_PK, alice, bob, _amount, _validAfter, _validBefore, _nonce2
      );
    bytes memory _cancelSig2 =
      _signCancelAuthorization(ALICE_PK, alice, _nonce2);
    uint256 _aliceBalanceBefore = token.balanceOf(alice);

    // Transfer wins.
    token.transferWithAuthorization(
      alice, bob, _amount, _validAfter, _validBefore, _nonce2, _transferSig2
    );

    // Cancel now fails (nonce already used).
    vm.expectRevert(IERC3009.AuthorizationAlreadyUsed.selector);
    token.cancelAuthorization(alice, _nonce2, _cancelSig2);

    // State is consistent: transfer happened.
    assertEq(token.balanceOf(alice), _aliceBalanceBefore - _amount);
  }

  /**
    Verify that infinite approvals persist across multiple transfer and burn
    operations without decrementing.
  */
  function test_integration_infiniteApproval_persistsAcrossOperations ()
    public {
    uint256 _infinite = type(uint256).max;

    // Alice gives Bob infinite approval.
    vm.prank(alice);
    token.approve(bob, _infinite);

    // Bob performs multiple operations.
    vm.startPrank(bob);

    // Transfer 1.
    token.transferFrom(alice, bob, 100 ether);
    assertEq(token.allowance(alice, bob), _infinite);

    // Burn.
    token.burnFrom(alice, 100 ether);
    assertEq(token.allowance(alice, bob), _infinite);

    // Transfer 2.
    token.transferFrom(alice, bob, 100 ether);
    assertEq(token.allowance(alice, bob), _infinite);
    vm.stopPrank();

    // Infinite approval never decreases.
    assertEq(token.allowance(alice, bob), _infinite);
  }

  /**
    Sign an ERC-2612 permit message.

    @param _pk The private key to sign with.
    @param _owner The token owner granting approval.
    @param _spender The address being approved to spend.
    @param _value The amount to approve.
    @param _nonce The permit nonce.
    @param _deadline The deadline for the permit.

    @return _ The packed signature (r, s, v).
  */
  function _signPermit (
    uint256 _pk,
    address _owner,
    address _spender,
    uint256 _value,
    uint256 _nonce,
    uint256 _deadline
  ) internal view returns (bytes memory) {
    bytes32 _structHash =
      keccak256(
        abi.encode(
          PERMIT_TYPEHASH, _owner, _spender, _value, _nonce, _deadline
        )
      );
    bytes32 _digest =
      keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, _structHash));
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(_pk, _digest);
    return abi.encodePacked(_r, _s, _v);
  }

  /**
    Sign an ERC-3009 transferWithAuthorization message.

    @param _pk The private key to sign with.
    @param _from The address tokens are transferred from.
    @param _to The address tokens are transferred to.
    @param _amount The amount to transfer.
    @param _validAfter The earliest valid timestamp.
    @param _validBefore The latest valid timestamp.
    @param _nonce The authorization nonce.

    @return _ The packed signature (r, s, v).
  */
  function _signTransferAuthorization (
    uint256 _pk,
    address _from,
    address _to,
    uint256 _amount,
    uint256 _validAfter,
    uint256 _validBefore,
    bytes32 _nonce
  ) internal view returns (bytes memory) {
    bytes32 _structHash =
      keccak256(
        abi.encode(
          TRANSFER_WITH_AUTHORIZATION_TYPEHASH, _from, _to, _amount,
          _validAfter, _validBefore, _nonce
        )
      );
    bytes32 _digest =
      keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, _structHash));
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(_pk, _digest);
    return abi.encodePacked(_r, _s, _v);
  }

  /**
    Sign a burnWithAuthorization message.

    @param _pk The private key to sign with.
    @param _from The address tokens are burned from.
    @param _amount The amount to burn.
    @param _validAfter The earliest valid timestamp.
    @param _validBefore The latest valid timestamp.
    @param _nonce The authorization nonce.

    @return _ The packed signature (r, s, v).
  */
  function _signBurnAuthorization (
    uint256 _pk,
    address _from,
    uint256 _amount,
    uint256 _validAfter,
    uint256 _validBefore,
    bytes32 _nonce
  ) internal view returns (bytes memory) {
    bytes32 _structHash =
      keccak256(
        abi.encode(
          BURN_WITH_AUTHORIZATION_TYPEHASH, _from, _amount, _validAfter,
          _validBefore, _nonce
        )
      );
    bytes32 _digest =
      keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, _structHash));
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(_pk, _digest);
    return abi.encodePacked(_r, _s, _v);
  }

  /**
    Sign an ERC-3009 cancelAuthorization message.

    @param _pk The private key to sign with.
    @param _authorizer The address canceling their authorization.
    @param _nonce The authorization nonce to cancel.

    @return _ The packed signature (r, s, v).
  */
  function _signCancelAuthorization (
    uint256 _pk,
    address _authorizer,
    bytes32 _nonce
  ) internal view returns (bytes memory) {
    bytes32 _cancelTypehash =
      0x158b0a9edf7a828aad02f63cd515c68ef2f50ba807396f6d12842833a1597429;
    bytes32 _structHash =
      keccak256(abi.encode(_cancelTypehash, _authorizer, _nonce));
    bytes32 _digest =
      keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, _structHash));
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(_pk, _digest);
    return abi.encodePacked(_r, _s, _v);
  }
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title ReentrantReceiver
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A test receiver that performs a nested transfer during the ERC-1363 callback.

  @custom:date February 3rd, 2026.
*/
contract ReentrantReceiver is
  IERC1363Receiver {

  /// The Sigil token contract.
  Sigil public token;

  /// Whether the nested transfer has been attempted.
  bool public attacked;

  /**
    Construct a new ReentrantReceiver.

    @param _token The Sigil token address.
  */
  constructor (
    address _token
  ) {
    token = Sigil(_token);
  }

  /**
    Handle token receipt by attempting a nested transfer back to the sender.

    @param _from The address tokens were transferred from.
    @param _amount The amount of tokens received.

    @return _ The function selector to accept the transfer.
  */
  function onTransferReceived (
    address,
    address _from,
    uint256 _amount,
    bytes calldata
  ) external override returns (bytes4) {

    // Attempt reentrancy: try to transfer tokens back during callback.
    if (!attacked && token.balanceOf(address(this)) >= _amount) {
      attacked = true;

      // Try to transfer back to sender (reentrancy attempt).
      try token.transfer(_from, _amount / 2){ /* block */ } catch {}
    }
    return IERC1363Receiver.onTransferReceived.selector;
  }
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title DelegatingReceiver
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A test receiver that self-delegates during the ERC-1363 callback.

  @custom:date February 3rd, 2026.
*/
contract DelegatingReceiver is
  IERC1363Receiver {

  /// The Sigil token contract.
  Sigil public token;

  /**
    Construct a new DelegatingReceiver.

    @param _token The Sigil token address.
  */
  constructor (
    address _token
  ) {
    token = Sigil(_token);
  }

  /**
    Handle token receipt by self-delegating to activate voting power.

    @return _ The function selector to accept the transfer.
  */
  function onTransferReceived (
    address,
    address,
    uint256,
    bytes calldata
  ) external override returns (bytes4) {

    // Self-delegate during callback.
    token.delegate(address(this));
    return IERC1363Receiver.onTransferReceived.selector;
  }
}

