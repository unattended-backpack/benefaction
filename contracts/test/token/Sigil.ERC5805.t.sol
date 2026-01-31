// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { MockERC1271Signer } from "./signers/MockERC1271Signer.sol";
import { MockERC1271SignerFactory } from
  "./signers/MockERC1271SignerFactory.sol";
import { MockERC7739Signer } from "./signers/MockERC7739Signer.sol";
import { Test } from "forge-std/Test.sol";
import { ISignatureHelper } from "token/interfaces/ISignatureHelper.sol";
import { Sigil } from "token/Sigil.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Tests for ERC-5805 voting and delegateBySig functionality.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  Test that the ERC-5805 voting and delegation implementation works correctly.
  These tests verify the existing Solady implementation to ensure correctness is
  maintained when we override with unified signature support.

  @custom:date January 29th, 2026.
*/
contract SigilERC5805Test is
  Test {

  /**
    Emitted when an account changes its delegate.

    @param delegator The account that changed its delegate.
    @param fromDelegate The previous delegate address.
    @param toDelegate The new delegate address.
  */
  event DelegateChanged (
    address indexed delegator,
    address indexed fromDelegate,
    address indexed toDelegate
  );

  /**
    Emitted when a delegate's vote balance changes.

    @param delegate The delegate whose vote count changed.
    @param previousVotes The previous vote balance.
    @param newVotes The new vote balance.
  */
  event DelegateVotesChanged (
    address indexed delegate,
    uint256 previousVotes,
    uint256 newVotes
  );

  /// The EIP-712 typehash for the delegation struct.
  bytes32 private constant _DELEGATION_TYPEHASH =
    keccak256("Delegation(address delegatee,uint256 nonce,uint256 expiry)");

  /// The EIP-712 domain typehash.
  bytes32 private constant _DOMAIN_TYPEHASH =
    keccak256(
      "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

  /// The ERC-6492 universal signature validator address used by Solady.
  address internal constant EIP6492_UNIVERSAL_VALIDATOR =
    0x00007bd799e4A591FeA53f8A8a3E9f931626Ba7e;

  /// The Sigil token for testing.
  Sigil public token;

  /// Alice's address (derived from private key).
  address internal alice;

  /// Alice's private key for signing.
  uint256 internal alicePrivateKey;

  /// Bob's address.
  address internal bob;

  /// Bob's private key for signing.
  uint256 internal bobPrivateKey;

  /// Carol's address.
  address internal carol;

  /// Dave's address.
  address internal dave;

  /// Set up the test.
  function setUp () public {
    token = new Sigil(address(this));

    // Create users with known private keys for signing.
    alicePrivateKey = 0xA11CE;
    alice = vm.addr(alicePrivateKey);
    bobPrivateKey = 0xB0B;
    bob = vm.addr(bobPrivateKey);
    carol = makeAddr("carol");
    dave = makeAddr("dave");

    // Distribute tokens.
    token.transfer(alice, 300 ether);
    token.transfer(bob, 200 ether);
    token.transfer(carol, 100 ether);

    /*
      Deploy the ERC-6492 universal signature validator for counterfactual
      signature testing. This bytecode is the non-reverting verifier that
      Solady's SignatureCheckerLib expects at this address.
    */
    vm.etch(
      EIP6492_UNIVERSAL_VALIDATOR,
      hex"36383d373d3d6020515160208051013d3d515af160203851516084018038385101606037303452813582523838523490601c34355afa34513060e01b141634fd"
    );
  }

  /**
    Compute the EIP-712 domain separator for the token.

    @return _ The domain separator.
  */
  function _computeDomainSeparator () internal view returns (bytes32) {
    return keccak256(
      abi.encode(
        _DOMAIN_TYPEHASH, keccak256(bytes("Sigil")), keccak256(bytes("1")),
        block.chainid, address(token)
      )
    );
  }

  /**
    Compute the EIP-712 digest for a delegation.

    @param _delegatee The address to delegate to.
    @param _nonce The current nonce.
    @param _expiry The expiry timestamp.

    @return _ The digest to sign.
  */
  function _computeDelegationDigest (
    address _delegatee,
    uint256 _nonce,
    uint256 _expiry
  ) internal view returns (bytes32) {
    bytes32 _structHash =
      keccak256(abi.encode(_DELEGATION_TYPEHASH, _delegatee, _nonce, _expiry));
    return keccak256(
      abi.encodePacked("\x19\x01", _computeDomainSeparator(), _structHash)
    );
  }

  /**
    Sign a delegation and return the signature components.

    @param _privateKey The private key to sign with.
    @param _delegatee The address to delegate to.
    @param _nonce The current nonce.
    @param _expiry The expiry timestamp.

    @return _ The recovery byte.
    @return _ The r component.
    @return _ The s component.
  */
  function _signDelegation (
    uint256 _privateKey,
    address _delegatee,
    uint256 _nonce,
    uint256 _expiry
  ) internal view returns (uint8, bytes32, bytes32) {
    bytes32 _digest = _computeDelegationDigest(_delegatee, _nonce, _expiry);
    return vm.sign(_privateKey, _digest);
  }

  /**
    Sign a delegation and return the signature as packed bytes.

    @param _privateKey The private key to sign with.
    @param _delegatee The address to delegate to.
    @param _nonce The current nonce.
    @param _expiry The expiry timestamp.

    @return _ The packed signature bytes.
  */
  function _signDelegationBytes (
    uint256 _privateKey,
    address _delegatee,
    uint256 _nonce,
    uint256 _expiry
  ) internal view returns (bytes memory) {
    bytes32 _digest = _computeDelegationDigest(_delegatee, _nonce, _expiry);
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(_privateKey, _digest);
    return abi.encodePacked(_r, _s, _v);
  }

  /// clock() returns the current block number.
  function test_clock () public view {
    assertEq(token.clock(), block.number);
  }

  /// CLOCK_MODE returns the correct string.
  function test_clockMode () public view {
    assertEq(token.CLOCK_MODE(), "mode=blocknumber&from=default");
  }

  /// Initial state: no delegation, no votes.
  function test_initialState () public view {
    assertEq(token.delegates(alice), address(0));
    assertEq(token.getVotes(alice), 0);
  }

  /// delegate() sets the delegatee.
  function test_delegate () public {
    vm.prank(alice);
    token.delegate(bob);
    assertEq(token.delegates(alice), bob);
  }

  /// delegate() transfers voting power to delegatee.
  function test_delegate_transfersVotingPower () public {
    assertEq(token.getVotes(bob), 0);
    vm.prank(alice);
    token.delegate(bob);
    assertEq(token.getVotes(bob), 300 ether);
  }

  /// delegate() emits DelegateChanged event.
  function test_delegate_emitsDelegateChanged () public {
    vm.expectEmit(true, true, true, false);
    emit DelegateChanged(alice, address(0), bob);
    vm.prank(alice);
    token.delegate(bob);
  }

  /// delegate() emits DelegateVotesChanged event.
  function test_delegate_emitsDelegateVotesChanged () public {
    vm.expectEmit(true, false, false, true);
    emit DelegateVotesChanged(bob, 0, 300 ether);
    vm.prank(alice);
    token.delegate(bob);
  }

  /// Self-delegation works.
  function test_delegate_self () public {
    vm.prank(alice);
    token.delegate(alice);
    assertEq(token.delegates(alice), alice);
    assertEq(token.getVotes(alice), 300 ether);
  }

  /// Changing delegation moves votes.
  function test_delegate_change () public {
    vm.prank(alice);
    token.delegate(bob);
    assertEq(token.getVotes(bob), 300 ether);
    assertEq(token.getVotes(carol), 0);
    vm.prank(alice);
    token.delegate(carol);
    assertEq(token.getVotes(bob), 0);
    assertEq(token.getVotes(carol), 300 ether);
  }

  /// Delegation to zero address removes votes.
  function test_delegate_toZero () public {
    vm.prank(alice);
    token.delegate(bob);
    assertEq(token.getVotes(bob), 300 ether);
    vm.prank(alice);
    token.delegate(address(0));
    assertEq(token.getVotes(bob), 0);
    assertEq(token.delegates(alice), address(0));
  }

  /// delegateBySig with valid signature sets delegate.
  function test_delegateBySig () public {
    uint256 _nonce = token.nonces(alice);
    uint256 _expiry = block.timestamp + 1 hours;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signDelegation(
      alicePrivateKey, bob, _nonce, _expiry
    );
    token.delegateBySig(bob, _nonce, _expiry, _v, _r, _s);
    assertEq(token.delegates(alice), bob);
    assertEq(token.getVotes(bob), 300 ether);
  }

  /// delegateBySig increments nonce.
  function test_delegateBySig_incrementsNonce () public {
    assertEq(token.nonces(alice), 0);
    uint256 _expiry = block.timestamp + 1 hours;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signDelegation(
      alicePrivateKey, bob, 0, _expiry
    );
    token.delegateBySig(bob, 0, _expiry, _v, _r, _s);
    assertEq(token.nonces(alice), 1);
  }

  /// delegateBySig emits DelegateChanged event.
  function test_delegateBySig_emitsDelegateChanged () public {
    uint256 _expiry = block.timestamp + 1 hours;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signDelegation(
      alicePrivateKey, bob, 0, _expiry
    );
    vm.expectEmit(true, true, true, false);
    emit DelegateChanged(alice, address(0), bob);
    token.delegateBySig(bob, 0, _expiry, _v, _r, _s);
  }

  /// delegateBySig can be called by anyone.
  function test_delegateBySig_calledByAnyone () public {
    uint256 _expiry = block.timestamp + 1 hours;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signDelegation(
      alicePrivateKey, bob, 0, _expiry
    );

    // Carol submits on behalf of Alice.
    vm.prank(carol);
    token.delegateBySig(bob, 0, _expiry, _v, _r, _s);
    assertEq(token.delegates(alice), bob);
  }

  /// delegateBySig to self works.
  function test_delegateBySig_self () public {
    uint256 _expiry = block.timestamp + 1 hours;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signDelegation(
      alicePrivateKey, alice, 0, _expiry
    );
    token.delegateBySig(alice, 0, _expiry, _v, _r, _s);
    assertEq(token.delegates(alice), alice);
    assertEq(token.getVotes(alice), 300 ether);
  }

  /// delegateBySig to zero address works.
  function test_delegateBySig_toZero () public {

    // First delegate to bob via signature.
    uint256 _expiry = block.timestamp + 1 hours;
    (uint8 _v1, bytes32 _r1, bytes32 _s1) = _signDelegation(
      alicePrivateKey, bob, 0, _expiry
    );
    token.delegateBySig(bob, 0, _expiry, _v1, _r1, _s1);
    assertEq(token.getVotes(bob), 300 ether);

    // Then undelegate via signature (nonce is now 1).
    (uint8 _v2, bytes32 _r2, bytes32 _s2) = _signDelegation(
      alicePrivateKey, address(0), 1, _expiry
    );
    token.delegateBySig(address(0), 1, _expiry, _v2, _r2, _s2);
    assertEq(token.delegates(alice), address(0));
    assertEq(token.getVotes(bob), 0);
  }

  /// delegateBySig fails with expired signature.
  function test_delegateBySig_expired_reverts () public {

    // Already expired.
    uint256 _expiry = block.timestamp - 1;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signDelegation(
      alicePrivateKey, bob, 0, _expiry
    );

    // ERC5805DelegateSignatureExpired()
    vm.expectRevert(bytes4(0x3480e9e1));
    token.delegateBySig(bob, 0, _expiry, _v, _r, _s);
  }

  /// delegateBySig succeeds with expiry at current timestamp (boundary).
  function test_delegateBySig_expiryAtTimestamp () public {

    // Exactly at timestamp is still valid.
    uint256 _expiry = block.timestamp;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signDelegation(
      alicePrivateKey, bob, 0, _expiry
    );

    // Solady uses `timestamp() > expiry`, so equality is valid.
    token.delegateBySig(bob, 0, _expiry, _v, _r, _s);
    assertEq(token.delegates(alice), bob);
  }

  /// delegateBySig fails with wrong nonce.
  function test_delegateBySig_wrongNonce_reverts () public {
    uint256 _expiry = block.timestamp + 1 hours;

    // Sign with nonce 5 but current nonce is 0.
    (uint8 _v, bytes32 _r, bytes32 _s) = _signDelegation(
      alicePrivateKey, bob, 5, _expiry
    );

    // ERC5805DelegateInvalidSignature()
    vm.expectRevert(bytes4(0x1838d95c));
    token.delegateBySig(bob, 5, _expiry, _v, _r, _s);
  }

  /// delegateBySig with wrong delegatee does not delegate for Alice.
  function test_delegateBySig_wrongDelegatee_wrongSigner () public {
    uint256 _expiry = block.timestamp + 1 hours;

    // Sign for bob.
    (uint8 _v, bytes32 _r, bytes32 _s) = _signDelegation(
      alicePrivateKey, bob, 0, _expiry
    );

    // But call with carol - recovers to different address.
    token.delegateBySig(carol, 0, _expiry, _v, _r, _s);

    // Alice's delegate should be unchanged.
    assertEq(token.delegates(alice), address(0));
  }

  /// delegateBySig with wrong expiry does not delegate for Alice.
  function test_delegateBySig_wrongExpiry_wrongSigner () public {
    uint256 _expiry = block.timestamp + 1 hours;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signDelegation(
      alicePrivateKey, bob, 0, _expiry
    );

    // Call with different expiry - recovers to different address.
    token.delegateBySig(bob, 0, _expiry + 1, _v, _r, _s);

    // Alice's delegate should be unchanged.
    assertEq(token.delegates(alice), address(0));
  }

  /// delegateBySig fails with replay attack.
  function test_delegateBySig_replayAttack_reverts () public {
    uint256 _expiry = block.timestamp + 1 hours;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signDelegation(
      alicePrivateKey, bob, 0, _expiry
    );

    // First call succeeds.
    token.delegateBySig(bob, 0, _expiry, _v, _r, _s);

    // ERC5805DelegateInvalidSignature()
    vm.expectRevert(bytes4(0x1838d95c));
    token.delegateBySig(bob, 0, _expiry, _v, _r, _s);
  }

  /**
    delegateBySig with corrupted v does not delegate for Alice. Note: Corrupted
    signatures may recover to random addresses with nonce 0, so they might not
    revert but will delegate for wrong signer.
  */
  function test_delegateBySig_corruptedV_wrongSigner () public {
    uint256 _expiry = block.timestamp + 1 hours;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signDelegation(
      alicePrivateKey, bob, 0, _expiry
    );

    // This may succeed but for a different recovered address.
    token.delegateBySig(bob, 0, _expiry, _v + 1, _r, _s);

    // Alice's delegate should be unchanged.
    assertEq(token.delegates(alice), address(0));
  }

  /// delegateBySig with corrupted r does not delegate for Alice.
  function test_delegateBySig_corruptedR_wrongSigner () public {
    uint256 _expiry = block.timestamp + 1 hours;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signDelegation(
      alicePrivateKey, bob, 0, _expiry
    );
    token.delegateBySig(bob, 0, _expiry, _v, bytes32(uint256(_r) + 1), _s);

    // Alice's delegate should be unchanged.
    assertEq(token.delegates(alice), address(0));
  }

  /// delegateBySig with corrupted s does not delegate for Alice.
  function test_delegateBySig_corruptedS_wrongSigner () public {
    uint256 _expiry = block.timestamp + 1 hours;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signDelegation(
      alicePrivateKey, bob, 0, _expiry
    );
    token.delegateBySig(bob, 0, _expiry, _v, _r, bytes32(uint256(_s) + 1));

    // Alice's delegate should be unchanged.
    assertEq(token.delegates(alice), address(0));
  }

  /// Multiple delegateBySig calls in sequence.
  function test_delegateBySig_sequential () public {
    uint256 _expiry = block.timestamp + 1 hours;

    // First delegation.
    (uint8 _v1, bytes32 _r1, bytes32 _s1) = _signDelegation(
      alicePrivateKey, bob, 0, _expiry
    );
    token.delegateBySig(bob, 0, _expiry, _v1, _r1, _s1);
    assertEq(token.delegates(alice), bob);
    assertEq(token.nonces(alice), 1);

    // Second delegation to different address.
    (uint8 _v2, bytes32 _r2, bytes32 _s2) = _signDelegation(
      alicePrivateKey, carol, 1, _expiry
    );
    token.delegateBySig(carol, 1, _expiry, _v2, _r2, _s2);
    assertEq(token.delegates(alice), carol);
    assertEq(token.nonces(alice), 2);

    // Verify votes moved.
    assertEq(token.getVotes(bob), 0);
    assertEq(token.getVotes(carol), 300 ether);
  }

  /// Checkpoints are created on delegation.
  function test_checkpoints_created () public {
    assertEq(token.checkpointCount(bob), 0);
    vm.prank(alice);
    token.delegate(bob);
    assertEq(token.checkpointCount(bob), 1);
  }

  /// checkpointAt returns correct values.
  function test_checkpointAt () public {
    vm.prank(alice);
    token.delegate(bob);
    (uint48 _checkpointClock, uint256 _checkpointValue) = token.checkpointAt(
      bob, 0
    );
    assertEq(_checkpointClock, block.number);
    assertEq(_checkpointValue, 300 ether);
  }

  /// Multiple checkpoints are recorded.
  function test_checkpoints_multiple () public {
    vm.prank(alice);
    token.delegate(bob);
    vm.roll(block.number + 10);
    vm.prank(carol);
    token.delegate(bob);
    assertEq(token.checkpointCount(bob), 2);
    (uint48 _clock1, uint256 _value1) = token.checkpointAt(bob, 0);
    (uint48 _clock2, uint256 _value2) = token.checkpointAt(bob, 1);
    assertEq(_value1, 300 ether);

    // 300 + 100
    assertEq(_value2, 400 ether);
    assertTrue(_clock2 > _clock1);
  }

  /// checkpointAt reverts for out of bounds index.
  function test_checkpointAt_outOfBounds_reverts () public {
    vm.prank(alice);
    token.delegate(bob);

    // ERC5805CheckpointIndexOutOfBounds()
    vm.expectRevert(bytes4(0x86df9d10));
    token.checkpointAt(bob, 1);
  }

  /// getPastVotes returns historical voting power.
  function test_getPastVotes () public {
    vm.prank(alice);
    token.delegate(bob);
    uint256 _delegationBlock = block.number;

    // Move forward.
    vm.roll(block.number + 10);

    // Check past votes at delegation block.
    assertEq(token.getPastVotes(bob, _delegationBlock), 300 ether);
  }

  /// getPastVotes returns zero before delegation.
  function test_getPastVotes_beforeDelegation () public {
    uint256 _beforeBlock = block.number;
    vm.roll(block.number + 5);
    vm.prank(alice);
    token.delegate(bob);
    vm.roll(block.number + 5);

    // Before delegation, votes were zero.
    assertEq(token.getPastVotes(bob, _beforeBlock), 0);
  }

  /// getPastVotes reverts for future timepoint.
  function test_getPastVotes_future_reverts () public {

    // ERC5805FutureLookup()
    vm.expectRevert(bytes4(0xf9874464));
    token.getPastVotes(bob, block.number);
  }

  /**
    getVotesTotalSupply returns total token supply (all minted tokens). Note: In
    Solady's implementation, total voting supply tracks all minted tokens, not
    just delegated ones. Individual getVotes requires delegation.
  */
  function test_getVotesTotalSupply () public view {

    // Total voting supply equals total token supply (1B).
    assertEq(token.getVotesTotalSupply(), 1_000_000_000 ether);
  }

  /// getVotes requires delegation but getVotesTotalSupply does not.
  function test_getVotes_requiresDelegation () public {

    // Alice has tokens but hasn't delegated.
    assertEq(token.balanceOf(alice), 300 ether);
    assertEq(token.getVotes(alice), 0);

    // After self-delegation, votes become active.
    vm.prank(alice);
    token.delegate(alice);
    assertEq(token.getVotes(alice), 300 ether);
  }

  /// getPastVotesTotalSupply returns historical total supply.
  function test_getPastVotesTotalSupply () public {
    uint256 _initialBlock = block.number;
    vm.roll(block.number + 10);

    // Past total supply equals total minted at that time.
    assertEq(token.getPastVotesTotalSupply(_initialBlock), 1_000_000_000 ether);
  }

  /// Token transfer updates delegated votes.
  function test_transfer_updatesDelegatedVotes () public {
    vm.prank(alice);
    token.delegate(bob);
    assertEq(token.getVotes(bob), 300 ether);

    // Alice transfers some tokens.
    vm.prank(alice);
    token.transfer(carol, 100 ether);

    // Bob's delegated votes decrease.
    assertEq(token.getVotes(bob), 200 ether);
  }

  /// Receiving tokens updates delegated votes.
  function test_receive_updatesDelegatedVotes () public {
    vm.prank(alice);
    token.delegate(bob);

    // Carol sends tokens to Alice.
    vm.prank(carol);
    token.transfer(alice, 50 ether);

    // Bob's delegated votes increase.
    assertEq(token.getVotes(bob), 350 ether);
  }

  /// Transfer between delegated accounts moves votes correctly.
  function test_transfer_betweenDelegatedAccounts () public {
    vm.prank(alice);
    token.delegate(dave);
    vm.prank(bob);
    token.delegate(carol);
    assertEq(token.getVotes(dave), 300 ether);
    assertEq(token.getVotes(carol), 200 ether);

    // Alice sends to Bob.
    vm.prank(alice);
    token.transfer(bob, 100 ether);
    assertEq(token.getVotes(dave), 200 ether);
    assertEq(token.getVotes(carol), 300 ether);
  }

  /// getPastVotesTotalSupply reverts for future timepoint.
  function test_getPastVotesTotalSupply_future_reverts () public {

    // ERC5805FutureLookup()
    vm.expectRevert(bytes4(0xf9874464));
    token.getPastVotesTotalSupply(block.number);
  }

  /// Delegation with zero balance still sets delegate but gives no votes.
  function test_delegate_zeroBalance () public {

    // Dave has no tokens.
    assertEq(token.balanceOf(dave), 0);
    vm.prank(dave);
    token.delegate(bob);
    assertEq(token.delegates(dave), bob);
    assertEq(token.getVotes(bob), 0);
  }

  /// delegateBySig with zero balance still sets delegate.
  function test_delegateBySig_zeroBalance () public {

    // Create a new user with known private key but no tokens.
    uint256 _evePrivateKey = 0xE7E;
    address _eve = vm.addr(_evePrivateKey);
    assertEq(token.balanceOf(_eve), 0);
    uint256 _expiry = block.timestamp + 1 hours;
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(
      _evePrivateKey, _computeDelegationDigest(bob, 0, _expiry)
    );
    token.delegateBySig(bob, 0, _expiry, _v, _r, _s);
    assertEq(token.delegates(_eve), bob);
    assertEq(token.getVotes(bob), 0);
  }

  /// Same-block checkpoint consolidation: multiple changes in one block.
  function test_checkpoints_sameBlockConsolidation () public {

    // Alice delegates to bob.
    vm.prank(alice);
    token.delegate(bob);

    // In the same block, carol also delegates to bob.
    vm.prank(carol);
    token.delegate(bob);

    // Should have only one checkpoint for bob (consolidated).
    assertEq(token.checkpointCount(bob), 1);
    (uint48 _checkpointClock, uint256 _checkpointValue) = token.checkpointAt(
      bob, 0
    );
    assertEq(_checkpointClock, block.number);

    // 300 + 100
    assertEq(_checkpointValue, 400 ether);
  }

  /// Same-block: delegation change consolidates into single checkpoint.
  function test_checkpoints_sameBlockDelegationChange () public {

    // Alice delegates to bob.
    vm.prank(alice);
    token.delegate(bob);

    // In the same block, alice changes delegation to carol.
    vm.prank(alice);
    token.delegate(carol);

    // Bob should have one checkpoint showing final state (0 votes).
    assertEq(token.checkpointCount(bob), 1);
    (, uint256 _bobValue) = token.checkpointAt(bob, 0);
    assertEq(_bobValue, 0);

    // Carol should have one checkpoint showing 300 ether.
    assertEq(token.checkpointCount(carol), 1);
    (, uint256 _carolValue) = token.checkpointAt(carol, 0);
    assertEq(_carolValue, 300 ether);
  }

  /// getPastVotes with many checkpoints verifies binary search works.
  function test_getPastVotes_manyCheckpoints () public {

    // Self-delegate alice so transfers affect her votes.
    vm.prank(alice);
    token.delegate(alice);
    uint256[] memory _blocks = new uint256[](10);
    uint256[] memory _expectedVotes = new uint256[](10);

    // Create many checkpoints by transferring tokens across blocks.
    uint256 _currentBalance = 300 ether;
    for (uint256 i = 0; i < 10; i++) {
      _blocks[i] = block.number;
      _expectedVotes[i] = _currentBalance;
      vm.roll(block.number + 5);

      // Transfer 10 ether to carol each iteration (reduces alice's votes).
      if (i < 9) {
        vm.prank(alice);
        token.transfer(carol, 10 ether);
        _currentBalance -= 10 ether;
      }
    }

    // Now verify getPastVotes returns correct values for each historical block.
    for (uint256 i = 0; i < 10; i++) {
      assertEq(
        token.getPastVotes(alice, _blocks[i]), _expectedVotes[i],
        string.concat("Mismatch at checkpoint ", vm.toString(i))
      );
    }
  }

  /**
    getPastVotes binary search: query between checkpoints returns earlier value.
  */
  function test_getPastVotes_betweenCheckpoints () public {
    vm.prank(alice);
    token.delegate(bob);
    uint256 _block1 = block.number;
    vm.roll(block.number + 100);
    vm.prank(carol);
    token.delegate(bob);
    uint256 _block2 = block.number;
    vm.roll(block.number + 100);

    // Query a block between the two checkpoints.
    uint256 _midBlock = _block1 + 50;
    assertEq(token.getPastVotes(bob, _midBlock), 300 ether);

    // Query a block after second checkpoint.
    uint256 _afterBlock = _block2 + 50;
    assertEq(token.getPastVotes(bob, _afterBlock), 400 ether);
  }

  /**
    delegateBySig with malleable signature succeeds. Note: Solady's ecrecover
    does not reject malleable signatures. Both (v,r,s) and (v',r,n-s) recover to
    the same address. This is not a security concern for nonce-based systems
    like delegateBySig since replay attacks are prevented.
  */
  function test_delegateBySig_malleableSignature_succeeds () public {
    uint256 _expiry = block.timestamp + 1 hours;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signDelegation(
      alicePrivateKey, bob, 0, _expiry
    );

    // secp256k1 curve order.
    uint256 _curveOrder =
      0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    // Flip s to upper half (s' = curveOrder - s).
    bytes32 _malleableS = bytes32(_curveOrder - uint256(_s));

    // Flip v (27 <-> 28).
    uint8 _malleableV = _v == 27 ? 28 : 27;

    // The malleable signature recovers to the same address and succeeds.
    token.delegateBySig(bob, 0, _expiry, _malleableV, _r, _malleableS);
    assertEq(token.delegates(alice), bob);
    assertEq(token.getVotes(bob), 300 ether);
    assertEq(token.nonces(alice), 1);
  }

  /**
    Fuzz test: delegateBySig with various expiries.

    @param _expiryOffset The offset from current timestamp for the expiry.
  */
  function testFuzz_delegateBySig (
    uint256 _expiryOffset
  ) public {
    _expiryOffset = bound(_expiryOffset, 1, 365 days);
    uint256 _expiry = block.timestamp + _expiryOffset;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signDelegation(
      alicePrivateKey, bob, 0, _expiry
    );
    token.delegateBySig(bob, 0, _expiry, _v, _r, _s);
    assertEq(token.delegates(alice), bob);
    assertEq(token.getVotes(bob), 300 ether);
  }

  /// delegateBySig with bytes signature and ECDSA signer succeeds.
  function test_delegateBySig_bytes_ecdsa_succeeds () public {
    uint256 _expiry = block.timestamp + 1 hours;
    bytes memory _signature =
      _signDelegationBytes(alicePrivateKey, bob, 0, _expiry);
    vm.expectEmit(true, true, true, false);
    emit DelegateChanged(alice, address(0), bob);
    token.delegateBySig(alice, bob, 0, _expiry, _signature);
    assertEq(token.delegates(alice), bob);
    assertEq(token.getVotes(bob), 300 ether);
    assertEq(token.nonces(alice), 1);
  }

  /// delegateBySig with bytes signature fails with expired signature.
  function test_delegateBySig_bytes_expired_reverts () public {

    // Already expired.
    uint256 _expiry = block.timestamp - 1;
    bytes memory _signature =
      _signDelegationBytes(alicePrivateKey, bob, 0, _expiry);

    // ERC5805DelegateSignatureExpired()
    vm.expectRevert(bytes4(0x3480e9e1));
    token.delegateBySig(alice, bob, 0, _expiry, _signature);
  }

  /// delegateBySig with bytes signature fails with wrong nonce.
  function test_delegateBySig_bytes_wrongNonce_reverts () public {
    uint256 _expiry = block.timestamp + 1 hours;

    // Sign with nonce 5 but current nonce is 0.
    bytes memory _signature =
      _signDelegationBytes(alicePrivateKey, bob, 5, _expiry);

    // ERC5805DelegateInvalidSignature()
    vm.expectRevert(bytes4(0x1838d95c));
    token.delegateBySig(alice, bob, 5, _expiry, _signature);
  }

  /// An ERC-1271 signer can delegateBySig via its owner's signature.
  function test_delegateBySig_erc1271Signer_succeeds () public {

    // Create a smart contract signer owned by Alice.
    MockERC1271Signer _signer = new MockERC1271Signer(alice);
    address _signerAddress = address(_signer);

    // Give tokens to the signer contract.
    token.transfer(_signerAddress, 100 ether);
    uint256 _expiry = block.timestamp + 1 hours;
    uint256 _nonce = token.nonces(_signerAddress);

    // Sign as Alice (the owner of the signer contract).
    bytes memory _signature =
      _signDelegationBytes(alicePrivateKey, bob, _nonce, _expiry);
    vm.expectEmit(true, true, true, false);
    emit DelegateChanged(_signerAddress, address(0), bob);
    token.delegateBySig(_signerAddress, bob, _nonce, _expiry, _signature);
    assertEq(token.delegates(_signerAddress), bob);
    assertEq(token.getVotes(bob), 100 ether);
    assertEq(token.nonces(_signerAddress), 1);
  }

  /// An ERC-1271 signer rejects signatures from non-owners.
  function test_delegateBySig_erc1271Signer_wrongOwner_reverts () public {

    // Create a smart contract signer owned by Alice.
    MockERC1271Signer _signer = new MockERC1271Signer(alice);
    address _signerAddress = address(_signer);

    // Give tokens to the signer contract.
    token.transfer(_signerAddress, 100 ether);
    uint256 _expiry = block.timestamp + 1 hours;

    // Sign as Bob (NOT the owner of the signer contract).
    bytes memory _signature =
      _signDelegationBytes(bobPrivateKey, bob, 0, _expiry);
    vm.expectRevert(ISignatureHelper.InvalidSignature.selector);
    token.delegateBySig(_signerAddress, bob, 0, _expiry, _signature);
  }

  /// An ERC-1271 signer can change delegation via sequential signatures.
  function test_delegateBySig_erc1271Signer_sequential () public {

    // Create a smart contract signer owned by Alice.
    MockERC1271Signer _signer = new MockERC1271Signer(alice);
    address _signerAddress = address(_signer);

    // Give tokens to the signer contract.
    token.transfer(_signerAddress, 100 ether);
    uint256 _expiry = block.timestamp + 1 hours;

    // First delegation to bob.
    bytes memory _signature1 =
      _signDelegationBytes(alicePrivateKey, bob, 0, _expiry);
    token.delegateBySig(_signerAddress, bob, 0, _expiry, _signature1);
    assertEq(token.delegates(_signerAddress), bob);
    assertEq(token.getVotes(bob), 100 ether);

    // Second delegation to carol (nonce is now 1).
    bytes memory _signature2 =
      _signDelegationBytes(alicePrivateKey, carol, 1, _expiry);
    token.delegateBySig(_signerAddress, carol, 1, _expiry, _signature2);
    assertEq(token.delegates(_signerAddress), carol);
    assertEq(token.getVotes(bob), 0);
    assertEq(token.getVotes(carol), 100 ether);
    assertEq(token.nonces(_signerAddress), 2);
  }

  /// An ERC-1271 signer delegation fails on replay attack.
  function test_delegateBySig_erc1271Signer_replayAttack_reverts () public {

    // Create a smart contract signer owned by Alice.
    MockERC1271Signer _signer = new MockERC1271Signer(alice);
    address _signerAddress = address(_signer);

    // Give tokens to the signer contract.
    token.transfer(_signerAddress, 100 ether);
    uint256 _expiry = block.timestamp + 1 hours;

    // First delegation succeeds.
    bytes memory _signature =
      _signDelegationBytes(alicePrivateKey, bob, 0, _expiry);
    token.delegateBySig(_signerAddress, bob, 0, _expiry, _signature);

    // Replay attack fails (nonce mismatch). ERC5805DelegateInvalidSignature()
    vm.expectRevert(bytes4(0x1838d95c));
    token.delegateBySig(_signerAddress, bob, 0, _expiry, _signature);
  }

  /// An ERC-6492 signature authorizes delegation from an undeployed signer.
  function test_delegateBySig_erc6492Signer_succeeds () public {

    // Create a factory for deploying signers.
    MockERC1271SignerFactory _factory = new MockERC1271SignerFactory();

    // Compute the address where the signer WOULD be deployed.
    bytes32 _salt = bytes32(uint256(200));
    address _signerAddress = _factory.computeAddress(alice, _salt);

    // Give tokens to the not-yet-deployed signer address.
    token.transfer(_signerAddress, 100 ether);
    uint256 _expiry = block.timestamp + 1 hours;

    // Create the inner signature from Alice (the future owner).
    bytes memory _innerSignature =
      _signDelegationBytes(alicePrivateKey, bob, 0, _expiry);

    /*
      Build the ERC-6492 signature: abi.encode(factory, calldata, signature) +
      magic suffix.
    */
    bytes memory _factoryCalldata =
      abi.encodeWithSelector(
        MockERC1271SignerFactory.deployWithSalt.selector, alice, _salt
      );
    bytes memory _erc6492Signature =
      abi.encodePacked(
        abi.encode(address(_factory), _factoryCalldata, _innerSignature),
        bytes32(
          0x6492649264926492649264926492649264926492649264926492649264926492
        )
      );

    // Verify the signer is not yet deployed.
    assertEq(_signerAddress.code.length, 0);
    vm.expectEmit(true, true, true, false);
    emit DelegateChanged(_signerAddress, address(0), bob);
    token.delegateBySig(_signerAddress, bob, 0, _expiry, _erc6492Signature);
    assertEq(token.delegates(_signerAddress), bob);
    assertEq(token.getVotes(bob), 100 ether);
    assertEq(token.nonces(_signerAddress), 1);
  }

  /// An ERC-6492 signature with wrong owner is rejected.
  function test_delegateBySig_erc6492Signer_wrongOwner_reverts () public {

    // Create a factory for deploying signers.
    MockERC1271SignerFactory _factory = new MockERC1271SignerFactory();

    // Compute the address where the signer WOULD be deployed (owned by Alice).
    bytes32 _salt = bytes32(uint256(201));
    address _signerAddress = _factory.computeAddress(alice, _salt);

    // Give tokens to the not-yet-deployed signer address.
    token.transfer(_signerAddress, 100 ether);
    uint256 _expiry = block.timestamp + 1 hours;

    // Create the inner signature from Bob (NOT the future owner).
    bytes memory _innerSignature =
      _signDelegationBytes(bobPrivateKey, bob, 0, _expiry);

    // Build the ERC-6492 signature.
    bytes memory _factoryCalldata =
      abi.encodeWithSelector(
        MockERC1271SignerFactory.deployWithSalt.selector, alice, _salt
      );
    bytes memory _erc6492Signature =
      abi.encodePacked(
        abi.encode(address(_factory), _factoryCalldata, _innerSignature),
        bytes32(
          0x6492649264926492649264926492649264926492649264926492649264926492
        )
      );

    // Verify the signer is not yet deployed.
    assertEq(_signerAddress.code.length, 0);
    vm.expectRevert(ISignatureHelper.InvalidSignature.selector);
    token.delegateBySig(_signerAddress, bob, 0, _expiry, _erc6492Signature);
  }

  /// An ERC-7739 signer validates nested EIP-712 signatures correctly.
  function test_delegateBySig_erc7739Signer_succeeds () public {

    // Create a smart contract signer that uses nested EIP-712.
    MockERC7739Signer _signer = new MockERC7739Signer(alice);
    address _signerAddress = address(_signer);

    // Give tokens to the signer contract.
    token.transfer(_signerAddress, 100 ether);
    uint256 _expiry = block.timestamp + 1 hours;

    // Compute the application's hash and get the wrapped hash for ERC-7739.
    bytes32 _appHash =
      keccak256(
        abi.encodePacked(
          "\x19\x01", _computeDomainSeparator(),
          keccak256(abi.encode(_DELEGATION_TYPEHASH, bob, 0, _expiry))
        )
      );

    // Sign the wrapped hash as Alice (the owner).
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(
      alicePrivateKey, _signer.getWrappedHash(_appHash)
    );
    vm.expectEmit(true, true, true, false);
    emit DelegateChanged(_signerAddress, address(0), bob);
    token.delegateBySig(
      _signerAddress, bob, 0, _expiry, abi.encodePacked(_r, _s, _v)
    );
    assertEq(token.delegates(_signerAddress), bob);
    assertEq(token.getVotes(bob), 100 ether);
    assertEq(token.nonces(_signerAddress), 1);
  }

  /// An ERC-7739 signer rejects signatures over the unwrapped hash.
  function test_delegateBySig_erc7739Signer_unwrappedHash_reverts () public {

    // Create a smart contract signer that uses nested EIP-712.
    address _signerAddress = address(new MockERC7739Signer(alice));

    // Give tokens to the signer contract.
    token.transfer(_signerAddress, 100 ether);
    uint256 _expiry = block.timestamp + 1 hours;

    // Sign the application hash directly (without wrapping) - this should fail.
    bytes memory _signature =
      _signDelegationBytes(alicePrivateKey, bob, 0, _expiry);
    vm.expectRevert(ISignatureHelper.InvalidSignature.selector);
    token.delegateBySig(_signerAddress, bob, 0, _expiry, _signature);
  }

  /// An ERC-7739 signer can change delegation via sequential signatures.
  function test_delegateBySig_erc7739Signer_sequential () public {

    // Create a smart contract signer that uses nested EIP-712.
    MockERC7739Signer _signer = new MockERC7739Signer(alice);
    address _signerAddress = address(_signer);

    // Give tokens to the signer contract.
    token.transfer(_signerAddress, 100 ether);
    uint256 _expiry = block.timestamp + 1 hours;

    // First delegation to bob.
    bytes32 _appHash1 =
      keccak256(
        abi.encodePacked(
          "\x19\x01", _computeDomainSeparator(),
          keccak256(abi.encode(_DELEGATION_TYPEHASH, bob, 0, _expiry))
        )
      );
    (uint8 _v1, bytes32 _r1, bytes32 _s1) = vm.sign(
      alicePrivateKey, _signer.getWrappedHash(_appHash1)
    );
    token.delegateBySig(
      _signerAddress, bob, 0, _expiry, abi.encodePacked(_r1, _s1, _v1)
    );
    assertEq(token.delegates(_signerAddress), bob);
    assertEq(token.getVotes(bob), 100 ether);

    // Second delegation to carol (nonce is now 1).
    bytes32 _appHash2 =
      keccak256(
        abi.encodePacked(
          "\x19\x01", _computeDomainSeparator(),
          keccak256(abi.encode(_DELEGATION_TYPEHASH, carol, 1, _expiry))
        )
      );
    (uint8 _v2, bytes32 _r2, bytes32 _s2) = vm.sign(
      alicePrivateKey, _signer.getWrappedHash(_appHash2)
    );
    token.delegateBySig(
      _signerAddress, carol, 1, _expiry, abi.encodePacked(_r2, _s2, _v2)
    );
    assertEq(token.delegates(_signerAddress), carol);
    assertEq(token.getVotes(bob), 0);
    assertEq(token.getVotes(carol), 100 ether);
    assertEq(token.nonces(_signerAddress), 2);
  }
}

