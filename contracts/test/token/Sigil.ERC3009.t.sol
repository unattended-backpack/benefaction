// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { MockERC1271Signer } from "./signers/MockERC1271Signer.sol";
import { MockERC1271SignerFactory } from
  "./signers/MockERC1271SignerFactory.sol";
import { MockERC7739Signer } from "./signers/MockERC7739Signer.sol";
import { Test } from "forge-std/Test.sol";
import { IERC3009 } from "token/interfaces/IERC3009.sol";
import { Sigil } from "token/Sigil.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Tests for ERC-3009 functionality in the Sigil token.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  Test that Sigil has implemented ERC-3009 correctly.

  @custom:date January 21st, 2026.
*/
contract SigilERC3009Test is
  Test {

  /**
    The ERC-20 Transfer event.

    @param from The sender address.
    @param to The recipient address.
    @param amount The amount transferred.
  */
  event Transfer (
    address indexed from,
    address indexed to,
    uint256 amount
  );

  /// A testing private key for our Alice user.
  uint256 internal constant ALICE_PK = 0xA11CE;

  /// A testing private key for our Bob user.
  uint256 internal constant BOB_PK = 0xB0B;

  /// The ERC-3009 transfer typehash.
  bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH =
    0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267;

  /// The ERC-3009 receive typehash.
  bytes32 public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH =
    0xd099cc98ef71107a616c4f0f941f04c322d8e254fe26b3c6668db87aae413de8;

  /// The ERC-3009 cancel typehash.
  bytes32 public constant CANCEL_AUTHORIZATION_TYPEHASH =
    0x158b0a9edf7a828aad02f63cd515c68ef2f50ba807396f6d12842833a1597429;

  /// The ERC-6492 universal signature validator address used by Solady.
  address internal constant EIP6492_UNIVERSAL_VALIDATOR =
    0x00007bd799e4A591FeA53f8A8a3E9f931626Ba7e;

  /// Store the address of a created Sigil token for testing.
  Sigil public token;

  /// Store Alice's address.
  address internal alice;

  /// Store Bob's address.
  address internal bob;

  /// Store Charlie's address.
  address internal charlie;

  /// Store the EIP-712 domain separator.
  bytes32 internal DOMAIN_SEPARATOR;

  /// Set up the test.
  function setUp () public {
    token = new Sigil(address(this));
    alice = vm.addr(ALICE_PK);
    bob = vm.addr(BOB_PK);
    charlie = makeAddr("charlie");

    // Give tokens to Alice for testing.
    token.transfer(alice, 1000_000000000000000000);

    // Get the domain separator.
    DOMAIN_SEPARATOR = token.DOMAIN_SEPARATOR();

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
    Helper to create a transfer authorization signature.

    @param _signerPk The authorizer's private key.
    @param _from The payer's address.
    @param _to The recipient address.
    @param _amount The amount of tokens to transfer.
    @param _validAfter The timestamp when the authorization becomes valid.
    @param _validBefore The timestamp when the authorization becomes invalid.
    @param _nonce The authorization nonce.

    @return _ The authorization signature.
  */
  function _signTransferAuthorization (
    uint256 _signerPk,
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
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(_signerPk, _digest);
    return abi.encodePacked(_r, _s, _v);
  }

  /**
    Helper to create a receive authorization signature.

    @param _signerPk The authorizer's private key.
    @param _from The payer's address.
    @param _to The recipient address.
    @param _amount The amount of tokens to transfer.
    @param _validAfter The timestamp when the authorization becomes valid.
    @param _validBefore The timestamp when the authorization becomes invalid.
    @param _nonce The authorization nonce.

    @return _ The authorization signature.
  */
  function _signReceiveAuthorization (
    uint256 _signerPk,
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
          RECEIVE_WITH_AUTHORIZATION_TYPEHASH, _from, _to, _amount, _validAfter,
          _validBefore, _nonce
        )
      );
    bytes32 _digest =
      keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, _structHash));
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(_signerPk, _digest);
    return abi.encodePacked(_r, _s, _v);
  }

  /**
    Helper to create a cancel authorization signature.

    @param _signerPk The authorizer's private key.
    @param _authorizer The authorizer's address.
    @param _nonce The authorization nonce.

    @return _ The authorization signature.
  */
  function _signCancelAuthorization (
    uint256 _signerPk,
    address _authorizer,
    bytes32 _nonce
  ) internal view returns (bytes memory) {
    bytes32 _structHash =
      keccak256(abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, _authorizer, _nonce));
    bytes32 _digest =
      keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, _structHash));
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(_signerPk, _digest);
    return abi.encodePacked(_r, _s, _v);
  }

  /// A valid signed authorization allows any caller to execute the transfer.
  function test_transferWithAuthorization_succeeds () public {
    uint256 _amount = 100 ether;
    bytes32 _nonce = bytes32(uint256(1));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;
    bytes memory _signature =
      _signTransferAuthorization(
        ALICE_PK, alice, bob, _amount, _validAfter, _validBefore, _nonce
      );
    uint256 _aliceBalanceBefore = token.balanceOf(alice);
    uint256 _bobBalanceBefore = token.balanceOf(bob);

    // Anyone can submit the transfer.
    vm.prank(charlie);
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationUsed(alice, _nonce);
    vm.expectEmit(true, true, false, true, address(token));
    emit Transfer(alice, bob, _amount);
    token.transferWithAuthorization(
      alice, bob, _amount, _validAfter, _validBefore, _nonce, _signature
    );
    assertEq(token.balanceOf(alice), _aliceBalanceBefore - _amount);
    assertEq(token.balanceOf(bob), _bobBalanceBefore + _amount);
    assertTrue(token.authorizationState(alice, _nonce));
  }

  /// The v, r, s signature variant also executes transfers correctly.
  function test_transferWithAuthorization_withVRS_succeeds () public {
    uint256 _amount = 100 ether;
    bytes32 _nonce = bytes32(uint256(2));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;
    bytes32 _structHash =
      keccak256(
        abi.encode(
          TRANSFER_WITH_AUTHORIZATION_TYPEHASH, alice, bob, _amount,
          _validAfter, _validBefore, _nonce
        )
      );
    bytes32 _digest =
      keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, _structHash));
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(ALICE_PK, _digest);
    uint256 _aliceBalanceBefore = token.balanceOf(alice);
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationUsed(alice, _nonce);
    vm.expectEmit(true, true, false, true, address(token));
    emit Transfer(alice, bob, _amount);
    token.transferWithAuthorization(
      alice, bob, _amount, _validAfter, _validBefore, _nonce, _v, _r, _s
    );
    assertEq(token.balanceOf(alice), _aliceBalanceBefore - _amount);
  }

  /// An authorization that has expired cannot be used for a transfer.
  function test_transferWithAuthorization_expired_reverts () public {

    // Warp to a future time to avoid underflow.
    vm.warp(10 hours);
    uint256 _amount = 100 ether;
    bytes32 _nonce = bytes32(uint256(3));
    uint256 _validAfter = block.timestamp - 2 hours;

    // Expired.
    uint256 _validBefore = block.timestamp - 1 hours;
    bytes memory _signature =
      _signTransferAuthorization(
        ALICE_PK, alice, bob, _amount, _validAfter, _validBefore, _nonce
      );
    vm.expectRevert(IERC3009.AuthorizationExpired.selector);
    token.transferWithAuthorization(
      alice, bob, _amount, _validAfter, _validBefore, _nonce, _signature
    );
  }

  /// An authorization that is not yet valid cannot be used for a transfer.
  function test_transferWithAuthorization_notYetValid_reverts () public {
    uint256 _amount = 100 ether;
    bytes32 _nonce = bytes32(uint256(4));

    // Not yet valid.
    uint256 _validAfter = block.timestamp + 1 hours;
    uint256 _validBefore = block.timestamp + 2 hours;
    bytes memory _signature =
      _signTransferAuthorization(
        ALICE_PK, alice, bob, _amount, _validAfter, _validBefore, _nonce
      );
    vm.expectRevert(IERC3009.AuthorizationNotYetValid.selector);
    token.transferWithAuthorization(
      alice, bob, _amount, _validAfter, _validBefore, _nonce, _signature
    );
  }

  /// A nonce that has already been used cannot be reused for another transfer.
  function test_transferWithAuthorization_reusedNonce_reverts () public {
    uint256 _amount = 100 ether;
    bytes32 _nonce = bytes32(uint256(5));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;
    bytes memory _signature =
      _signTransferAuthorization(
        ALICE_PK, alice, bob, _amount, _validAfter, _validBefore, _nonce
      );

    // First transfer succeeds.
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationUsed(alice, _nonce);
    vm.expectEmit(true, true, false, true, address(token));
    emit Transfer(alice, bob, _amount);
    token.transferWithAuthorization(
      alice, bob, _amount, _validAfter, _validBefore, _nonce, _signature
    );

    // Second transfer with same nonce reverts.
    vm.expectRevert(IERC3009.AuthorizationAlreadyUsed.selector);
    token.transferWithAuthorization(
      alice, bob, _amount, _validAfter, _validBefore, _nonce, _signature
    );
  }

  /// An authorization signed by the wrong key is rejected.
  function test_transferWithAuthorization_invalidSignature_reverts () public {
    uint256 _amount = 100 ether;
    bytes32 _nonce = bytes32(uint256(6));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;

    // Sign with Bob's key instead of Alice's.
    bytes memory _signature =
      _signTransferAuthorization(
        BOB_PK, alice, bob, _amount, _validAfter, _validBefore, _nonce
      );
    vm.expectRevert(IERC3009.InvalidSignature.selector);
    token.transferWithAuthorization(
      alice, bob, _amount, _validAfter, _validBefore, _nonce, _signature
    );
  }

  /// The designated recipient can receive tokens using a signed authorization.
  function test_receiveWithAuthorization_succeeds () public {
    uint256 _amount = 100 ether;
    bytes32 _nonce = bytes32(uint256(10));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;
    bytes memory _signature =
      _signReceiveAuthorization(
        ALICE_PK, alice, bob, _amount, _validAfter, _validBefore, _nonce
      );
    uint256 _aliceBalanceBefore = token.balanceOf(alice);
    uint256 _bobBalanceBefore = token.balanceOf(bob);

    // Bob (the recipient) must call this function.
    vm.prank(bob);
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationUsed(alice, _nonce);
    vm.expectEmit(true, true, false, true, address(token));
    emit Transfer(alice, bob, _amount);
    token.receiveWithAuthorization(
      alice, bob, _amount, _validAfter, _validBefore, _nonce, _signature
    );
    assertEq(token.balanceOf(alice), _aliceBalanceBefore - _amount);
    assertEq(token.balanceOf(bob), _bobBalanceBefore + _amount);
  }

  /// The v, r, s signature variant also executes receives correctly.
  function test_receiveWithAuthorization_withVRS_succeeds () public {
    bytes32 _nonce = bytes32(uint256(12));
    bytes32 _digest =
      keccak256(
        abi.encodePacked(
          "\x19\x01", DOMAIN_SEPARATOR,
          keccak256(
            abi.encode(
              RECEIVE_WITH_AUTHORIZATION_TYPEHASH, alice, bob, 100 ether,
              block.timestamp - 1, block.timestamp + 1 hours, _nonce
            )
          )
        )
      );
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(ALICE_PK, _digest);
    uint256 _aliceBalanceBefore = token.balanceOf(alice);

    // Bob (the recipient) must call this function.
    vm.prank(bob);
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationUsed(alice, _nonce);
    token.receiveWithAuthorization(
      alice, bob, 100 ether, block.timestamp - 1, block.timestamp + 1 hours,
      _nonce, _v, _r, _s
    );
    assertEq(token.balanceOf(alice), _aliceBalanceBefore - 100 ether);
    assertTrue(token.authorizationState(alice, _nonce));
  }

  /// Only the designated recipient can call receiveWithAuthorization.
  function test_receiveWithAuthorization_callerNotRecipient_reverts () public {
    uint256 _amount = 100 ether;
    bytes32 _nonce = bytes32(uint256(11));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;
    bytes memory _signature =
      _signReceiveAuthorization(
        ALICE_PK, alice, bob, _amount, _validAfter, _validBefore, _nonce
      );

    // Charlie (not the recipient) tries to call this function.
    vm.prank(charlie);
    vm.expectRevert(IERC3009.CallerMustBePayee.selector);
    token.receiveWithAuthorization(
      alice, bob, _amount, _validAfter, _validBefore, _nonce, _signature
    );
  }

  /// An authorizer can cancel a nonce to prevent its future use.
  function test_cancelAuthorization_succeeds () public {
    bytes32 _nonce = bytes32(uint256(20));
    bytes memory _signature =
      _signCancelAuthorization(ALICE_PK, alice, _nonce);
    assertFalse(token.authorizationState(alice, _nonce));
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationCanceled(alice, _nonce);
    token.cancelAuthorization(alice, _nonce, _signature);
    assertTrue(token.authorizationState(alice, _nonce));
  }

  /// The v, r, s signature variant also executes cancels correctly.
  function test_cancelAuthorization_withVRS_succeeds () public {
    bytes32 _nonce = bytes32(uint256(24));
    bytes32 _structHash =
      keccak256(abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, alice, _nonce));
    bytes32 _digest =
      keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, _structHash));
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(ALICE_PK, _digest);
    assertFalse(token.authorizationState(alice, _nonce));
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationCanceled(alice, _nonce);
    token.cancelAuthorization(alice, _nonce, _v, _r, _s);
    assertTrue(token.authorizationState(alice, _nonce));
  }

  /// A canceled nonce cannot be used for a subsequent transfer.
  function test_cancelAuthorization_preventsTransfer () public {
    uint256 _amount = 100 ether;
    bytes32 _nonce = bytes32(uint256(21));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;

    // First cancel the authorization.
    bytes memory _cancelSig =
      _signCancelAuthorization(ALICE_PK, alice, _nonce);
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationCanceled(alice, _nonce);
    token.cancelAuthorization(alice, _nonce, _cancelSig);

    // Now try to use the same nonce for a transfer.
    bytes memory _transferSig =
      _signTransferAuthorization(
        ALICE_PK, alice, bob, _amount, _validAfter, _validBefore, _nonce
      );
    vm.expectRevert(IERC3009.AuthorizationAlreadyUsed.selector);
    token.transferWithAuthorization(
      alice, bob, _amount, _validAfter, _validBefore, _nonce, _transferSig
    );
  }

  /// A nonce that was already canceled cannot be canceled again.
  function test_cancelAuthorization_alreadyCanceled_reverts () public {
    bytes32 _nonce = bytes32(uint256(22));
    bytes memory _signature =
      _signCancelAuthorization(ALICE_PK, alice, _nonce);

    // First cancel succeeds.
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationCanceled(alice, _nonce);
    token.cancelAuthorization(alice, _nonce, _signature);

    // Second cancel reverts.
    vm.expectRevert(IERC3009.AuthorizationAlreadyUsed.selector);
    token.cancelAuthorization(alice, _nonce, _signature);
  }

  /// A cancellation signed by the wrong key is rejected.
  function test_cancelAuthorization_invalidSignature_reverts () public {
    bytes32 _nonce = bytes32(uint256(23));

    // Sign with Bob's key instead of Alice's.
    bytes memory _signature = _signCancelAuthorization(BOB_PK, alice, _nonce);
    vm.expectRevert(IERC3009.InvalidSignature.selector);
    token.cancelAuthorization(alice, _nonce, _signature);
  }

  /// A zero amount transfer succeeds.
  function test_transferWithAuthorization_zeroAmount_succeeds () public {
    uint256 _amount = 0;
    bytes32 _nonce = bytes32(uint256(60));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;
    bytes memory _signature =
      _signTransferAuthorization(
        ALICE_PK, alice, bob, _amount, _validAfter, _validBefore, _nonce
      );
    uint256 _aliceBalanceBefore = token.balanceOf(alice);
    uint256 _bobBalanceBefore = token.balanceOf(bob);
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationUsed(alice, _nonce);
    vm.expectEmit(true, true, false, true, address(token));
    emit Transfer(alice, bob, _amount);
    token.transferWithAuthorization(
      alice, bob, _amount, _validAfter, _validBefore, _nonce, _signature
    );
    assertEq(token.balanceOf(alice), _aliceBalanceBefore);
    assertEq(token.balanceOf(bob), _bobBalanceBefore);
    assertTrue(token.authorizationState(alice, _nonce));
  }

  /// A transfer exceeding balance reverts.
  function test_transferWithAuthorization_insufficientBalance_reverts ()
    public {
    uint256 _amount = token.balanceOf(alice) + 1;
    bytes32 _nonce = bytes32(uint256(61));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;
    bytes memory _signature =
      _signTransferAuthorization(
        ALICE_PK, alice, bob, _amount, _validAfter, _validBefore, _nonce
      );
    vm.expectRevert();
    token.transferWithAuthorization(
      alice, bob, _amount, _validAfter, _validBefore, _nonce, _signature
    );
  }

  /// A transfer exactly at validAfter timestamp is rejected.
  function test_transferWithAuthorization_exactlyAtValidAfter_reverts ()
    public {
    uint256 _amount = 100 ether;
    bytes32 _nonce = bytes32(uint256(62));
    uint256 _validAfter = block.timestamp;
    uint256 _validBefore = block.timestamp + 1 hours;
    bytes memory _signature =
      _signTransferAuthorization(
        ALICE_PK, alice, bob, _amount, _validAfter, _validBefore, _nonce
      );

    // ERC-3009 requires block.timestamp > validAfter (strict inequality).
    vm.expectRevert(IERC3009.AuthorizationNotYetValid.selector);
    token.transferWithAuthorization(
      alice, bob, _amount, _validAfter, _validBefore, _nonce, _signature
    );
  }

  /// A transfer exactly at validBefore timestamp is rejected.
  function test_transferWithAuthorization_exactlyAtValidBefore_reverts ()
    public {

    // Warp forward to avoid underflow when computing validAfter.
    vm.warp(2 hours);
    uint256 _amount = 100 ether;
    bytes32 _nonce = bytes32(uint256(63));
    uint256 _validAfter = block.timestamp - 1 hours;
    uint256 _validBefore = block.timestamp;
    bytes memory _signature =
      _signTransferAuthorization(
        ALICE_PK, alice, bob, _amount, _validAfter, _validBefore, _nonce
      );

    // ERC-3009 requires block.timestamp < validBefore (strict inequality).
    vm.expectRevert(IERC3009.AuthorizationExpired.selector);
    token.transferWithAuthorization(
      alice, bob, _amount, _validAfter, _validBefore, _nonce, _signature
    );
  }

  /// Using a transfer signature for receive is rejected.
  function test_receiveWithAuthorization_wrongTypehash_reverts () public {
    uint256 _amount = 100 ether;
    bytes32 _nonce = bytes32(uint256(64));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;

    // Sign with TRANSFER typehash instead of RECEIVE typehash.
    bytes memory _signature =
      _signTransferAuthorization(
        ALICE_PK, alice, bob, _amount, _validAfter, _validBefore, _nonce
      );
    vm.prank(bob);
    vm.expectRevert(IERC3009.InvalidSignature.selector);
    token.receiveWithAuthorization(
      alice, bob, _amount, _validAfter, _validBefore, _nonce, _signature
    );
  }

  /// A transfer to the zero address succeeds (Solady ERC-20 allows this).
  function test_transferWithAuthorization_toZeroAddress_succeeds () public {
    uint256 _amount = 100 ether;
    bytes32 _nonce = bytes32(uint256(65));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;
    bytes memory _signature =
      _signTransferAuthorization(
        ALICE_PK, alice, address(0), _amount, _validAfter, _validBefore, _nonce
      );
    uint256 _aliceBalanceBefore = token.balanceOf(alice);
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationUsed(alice, _nonce);
    vm.expectEmit(true, true, false, true, address(token));
    emit Transfer(alice, address(0), _amount);
    token.transferWithAuthorization(
      alice, address(0), _amount, _validAfter, _validBefore, _nonce, _signature
    );
    assertEq(token.balanceOf(alice), _aliceBalanceBefore - _amount);
    assertTrue(token.authorizationState(alice, _nonce));
  }

  /// A transfer to self succeeds.
  function test_transferWithAuthorization_toSelf_succeeds () public {
    uint256 _amount = 100 ether;
    bytes32 _nonce = bytes32(uint256(66));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;
    bytes memory _signature =
      _signTransferAuthorization(
        ALICE_PK, alice, alice, _amount, _validAfter, _validBefore, _nonce
      );
    uint256 _aliceBalanceBefore = token.balanceOf(alice);
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationUsed(alice, _nonce);
    vm.expectEmit(true, true, false, true, address(token));
    emit Transfer(alice, alice, _amount);
    token.transferWithAuthorization(
      alice, alice, _amount, _validAfter, _validBefore, _nonce, _signature
    );

    // Balance unchanged since transferring to self.
    assertEq(token.balanceOf(alice), _aliceBalanceBefore);
    assertTrue(token.authorizationState(alice, _nonce));
  }

  /// An ERC-1271 signer can authorize transfers via its owner's signature.
  function test_transferWithAuthorization_erc1271Signer_succeeds () public {

    // Create a smart contract signer owned by Alice.
    MockERC1271Signer _signer = new MockERC1271Signer(alice);
    address _signerAddress = address(_signer);

    // Give tokens to the signer contract.
    uint256 _amount = 100 ether;
    token.transfer(_signerAddress, _amount);
    bytes32 _nonce = bytes32(uint256(30));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;

    // Sign as Alice (the owner of the signer contract).
    bytes memory _signature =
      _signTransferAuthorization(
        ALICE_PK, _signerAddress, bob, _amount, _validAfter, _validBefore,
        _nonce
      );
    uint256 _signerBalanceBefore = token.balanceOf(_signerAddress);
    uint256 _bobBalanceBefore = token.balanceOf(bob);
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationUsed(_signerAddress, _nonce);
    vm.expectEmit(true, true, false, true, address(token));
    emit Transfer(_signerAddress, bob, _amount);
    token.transferWithAuthorization(
      _signerAddress, bob, _amount, _validAfter, _validBefore, _nonce,
      _signature
    );
    assertEq(token.balanceOf(_signerAddress), _signerBalanceBefore - _amount);
    assertEq(token.balanceOf(bob), _bobBalanceBefore + _amount);
    assertTrue(token.authorizationState(_signerAddress, _nonce));
  }

  /// An ERC-1271 signer rejects signatures from non-owners.
  function test_transferWithAuthorization_erc1271Signer_wrongOwner_reverts ()
    public {

    // Create a smart contract signer owned by Alice.
    MockERC1271Signer _signer = new MockERC1271Signer(alice);
    address _signerAddress = address(_signer);

    // Give tokens to the signer contract.
    uint256 _amount = 100 ether;
    token.transfer(_signerAddress, _amount);
    bytes32 _nonce = bytes32(uint256(31));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;

    // Sign as Bob (NOT the owner of the signer contract).
    bytes memory _signature =
      _signTransferAuthorization(
        BOB_PK, _signerAddress, bob, _amount, _validAfter, _validBefore, _nonce
      );
    vm.expectRevert(IERC3009.InvalidSignature.selector);
    token.transferWithAuthorization(
      _signerAddress, bob, _amount, _validAfter, _validBefore, _nonce,
      _signature
    );
  }

  /// An ERC-1271 signer can cancel authorizations via its owner's signature.
  function test_cancelAuthorization_erc1271Signer_succeeds () public {

    // Create a smart contract signer owned by Alice.
    MockERC1271Signer _signer = new MockERC1271Signer(alice);
    address _signerAddress = address(_signer);
    bytes32 _nonce = bytes32(uint256(32));

    // Sign cancellation as Alice (the owner).
    bytes memory _signature =
      _signCancelAuthorization(ALICE_PK, _signerAddress, _nonce);
    assertFalse(token.authorizationState(_signerAddress, _nonce));
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationCanceled(_signerAddress, _nonce);
    token.cancelAuthorization(_signerAddress, _nonce, _signature);
    assertTrue(token.authorizationState(_signerAddress, _nonce));
  }

  /// An ERC-1271 signer can receive tokens via its owner's signature.
  function test_receiveWithAuthorization_erc1271Signer_succeeds () public {

    // Create a smart contract signer owned by Alice.
    MockERC1271Signer _signer = new MockERC1271Signer(alice);
    address _signerAddress = address(_signer);

    // Give tokens to the signer contract.
    uint256 _amount = 100 ether;
    token.transfer(_signerAddress, _amount);
    bytes32 _nonce = bytes32(uint256(33));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;

    // Sign as Alice (the owner of the signer contract).
    bytes memory _signature =
      _signReceiveAuthorization(
        ALICE_PK, _signerAddress, bob, _amount, _validAfter, _validBefore,
        _nonce
      );
    uint256 _signerBalanceBefore = token.balanceOf(_signerAddress);
    uint256 _bobBalanceBefore = token.balanceOf(bob);

    // Bob (the recipient) must call this function.
    vm.prank(bob);
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationUsed(_signerAddress, _nonce);
    vm.expectEmit(true, true, false, true, address(token));
    emit Transfer(_signerAddress, bob, _amount);
    token.receiveWithAuthorization(
      _signerAddress, bob, _amount, _validAfter, _validBefore, _nonce,
      _signature
    );
    assertEq(token.balanceOf(_signerAddress), _signerBalanceBefore - _amount);
    assertEq(token.balanceOf(bob), _bobBalanceBefore + _amount);
    assertTrue(token.authorizationState(_signerAddress, _nonce));
  }

  /// An ERC-6492 signature authorizes transfers from an undeployed signer.
  function test_transferWithAuthorization_erc6492Signer_succeeds () public {

    // Create a factory for deploying signers.
    MockERC1271SignerFactory _factory = new MockERC1271SignerFactory();

    // Compute the address where the signer WOULD be deployed.
    bytes32 _salt = bytes32(uint256(100));
    address _signerAddress = _factory.computeAddress(alice, _salt);

    // Give tokens to the not-yet-deployed signer address.
    uint256 _amount = 100 ether;
    token.transfer(_signerAddress, _amount);
    bytes32 _nonce = bytes32(uint256(40));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;

    // Create the inner signature from Alice (the future owner).
    bytes memory _innerSignature =
      _signTransferAuthorization(
        ALICE_PK, _signerAddress, bob, _amount, _validAfter, _validBefore,
        _nonce
      );

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
    uint256 _signerBalanceBefore = token.balanceOf(_signerAddress);
    uint256 _bobBalanceBefore = token.balanceOf(bob);
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationUsed(_signerAddress, _nonce);
    vm.expectEmit(true, true, false, true, address(token));
    emit Transfer(_signerAddress, bob, _amount);
    token.transferWithAuthorization(
      _signerAddress, bob, _amount, _validAfter, _validBefore, _nonce,
      _erc6492Signature
    );
    assertEq(token.balanceOf(_signerAddress), _signerBalanceBefore - _amount);
    assertEq(token.balanceOf(bob), _bobBalanceBefore + _amount);
    assertTrue(token.authorizationState(_signerAddress, _nonce));
  }

  /// An ERC-6492 signature authorizes receives from an undeployed signer.
  function test_receiveWithAuthorization_erc6492Signer_succeeds () public {

    // Create a factory for deploying signers.
    MockERC1271SignerFactory _factory = new MockERC1271SignerFactory();

    // Compute the address where the signer WOULD be deployed.
    bytes32 _salt = bytes32(uint256(101));
    address _signerAddress = _factory.computeAddress(alice, _salt);

    // Give tokens to the not-yet-deployed signer address.
    uint256 _amount = 100 ether;
    token.transfer(_signerAddress, _amount);
    bytes32 _nonce = bytes32(uint256(41));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;

    // Create the inner signature from Alice (the future owner).
    bytes memory _innerSignature =
      _signReceiveAuthorization(
        ALICE_PK, _signerAddress, bob, _amount, _validAfter, _validBefore,
        _nonce
      );

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
    uint256 _signerBalanceBefore = token.balanceOf(_signerAddress);
    uint256 _bobBalanceBefore = token.balanceOf(bob);

    // Bob (the recipient) must call this function.
    vm.prank(bob);
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationUsed(_signerAddress, _nonce);
    vm.expectEmit(true, true, false, true, address(token));
    emit Transfer(_signerAddress, bob, _amount);
    token.receiveWithAuthorization(
      _signerAddress, bob, _amount, _validAfter, _validBefore, _nonce,
      _erc6492Signature
    );
    assertEq(token.balanceOf(_signerAddress), _signerBalanceBefore - _amount);
    assertEq(token.balanceOf(bob), _bobBalanceBefore + _amount);
    assertTrue(token.authorizationState(_signerAddress, _nonce));
  }

  /// An ERC-6492 signature authorizes cancellation from an undeployed signer.
  function test_cancelAuthorization_erc6492Signer_succeeds () public {

    // Create a factory for deploying signers.
    MockERC1271SignerFactory _factory = new MockERC1271SignerFactory();

    // Compute the address where the signer WOULD be deployed.
    bytes32 _salt = bytes32(uint256(102));
    address _signerAddress = _factory.computeAddress(alice, _salt);
    bytes32 _nonce = bytes32(uint256(42));

    // Create the inner signature from Alice (the future owner).
    bytes memory _innerSignature =
      _signCancelAuthorization(ALICE_PK, _signerAddress, _nonce);

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
    assertFalse(token.authorizationState(_signerAddress, _nonce));
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationCanceled(_signerAddress, _nonce);
    token.cancelAuthorization(_signerAddress, _nonce, _erc6492Signature);
    assertTrue(token.authorizationState(_signerAddress, _nonce));
  }

  /// An ERC-7739 signer validates nested EIP-712 signatures correctly.
  function test_transferWithAuthorization_erc7739Signer_succeeds () public {

    // Create a smart contract signer that uses nested EIP-712.
    MockERC7739Signer _signer = new MockERC7739Signer(alice);
    address _signerAddress = address(_signer);

    // Give tokens to the signer contract.
    token.transfer(_signerAddress, 100 ether);
    bytes32 _nonce = bytes32(uint256(50));

    // Compute the application's hash and get the wrapped hash for ERC-7739.
    bytes32 _appHash =
      keccak256(
        abi.encodePacked(
          "\x19\x01", DOMAIN_SEPARATOR,
          keccak256(
            abi.encode(
              TRANSFER_WITH_AUTHORIZATION_TYPEHASH, _signerAddress, bob,
              100 ether, block.timestamp - 1, block.timestamp + 1 hours, _nonce
            )
          )
        )
      );

    // Sign the wrapped hash as Alice (the owner).
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(
      ALICE_PK, _signer.getWrappedHash(_appHash)
    );
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationUsed(_signerAddress, _nonce);
    vm.expectEmit(true, true, false, true, address(token));
    emit Transfer(_signerAddress, bob, 100 ether);
    token.transferWithAuthorization(
      _signerAddress, bob, 100 ether, block.timestamp - 1,
      block.timestamp + 1 hours, _nonce, abi.encodePacked(_r, _s, _v)
    );
    assertEq(token.balanceOf(_signerAddress), 0);
    assertEq(token.balanceOf(bob), 100 ether);
    assertTrue(token.authorizationState(_signerAddress, _nonce));
  }

  /// An ERC-7739 signer rejects signatures over the unwrapped hash.
  function test_transferWithAuthorization_erc7739Signer_unwrappedHash_reverts ()
    public {

    // Create a smart contract signer that uses nested EIP-712.
    address _signerAddress = address(new MockERC7739Signer(alice));

    // Give tokens to the signer contract.
    token.transfer(_signerAddress, 100 ether);
    bytes32 _nonce = bytes32(uint256(51));

    // Sign the application hash directly (without wrapping) - this should fail.
    bytes memory _signature =
      _signTransferAuthorization(
        ALICE_PK, _signerAddress, bob, 100 ether, block.timestamp - 1,
        block.timestamp + 1 hours, _nonce
      );
    vm.expectRevert(IERC3009.InvalidSignature.selector);
    token.transferWithAuthorization(
      _signerAddress, bob, 100 ether, block.timestamp - 1,
      block.timestamp + 1 hours, _nonce, _signature
    );
  }

  /// An ERC-7739 signer can receive tokens via nested EIP-712 signatures.
  function test_receiveWithAuthorization_erc7739Signer_succeeds () public {

    // Create a smart contract signer that uses nested EIP-712.
    MockERC7739Signer _signer = new MockERC7739Signer(alice);
    address _signerAddress = address(_signer);

    // Give tokens to the signer contract.
    uint256 _amount = 100 ether;
    token.transfer(_signerAddress, _amount);
    bytes32 _nonce = bytes32(uint256(52));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;

    // Compute the application's hash and get the wrapped hash for ERC-7739.
    bytes32 _appHash =
      keccak256(
        abi.encodePacked(
          "\x19\x01", DOMAIN_SEPARATOR,
          keccak256(
            abi.encode(
              RECEIVE_WITH_AUTHORIZATION_TYPEHASH, _signerAddress, bob, _amount,
              _validAfter, _validBefore, _nonce
            )
          )
        )
      );

    // Sign the wrapped hash as Alice (the owner).
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(
      ALICE_PK, _signer.getWrappedHash(_appHash)
    );
    uint256 _signerBalanceBefore = token.balanceOf(_signerAddress);
    uint256 _bobBalanceBefore = token.balanceOf(bob);

    // Bob (the recipient) must call this function.
    vm.prank(bob);
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationUsed(_signerAddress, _nonce);
    vm.expectEmit(true, true, false, true, address(token));
    emit Transfer(_signerAddress, bob, _amount);
    token.receiveWithAuthorization(
      _signerAddress, bob, _amount, _validAfter, _validBefore, _nonce,
      abi.encodePacked(_r, _s, _v)
    );
    assertEq(token.balanceOf(_signerAddress), _signerBalanceBefore - _amount);
    assertEq(token.balanceOf(bob), _bobBalanceBefore + _amount);
    assertTrue(token.authorizationState(_signerAddress, _nonce));
  }

  /**
    An ERC-7739 signer can cancel authorizations via nested EIP-712 signatures.
  */
  function test_cancelAuthorization_erc7739Signer_succeeds () public {

    // Create a smart contract signer that uses nested EIP-712.
    MockERC7739Signer _signer = new MockERC7739Signer(alice);
    address _signerAddress = address(_signer);
    bytes32 _nonce = bytes32(uint256(53));

    // Compute the application's hash and get the wrapped hash for ERC-7739.
    bytes32 _appHash =
      keccak256(
        abi.encodePacked(
          "\x19\x01", DOMAIN_SEPARATOR,
          keccak256(
            abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, _signerAddress, _nonce)
          )
        )
      );

    // Sign the wrapped hash as Alice (the owner).
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(
      ALICE_PK, _signer.getWrappedHash(_appHash)
    );
    assertFalse(token.authorizationState(_signerAddress, _nonce));
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationCanceled(_signerAddress, _nonce);
    token.cancelAuthorization(
      _signerAddress, _nonce, abi.encodePacked(_r, _s, _v)
    );
    assertTrue(token.authorizationState(_signerAddress, _nonce));
  }
}

