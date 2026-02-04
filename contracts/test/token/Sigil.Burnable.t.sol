// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { MockERC1271Signer } from "./signers/MockERC1271Signer.sol";
import { MockERC1271SignerFactory } from
  "./signers/MockERC1271SignerFactory.sol";
import { MockERC7739Signer } from "./signers/MockERC7739Signer.sol";
import { SigilTestBase } from "./utils/SigilTestBase.sol";
import { IERC3009 } from "token/interfaces/IERC3009.sol";
import { ISignatureHelper } from "token/interfaces/ISignatureHelper.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Tests for burnable functionality in the Sigil token.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  Test that Sigil has implemented BurnableERC3009 correctly.

  @custom:date February 3rd, 2026.
*/
contract SigilBurnableTest is
  SigilTestBase {

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

  /// The burn with authorization typehash.
  bytes32 public constant BURN_WITH_AUTHORIZATION_TYPEHASH =
    0x2808d214735158921f7f8a6ca28e887d7f781959759f5c1cd6645228bdfe6386;

  /// The ERC-3009 cancel typehash.
  bytes32 public constant CANCEL_AUTHORIZATION_TYPEHASH =
    0x158b0a9edf7a828aad02f63cd515c68ef2f50ba807396f6d12842833a1597429;

  /// The ERC-6492 universal signature validator address used by Solady.
  address internal constant EIP6492_UNIVERSAL_VALIDATOR =
    0x00007bd799e4A591FeA53f8A8a3E9f931626Ba7e;

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
    _setUpSigil();
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
    Helper to create a burn authorization signature.

    @param _signerPk The authorizer's private key.
    @param _from The address whose tokens will be burned.
    @param _amount The amount of tokens to burn.
    @param _validAfter The timestamp when the authorization becomes valid.
    @param _validBefore The timestamp when the authorization becomes invalid.
    @param _nonce The authorization nonce.

    @return _ The authorization signature.
  */
  function _signBurnAuthorization (
    uint256 _signerPk,
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
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(_signerPk, _digest);
    return abi.encodePacked(_r, _s, _v);
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

  /// A caller can burn their own tokens.
  function test_burn_succeeds () public {
    uint256 _amount = 100 ether;
    uint256 _aliceBalanceBefore = token.balanceOf(alice);
    uint256 _totalSupplyBefore = token.totalSupply();
    vm.prank(alice);
    vm.expectEmit(true, true, false, true, address(token));
    emit Transfer(alice, address(0), _amount);
    token.burn(_amount);
    assertEq(token.balanceOf(alice), _aliceBalanceBefore - _amount);
    assertEq(token.totalSupply(), _totalSupplyBefore - _amount);
  }

  /// Burning zero tokens succeeds.
  function test_burn_zeroAmount_succeeds () public {
    uint256 _aliceBalanceBefore = token.balanceOf(alice);
    uint256 _totalSupplyBefore = token.totalSupply();
    vm.prank(alice);
    vm.expectEmit(true, true, false, true, address(token));
    emit Transfer(alice, address(0), 0);
    token.burn(0);
    assertEq(token.balanceOf(alice), _aliceBalanceBefore);
    assertEq(token.totalSupply(), _totalSupplyBefore);
  }

  /// Burning more than balance reverts.
  function test_burn_insufficientBalance_reverts () public {
    uint256 _amount = token.balanceOf(alice) + 1;
    vm.prank(alice);
    vm.expectRevert();
    token.burn(_amount);
  }

  /// A caller with no balance cannot burn tokens.
  function test_burn_noBalance_reverts () public {
    vm.prank(charlie);
    vm.expectRevert();
    token.burn(1);
  }

  /// A spender with allowance can burn tokens from another account.
  function test_burnFrom_withAllowance_succeeds () public {
    uint256 _amount = 100 ether;
    vm.prank(alice);
    token.approve(bob, _amount);
    uint256 _aliceBalanceBefore = token.balanceOf(alice);
    uint256 _totalSupplyBefore = token.totalSupply();
    vm.prank(bob);
    vm.expectEmit(true, true, false, true, address(token));
    emit Transfer(alice, address(0), _amount);
    token.burnFrom(alice, _amount);
    assertEq(token.balanceOf(alice), _aliceBalanceBefore - _amount);
    assertEq(token.totalSupply(), _totalSupplyBefore - _amount);
    assertEq(token.allowance(alice, bob), 0);
  }

  /// A spender with infinite allowance can burn without reducing allowance.
  function test_burnFrom_infiniteAllowance_succeeds () public {
    uint256 _amount = 100 ether;
    vm.prank(alice);
    token.approve(bob, type(uint256).max);
    uint256 _aliceBalanceBefore = token.balanceOf(alice);
    vm.prank(bob);
    token.burnFrom(alice, _amount);
    assertEq(token.balanceOf(alice), _aliceBalanceBefore - _amount);
    assertEq(token.allowance(alice, bob), type(uint256).max);
  }

  /// A spender without allowance cannot burn tokens from another account.
  function test_burnFrom_noAllowance_reverts () public {
    vm.prank(bob);
    vm.expectRevert();
    token.burnFrom(alice, 100 ether);
  }

  /// A spender with insufficient allowance cannot burn more than allowed.
  function test_burnFrom_insufficientAllowance_reverts () public {
    vm.prank(alice);
    token.approve(bob, 50 ether);
    vm.prank(bob);
    vm.expectRevert();
    token.burnFrom(alice, 100 ether);
  }

  /// burnFrom reverts if the from address has insufficient balance.
  function test_burnFrom_insufficientBalance_reverts () public {
    uint256 _aliceBalance = token.balanceOf(alice);
    vm.prank(alice);
    token.approve(bob, _aliceBalance + 1);
    vm.prank(bob);
    vm.expectRevert();
    token.burnFrom(alice, _aliceBalance + 1);
  }

  /// A valid signed authorization allows any caller to execute the burn.
  function test_burnWithAuthorization_succeeds () public {
    uint256 _amount = 100 ether;
    bytes32 _nonce = bytes32(uint256(1));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;
    bytes memory _signature =
      _signBurnAuthorization(
        ALICE_PK, alice, _amount, _validAfter, _validBefore, _nonce
      );
    uint256 _aliceBalanceBefore = token.balanceOf(alice);
    uint256 _totalSupplyBefore = token.totalSupply();

    // Anyone can submit the burn.
    vm.prank(charlie);
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationUsed(alice, _nonce);
    vm.expectEmit(true, true, false, true, address(token));
    emit Transfer(alice, address(0), _amount);
    token.burnWithAuthorization(
      alice, _amount, _validAfter, _validBefore, _nonce, _signature
    );
    assertEq(token.balanceOf(alice), _aliceBalanceBefore - _amount);
    assertEq(token.totalSupply(), _totalSupplyBefore - _amount);
    assertTrue(token.authorizationState(alice, _nonce));
  }

  /// The v, r, s signature variant also executes burns correctly.
  function test_burnWithAuthorization_withVRS_succeeds () public {
    uint256 _amount = 100 ether;
    bytes32 _nonce = bytes32(uint256(2));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;
    bytes32 _structHash =
      keccak256(
        abi.encode(
          BURN_WITH_AUTHORIZATION_TYPEHASH, alice, _amount, _validAfter,
          _validBefore, _nonce
        )
      );
    bytes32 _digest =
      keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, _structHash));
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(ALICE_PK, _digest);
    uint256 _aliceBalanceBefore = token.balanceOf(alice);
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationUsed(alice, _nonce);
    vm.expectEmit(true, true, false, true, address(token));
    emit Transfer(alice, address(0), _amount);
    token.burnWithAuthorization(
      alice, _amount, _validAfter, _validBefore, _nonce, _v, _r, _s
    );
    assertEq(token.balanceOf(alice), _aliceBalanceBefore - _amount);
  }

  /// An authorization that has expired cannot be used for a burn.
  function test_burnWithAuthorization_expired_reverts () public {

    // Warp to a future time to avoid underflow.
    vm.warp(10 hours);
    uint256 _amount = 100 ether;
    bytes32 _nonce = bytes32(uint256(3));
    uint256 _validAfter = block.timestamp - 2 hours;

    // Expired.
    uint256 _validBefore = block.timestamp - 1 hours;
    bytes memory _signature =
      _signBurnAuthorization(
        ALICE_PK, alice, _amount, _validAfter, _validBefore, _nonce
      );
    vm.expectRevert(IERC3009.AuthorizationExpired.selector);
    token.burnWithAuthorization(
      alice, _amount, _validAfter, _validBefore, _nonce, _signature
    );
  }

  /// An authorization that is not yet valid cannot be used for a burn.
  function test_burnWithAuthorization_notYetValid_reverts () public {
    uint256 _amount = 100 ether;
    bytes32 _nonce = bytes32(uint256(4));

    // Not yet valid.
    uint256 _validAfter = block.timestamp + 1 hours;
    uint256 _validBefore = block.timestamp + 2 hours;
    bytes memory _signature =
      _signBurnAuthorization(
        ALICE_PK, alice, _amount, _validAfter, _validBefore, _nonce
      );
    vm.expectRevert(IERC3009.AuthorizationNotYetValid.selector);
    token.burnWithAuthorization(
      alice, _amount, _validAfter, _validBefore, _nonce, _signature
    );
  }

  /// A nonce that has already been used cannot be reused for another burn.
  function test_burnWithAuthorization_reusedNonce_reverts () public {
    uint256 _amount = 100 ether;
    bytes32 _nonce = bytes32(uint256(5));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;
    bytes memory _signature =
      _signBurnAuthorization(
        ALICE_PK, alice, _amount, _validAfter, _validBefore, _nonce
      );

    // First burn succeeds.
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationUsed(alice, _nonce);
    token.burnWithAuthorization(
      alice, _amount, _validAfter, _validBefore, _nonce, _signature
    );

    // Second burn with same nonce reverts.
    vm.expectRevert(IERC3009.AuthorizationAlreadyUsed.selector);
    token.burnWithAuthorization(
      alice, _amount, _validAfter, _validBefore, _nonce, _signature
    );
  }

  /// An authorization signed by the wrong key is rejected.
  function test_burnWithAuthorization_invalidSignature_reverts () public {
    uint256 _amount = 100 ether;
    bytes32 _nonce = bytes32(uint256(6));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;

    // Sign with Bob's key instead of Alice's.
    bytes memory _signature =
      _signBurnAuthorization(
        BOB_PK, alice, _amount, _validAfter, _validBefore, _nonce
      );
    vm.expectRevert(ISignatureHelper.InvalidSignature.selector);
    token.burnWithAuthorization(
      alice, _amount, _validAfter, _validBefore, _nonce, _signature
    );
  }

  /// A zero amount burn succeeds.
  function test_burnWithAuthorization_zeroAmount_succeeds () public {
    uint256 _amount = 0;
    bytes32 _nonce = bytes32(uint256(7));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;
    bytes memory _signature =
      _signBurnAuthorization(
        ALICE_PK, alice, _amount, _validAfter, _validBefore, _nonce
      );
    uint256 _aliceBalanceBefore = token.balanceOf(alice);
    uint256 _totalSupplyBefore = token.totalSupply();
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationUsed(alice, _nonce);
    token.burnWithAuthorization(
      alice, _amount, _validAfter, _validBefore, _nonce, _signature
    );
    assertEq(token.balanceOf(alice), _aliceBalanceBefore);
    assertEq(token.totalSupply(), _totalSupplyBefore);
    assertTrue(token.authorizationState(alice, _nonce));
  }

  /// A burn exceeding balance reverts.
  function test_burnWithAuthorization_insufficientBalance_reverts () public {
    uint256 _amount = token.balanceOf(alice) + 1;
    bytes32 _nonce = bytes32(uint256(8));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;
    bytes memory _signature =
      _signBurnAuthorization(
        ALICE_PK, alice, _amount, _validAfter, _validBefore, _nonce
      );
    vm.expectRevert();
    token.burnWithAuthorization(
      alice, _amount, _validAfter, _validBefore, _nonce, _signature
    );
  }

  /// A burn exactly at validAfter timestamp succeeds.
  function test_burnWithAuthorization_exactlyAtValidAfter_succeeds () public {
    uint256 _amount = 100 ether;
    bytes32 _nonce = bytes32(uint256(9));
    uint256 _validAfter = block.timestamp;
    uint256 _validBefore = block.timestamp + 1 hours;
    bytes memory _signature =
      _signBurnAuthorization(
        ALICE_PK, alice, _amount, _validAfter, _validBefore, _nonce
      );
    uint256 _aliceBalanceBefore = token.balanceOf(alice);

    // Boundary: block.timestamp == validAfter is valid (uses < not <=).
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationUsed(alice, _nonce);
    token.burnWithAuthorization(
      alice, _amount, _validAfter, _validBefore, _nonce, _signature
    );
    assertEq(token.balanceOf(alice), _aliceBalanceBefore - _amount);
  }

  /// A burn exactly at validBefore timestamp succeeds.
  function test_burnWithAuthorization_exactlyAtValidBefore_succeeds () public {

    // Warp forward to avoid underflow when computing validAfter.
    vm.warp(2 hours);
    uint256 _amount = 100 ether;
    bytes32 _nonce = bytes32(uint256(10));
    uint256 _validAfter = block.timestamp - 1 hours;
    uint256 _validBefore = block.timestamp;
    bytes memory _signature =
      _signBurnAuthorization(
        ALICE_PK, alice, _amount, _validAfter, _validBefore, _nonce
      );
    uint256 _aliceBalanceBefore = token.balanceOf(alice);

    // Boundary: block.timestamp == validBefore is valid (uses > not >=).
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationUsed(alice, _nonce);
    token.burnWithAuthorization(
      alice, _amount, _validAfter, _validBefore, _nonce, _signature
    );
    assertEq(token.balanceOf(alice), _aliceBalanceBefore - _amount);
  }

  /// A nonce used for transfer cannot be reused for burn.
  function test_burnWithAuthorization_nonceUsedByTransfer_reverts () public {
    uint256 _amount = 100 ether;
    bytes32 _nonce = bytes32(uint256(100));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;

    // First, use the nonce for a transfer.
    bytes memory _transferSig =
      _signTransferAuthorization(
        ALICE_PK, alice, bob, _amount, _validAfter, _validBefore, _nonce
      );
    token.transferWithAuthorization(
      alice, bob, _amount, _validAfter, _validBefore, _nonce, _transferSig
    );
    assertTrue(token.authorizationState(alice, _nonce));

    // Now try to use the same nonce for a burn.
    bytes memory _burnSig =
      _signBurnAuthorization(
        ALICE_PK, alice, _amount, _validAfter, _validBefore, _nonce
      );
    vm.expectRevert(IERC3009.AuthorizationAlreadyUsed.selector);
    token.burnWithAuthorization(
      alice, _amount, _validAfter, _validBefore, _nonce, _burnSig
    );
  }

  /// A nonce used for burn cannot be reused for transfer.
  function test_transferWithAuthorization_nonceUsedByBurn_reverts () public {
    uint256 _amount = 100 ether;
    bytes32 _nonce = bytes32(uint256(101));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;

    // First, use the nonce for a burn.
    bytes memory _burnSig =
      _signBurnAuthorization(
        ALICE_PK, alice, _amount, _validAfter, _validBefore, _nonce
      );
    token.burnWithAuthorization(
      alice, _amount, _validAfter, _validBefore, _nonce, _burnSig
    );
    assertTrue(token.authorizationState(alice, _nonce));

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

  /// A canceled nonce cannot be used for burn.
  function test_burnWithAuthorization_canceledNonce_reverts () public {
    uint256 _amount = 100 ether;
    bytes32 _nonce = bytes32(uint256(102));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;

    // First cancel the authorization.
    bytes memory _cancelSig =
      _signCancelAuthorization(ALICE_PK, alice, _nonce);
    token.cancelAuthorization(alice, _nonce, _cancelSig);
    assertTrue(token.authorizationState(alice, _nonce));

    // Now try to use the same nonce for a burn.
    bytes memory _burnSig =
      _signBurnAuthorization(
        ALICE_PK, alice, _amount, _validAfter, _validBefore, _nonce
      );
    vm.expectRevert(IERC3009.AuthorizationAlreadyUsed.selector);
    token.burnWithAuthorization(
      alice, _amount, _validAfter, _validBefore, _nonce, _burnSig
    );
  }

  /// An ERC-1271 signer can authorize burns via its owner's signature.
  function test_burnWithAuthorization_erc1271Signer_succeeds () public {

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
      _signBurnAuthorization(
        ALICE_PK, _signerAddress, _amount, _validAfter, _validBefore, _nonce
      );
    uint256 _signerBalanceBefore = token.balanceOf(_signerAddress);
    uint256 _totalSupplyBefore = token.totalSupply();
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationUsed(_signerAddress, _nonce);
    vm.expectEmit(true, true, false, true, address(token));
    emit Transfer(_signerAddress, address(0), _amount);
    token.burnWithAuthorization(
      _signerAddress, _amount, _validAfter, _validBefore, _nonce, _signature
    );
    assertEq(token.balanceOf(_signerAddress), _signerBalanceBefore - _amount);
    assertEq(token.totalSupply(), _totalSupplyBefore - _amount);
    assertTrue(token.authorizationState(_signerAddress, _nonce));
  }

  /// An ERC-1271 signer rejects signatures from non-owners.
  function test_burnWithAuthorization_erc1271Signer_wrongOwner_reverts ()
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
      _signBurnAuthorization(
        BOB_PK, _signerAddress, _amount, _validAfter, _validBefore, _nonce
      );
    vm.expectRevert(ISignatureHelper.InvalidSignature.selector);
    token.burnWithAuthorization(
      _signerAddress, _amount, _validAfter, _validBefore, _nonce, _signature
    );
  }

  /// An ERC-6492 signature authorizes burns from an undeployed signer.
  function test_burnWithAuthorization_erc6492Signer_succeeds () public {

    // Create a factory for deploying signers.
    MockERC1271SignerFactory _factory = new MockERC1271SignerFactory();

    // Compute the address where the signer WOULD be deployed.
    bytes32 _salt = bytes32(uint256(200));
    address _signerAddress = _factory.computeAddress(alice, _salt);

    // Give tokens to the not-yet-deployed signer address.
    uint256 _amount = 100 ether;
    token.transfer(_signerAddress, _amount);
    bytes32 _nonce = bytes32(uint256(40));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;

    // Create the inner signature from Alice (the future owner).
    bytes memory _innerSignature =
      _signBurnAuthorization(
        ALICE_PK, _signerAddress, _amount, _validAfter, _validBefore, _nonce
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
    uint256 _totalSupplyBefore = token.totalSupply();
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationUsed(_signerAddress, _nonce);
    vm.expectEmit(true, true, false, true, address(token));
    emit Transfer(_signerAddress, address(0), _amount);
    token.burnWithAuthorization(
      _signerAddress, _amount, _validAfter, _validBefore, _nonce,
      _erc6492Signature
    );
    assertEq(token.balanceOf(_signerAddress), _signerBalanceBefore - _amount);
    assertEq(token.totalSupply(), _totalSupplyBefore - _amount);
    assertTrue(token.authorizationState(_signerAddress, _nonce));
  }

  /// An ERC-7739 signer validates nested EIP-712 signatures correctly.
  function test_burnWithAuthorization_erc7739Signer_succeeds () public {

    // Create a smart contract signer that uses nested EIP-712.
    MockERC7739Signer _signer = new MockERC7739Signer(alice);
    address _signerAddress = address(_signer);

    // Give tokens to the signer contract.
    uint256 _amount = 100 ether;
    token.transfer(_signerAddress, _amount);
    bytes32 _nonce = bytes32(uint256(50));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;

    // Compute the application's hash and get the wrapped hash for ERC-7739.
    bytes32 _appHash =
      keccak256(
        abi.encodePacked(
          "\x19\x01", DOMAIN_SEPARATOR,
          keccak256(
            abi.encode(
              BURN_WITH_AUTHORIZATION_TYPEHASH, _signerAddress, _amount,
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
    uint256 _totalSupplyBefore = token.totalSupply();
    vm.expectEmit(true, true, false, false, address(token));
    emit IERC3009.AuthorizationUsed(_signerAddress, _nonce);
    vm.expectEmit(true, true, false, true, address(token));
    emit Transfer(_signerAddress, address(0), _amount);
    token.burnWithAuthorization(
      _signerAddress, _amount, _validAfter, _validBefore, _nonce,
      abi.encodePacked(_r, _s, _v)
    );
    assertEq(token.balanceOf(_signerAddress), _signerBalanceBefore - _amount);
    assertEq(token.totalSupply(), _totalSupplyBefore - _amount);
    assertTrue(token.authorizationState(_signerAddress, _nonce));
  }

  /// An ERC-7739 signer rejects signatures over the unwrapped hash.
  function test_burnWithAuthorization_erc7739Signer_unwrappedHash_reverts ()
    public {

    // Create a smart contract signer that uses nested EIP-712.
    address _signerAddress = address(new MockERC7739Signer(alice));

    // Give tokens to the signer contract.
    uint256 _amount = 100 ether;
    token.transfer(_signerAddress, _amount);
    bytes32 _nonce = bytes32(uint256(51));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;

    // Sign the application hash directly (without wrapping) - this should fail.
    bytes memory _signature =
      _signBurnAuthorization(
        ALICE_PK, _signerAddress, _amount, _validAfter, _validBefore, _nonce
      );
    vm.expectRevert(ISignatureHelper.InvalidSignature.selector);
    token.burnWithAuthorization(
      _signerAddress, _amount, _validAfter, _validBefore, _nonce, _signature
    );
  }

  /// Using a transfer signature for a burn call fails (wrong typehash).
  function test_burnWithAuthorization_transferTypehash_reverts () public {
    uint256 _amount = 100 ether;
    bytes32 _nonce = bytes32(uint256(200));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;

    // Sign with TRANSFER typehash instead of BURN typehash.
    bytes memory _signature =
      _signTransferAuthorization(
        ALICE_PK, alice, bob, _amount, _validAfter, _validBefore, _nonce
      );

    // The nonce is fresh, but the typehash is wrong.
    assertFalse(token.authorizationState(alice, _nonce));
    vm.expectRevert(ISignatureHelper.InvalidSignature.selector);
    token.burnWithAuthorization(
      alice, _amount, _validAfter, _validBefore, _nonce, _signature
    );
  }

  /// Using a burn signature for a transfer call fails (wrong typehash).
  function test_transferWithAuthorization_burnTypehash_reverts () public {
    uint256 _amount = 100 ether;
    bytes32 _nonce = bytes32(uint256(201));
    uint256 _validAfter = block.timestamp - 1;
    uint256 _validBefore = block.timestamp + 1 hours;

    // Sign with BURN typehash instead of TRANSFER typehash.
    bytes memory _signature =
      _signBurnAuthorization(
        ALICE_PK, alice, _amount, _validAfter, _validBefore, _nonce
      );

    // The nonce is fresh, but the typehash is wrong.
    assertFalse(token.authorizationState(alice, _nonce));
    vm.expectRevert(ISignatureHelper.InvalidSignature.selector);
    token.transferWithAuthorization(
      alice, bob, _amount, _validAfter, _validBefore, _nonce, _signature
    );
  }

  /// Burning the entire balance succeeds.
  function test_burn_entireBalance_succeeds () public {
    uint256 _aliceBalance = token.balanceOf(alice);
    uint256 _totalSupplyBefore = token.totalSupply();
    vm.prank(alice);
    vm.expectEmit(true, true, false, true, address(token));
    emit Transfer(alice, address(0), _aliceBalance);
    token.burn(_aliceBalance);
    assertEq(token.balanceOf(alice), 0);
    assertEq(token.totalSupply(), _totalSupplyBefore - _aliceBalance);
  }

  /// A caller can use burnFrom on themselves.
  function test_burnFrom_self_succeeds () public {
    uint256 _amount = 100 ether;

    // Alice approves herself.
    vm.prank(alice);
    token.approve(alice, _amount);
    uint256 _aliceBalanceBefore = token.balanceOf(alice);
    uint256 _totalSupplyBefore = token.totalSupply();

    // Alice burns from herself.
    vm.prank(alice);
    vm.expectEmit(true, true, false, true, address(token));
    emit Transfer(alice, address(0), _amount);
    token.burnFrom(alice, _amount);
    assertEq(token.balanceOf(alice), _aliceBalanceBefore - _amount);
    assertEq(token.totalSupply(), _totalSupplyBefore - _amount);
  }

  /// The token supports the IBurnableERC3009 interface.
  function test_supportsInterface_burnableERC3009 () public view {
    bytes4 _burnableInterfaceId = 0xe279933e;
    assertTrue(token.supportsInterface(_burnableInterfaceId));
  }
}

