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
  @title Tests for ERC-2612 permit functionality.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  Test that the ERC-2612 permit implementation works correctly. These tests
  verify the existing Solady implementation to ensure correctness is maintained
  when we override with unified signature support.

  @custom:date January 29th, 2026.
*/
contract SigilERC2612Test is
  Test {

  /**
    Declare the Approval event for expectEmit.

    @param owner The token owner granting approval.
    @param spender The address approved to spend tokens.
    @param value The amount of tokens approved.
  */
  event Approval (
    address indexed owner,
    address indexed spender,
    uint256 value
  );

  /// The EIP-712 typehash for the permit struct.
  bytes32 private constant _PERMIT_TYPEHASH =
    keccak256(
      "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );

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

  /// Bob's address (spender).
  address internal bob;

  /// Carol's address (another user).
  address internal carol;

  /// Set up the test.
  function setUp () public {
    token = new Sigil(address(this));

    // Create Alice with a known private key for signing.
    alicePrivateKey = 0xA11CE;
    alice = vm.addr(alicePrivateKey);
    bob = makeAddr("bob");
    carol = makeAddr("carol");

    // Give Alice some tokens.
    token.transfer(alice, 1000 ether);

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
    Compute the EIP-712 digest for a permit.

    @param _owner The owner of the tokens.
    @param _spender The spender to approve.
    @param _value The amount to approve.
    @param _nonce The current nonce.
    @param _deadline The deadline for the permit.

    @return _ The digest to sign.
  */
  function _computePermitDigest (
    address _owner,
    address _spender,
    uint256 _value,
    uint256 _nonce,
    uint256 _deadline
  ) internal view returns (bytes32) {
    bytes32 _structHash =
      keccak256(
        abi.encode(
          _PERMIT_TYPEHASH, _owner, _spender, _value, _nonce, _deadline
        )
      );
    return keccak256(
      abi.encodePacked("\x19\x01", _computeDomainSeparator(), _structHash)
    );
  }

  /**
    Sign a permit and return the signature components.

    @param _privateKey The private key to sign with.
    @param _owner The owner of the tokens.
    @param _spender The spender to approve.
    @param _value The amount to approve.
    @param _nonce The current nonce.
    @param _deadline The deadline for the permit.

    @return _ The recovery byte.
    @return _ The r component.
    @return _ The s component.
  */
  function _signPermit (
    uint256 _privateKey,
    address _owner,
    address _spender,
    uint256 _value,
    uint256 _nonce,
    uint256 _deadline
  ) internal view returns (uint8, bytes32, bytes32) {
    bytes32 _digest =
      _computePermitDigest(_owner, _spender, _value, _nonce, _deadline);
    return vm.sign(_privateKey, _digest);
  }

  /**
    Sign a permit and return the signature as packed bytes.

    @param _privateKey The private key to sign with.
    @param _owner The owner of the tokens.
    @param _spender The spender to approve.
    @param _value The amount to approve.
    @param _nonce The current nonce.
    @param _deadline The deadline for the permit.

    @return _ The packed signature bytes.
  */
  function _signPermitBytes (
    uint256 _privateKey,
    address _owner,
    address _spender,
    uint256 _value,
    uint256 _nonce,
    uint256 _deadline
  ) internal view returns (bytes memory) {
    bytes32 _digest =
      _computePermitDigest(_owner, _spender, _value, _nonce, _deadline);
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(_privateKey, _digest);
    return abi.encodePacked(_r, _s, _v);
  }

  /// DOMAIN_SEPARATOR returns the correct value.
  function test_domainSeparator () public view {
    assertEq(token.DOMAIN_SEPARATOR(), _computeDomainSeparator());
  }

  /// DOMAIN_SEPARATOR changes with chain ID.
  function test_domainSeparator_changesWithChainId () public {
    bytes32 _originalSeparator = token.DOMAIN_SEPARATOR();

    // Change chain ID.
    vm.chainId(999);
    bytes32 _newSeparator = token.DOMAIN_SEPARATOR();
    assertTrue(_originalSeparator != _newSeparator);
    assertEq(_newSeparator, _computeDomainSeparator());
  }

  /// Initial nonce is zero.
  function test_nonces_initiallyZero () public view {
    assertEq(token.nonces(alice), 0);
    assertEq(token.nonces(bob), 0);
  }

  /// Permit with valid signature sets allowance.
  function test_permit_setsAllowance () public {
    uint256 _value = 100 ether;
    uint256 _deadline = block.timestamp + 1 hours;
    uint256 _nonce = token.nonces(alice);
    (uint8 _v, bytes32 _r, bytes32 _s) = _signPermit(
      alicePrivateKey, alice, bob, _value, _nonce, _deadline
    );
    token.permit(alice, bob, _value, _deadline, _v, _r, _s);
    assertEq(token.allowance(alice, bob), _value);
  }

  /// Permit increments nonce.
  function test_permit_incrementsNonce () public {
    uint256 _value = 100 ether;
    uint256 _deadline = block.timestamp + 1 hours;
    assertEq(token.nonces(alice), 0);
    (uint8 _v, bytes32 _r, bytes32 _s) = _signPermit(
      alicePrivateKey, alice, bob, _value, 0, _deadline
    );
    token.permit(alice, bob, _value, _deadline, _v, _r, _s);
    assertEq(token.nonces(alice), 1);
  }

  /// Permit emits Approval event.
  function test_permit_emitsApproval () public {
    uint256 _value = 100 ether;
    uint256 _deadline = block.timestamp + 1 hours;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signPermit(
      alicePrivateKey, alice, bob, _value, 0, _deadline
    );
    vm.expectEmit(true, true, false, true);
    emit Approval(alice, bob, _value);
    token.permit(alice, bob, _value, _deadline, _v, _r, _s);
  }

  /// Permit with zero value works.
  function test_permit_zeroValue () public {
    uint256 _deadline = block.timestamp + 1 hours;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signPermit(
      alicePrivateKey, alice, bob, 0, 0, _deadline
    );
    token.permit(alice, bob, 0, _deadline, _v, _r, _s);
    assertEq(token.allowance(alice, bob), 0);
    assertEq(token.nonces(alice), 1);
  }

  /// Permit with max uint256 value works.
  function test_permit_maxValue () public {
    uint256 _value = type(uint256).max;
    uint256 _deadline = block.timestamp + 1 hours;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signPermit(
      alicePrivateKey, alice, bob, _value, 0, _deadline
    );
    token.permit(alice, bob, _value, _deadline, _v, _r, _s);
    assertEq(token.allowance(alice, bob), _value);
  }

  /// Permit can be called by anyone (not just owner or spender).
  function test_permit_calledByAnyone () public {
    uint256 _value = 100 ether;
    uint256 _deadline = block.timestamp + 1 hours;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signPermit(
      alicePrivateKey, alice, bob, _value, 0, _deadline
    );

    // Carol submits the permit on behalf of Alice.
    vm.prank(carol);
    token.permit(alice, bob, _value, _deadline, _v, _r, _s);
    assertEq(token.allowance(alice, bob), _value);
  }

  /// Permit overwrites previous allowance.
  function test_permit_overwritesAllowance () public {
    uint256 _deadline = block.timestamp + 1 hours;

    // First permit for 100.
    (uint8 _v1, bytes32 _r1, bytes32 _s1) = _signPermit(
      alicePrivateKey, alice, bob, 100 ether, 0, _deadline
    );
    token.permit(alice, bob, 100 ether, _deadline, _v1, _r1, _s1);
    assertEq(token.allowance(alice, bob), 100 ether);

    // Second permit for 50.
    (uint8 _v2, bytes32 _r2, bytes32 _s2) = _signPermit(
      alicePrivateKey, alice, bob, 50 ether, 1, _deadline
    );
    token.permit(alice, bob, 50 ether, _deadline, _v2, _r2, _s2);
    assertEq(token.allowance(alice, bob), 50 ether);
  }

  /// Permit fails with expired deadline.
  function test_permit_expiredDeadline_reverts () public {
    uint256 _value = 100 ether;

    // Already expired.
    uint256 _deadline = block.timestamp - 1;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signPermit(
      alicePrivateKey, alice, bob, _value, 0, _deadline
    );

    // PermitExpired()
    vm.expectRevert(bytes4(0x1a15a3cc));
    token.permit(alice, bob, _value, _deadline, _v, _r, _s);
  }

  /// Permit succeeds with deadline at current timestamp (boundary).
  function test_permit_deadlineAtTimestamp () public {
    uint256 _value = 100 ether;

    // Exactly at timestamp is still valid.
    uint256 _deadline = block.timestamp;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signPermit(
      alicePrivateKey, alice, bob, _value, 0, _deadline
    );

    // Solady uses `timestamp() > deadline`, so equality is valid.
    token.permit(alice, bob, _value, _deadline, _v, _r, _s);
    assertEq(token.allowance(alice, bob), _value);
  }

  /// Permit fails with wrong signer.
  function test_permit_wrongSigner_reverts () public {
    uint256 _value = 100 ether;
    uint256 _deadline = block.timestamp + 1 hours;
    uint256 _wrongPrivateKey = 0xBAD;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signPermit(
      _wrongPrivateKey, alice, bob, _value, 0, _deadline
    );

    // InvalidSignature()
    vm.expectRevert(ISignatureHelper.InvalidSignature.selector);
    token.permit(alice, bob, _value, _deadline, _v, _r, _s);
  }

  /// Permit fails with wrong owner in call (signature mismatch).
  function test_permit_wrongOwner_reverts () public {
    uint256 _value = 100 ether;
    uint256 _deadline = block.timestamp + 1 hours;

    // Sign for alice.
    (uint8 _v, bytes32 _r, bytes32 _s) = _signPermit(
      alicePrivateKey, alice, bob, _value, 0, _deadline
    );

    // InvalidSignature()
    vm.expectRevert(ISignatureHelper.InvalidSignature.selector);
    token.permit(carol, bob, _value, _deadline, _v, _r, _s);
  }

  /// Permit fails with wrong spender in call.
  function test_permit_wrongSpender_reverts () public {
    uint256 _value = 100 ether;
    uint256 _deadline = block.timestamp + 1 hours;

    // Sign for bob as spender.
    (uint8 _v, bytes32 _r, bytes32 _s) = _signPermit(
      alicePrivateKey, alice, bob, _value, 0, _deadline
    );

    // InvalidSignature()
    vm.expectRevert(ISignatureHelper.InvalidSignature.selector);
    token.permit(alice, carol, _value, _deadline, _v, _r, _s);
  }

  /// Permit fails with wrong value in call.
  function test_permit_wrongValue_reverts () public {
    uint256 _deadline = block.timestamp + 1 hours;

    // Sign for 100 ether.
    (uint8 _v, bytes32 _r, bytes32 _s) = _signPermit(
      alicePrivateKey, alice, bob, 100 ether, 0, _deadline
    );

    // InvalidSignature()
    vm.expectRevert(ISignatureHelper.InvalidSignature.selector);
    token.permit(alice, bob, 200 ether, _deadline, _v, _r, _s);
  }

  /// Permit fails with wrong deadline in call.
  function test_permit_wrongDeadline_reverts () public {
    uint256 _value = 100 ether;
    uint256 _deadline = block.timestamp + 1 hours;

    // Sign with one deadline.
    (uint8 _v, bytes32 _r, bytes32 _s) = _signPermit(
      alicePrivateKey, alice, bob, _value, 0, _deadline
    );

    // InvalidSignature()
    vm.expectRevert(ISignatureHelper.InvalidSignature.selector);
    token.permit(alice, bob, _value, _deadline + 1, _v, _r, _s);
  }

  /// Permit fails with wrong nonce (replay attack).
  function test_permit_replayAttack_reverts () public {
    uint256 _value = 100 ether;
    uint256 _deadline = block.timestamp + 1 hours;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signPermit(
      alicePrivateKey, alice, bob, _value, 0, _deadline
    );

    // First permit succeeds.
    token.permit(alice, bob, _value, _deadline, _v, _r, _s);

    // InvalidSignature()
    vm.expectRevert(ISignatureHelper.InvalidSignature.selector);
    token.permit(alice, bob, _value, _deadline, _v, _r, _s);
  }

  /// Permit fails with future nonce.
  function test_permit_futureNonce_reverts () public {
    uint256 _value = 100 ether;
    uint256 _deadline = block.timestamp + 1 hours;

    // Sign with nonce 5 but current nonce is 0.
    (uint8 _v, bytes32 _r, bytes32 _s) = _signPermit(
      alicePrivateKey, alice, bob, _value, 5, _deadline
    );

    // InvalidSignature()
    vm.expectRevert(ISignatureHelper.InvalidSignature.selector);
    token.permit(alice, bob, _value, _deadline, _v, _r, _s);
  }

  /// Permit fails with invalid v value.
  function test_permit_invalidV_reverts () public {
    uint256 _value = 100 ether;
    uint256 _deadline = block.timestamp + 1 hours;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signPermit(
      alicePrivateKey, alice, bob, _value, 0, _deadline
    );

    // InvalidSignature()
    vm.expectRevert(ISignatureHelper.InvalidSignature.selector);
    token.permit(alice, bob, _value, _deadline, _v + 1, _r, _s);
  }

  /// Permit fails with corrupted r.
  function test_permit_corruptedR_reverts () public {
    uint256 _value = 100 ether;
    uint256 _deadline = block.timestamp + 1 hours;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signPermit(
      alicePrivateKey, alice, bob, _value, 0, _deadline
    );

    // InvalidSignature()
    vm.expectRevert(ISignatureHelper.InvalidSignature.selector);
    token.permit(
      alice, bob, _value, _deadline, _v, bytes32(uint256(_r) + 1), _s
    );
  }

  /// Permit fails with corrupted s.
  function test_permit_corruptedS_reverts () public {
    uint256 _value = 100 ether;
    uint256 _deadline = block.timestamp + 1 hours;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signPermit(
      alicePrivateKey, alice, bob, _value, 0, _deadline
    );

    // InvalidSignature()
    vm.expectRevert(ISignatureHelper.InvalidSignature.selector);
    token.permit(
      alice, bob, _value, _deadline, _v, _r, bytes32(uint256(_s) + 1)
    );
  }

  /// Multiple permits in sequence work correctly.
  function test_permit_sequential () public {
    uint256 _deadline = block.timestamp + 1 hours;

    // First permit.
    (uint8 _v1, bytes32 _r1, bytes32 _s1) = _signPermit(
      alicePrivateKey, alice, bob, 100 ether, 0, _deadline
    );
    token.permit(alice, bob, 100 ether, _deadline, _v1, _r1, _s1);
    assertEq(token.nonces(alice), 1);

    // Second permit to different spender.
    (uint8 _v2, bytes32 _r2, bytes32 _s2) = _signPermit(
      alicePrivateKey, alice, carol, 200 ether, 1, _deadline
    );
    token.permit(alice, carol, 200 ether, _deadline, _v2, _r2, _s2);
    assertEq(token.nonces(alice), 2);

    // Third permit.
    (uint8 _v3, bytes32 _r3, bytes32 _s3) = _signPermit(
      alicePrivateKey, alice, bob, 300 ether, 2, _deadline
    );
    token.permit(alice, bob, 300 ether, _deadline, _v3, _r3, _s3);
    assertEq(token.nonces(alice), 3);

    // Verify final allowances.
    assertEq(token.allowance(alice, bob), 300 ether);
    assertEq(token.allowance(alice, carol), 200 ether);
  }

  /// Permit followed by transferFrom works correctly.
  function test_permit_thenTransferFrom () public {
    uint256 _value = 100 ether;
    uint256 _deadline = block.timestamp + 1 hours;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signPermit(
      alicePrivateKey, alice, bob, _value, 0, _deadline
    );
    token.permit(alice, bob, _value, _deadline, _v, _r, _s);
    uint256 _aliceBalanceBefore = token.balanceOf(alice);
    uint256 _carolBalanceBefore = token.balanceOf(carol);
    vm.prank(bob);
    token.transferFrom(alice, carol, _value);
    assertEq(token.balanceOf(alice), _aliceBalanceBefore - _value);
    assertEq(token.balanceOf(carol), _carolBalanceBefore + _value);
    assertEq(token.allowance(alice, bob), 0);
  }

  /// Permit with address(0) as owner reverts.
  function test_permit_zeroOwner_reverts () public {
    uint256 _value = 100 ether;
    uint256 _deadline = block.timestamp + 1 hours;

    // Sign as if owner is address(0) - this will produce an invalid signature.
    bytes32 _digest =
      _computePermitDigest(address(0), bob, _value, 0, _deadline);
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(alicePrivateKey, _digest);

    // InvalidSignature()
    vm.expectRevert(ISignatureHelper.InvalidSignature.selector);
    token.permit(address(0), bob, _value, _deadline, _v, _r, _s);
  }

  /// Permit with address(0) as spender works (sets zero allowance for zero).
  function test_permit_zeroSpender () public {
    uint256 _value = 100 ether;
    uint256 _deadline = block.timestamp + 1 hours;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signPermit(
      alicePrivateKey, alice, address(0), _value, 0, _deadline
    );
    token.permit(alice, address(0), _value, _deadline, _v, _r, _s);
    assertEq(token.allowance(alice, address(0)), _value);
    assertEq(token.nonces(alice), 1);
  }

  /// Permit for self-approval (owner == spender) works.
  function test_permit_selfApproval () public {
    uint256 _value = 100 ether;
    uint256 _deadline = block.timestamp + 1 hours;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signPermit(
      alicePrivateKey, alice, alice, _value, 0, _deadline
    );
    token.permit(alice, alice, _value, _deadline, _v, _r, _s);
    assertEq(token.allowance(alice, alice), _value);
    assertEq(token.nonces(alice), 1);
  }

  /**
    Permit with malleable signature (s in upper half) succeeds. Note: Solady's
    ecrecover does not reject malleable signatures. Both (v,r,s) and (v',r,n-s)
    recover to the same address. This is not a security concern for nonce-based
    systems like permit since replay attacks are prevented.
  */
  function test_permit_malleableSignature_succeeds () public {
    uint256 _value = 100 ether;
    uint256 _deadline = block.timestamp + 1 hours;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signPermit(
      alicePrivateKey, alice, bob, _value, 0, _deadline
    );

    // secp256k1 curve order.
    uint256 _curveOrder =
      0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    // Flip s to upper half (s' = curveOrder - s).
    bytes32 _malleableS = bytes32(_curveOrder - uint256(_s));

    // Flip v (27 <-> 28).
    uint8 _malleableV = _v == 27 ? 28 : 27;

    // The malleable signature recovers to the same address and succeeds.
    token.permit(alice, bob, _value, _deadline, _malleableV, _r, _malleableS);
    assertEq(token.allowance(alice, bob), _value);
    assertEq(token.nonces(alice), 1);
  }

  /**
    Fuzz test: permit with various values and deadlines.

    @param _value The permit approval amount.
    @param _deadlineOffset The offset from current timestamp for the deadline.
  */
  function testFuzz_permit (
    uint256 _value,
    uint256 _deadlineOffset
  ) public {

    // Bound deadline to reasonable range.
    _deadlineOffset = bound(_deadlineOffset, 1, 365 days);
    uint256 _deadline = block.timestamp + _deadlineOffset;
    (uint8 _v, bytes32 _r, bytes32 _s) = _signPermit(
      alicePrivateKey, alice, bob, _value, 0, _deadline
    );
    token.permit(alice, bob, _value, _deadline, _v, _r, _s);
    assertEq(token.allowance(alice, bob), _value);
    assertEq(token.nonces(alice), 1);
  }

  /// An ERC-1271 signer can permit via its owner's signature.
  function test_permit_erc1271Signer_succeeds () public {

    // Create a smart contract signer owned by Alice.
    MockERC1271Signer _signer = new MockERC1271Signer(alice);
    address _signerAddress = address(_signer);

    // Give tokens to the signer contract.
    uint256 _value = 100 ether;
    token.transfer(_signerAddress, _value);
    uint256 _deadline = block.timestamp + 1 hours;
    uint256 _nonce = token.nonces(_signerAddress);

    // Sign as Alice (the owner of the signer contract).
    bytes memory _signature =
      _signPermitBytes(
        alicePrivateKey, _signerAddress, bob, _value, _nonce, _deadline
      );
    vm.expectEmit(true, true, false, true);
    emit Approval(_signerAddress, bob, _value);
    token.permit(_signerAddress, bob, _value, _deadline, _signature);
    assertEq(token.allowance(_signerAddress, bob), _value);
    assertEq(token.nonces(_signerAddress), 1);
  }

  /// An ERC-1271 signer rejects signatures from non-owners.
  function test_permit_erc1271Signer_wrongOwner_reverts () public {

    // Create a smart contract signer owned by Alice.
    MockERC1271Signer _signer = new MockERC1271Signer(alice);
    address _signerAddress = address(_signer);

    // Give tokens to the signer contract.
    uint256 _value = 100 ether;
    token.transfer(_signerAddress, _value);
    uint256 _deadline = block.timestamp + 1 hours;

    // Sign as Bob (NOT the owner of the signer contract).
    uint256 _bobPrivateKey = 0xB0B;
    bytes memory _signature =
      _signPermitBytes(
        _bobPrivateKey, _signerAddress, bob, _value, 0, _deadline
      );
    vm.expectRevert(ISignatureHelper.InvalidSignature.selector);
    token.permit(_signerAddress, bob, _value, _deadline, _signature);
  }

  /// An ERC-1271 signer can use the v, r, s permit variant.
  function test_permit_erc1271Signer_vrs_succeeds () public {

    // Create a smart contract signer owned by Alice.
    MockERC1271Signer _signer = new MockERC1271Signer(alice);
    address _signerAddress = address(_signer);

    // Give tokens to the signer contract.
    uint256 _value = 100 ether;
    token.transfer(_signerAddress, _value);
    uint256 _deadline = block.timestamp + 1 hours;

    // Sign as Alice (the owner of the signer contract).
    (uint8 _v, bytes32 _r, bytes32 _s) = _signPermit(
      alicePrivateKey, _signerAddress, bob, _value, 0, _deadline
    );
    vm.expectEmit(true, true, false, true);
    emit Approval(_signerAddress, bob, _value);
    token.permit(_signerAddress, bob, _value, _deadline, _v, _r, _s);
    assertEq(token.allowance(_signerAddress, bob), _value);
    assertEq(token.nonces(_signerAddress), 1);
  }

  /// An ERC-6492 signature authorizes permit from an undeployed signer.
  function test_permit_erc6492Signer_succeeds () public {

    // Create a factory for deploying signers.
    MockERC1271SignerFactory _factory = new MockERC1271SignerFactory();

    // Compute the address where the signer WOULD be deployed.
    bytes32 _salt = bytes32(uint256(100));
    address _signerAddress = _factory.computeAddress(alice, _salt);

    // Give tokens to the not-yet-deployed signer address.
    uint256 _value = 100 ether;
    token.transfer(_signerAddress, _value);
    uint256 _deadline = block.timestamp + 1 hours;

    // Create the inner signature from Alice (the future owner).
    bytes memory _innerSignature =
      _signPermitBytes(
        alicePrivateKey, _signerAddress, bob, _value, 0, _deadline
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
    vm.expectEmit(true, true, false, true);
    emit Approval(_signerAddress, bob, _value);
    token.permit(_signerAddress, bob, _value, _deadline, _erc6492Signature);
    assertEq(token.allowance(_signerAddress, bob), _value);
    assertEq(token.nonces(_signerAddress), 1);
  }

  /// An ERC-6492 signature with wrong owner is rejected.
  function test_permit_erc6492Signer_wrongOwner_reverts () public {

    // Create a factory for deploying signers.
    MockERC1271SignerFactory _factory = new MockERC1271SignerFactory();

    // Compute the address where the signer WOULD be deployed (owned by Alice).
    bytes32 _salt = bytes32(uint256(101));
    address _signerAddress = _factory.computeAddress(alice, _salt);

    // Give tokens to the not-yet-deployed signer address.
    uint256 _value = 100 ether;
    token.transfer(_signerAddress, _value);
    uint256 _deadline = block.timestamp + 1 hours;

    // Create the inner signature from Bob (NOT the future owner).
    uint256 _bobPrivateKey = 0xB0B;
    bytes memory _innerSignature =
      _signPermitBytes(
        _bobPrivateKey, _signerAddress, bob, _value, 0, _deadline
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
    vm.expectRevert(ISignatureHelper.InvalidSignature.selector);
    token.permit(_signerAddress, bob, _value, _deadline, _erc6492Signature);
  }

  /// An ERC-7739 signer validates nested EIP-712 signatures correctly.
  function test_permit_erc7739Signer_succeeds () public {

    // Create a smart contract signer that uses nested EIP-712.
    MockERC7739Signer _signer = new MockERC7739Signer(alice);
    address _signerAddress = address(_signer);

    // Give tokens to the signer contract.
    uint256 _value = 100 ether;
    token.transfer(_signerAddress, _value);
    uint256 _deadline = block.timestamp + 1 hours;

    // Compute the application's hash and get the wrapped hash for ERC-7739.
    bytes32 _appHash =
      keccak256(
        abi.encodePacked(
          "\x19\x01", _computeDomainSeparator(),
          keccak256(
            abi.encode(
              _PERMIT_TYPEHASH, _signerAddress, bob, _value, 0, _deadline
            )
          )
        )
      );

    // Sign the wrapped hash as Alice (the owner).
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(
      alicePrivateKey, _signer.getWrappedHash(_appHash)
    );
    vm.expectEmit(true, true, false, true);
    emit Approval(_signerAddress, bob, _value);
    token.permit(
      _signerAddress, bob, _value, _deadline, abi.encodePacked(_r, _s, _v)
    );
    assertEq(token.allowance(_signerAddress, bob), _value);
    assertEq(token.nonces(_signerAddress), 1);
  }

  /// An ERC-7739 signer rejects signatures over the unwrapped hash.
  function test_permit_erc7739Signer_unwrappedHash_reverts () public {

    // Create a smart contract signer that uses nested EIP-712.
    address _signerAddress = address(new MockERC7739Signer(alice));

    // Give tokens to the signer contract.
    uint256 _value = 100 ether;
    token.transfer(_signerAddress, _value);
    uint256 _deadline = block.timestamp + 1 hours;

    // Sign the application hash directly (without wrapping) - this should fail.
    bytes memory _signature =
      _signPermitBytes(
        alicePrivateKey, _signerAddress, bob, _value, 0, _deadline
      );
    vm.expectRevert(ISignatureHelper.InvalidSignature.selector);
    token.permit(_signerAddress, bob, _value, _deadline, _signature);
  }

  /// An ERC-7739 signer can use the v, r, s permit variant.
  function test_permit_erc7739Signer_vrs_succeeds () public {

    // Create a smart contract signer that uses nested EIP-712.
    MockERC7739Signer _signer = new MockERC7739Signer(alice);
    address _signerAddress = address(_signer);

    // Give tokens to the signer contract.
    uint256 _value = 100 ether;
    token.transfer(_signerAddress, _value);
    uint256 _deadline = block.timestamp + 1 hours;

    // Compute the application's hash and get the wrapped hash for ERC-7739.
    bytes32 _appHash =
      keccak256(
        abi.encodePacked(
          "\x19\x01", _computeDomainSeparator(),
          keccak256(
            abi.encode(
              _PERMIT_TYPEHASH, _signerAddress, bob, _value, 0, _deadline
            )
          )
        )
      );

    // Sign the wrapped hash as Alice (the owner).
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(
      alicePrivateKey, _signer.getWrappedHash(_appHash)
    );
    vm.expectEmit(true, true, false, true);
    emit Approval(_signerAddress, bob, _value);
    token.permit(_signerAddress, bob, _value, _deadline, _v, _r, _s);
    assertEq(token.allowance(_signerAddress, bob), _value);
    assertEq(token.nonces(_signerAddress), 1);
  }
}

