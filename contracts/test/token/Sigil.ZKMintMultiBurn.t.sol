// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { SigilTestBase } from "./utils/SigilTestBase.sol";
import { IZKMint } from "token/zk_mint/interfaces/IZKMint.sol";
import { VmSafe } from "forge-std/Vm.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Tests for multi-burn ZK mints in the Sigil token.
  @author Tim Clancy <tim-clancy.eth>

  These tests use real proofs generated with 2 burns per proof to exercise the
  multi-burn contract code paths: `_processNullifiers` loop, interleaved
  `_formatPublicInputs`, `_insertManyInTree`, and multi-entry
  `_hashTotalMintedEncrypted` / `_processMint`.

  Burn 0 uses the regular VK derived from KEY1; burn 1 uses an arbitrary
  VK (0x42) — a stealth address. From the contract's perspective they are
  indistinguishable.

  @custom:date February 2026
*/
contract SigilZKMintMultiBurnTest is
  SigilTestBase {

  /// Burn addresses for the two burns.
  address constant BURN1 =
    0xAAaE88C9D59da8724Cd824aF8774c6d3c2f3D690;
  address constant BURN_STEALTH =
    0x20ACcbcc714E2044B5325b9eA1A3Bdba7fAdBa13;

  /// Amount sent to each burn address.
  uint256 constant BURN_AMOUNT = 100 ether;

  /// Per-burn mint amounts.
  uint256 constant BURN0_MINT = 30 ether;
  uint256 constant BURN1_MINT = 70 ether;

  /// Total transfer amount (sum of both burn mints).
  uint256 constant TOTAL_AMOUNT = 100 ether;

  /// Decoded public inputs from the multi_burn fixture.
  uint256 internal amount;
  address internal to;
  IZKMint.RewardData internal rewardData;
  IZKMint.BurnInput[] internal burns;
  uint256 internal fixtureRoot;

  /// The raw multi-burn proof bytes.
  bytes internal proof;

  /// Re-declare events for `vm.expectEmit`.
  event ZKMintExecuted (uint256 amount);
  event Nullified (uint256 indexed nullifier, bytes totalMintedEncrypted);
  event NewLeaf (uint256 leaf);

  /// Decode 67 x 32-byte big-endian public inputs into typed values.
  /// Noir serializes [BurnDataPublic; 32] with interleaved struct fields:
  /// [0] amount, [1] sigHash, [2] hash0, [3] null0, [4] hash1, [5] null1,
  /// ..., [64] hash31, [65] null31, [66] root.
  function _decodePublicInputs (
    bytes memory _raw
  ) internal pure returns (
    uint256 amount_,
    uint256[] memory accountNoteHashes_,
    uint256[] memory accountNoteNullifiers_,
    uint256 root_,
    uint256 numActive_
  ) {
    require(_raw.length == 67 * 32, "unexpected public_inputs size");
    assembly {
      amount_ := mload(add(_raw, 0x20))
    }

    accountNoteHashes_ = new uint256[](32);
    accountNoteNullifiers_ = new uint256[](32);

    for (uint256 i = 0; i < 32; i++) {
      uint256 hashOffset = 0x60 + i * 0x40;
      uint256 nullOffset = 0x80 + i * 0x40;
      uint256 h;
      uint256 n;
      assembly {
        h := mload(add(_raw, hashOffset))
        n := mload(add(_raw, nullOffset))
      }
      accountNoteHashes_[i] = h;
      accountNoteNullifiers_[i] = n;
    }

    assembly {
      root_ := mload(add(_raw, 0x860))
    }

    numActive_ = 0;
    for (uint256 i = 0; i < 32; i++) {
      if (accountNoteHashes_[i] != 0) {
        numActive_ = i + 1;
      } else {
        break;
      }
    }
  }

  /// Build a BurnInput array with per-burn totalMintedEncrypted values.
  function _buildMultiBurns (
    uint256[] memory _hashes,
    uint256[] memory _nullifiers,
    uint256 _numActive,
    uint256[] memory _perBurnTotalMinted
  ) internal pure returns (IZKMint.BurnInput[] memory burns_) {
    require(_numActive == _perBurnTotalMinted.length, "length mismatch");
    burns_ = new IZKMint.BurnInput[](_numActive);
    for (uint256 i = 0; i < _numActive; i++) {
      burns_[i] = IZKMint.BurnInput({
        accountNoteHash: _hashes[i],
        accountNoteNullifier: _nullifiers[i],
        totalMintedEncrypted: abi.encode(_perBurnTotalMinted[i])
      });
    }
  }

  /// Set up the test environment with two burn addresses.
  function setUp () public {
    _setUpSigil();

    // Transfer to both burn addresses creates two balance leaves.
    token.transfer(BURN1, BURN_AMOUNT);
    token.transfer(BURN_STEALTH, BURN_AMOUNT);

    // Load multi_burn proof fixture.
    proof = vm.readFileBinary("test/token/data/multi_burn_proof");
    bytes memory _raw = vm.readFileBinary(
      "test/token/data/multi_burn_public_inputs"
    );

    uint256 _numActive;
    uint256[] memory _hashes;
    uint256[] memory _nullifiers;

    (amount, _hashes, _nullifiers, fixtureRoot, _numActive) =
      _decodePublicInputs(_raw);

    // Build per-burn totalMintedEncrypted: 30 ether for burn 0, 70 ether for
    // burn 1 (each burn's new_total_minted = its mint amount since prev=0).
    uint256[] memory _perBurnTotalMinted = new uint256[](_numActive);
    _perBurnTotalMinted[0] = BURN0_MINT;
    _perBurnTotalMinted[1] = BURN1_MINT;

    IZKMint.BurnInput[] memory _burns =
      _buildMultiBurns(_hashes, _nullifiers, _numActive, _perBurnTotalMinted);
    for (uint256 i = 0; i < _burns.length; i++) {
      burns.push(_burns[i]);
    }

    // Self-relay reward data.
    to = makeAddr("recipient");
    rewardData = IZKMint.RewardData({
      relayerAddress: address(0),
      priorityFee: 0,
      conversionRate: 0,
      maxReward: 0
    });
  }

  // -----------------------------------------------------------------------
  // Test 1: Happy path multi-burn
  // -----------------------------------------------------------------------

  /// Full real-proof multi-burn ZK mint with self-relay.
  function test_zkMint_multiBurn () public {
    assertEq(amount, TOTAL_AMOUNT, "fixture amount should be 100 ether");
    assertEq(burns.length, 2, "should have 2 burns");

    assertEq(
      token.root(), fixtureRoot, "tree root mismatch -- regenerate fixtures"
    );
    uint256 _supplyBefore = token.totalSupply();
    uint256 _recipientBefore = token.balanceOf(to);

    token.zkMint(
      amount, to, rewardData, burns, fixtureRoot, proof
    );

    assertEq(token.balanceOf(to), _recipientBefore + amount);
    assertEq(token.totalSupply(), _supplyBefore);

    // Both nullifiers stored with value amount + 1.
    assertEq(
      token.nullifiers(burns[0].accountNoteNullifier), amount + 1,
      "burn 0 nullifier not stored"
    );
    assertEq(
      token.nullifiers(burns[1].accountNoteNullifier), amount + 1,
      "burn 1 nullifier not stored"
    );
  }

  // -----------------------------------------------------------------------
  // Test 2: Event emission
  // -----------------------------------------------------------------------

  /// Multi-burn emits 2 Nullified events with correct per-burn content
  /// and 1 ZKMintExecuted event.
  function test_zkMint_multiBurnEvents () public {
    vm.recordLogs();
    token.zkMint(
      amount, to, rewardData, burns, fixtureRoot, proof
    );
    VmSafe.Log[] memory _logs = vm.getRecordedLogs();

    bytes32 _nullSig = Nullified.selector;
    bytes32 _pteSig = ZKMintExecuted.selector;

    uint256 _nullCount;
    uint256 _pteCount;
    for (uint256 i; i < _logs.length; ++i) {
      if (
        _logs[i].topics.length > 0 && _logs[i].topics[0] == _nullSig
      ) {
        // Verify indexed nullifier matches the expected burn.
        uint256 _nullifier = uint256(_logs[i].topics[1]);
        assertEq(
          _nullifier,
          burns[_nullCount].accountNoteNullifier,
          "Nullified indexed nullifier mismatch"
        );

        // Verify TSE data matches per-burn totalMintedEncrypted.
        bytes memory _tse = abi.decode(_logs[i].data, (bytes));
        assertEq(
          keccak256(_tse),
          keccak256(burns[_nullCount].totalMintedEncrypted),
          "Nullified TSE data mismatch"
        );
        _nullCount++;
      } else if (
        _logs[i].topics.length > 0 && _logs[i].topics[0] == _pteSig
      ) {
        uint256 _emittedAmount = abi.decode(_logs[i].data, (uint256));
        assertEq(_emittedAmount, amount, "PTE amount mismatch");
        _pteCount++;
      }
    }

    assertEq(_nullCount, 2, "should emit 2 Nullified events");
    assertEq(_pteCount, 1, "should emit 1 ZKMintExecuted event");
  }

  // -----------------------------------------------------------------------
  // Test 3: Tree update
  // -----------------------------------------------------------------------

  /// Root changes after multi-burn; correct NewLeaf events emitted.
  function test_zkMint_multiBurnTreeUpdate () public {
    uint256 _rootBefore = token.root();

    vm.recordLogs();
    token.zkMint(
      amount, to, rewardData, burns, fixtureRoot, proof
    );
    VmSafe.Log[] memory _logs = vm.getRecordedLogs();

    uint256 _rootAfter = token.root();
    assertTrue(_rootAfter != _rootBefore, "root should change after transfer");
    assertTrue(token.roots(_rootAfter), "new root should be in roots mapping");

    // Count NewLeaf events: 2 account notes + 1 balance leaf = 3.
    bytes32 _nlSig = NewLeaf.selector;
    uint256 _leafCount;
    for (uint256 i; i < _logs.length; ++i) {
      if (_logs[i].topics.length > 0 && _logs[i].topics[0] == _nlSig) {
        _leafCount++;
      }
    }

    // 2 account note hashes + 1 balance leaf for recipient.
    assertEq(_leafCount, 3, "should emit 3 NewLeaf events");
  }

  // -----------------------------------------------------------------------
  // Test 4: Nullifier replay
  // -----------------------------------------------------------------------

  /// Second call with the same multi-burn proof reverts.
  function test_zkMint_multiBurnNullifierReplay () public {
    token.zkMint(
      amount, to, rewardData, burns, fixtureRoot, proof
    );

    vm.expectRevert(IZKMint.NullifierAlreadyExists.selector);
    token.zkMint(
      amount, to, rewardData, burns, fixtureRoot, proof
    );
  }

  // -----------------------------------------------------------------------
  // Test 5: Proof and public input tampering
  // -----------------------------------------------------------------------

  /// Flipping a byte in a multi-burn proof causes a revert.
  function test_zkMint_multiBurnRevertTamperedProof () public {
    bytes memory _tampered = proof;
    _tampered[0] = _tampered[0] ^ 0xff;

    vm.expectRevert();
    token.zkMint(
      amount, to, rewardData, burns, fixtureRoot, _tampered
    );
  }

  /// Swapping the burn order (burn[0] ↔ burn[1]) while keeping the original
  /// proof reverts because nullifiers and hashes no longer match their slots.
  function test_zkMint_multiBurnRevertSwappedBurns () public {
    IZKMint.BurnInput[] memory _swapped =
      new IZKMint.BurnInput[](2);
    _swapped[0] = burns[1];
    _swapped[1] = burns[0];

    vm.expectRevert();
    token.zkMint(
      amount, to, rewardData, _swapped, fixtureRoot, proof
    );
  }

  /// Submitting only 1 of the 2 burns with the 2-burn proof reverts.
  function test_zkMint_multiBurnRevertPartialBurns () public {
    IZKMint.BurnInput[] memory _partial =
      new IZKMint.BurnInput[](1);
    _partial[0] = burns[0];

    vm.expectRevert();
    token.zkMint(
      amount, to, rewardData, _partial, fixtureRoot, proof
    );
  }

  /// Tampering one nullifier in a multi-burn proof reverts.
  function test_zkMint_multiBurnRevertTamperedNullifier () public {
    IZKMint.BurnInput[] memory _tampered =
      new IZKMint.BurnInput[](2);
    _tampered[0] = burns[0];
    _tampered[1] = IZKMint.BurnInput({
      accountNoteHash: burns[1].accountNoteHash,
      accountNoteNullifier: burns[1].accountNoteNullifier ^ 1,
      totalMintedEncrypted: burns[1].totalMintedEncrypted
    });

    vm.expectRevert();
    token.zkMint(
      amount, to, rewardData, _tampered, fixtureRoot, proof
    );
  }

  /// Tampering one account note hash in a multi-burn proof reverts.
  function test_zkMint_multiBurnRevertTamperedHash () public {
    IZKMint.BurnInput[] memory _tampered =
      new IZKMint.BurnInput[](2);
    _tampered[0] = IZKMint.BurnInput({
      accountNoteHash: burns[0].accountNoteHash ^ 1,
      accountNoteNullifier: burns[0].accountNoteNullifier,
      totalMintedEncrypted: burns[0].totalMintedEncrypted
    });
    _tampered[1] = burns[1];

    vm.expectRevert();
    token.zkMint(
      amount, to, rewardData, _tampered, fixtureRoot, proof
    );
  }

  /// Wrong totalMintedEncrypted for one burn in multi-burn proof reverts
  /// (EIP-712 signature hash mismatch).
  function test_zkMint_multiBurnRevertWrongTSE () public {
    IZKMint.BurnInput[] memory _tampered =
      new IZKMint.BurnInput[](2);
    _tampered[0] = burns[0];
    _tampered[1] = IZKMint.BurnInput({
      accountNoteHash: burns[1].accountNoteHash,
      accountNoteNullifier: burns[1].accountNoteNullifier,
      totalMintedEncrypted: abi.encode(uint256(999 ether))
    });

    vm.expectRevert();
    token.zkMint(
      amount, to, rewardData, _tampered, fixtureRoot, proof
    );
  }

  /// Changing the amount on a multi-burn proof reverts.
  function test_zkMint_multiBurnRevertTamperedAmount () public {
    vm.expectRevert();
    token.zkMint(
      amount + 1, to, rewardData, burns, fixtureRoot, proof
    );
  }

  /// Changing the recipient on a multi-burn proof reverts.
  function test_zkMint_multiBurnRevertTamperedRecipient () public {
    address _wrong = makeAddr("wrong");

    vm.expectRevert();
    token.zkMint(
      amount, _wrong, rewardData, burns, fixtureRoot, proof
    );
  }

  // -----------------------------------------------------------------------
  // Relay fixture helper
  // -----------------------------------------------------------------------

  /// Load the multi_burn_relay fixture and return decoded components.
  function _loadRelayFixture () internal returns (
    uint256 amount_,
    IZKMint.BurnInput[] memory burns_,
    uint256 root_,
    bytes memory proof_
  ) {
    proof_ = vm.readFileBinary("test/token/data/multi_burn_relay_proof");
    bytes memory _raw = vm.readFileBinary(
      "test/token/data/multi_burn_relay_public_inputs"
    );

    uint256 _numActive;
    uint256[] memory _hashes;
    uint256[] memory _nullifiers;
    (amount_, _hashes, _nullifiers, root_, _numActive) =
      _decodePublicInputs(_raw);

    uint256[] memory _perBurnTotalMinted = new uint256[](_numActive);
    _perBurnTotalMinted[0] = BURN0_MINT;
    _perBurnTotalMinted[1] = BURN1_MINT;

    burns_ = _buildMultiBurns(
      _hashes, _nullifiers, _numActive, _perBurnTotalMinted
    );
  }

  // -----------------------------------------------------------------------
  // Test 5: Multi-burn with relay
  // -----------------------------------------------------------------------

  /// Multi-burn with generic relay: relayer receives reward, recipient gets
  /// remainder.
  function test_zkMint_multiBurnRelay () public {
    (
      uint256 _relayAmount,
      IZKMint.BurnInput[] memory _relayBurns,
      uint256 _root,
      bytes memory _relayProof
    ) = _loadRelayFixture();

    IZKMint.RewardData memory _relayReward = IZKMint.RewardData({
      relayerAddress: address(1),
      priorityFee: 1e9,
      conversionRate: 385000,
      maxReward: 1 ether
    });

    assertEq(
      token.root(), _root, "tree root mismatch -- regenerate fixtures"
    );

    uint256 _expectedReward =
      (_relayReward.priorityFee + block.basefee) * _relayReward.conversionRate;

    uint256 _relayerBefore = token.balanceOf(address(this));
    uint256 _recipientBefore = token.balanceOf(to);
    uint256 _supplyBefore = token.totalSupply();

    token.zkMint(
      _relayAmount, to, _relayReward, _relayBurns, _root, _relayProof
    );

    assertEq(
      token.balanceOf(address(this)),
      _relayerBefore + _expectedReward,
      "relayer reward incorrect"
    );
    assertEq(
      token.balanceOf(to),
      _recipientBefore + _relayAmount - _expectedReward,
      "recipient amount incorrect"
    );
    assertEq(token.totalSupply(), _supplyBefore, "supply should not change");
  }

  // -----------------------------------------------------------------------
  // Test 6: Multi-burn relay with reward cap
  // -----------------------------------------------------------------------

  /// High basefee causes the relay reward to be capped at maxReward.
  function test_zkMint_multiBurnRelayCapped () public {
    (
      uint256 _relayAmount,
      IZKMint.BurnInput[] memory _relayBurns,
      uint256 _root,
      bytes memory _relayProof
    ) = _loadRelayFixture();

    IZKMint.RewardData memory _relayReward = IZKMint.RewardData({
      relayerAddress: address(1),
      priorityFee: 1e9,
      conversionRate: 385000,
      maxReward: 1 ether
    });

    vm.fee(3e12);

    uint256 _relayerBefore = token.balanceOf(address(this));
    uint256 _recipientBefore = token.balanceOf(to);

    token.zkMint(
      _relayAmount, to, _relayReward, _relayBurns, _root, _relayProof
    );

    assertEq(
      token.balanceOf(address(this)) - _relayerBefore,
      _relayReward.maxReward,
      "relayer should receive maxReward when capped"
    );
    assertEq(
      token.balanceOf(to) - _recipientBefore,
      _relayAmount - _relayReward.maxReward,
      "recipient should receive amount minus maxReward"
    );
  }
}
