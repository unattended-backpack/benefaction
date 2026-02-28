// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { SigilTestBase } from "./utils/SigilTestBase.sol";
import { IZKMint } from "token/zk_mint/interfaces/IZKMint.sol";
import { IPoseidon2 } from "token/zk_mint/interfaces/IPoseidon2.sol";
import { VmSafe } from "forge-std/Vm.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Tests for the relayer reward mechanism in ZK mints.
  @author Tim Clancy <tim-clancy.eth>

  These tests use a proof generated with non-zero relayer reward parameters
  against a fresh single-leaf tree. Uses the new 67-input public input layout
  with EIP-712 signature hash binding.

  NOTE: All proof fixtures must be regenerated after the circuit migration.

  @custom:date February 2026
*/
contract SigilZKMintRelayerTest is
  SigilTestBase {

  /// Burn address for the relayer proof's PoW nonce.
  address constant BURN_ADDRESS =
    0x91c2025DB39Da9CD456344ac7cdcf64969eBfd61;

  /// Total sent to the burn address (100 ether).
  uint256 constant BURN_AMOUNT = 100 ether;

  /// Decoded public inputs from the relayer proof fixture.
  uint256 internal amount;
  address internal to;
  IZKMint.RewardData internal rewardData;
  IZKMint.BurnInput[] internal burns;
  uint256 internal fixtureRoot;

  /// The raw relayer proof bytes.
  bytes internal proof;

  /// Re-declare events.
  event ZKMintExecuted (uint256 amount);
  event Nullified (uint256 indexed nullifier, bytes totalMintedEncrypted);
  event NewLeaf (uint256 leaf);

  /// Decode 67 x 32-byte big-endian public inputs.
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
      // Interleaved pairs starting at field 2: (hash_i, null_i).
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

  /// Build a BurnInput array from decoded public inputs.
  function _buildBurns (
    uint256[] memory _hashes,
    uint256[] memory _nullifiers,
    uint256 _numActive,
    uint256 _newTotalMinted
  ) internal pure returns (IZKMint.BurnInput[] memory burns_) {
    burns_ = new IZKMint.BurnInput[](_numActive);
    for (uint256 i = 0; i < _numActive; i++) {
      burns_[i] = IZKMint.BurnInput({
        accountNoteHash: _hashes[i],
        accountNoteNullifier: _nullifiers[i],
        totalMintedEncrypted: abi.encode(_newTotalMinted)
      });
    }
  }

  /// Set up the test environment with the relayer burn address.
  function setUp () public {
    _setUpSigil();
    token.transfer(BURN_ADDRESS, BURN_AMOUNT);

    proof = vm.readFileBinary("test/token/data/relayer_proof");
    bytes memory _raw = vm.readFileBinary(
      "test/token/data/relayer_public_inputs"
    );

    uint256 _numActive;
    uint256[] memory _hashes;
    uint256[] memory _nullifiers;
    (amount, _hashes, _nullifiers, fixtureRoot, _numActive) =
      _decodePublicInputs(_raw);

    IZKMint.BurnInput[] memory _burns =
      _buildBurns(_hashes, _nullifiers, _numActive, amount);
    for (uint256 i = 0; i < _burns.length; i++) {
      burns.push(_burns[i]);
    }

    to = makeAddr("recipient");
    rewardData = IZKMint.RewardData({
      relayerAddress: address(1),
      priorityFee: 1e9,
      conversionRate: 385000,
      maxReward: 1 ether
    });
  }

  /// Relayer ZK mint: msg.sender receives the reward, recipient gets the
  /// remainder. Total supply unchanged.
  function test_zkMint_relayerReward () public {
    assertEq(
      token.root(), fixtureRoot, "tree root mismatch -- regenerate fixtures"
    );

    uint256 _expectedReward =
      (rewardData.priorityFee + block.basefee) * rewardData.conversionRate;
    assertTrue(
      _expectedReward < rewardData.maxReward, "reward should be below max reward cap"
    );
    uint256 _expectedRecipientAmount = amount - _expectedReward;

    uint256 _relayerBefore = token.balanceOf(address(this));
    uint256 _recipientBefore = token.balanceOf(to);
    uint256 _supplyBefore = token.totalSupply();

    token.zkMint(
      amount, to, rewardData, burns, fixtureRoot, proof
    );

    assertEq(
      token.balanceOf(address(this)),
      _relayerBefore + _expectedReward,
      "relayer reward incorrect"
    );
    assertEq(
      token.balanceOf(to),
      _recipientBefore + _expectedRecipientAmount,
      "recipient amount incorrect"
    );
    assertEq(token.totalSupply(), _supplyBefore, "supply should not change");
    assertEq(token.nullifiers(burns[0].accountNoteNullifier), amount + 1);
  }

  /// Verify the reward amounts match expected values with basefee = 0.
  function test_zkMint_relayerRewardValues () public {
    uint256 _relayerBefore = token.balanceOf(address(this));
    uint256 _recipientBefore = token.balanceOf(to);

    token.zkMint(
      amount, to, rewardData, burns, fixtureRoot, proof
    );

    uint256 _reward = 385_000_000_000_000;
    assertEq(
      token.balanceOf(address(this)) - _relayerBefore,
      _reward,
      "relayer should receive exactly 0.000385 ether"
    );
    assertEq(
      token.balanceOf(to) - _recipientBefore,
      amount - _reward,
      "recipient should receive amount minus reward"
    );
  }

  /// Verify the reward cap kicks in when basefee is high.
  function test_zkMint_relayerRewardCapped () public {
    vm.fee(3e12);

    uint256 _uncappedReward =
      (rewardData.priorityFee + block.basefee) * rewardData.conversionRate;
    assertTrue(
      _uncappedReward > rewardData.maxReward,
      "uncapped reward should exceed maxReward"
    );

    uint256 _relayerBefore = token.balanceOf(address(this));
    uint256 _recipientBefore = token.balanceOf(to);

    token.zkMint(
      amount, to, rewardData, burns, fixtureRoot, proof
    );

    assertEq(
      token.balanceOf(address(this)) - _relayerBefore,
      rewardData.maxReward,
      "relayer should receive maxReward when capped"
    );
    assertEq(
      token.balanceOf(to) - _recipientBefore,
      amount - rewardData.maxReward,
      "recipient should receive amount minus maxReward"
    );
  }

  /// Verify that the reward data values are as expected.
  function test_zkMint_relayerRewardDataDecoded () public view {
    assertEq(
      rewardData.relayerAddress, address(1), "relayer should be address(1)"
    );
    assertEq(rewardData.priorityFee, 1e9, "priorityFee should be 1 gwei");
    assertEq(rewardData.conversionRate, 385000, "conversionRate should be 385000");
    assertEq(rewardData.maxReward, 1 ether, "maxReward should be 1 ether");
  }

  // -----------------------------------------------------------------------
  // Relay reward data tampering
  // -----------------------------------------------------------------------

  /// Changing the relayer address while keeping the original proof reverts
  /// (EIP-712 signature hash mismatch).
  function test_zkMint_revertWrongRelayerAddress () public {
    IZKMint.RewardData memory _wrongReward = IZKMint.RewardData({
      relayerAddress: address(42),
      priorityFee: rewardData.priorityFee,
      conversionRate: rewardData.conversionRate,
      maxReward: rewardData.maxReward
    });

    vm.expectRevert();
    token.zkMint(
      amount, to, _wrongReward, burns, fixtureRoot, proof
    );
  }

  /// Changing the priority fee while keeping the original proof reverts.
  function test_zkMint_revertWrongPriorityFee () public {
    IZKMint.RewardData memory _wrongReward = IZKMint.RewardData({
      relayerAddress: rewardData.relayerAddress,
      priorityFee: rewardData.priorityFee + 1,
      conversionRate: rewardData.conversionRate,
      maxReward: rewardData.maxReward
    });

    vm.expectRevert();
    token.zkMint(
      amount, to, _wrongReward, burns, fixtureRoot, proof
    );
  }

  /// Changing the conversion rate while keeping the original proof reverts.
  function test_zkMint_revertWrongConversionRate () public {
    IZKMint.RewardData memory _wrongReward = IZKMint.RewardData({
      relayerAddress: rewardData.relayerAddress,
      priorityFee: rewardData.priorityFee,
      conversionRate: rewardData.conversionRate + 1,
      maxReward: rewardData.maxReward
    });

    vm.expectRevert();
    token.zkMint(
      amount, to, _wrongReward, burns, fixtureRoot, proof
    );
  }

  /// Changing the max reward while keeping the original proof reverts.
  function test_zkMint_revertWrongMaxReward () public {
    IZKMint.RewardData memory _wrongReward = IZKMint.RewardData({
      relayerAddress: rewardData.relayerAddress,
      priorityFee: rewardData.priorityFee,
      conversionRate: rewardData.conversionRate,
      maxReward: rewardData.maxReward - 1
    });

    vm.expectRevert();
    token.zkMint(
      amount, to, _wrongReward, burns, fixtureRoot, proof
    );
  }

  /// Switching from relay mode to self-relay while keeping the original proof
  /// reverts (EIP-712 signature hash mismatch).
  function test_zkMint_revertRelayToSelfRelay () public {
    IZKMint.RewardData memory _selfRelay = IZKMint.RewardData({
      relayerAddress: address(0),
      priorityFee: 0,
      conversionRate: 0,
      maxReward: 0
    });

    vm.expectRevert();
    token.zkMint(
      amount, to, _selfRelay, burns, fixtureRoot, proof
    );
  }

  // -----------------------------------------------------------------------
  // Fixture helpers
  // -----------------------------------------------------------------------

  /// Load a proof fixture and return decoded fields.
  function _loadFixture (
    string memory _proofPath,
    string memory _inputsPath
  ) internal returns (
    uint256 amount_,
    IZKMint.BurnInput[] memory burns_,
    uint256 root_,
    bytes memory proof_
  ) {
    proof_ = vm.readFileBinary(_proofPath);
    bytes memory _raw = vm.readFileBinary(_inputsPath);
    uint256 _numActive;
    uint256[] memory _hashes;
    uint256[] memory _nullifiers;
    (amount_, _hashes, _nullifiers, root_, _numActive) =
      _decodePublicInputs(_raw);
    burns_ = _buildBurns(_hashes, _nullifiers, _numActive, amount_);
  }

  /// Specific relayer address: the reward goes directly to the committed address.
  function test_zkMint_specificRelayer () public {
    address _specificRelayer = 0xB435c60573DFD2dACf3472DCD47a8Aed400680a2;

    (
      uint256 _specAmount,
      IZKMint.BurnInput[] memory _specBurns,
      uint256 _specRoot,
      bytes memory _specProof
    ) = _loadFixture(
      "test/token/data/specific_relayer_proof",
      "test/token/data/specific_relayer_public_inputs"
    );

    IZKMint.RewardData memory _specReward = IZKMint.RewardData({
      relayerAddress: _specificRelayer,
      priorityFee: 1e9,
      conversionRate: 385000,
      maxReward: 1 ether
    });

    uint256 _relayerBefore = token.balanceOf(_specificRelayer);
    uint256 _callerBefore = token.balanceOf(address(this));
    uint256 _supplyBefore = token.totalSupply();

    token.zkMint(
      _specAmount, to, _specReward, _specBurns, _specRoot, _specProof
    );

    uint256 _expectedReward =
      (_specReward.priorityFee + block.basefee) * _specReward.conversionRate;

    assertEq(
      token.balanceOf(_specificRelayer),
      _relayerBefore + _expectedReward,
      "specific relayer should receive reward"
    );
    assertEq(
      token.balanceOf(address(this)),
      _callerBefore,
      "msg.sender should not receive anything"
    );
    assertEq(
      token.balanceOf(to),
      _specAmount - _expectedReward,
      "recipient amount incorrect"
    );
    assertEq(token.totalSupply(), _supplyBefore, "supply should not change");
  }

  /// Relayer reward payment inserts a NewLeaf for the relayer's updated balance.
  function test_zkMint_relayerBalanceLeafInserted () public {
    bytes32 _nlSig = NewLeaf.selector;

    uint256 _relayerBefore = token.balanceOf(address(this));
    uint256 _expectedReward =
      (rewardData.priorityFee + block.basefee) * rewardData.conversionRate;

    vm.recordLogs();
    token.zkMint(
      amount, to, rewardData, burns, fixtureRoot, proof
    );
    VmSafe.Log[] memory _logs = vm.getRecordedLogs();

    // Compute expected relayer balance leaf.
    uint256 _expectedRelayerLeaf = IPoseidon2(token.poseidon2()).hash(
      uint256(uint160(address(this))),
      _relayerBefore + _expectedReward,
      token.TOTAL_BURNED_DOMAIN()
    );

    bool _foundRelayerLeaf;
    for (uint256 i; i < _logs.length; ++i) {
      if (_logs[i].topics.length > 0 && _logs[i].topics[0] == _nlSig) {
        uint256 _leaf = abi.decode(_logs[i].data, (uint256));
        if (_leaf == _expectedRelayerLeaf) {
          _foundRelayerLeaf = true;
        }
      }
    }

    assertTrue(
      _foundRelayerLeaf,
      "relayer balance leaf should be inserted as a NewLeaf"
    );
  }
}
