// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { IncrementalHashTree, HashTree, SNARK_SCALAR_FIELD } from
  "./IncrementalHashTree.sol";
import { IPoseidon2 } from "./interfaces/IPoseidon2.sol";
import { IVerifier } from "./interfaces/IVerifier.sol";
import { IZKMint } from "./interfaces/IZKMint.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Zero knowledge mint.
  @custom:blame Tim Clancy <tim-clancy.eth>
  @author Jimjim Valkema <jimjim.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"
  @custom:preserve

  This contract is based heavily on the original work of Jimjim. He deserves any
  credit for this contract working correctly. Tim has modified this contract. If
  it does not work correctly, blame Tim.

  This is an abstract contract implementing zero knowledge token minting.
  Callers may mint tokens in exchange for presenting proofs of prior token
  burns. It manages a Poseidon2-based incremental hash tree, nullifier tracking,
  and SNARK proof verification of bound EIP-712 signatures. The contract
  supports aggregating up to 32 burns per proof. Inheritors must implement
  `_remint` to handle the actual token minting and balance tracking.

  @custom:date February 21st, 2026.
*/
abstract contract ZKMint is
  IZKMint {

  using IncrementalHashTree for HashTree;

  /// The EIP-712 typehash for the ZKMint struct signed and verified in a proof.
  bytes32 private constant _ZK_MINT_TYPEHASH =
    keccak256(
      "ZKMint(address recipient,uint256 amount,address relayerAddress,uint256 priorityFee,uint256 conversionRate,uint256 maxReward,bytes[] totalMintedEncrypted)"
    );

  /**
    The domain separator for total burned balance leaves in the hash tree; this
    is `UTF8("BURN_TOTAL")`.
  */
  uint256 public constant TOTAL_BURNED_DOMAIN = 0x4255524e5f544f54414c;

  /// The maximum number of permitted burn addresses per proof.
  uint256 public constant BURN_ADDRESSES_LEN = 32;

  /// The hash tree of account balance commitments.
  HashTree internal tree;

  /**
    A mapping from account note nullifiers to a minted amount being nullified.
    The `_nullifiedAmount` is stored as (the actually-minted amount + 1); this
    is done so that we can preserve the invariant that a `_nullifiedAmount` of
    zero means the `_nullifier` is unused, even if the user attempts to mint
    zero tokens.

    @custom:param _nullifier The nullifier of a particular account note.

    @custom:return _nullifiedAmount The amount of tokens minted against the
      `_nullifier`; this supports minting partial amounts of burned tokens.
  */
  mapping (
    uint256 _nullifier => uint256 _nullifiedAmount
  ) public override nullifiers;

  /**
    A mapping of historical tree roots to their validity. This mapping allows
    any caller performing a zero knowledge mint to prove inclusion of prior
    corresponding burns in the hash tree.

    @custom:param _root Any historical root of the hash tree.

    @custom:return _isValid Whether or not the `_root` actually ever was a valid
      part of the hash tree.
  */
  mapping (
    uint256 _root => bool _isValid
  ) public roots;

  /// The timestamp when the current ZK minting rate limit window started.
  uint256 public rateLimitPeriodStart;

  /// The total amount ZK minted in the current rate limit window.
  uint256 public rateLimitMintedInPeriod;

  /// The address of the proof verifier contract.
  address public immutable verifier;

  /// The address of the Poseidon2 hashing contract.
  address public immutable poseidon2;

  /**
    The rate limit window duration in seconds; this is how often the limit
    resets.
  */
  uint256 public immutable rateLimitPeriod;

  /// The rate limit expressed as basis points of total token supply.
  uint256 public immutable rateLimitSupplyBasisPoints;

  /**
    A floor value for the rate limit. The rate limit is assessed as
    `max(rateLimitFloor, _totalSupply() * rateLimitSupplyBasisPoints)`. This
    allows specifying a minimum rate limit that is convenient in regimes where
    the total supply is expected to grow.
  */
  uint256 public immutable rateLimitFloor;

  /**
    Hash two field elements using the Poseidon2 contract. This function is
    passed to the incremental hash tree as its hasher function.

    @param _leaves The two field elements to hash.

    @return _ The Poseidon2 hash result.
  */
  function _hasher (
    uint256[2] memory _leaves
  ) public view returns (uint256) {
    return IPoseidon2(poseidon2).hash(_leaves[0], _leaves[1]);
  }

  /**
    Construct a new ZKMint instance by specifying the verifier contract,
    Poseidon2 contract, and ZK mint rate limiting details.

    @param _verifier The address of the proof verifier contract.
    @param _poseidon2 The address of the Poseidon2 hashing contract.
    @param _rateLimitPeriod The rate limit window duration in seconds.
    @param _rateLimitSupplyBasisPoints The rate limit expressed as basis points
      of total token supply.
    @param _rateLimitFloor A floor value for the rate limit.
  */
  constructor (
    address _verifier,
    address _poseidon2,
    uint256 _rateLimitPeriod,
    uint256 _rateLimitSupplyBasisPoints,
    uint256 _rateLimitFloor
  ) {
    verifier = _verifier;
    poseidon2 = _poseidon2;
    rateLimitPeriod = _rateLimitPeriod;
    rateLimitSupplyBasisPoints = _rateLimitSupplyBasisPoints;
    rateLimitFloor = _rateLimitFloor;

    // Set the hash function for the tree.
    tree.hash = _hasher;
  }

  /**
    Compute the EIP-712 typed data hash.

    @param _structHash The struct hash to wrap with domain separator.

    @return _ The full EIP-712 hash.
  */
  function _hashTypedData (
    bytes32 _structHash
  ) internal view virtual returns (bytes32);

  /**
    Return the current total supply of the token.

    @return _ The current total supply.
  */
  function _totalSupply () internal view virtual returns (uint256);

  /**
    Remint tokens to a recipient without increasing total supply.

    @param _to The recipient address.
    @param _amount The amount to remint.
    @param _accountNoteHashes The account note commitments to insert.
  */
  function _remint (
    address _to,
    uint256 _amount,
    uint256[] memory _accountNoteHashes
  ) internal virtual;

  /**
    Remint reward tokens to a relayer without increasing total supply. Relayers
    do not specify account note hashes for rewards they receive.

    @param _to The relayer address.
    @param _amount The amount to mint.
  */
  function _remintToRelayer (
    address _to,
    uint256 _amount
  ) internal virtual;

  /**
    Return the current tree root.

    @return _ The current root.
  */
  function root () external view override returns (uint256) {
    return tree.root();
  }

  /**
    Insert a single leaf into the commitment tree and record the updated
    historic root.

    @param _leaf The leaf value to insert.
  */
  function _insertInTree (
    uint256 _leaf
  ) private {
    tree.insert(_leaf);
    roots[tree.root()] = true;
    emit NewLeaf(_leaf);
  }

  /**
    Insert multiple leaves into the commitment tree and record the updated
    historic root.

    @param _leaves The leaf values to insert.
  */
  function _insertManyInTree (
    uint256[] memory _leaves
  ) private {
    tree.insertMany(_leaves);
    roots[tree.root()] = true;
    for (uint256 i = 0; i < _leaves.length; ) {
      emit NewLeaf(_leaves[i]);
      unchecked {
        ++i;
      }
    }
  }

  /**
    Hash a balance leaf using the Poseidon2 hashing contract.

    @param _address The recipient address.
    @param _balance The recipient's new balance.

    @return _ The Poseidon2 hash of the balance leaf.
  */
  function _hashBalanceLeaf (
    address _address,
    uint256 _balance
  ) private view returns (uint256) {
    return IPoseidon2(poseidon2).hash(
      uint256(uint160(_address)), _balance, TOTAL_BURNED_DOMAIN
    );
  }

  /**
    Update the commitment tree when a public balance changes. This should be
    called by the token's `_update` function on every transfer and mint. When
    `tx.origin` is the recipient, the balance leaf insertion is skipped since
    EOAs cannot ever be burn addresses.

    @param _to The recipient whose balance changed.
    @param _newBalance The recipient's new balance.
  */
  function _updateBalanceInTree (
    address _to,
    uint256 _newBalance
  ) internal {
    if (tx.origin == _to) {
      return;
    }
    uint256 _leaf = _hashBalanceLeaf(_to, _newBalance);
    if (!tree.has(_leaf)) {
      _insertInTree(_leaf);
    }
  }

  /**
    Update the commitment tree during a remint. This inserts the balance leaf
    (if new) and all account note hashes. When `tx.origin` is the recipient,
    only the account note hashes are inserted since EOAs cannot ever be burn
    addresses.

    @param _to The recipient whose balance changed.
    @param _newBalance The recipient's new balance.
    @param _accountNoteHashes The account note commitments to insert.
  */
  function _updateBalanceInTree (
    address _to,
    uint256 _newBalance,
    uint256[] memory _accountNoteHashes
  ) internal {

    // Only insert account note hashes.
    if (tx.origin == _to) {
      if (_accountNoteHashes.length == 1) {
        _insertInTree(_accountNoteHashes[0]);
      } else {
        _insertManyInTree(_accountNoteHashes);
      }
    } else {
      uint256 _balanceLeaf = _hashBalanceLeaf(_to, _newBalance);

      // Balance leaf already exists, just insert account note hashes.
      if (tree.has(_balanceLeaf)) {
        if (_accountNoteHashes.length == 1) {
          _insertInTree(_accountNoteHashes[0]);
        } else {
          _insertManyInTree(_accountNoteHashes);
        }
      } else {

        // Batch insert: [balanceLeaf, noteHash0, noteHash1, ...].
        uint256[] memory _leaves =
          new uint256[](_accountNoteHashes.length + 1);
        _leaves[0] = _balanceLeaf;
        for (uint256 i = 0; i < _accountNoteHashes.length; ) {
          _leaves[i + 1] = _accountNoteHashes[i];
          unchecked {
            ++i;
          }
        }
        _insertManyInTree(_leaves);
      }
    }
  }

  /**
    Enforce a rate limit on the ZK minting. The rate limit is assessed as
    `max(rateLimitFloor, _totalSupply() * rateLimitSupplyBasisPoints)`. This
    allows specifying a minimum rate limit that is convenient in regimes where
    the total supply is expected to grow. This rate limiting is a safety feature
    in the event that the circuit or cryptography behind the ZK minting
    mechanism is unsound; silent inflation is capped to some maximum rate.

    @param _amount The amount being minted.
  */
  function _enforceRateLimit (
    uint256 _amount
  ) private {
    if (block.timestamp >= rateLimitPeriodStart + rateLimitPeriod) {
      rateLimitPeriodStart = block.timestamp;
      rateLimitMintedInPeriod = _amount;
    } else {
      rateLimitMintedInPeriod += _amount;
    }
    uint256 _limit = _totalSupply() * rateLimitSupplyBasisPoints / 10_000;
    if (_limit < rateLimitFloor) {
      _limit = rateLimitFloor;
    }

    // Revert if the limit is exceeded.
    if (rateLimitMintedInPeriod > _limit) {
      revert RateLimitExceeded();
    }
  }

  /**
    Verify that all nullifiers are unused, then store the new account nullifier
    and emit an event.

    @param _amount The mint amount (stored as amount + 1).
    @param _burns The per-burn data containing note hashes, nullifiers, and
      encrypted mint totals.
  */
  function _processNullifiers (
    uint256 _amount,
    BurnInput[] calldata _burns
  ) private {
    for (uint256 i = 0; i < _burns.length; ) {
      if (nullifiers[_burns[i].accountNoteNullifier] != 0) {
        revert NullifierAlreadyExists();
      }
      nullifiers[_burns[i].accountNoteNullifier] = _amount + 1;
      emit Nullified(
        _burns[i].accountNoteNullifier, _burns[i].totalMintedEncrypted
      );
      unchecked {
        ++i;
      }
    }
  }

  /**
    Hash the `totalMintedEncrypted` entries from BurnInput structs for EIP-712
    encoding. Follows the EIP-712 standard for encoding dynamic `bytes[]`.

    @param _burns The per-burn data containing note hashes, nullifiers, and
      encrypted mint totals.

    @return _ The keccak256 hash of the concatenated item hashes.
  */
  function _hashTotalMintedEncrypted (
    BurnInput[] calldata _burns
  ) private pure returns (bytes32) {
    bytes memory _packed;
    for (uint256 i = 0; i < _burns.length; ) {
      _packed = abi.encodePacked(
        _packed, keccak256(_burns[i].totalMintedEncrypted)
      );
      unchecked {
        ++i;
      }
    }
    return keccak256(_packed);
  }

  /**
    Compute the EIP-712 signature hash that binds the proof to specific mint
    parameters.

    @param _to The recipient address.
    @param _amount The mint amount.
    @param _rewardData The relayer reward parameters.
    @param _burns The per-burn data containing note hashes, nullifiers, and
      encrypted mint totals.

    @return _ The signature hash (modulo the hash tree's `SNARK_SCALAR_FIELD`).
  */
  function _computeSignatureHash (
    address _to,
    uint256 _amount,
    RewardData calldata _rewardData,
    BurnInput[] calldata _burns
  ) private view returns (uint256) {
    bytes32 _structHash =
      keccak256(
        abi.encode(
          _ZK_MINT_TYPEHASH, _to, _amount, _rewardData.relayerAddress,
          _rewardData.priorityFee, _rewardData.conversionRate,
          _rewardData.maxReward, _hashTotalMintedEncrypted(_burns)
        )
      );
    bytes32 _digest = _hashTypedData(_structHash);
    return uint256(_digest) % SNARK_SCALAR_FIELD;
  }

  /**
    @custom:preserve
    Format the public inputs for the SNARK verifier (67-element layout).

    Noir serializes `[BurnDataPublic; 32]` with interleaved struct fields:

    [0]        amount
    [1]        signatureHash
    [2]        burn[0].accountNoteHash
    [3]        burn[0].accountNoteNullifier
    [4]        burn[1].accountNoteHash
    [5]        burn[1].accountNoteNullifier
    ...
    [64]       burn[31].accountNoteHash
    [65]       burn[31].accountNoteNullifier
    [66]       root

    @param _amount The mint amount.
    @param _signatureHash The EIP-712 hash mod SNARK_SCALAR_FIELD.
    @param _burns The per-burn data containing note hashes, nullifiers, and
      encrypted mint totals.
    @param _root The tree root.

    @return _ The public inputs as a bytes32 array.
  */
  function _formatPublicInputs (
    uint256 _amount,
    uint256 _signatureHash,
    BurnInput[] calldata _burns,
    uint256 _root
  ) private pure returns (bytes32[] memory) {
    bytes32[] memory _publicInputs = new bytes32[](67);
    _publicInputs[0] = bytes32(_amount);
    _publicInputs[1] = bytes32(_signatureHash);

    // Interleaved: [hash_i, nullifier_i] pairs (remaining slots stay zero).
    for (uint256 i = 0; i < _burns.length; ) {
      _publicInputs[2 + i * 2] = bytes32(_burns[i].accountNoteHash);
      _publicInputs[3 + i * 2] = bytes32(_burns[i].accountNoteNullifier);
      unchecked {
        ++i;
      }
    }
    _publicInputs[66] = bytes32(_root);
    return _publicInputs;
  }

  /**
    Recompute the EIP-712 signature hash used in the proof, format the public
    inputs to the proof, and verify the proof.

    @param _amount The mint amount.
    @param _to The recipient address.
    @param _rewardData The relayer reward parameters.
    @param _burns The per-burn data containing note hashes, nullifiers, and
      encrypted mint totals.
    @param _root The tree root that the proof was generated against.
    @param _proof The serialized proof.
  */
  function _verifyProof (
    uint256 _amount,
    address _to,
    RewardData calldata _rewardData,
    BurnInput[] calldata _burns,
    uint256 _root,
    bytes calldata _proof
  ) private view {
    uint256 _signatureHash =
      _computeSignatureHash(_to, _amount, _rewardData, _burns);
    bytes32[] memory _publicInputs =
      _formatPublicInputs(_amount, _signatureHash, _burns, _root);
    if (!IVerifier(verifier).verify(_proof, _publicInputs)) {
      revert VerificationFailed();
    }
  }

  /**
    Calculate the relayer reward and the net recipient amount.

    @param _rewardData The relayer reward parameters.
    @param _amount The total mint amount.

    @return _ A tuple consisting of (the reward paid to the relayer, the amount
      received by the recipient).
  */
  function _calculateReward (
    RewardData calldata _rewardData,
    uint256 _amount
  ) private view returns (uint256, uint256) {
    uint256 _relayerReward =
      (_rewardData.priorityFee + block.basefee) * _rewardData.conversionRate;
    if (_relayerReward > _rewardData.maxReward) {
      _relayerReward = _rewardData.maxReward;
    }
    uint256 _recipientAmount = _amount - _relayerReward;
    return (_relayerReward, _recipientAmount);
  }

  /**
    Handle reward calculation, minting, and event emission.

    @param _amount The mint amount.
    @param _to The recipient address.
    @param _rewardData The relayer reward parameters.
    @param _burns The per-burn data containing note hashes, nullifiers, and
      encrypted mint totals.
  */
  function _processMint (
    uint256 _amount,
    address _to,
    RewardData calldata _rewardData,
    BurnInput[] calldata _burns
  ) private {

    // Collect all account note hashes from the `_burns`.
    uint256[] memory _noteHashes = new uint256[](_burns.length);
    for (uint256 i = 0; i < _burns.length; ) {
      _noteHashes[i] = _burns[i].accountNoteHash;
      unchecked {
        ++i;
      }
    }

    // If using self-relaying, mint in full to the recipient.
    if (_rewardData.relayerAddress == address(0)) {
      _remint(_to, _amount, _noteHashes);

    /*
      If using relaying, mint a reward to the relayer. A relayer sentinel value
      of 0x0...1 allows the `msg.sender` to claim the reward as an open relayer.
    */
    } else {
      address _rewardRecipient =
        _rewardData.relayerAddress == address(1) ? msg.sender :
        _rewardData.relayerAddress;
      (uint256 _relayerReward, uint256 _recipientAmount) = _calculateReward(
        _rewardData, _amount
      );
      _remint(_to, _recipientAmount, _noteHashes);
      _remintToRelayer(_rewardRecipient, _relayerReward);
    }
    emit ZKMintExecuted(_amount);
  }

  /**
    Execute a ZK mint, verifying the proof and reminting tokens to the recipient
    without increasing total supply.

    @param _amount The mint amount.
    @param _to The recipient address.
    @param _rewardData The relayer reward parameters.
    @param _burns The per-burn data containing note hashes, nullifiers, and
      encrypted mint totals.
    @param _root The tree root that the proof was generated against.
    @param _proof The serialized proof.
  */
  function zkMint (
    uint256 _amount,
    address _to,
    RewardData calldata _rewardData,
    BurnInput[] calldata _burns,
    uint256 _root,
    bytes calldata _proof
  ) external override {

    // Validate burn array length.
    if (_burns.length == 0 || _burns.length > BURN_ADDRESSES_LEN) {
      revert InvalidArrayLength();
    }

    /*
      Reject public inputs that exceed the BN254 scalar field. The HONK verifier
      reduces values mod p internally; without this check an attacker could pass
      `p + x` to the contract (minting `p + x` tokens) while the verifier sees
      `x` and accepts a proof generated for `x`.
    */
    if (_amount >= SNARK_SCALAR_FIELD || _root >= SNARK_SCALAR_FIELD) {
      revert InputExceedsField();
    }
    for (uint256 i = 0; i < _burns.length; ) {
      if (
        _burns[i].accountNoteHash >= SNARK_SCALAR_FIELD
        || _burns[i].accountNoteNullifier >= SNARK_SCALAR_FIELD
      ) {
        revert InputExceedsField();
      }
      unchecked {
        ++i;
      }
    }

    // Verify that the relayer reward does not exceed the mint amount.
    if (_rewardData.maxReward >= _amount) {
      revert MaxRewardExceedsAmount();
    }

    // Verify that the claimed root is historically valid.
    if (!roots[_root]) {
      revert InvalidRoot();
    }

    // Enforce rate limits on minting.
    _enforceRateLimit(_amount);

    // Verify and process all nullifiers.
    _processNullifiers(_amount, _burns);

    // Verify the proof is valid for the given EIP-712 binding.
    _verifyProof(_amount, _to, _rewardData, _burns, _root, _proof);

    // Remint burned tokens to the recipient and relayer.
    _processMint(_amount, _to, _rewardData, _burns);
  }
}

