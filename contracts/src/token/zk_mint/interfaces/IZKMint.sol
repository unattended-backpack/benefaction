// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Zero knowledge mint interface.
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
interface IZKMint {

  /**
    A struct encoding relayer reward parameters for a ZK mint.

    @param relayerAddress The relayer address: `address(0)` for self-relay,
      `address(1)` for `msg.sender`, or any other address for a specific
      relayer.
    @param priorityFee The priority fee the minter is willing to pay the
      relayer.
    @param conversionRate A conversion rate factor: `gasUsage * tokenPriceInWei
      * bonusFactor`.
    @param maxReward The maximum reward the minter will accept.
  */
  struct RewardData {
    address relayerAddress;
    uint256 priorityFee;
    uint256 conversionRate;
    uint256 maxReward;
  }

  /**
    Per-burn data passed by the caller.

    @param accountNoteHash The new account note commitment.
    @param accountNoteNullifier The nullifier for the previous account note.
    @param totalMintedEncrypted Encrypted total-minted value for this burn
      address.
  */
  struct BurnInput {
    uint256 accountNoteHash;
    uint256 accountNoteNullifier;
    bytes totalMintedEncrypted;
  }

  /// An error emitted when the ZK mint rate limit is exceeded.
  error RateLimitExceeded ();

  /// An error emitted when a SNARK proof fails verification.
  error VerificationFailed ();

  /// An error emitted when a nullifier has already been consumed.
  error NullifierAlreadyExists ();

  /// An error emitted when the provided tree root is not recognized.
  error InvalidRoot ();

  /// An error emitted when array lengths are invalid.
  error InvalidArrayLength ();

  /// An error emitted when max_reward exceeds the transfer amount.
  error MaxRewardExceedsAmount ();

  /// An error emitted when a public input exceeds the BN254 scalar field.
  error InputExceedsField ();

  /**
    Emitted per nullifier consumed during a ZK mint.

    @param nullifier The consumed nullifier.
    @param totalMintedEncrypted The encrypted total-minted value.
  */
  event Nullified (
    uint256 indexed nullifier,
    bytes totalMintedEncrypted
  );

  /**
    Emitted when a ZK mint is executed.

    @param amount The amount minted.
  */
  event ZKMintExecuted (
    uint256 amount
  );

  /**
    Emitted when a new leaf is inserted into the commitment tree.

    @param leaf The value of the newly-inserted leaf.
  */
  event NewLeaf (
    uint256 leaf
  );

  /**
    Return the domain separator for total burned balance leaves in the hash
    tree; this is `UTF8("BURN_TOTAL")`.

    @return _ The total burned domain separator.
  */
  function TOTAL_BURNED_DOMAIN () external pure returns (uint256);

  /**
    Return the maximum number of permitted burn addresses per proof.

    @return _ The maxmimum number of permitted burns per proof.
  */
  function BURN_ADDRESSES_LEN () external pure returns (uint256);

  /**
    A mapping from account note nullifiers to a minted amount being nullified.
    The `_nullifiedAmount` is stored as (the actually-minted amount + 1); this
    is done so that we can preserve the invariant that a `_nullifiedAmount` of
    zero means the `_nullifier` is unused, even if the user attempts to mint
    zero tokens.

    @param _nullifier The nullifier of a particular account note.

    @return _ The amount of tokens minted against the `_nullifier`; this
      supports minting partial amounts of burned tokens.
  */
  function nullifiers (
    uint256 _nullifier
  ) external view returns (uint256);

  /**
    A mapping of historical tree roots to their validity. This mapping allows
    any caller performing a zero knowledge mint to prove inclusion of prior
    corresponding burns in the hash tree.

    @param _root Any historical root of the hash tree.

    @return _ Whether or not the `_root` actually ever was a valid part of the
      hash tree.
  */
  function roots (
    uint256 _root
  ) external view returns (bool);

  /**
    Return the timestamp when the current ZK minting rate limit window started.

    @return _ The timestamp when the current rate limit window started.
  */
  function rateLimitPeriodStart () external view returns (uint256);

  /**
    Return the total amount ZK minted in the current rate limit window.

    @return _ The total amount minted in the current rate limit window.
  */
  function rateLimitMintedInPeriod () external view returns (uint256);

  /**
    Return the address of the proof verifier contract.

    @return _ The proof verifier address.
  */
  function verifier () external view returns (address);

  /**
    Return the address of the Poseidon2 hashing contract.

    @return _ The address of the Poseidon2 hashing contract.
  */
  function poseidon2 () external view returns (address);

  /**
    Return the rate limit window duration in seconds; this is how often the
    limit resets.

    @return _ The rate limit window duration.
  */
  function rateLimitPeriod () external view returns (uint256);

  /**
    Return the rate limit expressed as basis points of total token supply.

    @return _ The rate limit as a function of total token supply.
  */
  function rateLimitSupplyBasisPoints () external view returns (uint256);

  /**
    Return the floor value for the rate limit. The rate limit is assessed as
    `max(rateLimitFloor, _totalSupply() * rateLimitSupplyBasisPoints)`. This
    allows specifying a minimum rate limit that is convenient in regimes where
    the total supply is expected to grow.

    @return _ The rate limit floor value.
  */
  function rateLimitFloor () external view returns (uint256);

  /**
    Hash two field elements using the Poseidon2 contract. This function is
    passed to the incremental hash tree as its hasher function.

    @param _leaves The two field elements to hash.

    @return _ The Poseidon2 hash result.
  */
  function _hasher (
    uint256[2] memory _leaves
  ) external view returns (uint256);

  /**
    Return the current tree root.

    @return _ The current root.
  */
  function root () external view returns (uint256);

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
  ) external;
}

