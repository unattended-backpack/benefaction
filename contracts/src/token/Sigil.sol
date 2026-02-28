// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { BurnableERC3009 } from "./BurnableERC3009.sol";
import { BurnOnlyERC4626 } from "./BurnOnlyERC4626.sol";
import { DelegateView } from "./DelegateView.sol";
import { ERC1363 } from "./ERC1363.sol";
import { ERC2612 } from "./ERC2612.sol";
import { ERC5805 } from "./ERC5805.sol";
import { EXTSLOAD } from "./EXTSLOAD.sol";
import { EXTTLOAD } from "./EXTTLOAD.sol";
import { ISigil } from "./interfaces/ISigil.sol";
import { ZKMint } from "./zk_mint/ZKMint.sol";
import { ERC20 } from "solady/tokens/ERC20.sol";
import { ERC20Votes } from "solady/tokens/ERC20Votes.sol";
import { EIP712 } from "solady/utils/EIP712.sol";
import { Lifebuoy } from "solady/utils/Lifebuoy.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title The Sigil ERC-20 token.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  The Sigil ERC-20 token.

  @custom:date January 4th, 2026.
*/
contract Sigil is
  ISigil,
  ERC1363,
  ERC2612,
  BurnableERC3009,
  ERC5805,
  BurnOnlyERC4626,
  ZKMint,
  EXTSLOAD,
  EXTTLOAD,
  DelegateView,
  Lifebuoy {

  /// An error emitted when attempting to rescue the ERC-4626 vault asset.
  error CannotRescueVaultAsset ();

  /// The total amount reminted through ZK mints.
  uint256 private _totalReminted;

  /// A flag to suppress the `_afterTokenTransfer` hook during remints.
  bool private _inRemint;

  /**
    Construct a new instance of the Sigil token by specifying the `_owner`,
    which is the privileged caller able to call the one-time `initialize`
    function and rescue any assets accidentally sent to this contract.

    @param _owner The owner of the token.
    @param _verifier The address of the proof verifier contract.
    @param _poseidon2 The address of the deployed Poseidon2 contract.
    @param _rateLimitPeriod The rate limit window duration in seconds.
    @param _rateLimitSupplyBasisPoints The rate limit as basis points of total
      supply.
    @param _rateLimitFloor A floor value for the rate limit.
  */
  constructor (
    address _owner,
    address _verifier,
    address _poseidon2,
    uint256 _rateLimitPeriod,
    uint256 _rateLimitSupplyBasisPoints,
    uint256 _rateLimitFloor
  )
    BurnOnlyERC4626(_owner) ZKMint(_verifier, _poseidon2, _rateLimitPeriod,
  _rateLimitSupplyBasisPoints, _rateLimitFloor) { }

  /**
    Return whether this contract supports a given interface.

    @param _interfaceId The interface identifier to check.

    @return _ Whether the interface is supported.
  */
  function supportsInterface (
    bytes4 _interfaceId
  ) public view override(
    ERC1363, ERC2612, BurnableERC3009, ERC5805, BurnOnlyERC4626
  ) returns (
    bool
  ) {
    return ERC1363.supportsInterface(_interfaceId)
    || ERC2612.supportsInterface(_interfaceId)
    || BurnableERC3009.supportsInterface(_interfaceId)
    || ERC5805.supportsInterface(_interfaceId)
    || BurnOnlyERC4626.supportsInterface(_interfaceId);
  }

  /**
    Return the number of share tokens to be initially minted. One billion.

    @return _ The initial token supply.
  */
  function _initialMint () internal pure override returns (uint256) {
    return 1000000000e18;
  }

  /**
    Return the name of the token.

    @return _ The name of the token.
  */
  function name () public pure override(ISigil, ERC20) returns (
    string memory
  ) {
    return "Sigil";
  }

  /**
    Return a constant hash of the token name to allow Solady to behave more
    optimally. This is set to `keccak256(bytes("Sigil"))`.

    @return _ The constant hash of the token name.
  */
  function _constantNameHash () internal pure override returns (bytes32) {
    return 0x186f3621aaa0f57aba0426c11019615813acda019a946a394416b38a82d50cdf;
  }

  /**
    Returns the symbol of the token.

    @return _ The symbol of the token.
  */
  function symbol () public pure override(ISigil, ERC20) returns (
    string memory
  ) {
    return "SIGIL";
  }

  /**
    Return the EIP-712 domain name and version.

    @return _ A tuple consisting of (the EIP-712 domain name, the EIP-712 domain
      version).
  */
  function _domainNameAndVersion () internal pure override returns (
    string memory, string memory
  ) {
    return ("Sigil", "1");
  }

  /**
    Returns the domain separator used in the encoding of the signature for
    `permit`, as defined by EIP-712.

    @return _ The EIP-712 domain separator.
  */
  function DOMAIN_SEPARATOR () public view override(ERC20, ERC2612) returns (
    bytes32
  ) {
    return _domainSeparator();
  }

  /**
    Returns the number of decimal places of the token, which is 18 because we're
    not savages.

    @return _ The number of decimal places of the token.
  */
  function decimals () public pure override(ERC20, BurnOnlyERC4626) returns (
    uint8
  ) {
    return 18;
  }

  /**
    Return the total supply of the token, offset by the total amount reminted
    through ZK mints. This prevents remints from inflating the visible supply,
    which is important for the `BurnOnlyERC4626` accounting.

    @return _ The total supply of the token.
  */
  function totalSupply () public view override returns (uint256) {
    return ERC20.totalSupply() - _totalReminted;
  }

  /**
    Return the underlying ERC-4626 vault asset. For us, this is wrapped Ether.
    There is no second best.

    @return _ The ERC-4626 vault asset that may be redeemed.
  */
  function asset () public pure override returns (address) {
    return 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
  }

  /**
    Override ERC-4626 to support the initial mint having a backing of one
    attoEther per token.

    @return _ The number of decimals to offset the minted supply of ERC-4626
      shares against the `asset` supply.
  */
  function _decimalsOffset () internal pure override returns (uint8) {
    return 18;
  }

  /**
    Use a valid signature by `_owner` to approve `_spender` to spend `_amount`
    tokens by `_deadline`. This function accepts an ECDSA signature split into
    its three component parts. We are using our ERC-2612 implementation as
    override here in order to support a much wider range of acceptable
    signatures.

    @param _owner The transfer authorizer's (payer's) address.
    @param _spender The approved spender.
    @param _amount The amount to be transferred.
    @param _deadline The maximum timestamp before which the authorized approval
      is valid.
    @param _v The "v" component of the authorizer's signature.
    @param _r The "r" component of the authorizer's signature.
    @param _s The "s" component of the authorizer's signature.
  */
  function permit (
    address _owner,
    address _spender,
    uint256 _amount,
    uint256 _deadline,
    uint8 _v,
    bytes32 _r,
    bytes32 _s
  ) public override(ERC20, ERC2612) {
    ERC2612.permit(
      _owner, _spender, _amount, _deadline, abi.encodePacked(_r, _s, _v)
    );
  }

  /**
    Returns the current nonce for `_owner`. This value must be included whenever
    a signature is generated for `permit` or `delegateBySig`.

    @param _owner The address to query the nonce for.

    @return _ The current nonce for `_owner`.
  */
  function nonces (
    address _owner
  ) public view override(ERC20, ERC2612, ERC5805) returns (uint256) {
    return ERC20.nonces(_owner);
  }

  /**
    Resolve the `_hashTypedData` diamond between Solady's EIP-712 implementation
    and the abstract declaration in ZKMint.

    @param _structHash The struct hash to wrap with domain separator.

    @return _ The full EIP-712 hash.
  */
  function _hashTypedData (
    bytes32 _structHash
  ) internal view override(EIP712, ZKMint) returns (bytes32) {
    return EIP712._hashTypedData(_structHash);
  }

  /**
    Return the current total supply used for rate limit calculations.

    @return _ The total supply of the token.
  */
  function _totalSupply () internal view override returns (uint256) {
    return totalSupply();
  }

  /**
    Remint tokens to a recipient as part of a ZK mint. The `_afterTokenTransfer`
    hook is suppressed so the balance leaf and account note hashes can be
    batch-inserted into the hash tree together.

    @param _to The recipient address.
    @param _amount The amount to remint.
    @param _accountNoteHashes The account note commitments to insert.
  */
  function _remint (
    address _to,
    uint256 _amount,
    uint256[] memory _accountNoteHashes
  ) internal override {
    _inRemint = true;
    _mint(_to, _amount);
    _inRemint = false;
    _totalReminted += _amount;
    _updateBalanceInTree(_to, balanceOf(_to), _accountNoteHashes);
  }

  /**
    Mint tokens to a relayer as a fee reward during a ZK mint. The
    `_afterTokenTransfer` hook fires normally, inserting the relayer's balance
    leaf into the tree.

    @param _to The relayer address.
    @param _amount The fee amount to mint.
  */
  function _remintToRelayer (
    address _to,
    uint256 _amount
  ) internal override {
    _mint(_to, _amount);
    _totalReminted += _amount;
  }

  /**
    This is a hook called after any transfer of tokens, including mint or burn.
    In this case, owing to our multiple inheritance, we explicitly opt for the
    ERC-5805 behavior of `ERC20Votes`. Additionally, we insert balance leaves
    into the hash tree for every receive, unless suppressed by a remint in
    progress.

    @param _from The address where tokens are transferring from.
    @param _to The address where tokens are transferring to.
    @param _amount The amount of tokens transferred.
  */
  function _afterTokenTransfer (
    address _from,
    address _to,
    uint256 _amount
  ) internal override(ERC20, ERC20Votes) {
    ERC20Votes._afterTokenTransfer(_from, _to, _amount);
    if (!_inRemint && _to != address(0)) {
      _updateBalanceInTree(_to, balanceOf(_to));
    }
  }

  /**
    Rescue ERC-20 tokens accidentally sent to this contract. The ERC-4626 vault
    asset (WETH) cannot be rescued.

    @param _token The address of the ERC-20 token to rescue.
    @param _to The address to send the rescued tokens to.
    @param _amount The amount of tokens to rescue.
  */
  function rescueERC20 (
    address _token,
    address _to,
    uint256 _amount
  ) public payable override onlyRescuer(_LIFEBUOY_RESCUE_ERC20_LOCK) {
    if (_token == asset()) {
      revert CannotRescueVaultAsset();
    }
    Lifebuoy.rescueERC20(_token, _to, _amount);
  }
}

