// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { ZKMint } from "token/zk_mint/ZKMint.sol";
import { ERC20 } from "solady/tokens/ERC20.sol";
import { EIP712 } from "solady/utils/EIP712.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title MockZKMintToken
  @author Tim Clancy <tim-clancy.eth>

  A minimal ERC20 + ZKMint contract that replicates Sigil's hash tree insertion
  logic without any of the ERC-4626, ERC-5805, ERC-1363, etc. complexity. Used
  by the integration test harness.

  @custom:date February 13th, 2026.
*/
contract MockZKMintToken is
  ERC20,
  EIP712,
  ZKMint {

  /// The total amount reminted through ZK mints.
  uint256 private _totalReminted;

  /// A flag to suppress the `_afterTokenTransfer` hook during remints.
  bool private _inRemint;

  /**
    Construct a new MockZKMintToken by specifying the verifier and
    Poseidon2 contract addresses.

    @param _verifier The address of the proof verifier contract.
    @param _poseidon2 The address of the deployed Poseidon2 contract.
    @param _rateLimitPeriod The rate limit window duration in seconds.
    @param _rateLimitSupplyBasisPoints The rate limit as basis points of total
      supply.
    @param _rateLimitFloor A floor value for the rate limit.
  */
  constructor (
    address _verifier,
    address _poseidon2,
    uint256 _rateLimitPeriod,
    uint256 _rateLimitSupplyBasisPoints,
    uint256 _rateLimitFloor
  ) ZKMint(
    _verifier, _poseidon2, _rateLimitPeriod, _rateLimitSupplyBasisPoints,
    _rateLimitFloor
  ) { }

  /**
    Return the name of the token.

    @return _ The name of the token.
  */
  function name () public pure override returns (string memory) {
    return "MockZKMint";
  }

  /**
    Returns the symbol of the token.

    @return _ The symbol of the token.
  */
  function symbol () public pure override returns (string memory) {
    return "MPT";
  }

  /**
    Return the EIP-712 domain name and version.

    @return _ A tuple of (name, version).
  */
  function _domainNameAndVersion () internal pure override returns (
    string memory, string memory
  ) {
    return ("MockZKMint", "1");
  }

  /**
    Resolve the `_hashTypedData` diamond between Solady's EIP-712 and the
    abstract declaration in ZKMint.


    @param _structHash The struct hash to wrap with domain separator.

    @return _ The full EIP-712 hash.
  */
  function _hashTypedData (
    bytes32 _structHash
  ) internal view override(EIP712, ZKMint) returns (bytes32) {
    return EIP712._hashTypedData(_structHash);
  }

  /**
    Public mint for test setup (no access control).

    @param _to The address to mint to.
    @param _amount The amount to mint.
  */
  function mint (
    address _to,
    uint256 _amount
  ) external {
    _mint(_to, _amount);
  }

  /**
    Return the total supply of the token, offset by the total amount reminted
    through ZK mints. This prevents remints from inflating the visible supply.

    @return _ The visible total supply.
  */
  function totalSupply () public view override returns (uint256) {
    return ERC20.totalSupply() - _totalReminted;
  }

  /**
    Return the current total supply used for rate limit calculations.

    @return _ The total supply of the token.
  */
  function _totalSupply () internal view override returns (uint256) {
    return totalSupply();
  }

  /**
    Hook called after any transfer. Inserts a balance leaf into the hash tree
    for every receive, unless suppressed by a remint in progress or the
    transfer is a burn.

    @param _from The sender address.
    @param _to The recipient address.
    @param _amount The amount transferred.
  */
  function _afterTokenTransfer (
    address _from,
    address _to,
    uint256 _amount
  ) internal override {
    (_from, _amount); // silence unused warnings
    if (!_inRemint && _to != address(0)) {
      _updateBalanceInTree(_to, balanceOf(_to));
    }
  }

  /**
    Remint tokens to a recipient as part of a ZK mint. The
    `_afterTokenTransfer` hook is suppressed so the balance leaf and account
    note hashes can be batch-inserted into the hash tree together.

    @param _to The recipient address.
    @param _amount The amount to re-mint.
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
}
