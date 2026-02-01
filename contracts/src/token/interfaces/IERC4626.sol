// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title An ERC-4626 Interface
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  This is an interface for the ERC-4626 Tokenized Vault Standard as defined in
  EIP-4626. It extends ERC-20 to add deposit, mint, withdraw, and redeem
  functions for a tokenized vault where shares represent proportional claims on
  an underlying asset.

  @custom:date January 31st, 2026.
*/
interface IERC4626 {

  /**
    Return whether this contract supports a given interface.

    @param _interfaceId The interface identifier to check.

    @return _ Whether the interface is supported.
  */
  function supportsInterface (
    bytes4 _interfaceId
  ) external view returns (bool);

  /**
    Return the address of the underlying asset token managed by the vault.

    @return _ The address of the underlying ERC-20 asset.
  */
  function asset () external view returns (address);

  /**
    Return the total amount of the underlying asset managed by the vault.

    @return _ The total amount of underlying assets.
  */
  function totalAssets () external view returns (uint256);

  /**
    Return the amount of shares that the vault would exchange for the amount of
    assets provided, in an ideal scenario where all conditions are met.

    @param _assets The amount of underlying assets to convert.

    @return _ The amount of vault shares.
  */
  function convertToShares (
    uint256 _assets
  ) external view returns (uint256);

  /**
    Return the amount of assets that the vault would exchange for the amount of
    shares provided, in an ideal scenario where all conditions are met.

    @param _shares The amount of vault shares to convert.

    @return _ The amount of underlying assets.
  */
  function convertToAssets (
    uint256 _shares
  ) external view returns (uint256);

  /**
    Return the maximum amount of the underlying asset that can be deposited into
    the vault for `_receiver` via a deposit call.

    @param _receiver The address that would receive the minted shares.

    @return _ The maximum amount of underlying assets that can be deposited.
  */
  function maxDeposit (
    address _receiver
  ) external view returns (uint256);

  /**
    Return the maximum amount of vault shares that can be minted for `_receiver`
    via a mint call.

    @param _receiver The address that would receive the minted shares.

    @return _ The maximum amount of vault shares that can be minted.
  */
  function maxMint (
    address _receiver
  ) external view returns (uint256);

  /**
    Return the maximum amount of the underlying asset that can be withdrawn from
    the `_owner` balance in the vault via a withdraw call.

    @param _owner The address that owns the shares.

    @return _ The maximum amount of underlying assets that can be withdrawn.
  */
  function maxWithdraw (
    address _owner
  ) external view returns (uint256);

  /**
    Return the maximum amount of vault shares that can be redeemed from the
    `_owner` balance in the vault via a redeem call.

    @param _owner The address that owns the shares.

    @return _ The maximum amount of vault shares that can be redeemed.
  */
  function maxRedeem (
    address _owner
  ) external view returns (uint256);

  /**
    Simulate the effects of a deposit at the current block, given current
    on-chain conditions.

    @param _assets The amount of underlying assets to deposit.

    @return _ The amount of vault shares that would be minted.
  */
  function previewDeposit (
    uint256 _assets
  ) external view returns (uint256);

  /**
    Simulate the effects of a mint at the current block, given current on-chain
    conditions.

    @param _shares The amount of vault shares to mint.

    @return _ The amount of underlying assets that would be required.
  */
  function previewMint (
    uint256 _shares
  ) external view returns (uint256);

  /**
    Simulate the effects of a withdrawal at the current block, given current
    on-chain conditions.

    @param _assets The amount of underlying assets to withdraw.

    @return _ The amount of vault shares that would be burned.
  */
  function previewWithdraw (
    uint256 _assets
  ) external view returns (uint256);

  /**
    Simulate the effects of a redemption at the current block, given current
    on-chain conditions.

    @param _shares The amount of vault shares to redeem.

    @return _ The amount of underlying assets that would be received.
  */
  function previewRedeem (
    uint256 _shares
  ) external view returns (uint256);

  /**
    Deposit `_assets` of underlying tokens into the vault, minting shares to
    `_receiver`.

    @param _assets The amount of underlying assets to deposit.
    @param _receiver The address that will receive the minted shares.

    @return _ The amount of vault shares minted to `_receiver`.
  */
  function deposit (
    uint256 _assets,
    address _receiver
  ) external returns (uint256);

  /**
    Mint exactly `_shares` vault shares to `_receiver` by depositing underlying
    tokens.

    @param _shares The amount of vault shares to mint.
    @param _receiver The address that will receive the minted shares.

    @return _ The amount of underlying assets deposited.
  */
  function mint (
    uint256 _shares,
    address _receiver
  ) external returns (uint256);

  /**
    Burn shares from `_owner` and send exactly `_assets` of underlying tokens to
    `_receiver`.

    @param _assets The amount of underlying assets to withdraw.
    @param _receiver The address that will receive the withdrawn assets.
    @param _owner The address that owns the shares being burned.

    @return _ The amount of vault shares burned from `_owner`.
  */
  function withdraw (
    uint256 _assets,
    address _receiver,
    address _owner
  ) external returns (uint256);

  /**
    Burn exactly `_shares` from `_owner` and send underlying tokens to
    `_receiver`.

    @param _shares The amount of vault shares to redeem.
    @param _receiver The address that will receive the underlying assets.
    @param _owner The address that owns the shares being burned.

    @return _ The amount of underlying assets sent to `_receiver`.
  */
  function redeem (
    uint256 _shares,
    address _receiver,
    address _owner
  ) external returns (uint256);
}

