// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { IERC4626 } from "./interfaces/IERC4626.sol";
import { Ownable } from "solady/auth/Ownable.sol";
import { ERC4626 } from "solady/tokens/ERC4626.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title An ERC-4626 implementation for burn-only redemptions.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  This is an ERC-4626 "implementation" which conditionally disables parts of the
  Solady implementation. The effect is to create an ERC-4626 vault which, after
  an initial token mint by a privileged owner, can only ever offer redemptions
  or withdrawals of the underlying ERC-4626 vault asset. The effect of this is
  to create a one-time supply of deflationary "share" tokens which are burned in
  exchange for the underlying asset. This is NOT SAFE to use for tokens whose
  total supply may increase after minting, unless you know quite well what you
  are doing.

  @custom:date January 30th, 2026.
*/
abstract contract BurnOnlyERC4626 is
  IERC4626,
  ERC4626,
  Ownable {

  /**
    An error emitted when attempting to deposit or mint ERC-4626 vault shares
    after this has been disabled following the one-time owner initialization.
  */
  error Disabled ();

  /// The ERC-165 interface ID for ERC-165 itself.
  bytes4 private constant ERC165_INTERFACE_ID = 0x01ffc9a7;

  /// The ERC-165 interface ID for ERC-20.
  bytes4 private constant ERC20_INTERFACE_ID = 0x36372b07;

  /// The ERC-165 interface ID for ERC-4626.
  bytes4 private constant ERC4626_INTERFACE_ID = 0x87dfe5a0;

  /// Whether or not the token has already been initialized.
  bool public initialized;

  /**
    Construct a new instance of the token by specifying the `_owner`, which is
    the privileged caller able to call the one-time `initialize` function and
    rescue any assets accidentally sent to this contract.

    @param _owner The owner of the token.
  */
  constructor (
    address _owner
  ) {
    _initializeOwner(_owner);
  }

  /**
    Return whether this contract supports a given interface.

    @param _interfaceId The interface identifier to check.

    @return _ Whether the interface is supported.
  */
  function supportsInterface (
    bytes4 _interfaceId
  ) public view virtual returns (bool) {
    return _interfaceId == ERC165_INTERFACE_ID
    || _interfaceId == ERC20_INTERFACE_ID
    || _interfaceId == ERC4626_INTERFACE_ID;
  }

  /**
    Returns the number of decimal places of the token.

    @return _ The number of decimal places of the token.
  */
  function decimals () public view override virtual returns (uint8) {
    return ERC4626.decimals();
  }

  /**
    Return the address of the underlying ERC-4626 redemption asset.

    @return _ The address of the redemption asset.
  */
  function asset () public view override(IERC4626, ERC4626) virtual returns (
    address
  );

  /**
    Return the number of shares to be initially minted.

    @return _ The initial token supply.
  */
  function _initialMint () internal view virtual returns (uint256);

  /**
    Allow the owner to initialize the token. This is a one-time action which
    provisions the starting ERC-4626 `asset` and mints the entire supply of
    shares to `_recipient`. This function can only be called once, after which
    future ERC-4626 mints or deposits are disabled. If the underlying ERC-4626
    `asset` is malicious, this function is unsafe.

    @param _recipient The recipient of the total token supply.
  */
  function initialize (
    address _recipient
  ) external onlyOwner {
    mint(_initialMint(), _recipient);

    /*
      We make use of the post-deposit hook as an extra safety guarantee, so this
      state change must come after our external `mint` call.
    */
    initialized = true;
  }

  /**
    Returns the maximum amount of the underlying asset that can be deposited
    into the ERC-4626 vault via a deposit call. Deposits are always disabled
    because all shares are minted via the one-time `initialize` function.

    @return _ Always zero because deposits are disabled.
  */
  function maxDeposit (
    address
  ) public pure override(IERC4626, ERC4626) returns (uint256) {
    return 0;
  }

  /**
    Returns the maximum number of the ERC-4626 vault shares that can be minted
    via a mint call.

    @return _ The maximum number of shares that can be minted.
  */
  function maxMint (
    address
  ) public view override(IERC4626, ERC4626) returns (uint256) {
    if (initialized) {
      return 0;
    } else {
      return _initialMint();
    }
  }

  /**
    Mints ERC-4626 vault shares by depositing an exact amount of the asset
    token. A burn-only ERC-4626 vault never does this, so this always reverts.

    @return _ This would be the number of minted shares if we didn't always
      revert.
  */
  function deposit (
    uint256,
    address
  ) public pure override(IERC4626, ERC4626) returns (uint256) {
    revert Disabled();
  }

  /**
    Allow a caller to simulate the effects of calling `deposit` at the current
    block. Given that `deposit` is always disabled, this always returns zero.

    @return _ Zero, because deposits are disabled.
  */
  function previewDeposit (
    uint256
  ) public pure override(IERC4626, ERC4626) returns (uint256) {
    return 0;
  }

  /**
    Mints exactly `_shares` ERC-4626 vault shares to `_recipient` by depositing
    the required number of the underlying `asset` token. This will revert if
    used after the one-time owner initialization. Only the owner may call this
    function, so as to prevent front-running the initialization. Do note that
    there is not any good reason for the owner to ever do this.

    @param _shares The number of tokens to mint.
    @param _recipient The recipient to receive the tokens.

    @return _ The amount of the underlying `asset` used in minting.
  */
  function mint (
    uint256 _shares,
    address _recipient
  ) public override(IERC4626, ERC4626) onlyOwner returns (uint256) {
    if (initialized) {
      revert Disabled();
    }
    return ERC4626.mint(_shares, _recipient);
  }

  /**
    Allow a caller to simulate the effects of calling `mint` at the current
    block. This is used to determine the required amount of the underlying
    `asset` token that must be deposited into the ERC-4626 vault. After the
    one-time owner initialization, this will always return zero because minting
    will have been disabled.

    @param _shares The number of tokens to mint.

    @return _ The amount of underlying `asset` token that must be deposited.
  */
  function previewMint (
    uint256 _shares
  ) public view override(IERC4626, ERC4626) returns (uint256) {
    if (initialized) {
      return 0;
    }
    return ERC4626.previewMint(_shares);
  }

  /**
    This hook is called after any deposit or mint. For extra precaution, we
    always force a revert after the one-time owner initialization.
  */
  function _afterDeposit (
    uint256,
    uint256
  ) internal view override {
    if (initialized) {
      revert Disabled();
    }
  }

  /**
    Return the total amount of the underlying asset managed by the vault.

    @return _ The total amount of underlying assets.
  */
  function totalAssets () public override(IERC4626, ERC4626) view returns (
    uint256
  ) {
    return ERC4626.totalAssets();
  }

  /**
    Return the amount of shares that the vault would exchange for the amount of
    assets provided, in an ideal scenario where all conditions are met.

    @param _assets The amount of underlying assets to convert.

    @return _ The amount of vault shares.
  */
  function convertToShares (
    uint256 _assets
  ) public view override(IERC4626, ERC4626) returns (uint256) {
    return ERC4626.convertToShares(_assets);
  }

  /**
    Return the amount of assets that the vault would exchange for the amount of
    shares provided, in an ideal scenario where all conditions are met.

    @param _shares The amount of vault shares to convert.

    @return _ The amount of underlying assets.
  */
  function convertToAssets (
    uint256 _shares
  ) public view override(IERC4626, ERC4626) returns (uint256) {
    return ERC4626.convertToAssets(_shares);
  }

  /**
    Return the maximum amount of the underlying asset that can be withdrawn from
    the `_owner` balance in the vault via a withdraw call.

    @param _owner The address that owns the shares.

    @return _ The maximum amount of underlying assets that can be withdrawn.
  */
  function maxWithdraw (
    address _owner
  ) public view override(IERC4626, ERC4626) returns (uint256) {
    return ERC4626.maxWithdraw(_owner);
  }

  /**
    Return the maximum amount of vault shares that can be redeemed from the
    `_owner` balance in the vault via a redeem call.

    @param _owner The address that owns the shares.

    @return _ The maximum amount of vault shares that can be redeemed.
  */
  function maxRedeem (
    address _owner
  ) public view override(IERC4626, ERC4626) returns (uint256) {
    return ERC4626.maxRedeem(_owner);
  }

  /**
    Simulate the effects of a redemption at the current block, given current
    on-chain conditions.

    @param _shares The amount of vault shares to redeem.

    @return _ The amount of underlying assets that would be received.
  */
  function previewRedeem (
    uint256 _shares
  ) public view override(IERC4626, ERC4626) returns (uint256) {
    return ERC4626.previewRedeem(_shares);
  }

  /**
    Simulate the effects of a withdrawal at the current block, given current
    on-chain conditions.

    @param _amount The amount of underlying assets to withdraw.

    @return _ The amount of vault shares that would be burned.
  */
  function previewWithdraw (
    uint256 _amount
  ) public view override(IERC4626, ERC4626) returns (uint256) {
    return ERC4626.previewWithdraw(_amount);
  }

  /**
    Burn shares from `_owner` and send exactly `_assets` of underlying tokens to
    `_receiver`.

    @param _amount The amount of underlying assets to withdraw.
    @param _receiver The address that will receive the withdrawn assets.
    @param _owner The address that owns the shares being burned.

    @return _ The amount of vault shares burned from `_owner`.
  */
  function withdraw (
    uint256 _amount,
    address _receiver,
    address _owner
  ) public override(IERC4626, ERC4626) returns (uint256) {
    return ERC4626.withdraw(_amount, _receiver, _owner);
  }

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
  ) public override(IERC4626, ERC4626) returns (uint256) {
    return ERC4626.redeem(_shares, _receiver, _owner);
  }
}

