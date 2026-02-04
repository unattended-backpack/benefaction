// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title An interface for a burnable ERC-3009 extension.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  This is an interface for burning tokens with support for ERC-3009 style
  signature-based authorization. It shares the nonce space with ERC-3009 to
  prevent replay attacks across authorization types.

  @custom:date February 3rd, 2026.
*/
interface IBurnableERC3009 {

  /**
    Return whether this contract supports a given interface.

    @param _interfaceId The interface identifier to check.

    @return _ Whether the interface is supported.
  */
  function supportsInterface (
    bytes4 _interfaceId
  ) external view returns (bool);

  /**
    Burn `_amount` of tokens from the caller's balance.

    @param _amount The amount of tokens to burn.
  */
  function burn (
    uint256 _amount
  ) external;

  /**
    Burn `_amount` of tokens from `_from`'s balance, deducting from the caller's
    allowance.

    @param _from The address to burn tokens from.
    @param _amount The amount of tokens to burn.
  */
  function burnFrom (
    address _from,
    uint256 _amount
  ) external;

  /**
    Burn tokens with a signed authorization using a signature provided as
    combined bytes.

    @param _from The address whose tokens will be burned.
    @param _amount The amount of tokens to burn.
    @param _validAfter The minimum timestamp after which the authorization is
      valid.
    @param _validBefore The maximum timestamp before which the authorization is
      valid.
    @param _nonce A unique nonce for this authorization.
    @param _signature The authorization signature.
  */
  function burnWithAuthorization (
    address _from,
    uint256 _amount,
    uint256 _validAfter,
    uint256 _validBefore,
    bytes32 _nonce,
    bytes memory _signature
  ) external;

  /**
    Burn tokens with a signed authorization using a signature split into its
    three component parts.

    @param _from The address whose tokens will be burned.
    @param _amount The amount of tokens to burn.
    @param _validAfter The minimum timestamp after which the authorization is
      valid.
    @param _validBefore The maximum timestamp before which the authorization is
      valid.
    @param _nonce A unique nonce for this authorization.
    @param _v The "v" component of the authorizer's signature.
    @param _r The "r" component of the authorizer's signature.
    @param _s The "s" component of the authorizer's signature.
  */
  function burnWithAuthorization (
    address _from,
    uint256 _amount,
    uint256 _validAfter,
    uint256 _validBefore,
    bytes32 _nonce,
    uint8 _v,
    bytes32 _r,
    bytes32 _s
  ) external;
}

