// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { ERC3009 } from "./ERC3009.sol";
import { IBurnableERC3009 } from "./interfaces/IBurnableERC3009.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title An extension to our ERC-3009 implementation supporting burns.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  This contract extends ERC-3009 to add burn functionality abd support for
  signature-based authorization. It shares the nonce space with ERC-3009's
  transfer authorizations to prevent replay attacks across authorization types.

  @custom:date February 3rd, 2026.
*/
abstract contract BurnableERC3009 is
  IBurnableERC3009,
  ERC3009 {

  /**
    This is the EIP-712 typehash for burns with authorization.

    keccak256("BurnWithAuthorization(address from,uint256 value,uint256
    validAfter,uint256 validBefore,bytes32 nonce)")
  */
  bytes32 private constant BURN_WITH_AUTHORIZATION_TYPEHASH =
    0x2808d214735158921f7f8a6ca28e887d7f781959759f5c1cd6645228bdfe6386;

  /// The ERC-165 interface ID for IBurnable3009.
  bytes4 private constant BURNABLE3009_INTERFACE_ID = 0xe279933e;

  /**
    Return whether this contract supports a given interface.

    @param _interfaceId The interface identifier to check.

    @return _ Whether the interface is supported.
  */
  function supportsInterface (
    bytes4 _interfaceId
  ) public view virtual override(IBurnableERC3009, ERC3009) returns (bool) {
    return _interfaceId == BURNABLE3009_INTERFACE_ID
    || ERC3009.supportsInterface(_interfaceId);
  }

  /**
    Burn `_amount` of tokens from the caller's balance.

    @param _amount The amount of tokens to burn.
  */
  function burn (
    uint256 _amount
  ) external {
    _burn(msg.sender, _amount);
  }

  /**
    Burn `_amount` of tokens from `_from`'s balance, deducting from the caller's
    allowance.

    @param _from The address to burn tokens from.
    @param _amount The amount of tokens to burn.
  */
  function burnFrom (
    address _from,
    uint256 _amount
  ) external {
    _spendAllowance(_from, msg.sender, _amount);
    _burn(_from, _amount);
  }

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
  ) public {

    // Validate the authorization timing and nonce.
    if (block.timestamp < _validAfter) {
      revert AuthorizationNotYetValid();
    }

    if (block.timestamp > _validBefore) {
      revert AuthorizationExpired();
    }

    if (authorizationState[_from][_nonce]) {
      revert AuthorizationAlreadyUsed();
    }

    // Mark the authorization as used.
    authorizationState[_from][_nonce] = true;
    emit AuthorizationUsed(_from, _nonce);

    // Validate the signature and burn the tokens.
    _requireValidSignature(
      _from,
      keccak256(
        abi.encode(
          BURN_WITH_AUTHORIZATION_TYPEHASH, _from, _amount, _validAfter,
          _validBefore, _nonce
        )
      ), _signature
    );
    _burn(_from, _amount);
  }

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
  ) external {
    burnWithAuthorization(
      _from, _amount, _validAfter, _validBefore, _nonce,
      abi.encodePacked(_r, _s, _v)
    );
  }
}

