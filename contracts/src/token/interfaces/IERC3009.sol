// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title An ERC-3009 Interface
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  This is a simple extension of ERC-20 to support ERC-3009 signature-based
  transfers.

  @custom:date January 4th, 2026.
*/
interface IERC3009 {

  /// Thrown when an authorization is used before its valid time window.
  error AuthorizationNotYetValid ();

  /// Thrown when an authorization is used after its valid time window.
  error AuthorizationExpired ();

  /// Thrown when an authorization nonce has already been used or canceled.
  error AuthorizationAlreadyUsed ();

  /// Thrown when the caller of `receiveWithAuthorization` is not the payee.
  error CallerMustBePayee ();

  /**
    An event emitted when an ERC-3009 authorization is used.

    @param authorizer The address of the authorizer.
    @param nonce The nonce of the authorization.
  */
  event AuthorizationUsed (
    address indexed authorizer,
    bytes32 indexed nonce
  );

  /**
    An event emitted when an ERC-3009 authorization is canceled.

    @param authorizer The address of the authorizer.
    @param nonce The nonce of the canceled authorization.
  */
  event AuthorizationCanceled (
    address indexed authorizer,
    bytes32 indexed nonce
  );

  /**
    Return whether this contract supports a given interface.

    @param _interfaceId The interface identifier to check.

    @return _ Whether the interface is supported.
  */
  function supportsInterface (
    bytes4 _interfaceId
  ) external view returns (bool);

  /**
    A double mapping from authorizer address to authorization nonce to whether
    or not the authorization nonce may still be used in a transfer.

    @param _authorizer The address of an authorizer.
    @param _nonce The nonce for a particular authorization.

    @return _ Whether or not the provided `_nonce` has been used for an
      authorized transfer or authorized cancel. If this is false, it means that
      `_nonce` can still be used for an authorized transfer.
  */
  function authorizationState (
    address _authorizer,
    bytes32 _nonce
  ) external view returns (bool);

  /**
    Execute a transfer with a signed authorization using a signature provided as
    combined bytes.

    @param _from The transfer authorizer's (payer's) address.
    @param _to The recipient's address.
    @param _amount The amount to be transferred.
    @param _validAfter The minimum timestamp after which the authorized transfer
      is valid.
    @param _validBefore The maximum timestamp before which the authorized
      transfer is valid.
    @param _nonce A unique nonce for this authorization.
    @param _signature The authorization signature.
  */
  function transferWithAuthorization (
    address _from,
    address _to,
    uint256 _amount,
    uint256 _validAfter,
    uint256 _validBefore,
    bytes32 _nonce,
    bytes memory _signature
  ) external;

  /**
    Execute a transfer with a signed authorization using a signature split into
    its three component parts.

    @param _from The transfer authorizer's (payer's) address.
    @param _to The recipient's address.
    @param _amount The amount to be transferred.
    @param _validAfter The minimum timestamp after which the authorized transfer
      is valid.
    @param _validBefore The maximum timestamp before which the authorized
      transfer is valid.
    @param _nonce A unique nonce for this authorization.
    @param _v The "v" component of the authorizer's signature.
    @param _r The "r" component of the authorizer's signature.
    @param _s The "s" component of the authorizer's signature.
  */
  function transferWithAuthorization (
    address _from,
    address _to,
    uint256 _amount,
    uint256 _validAfter,
    uint256 _validBefore,
    bytes32 _nonce,
    uint8 _v,
    bytes32 _r,
    bytes32 _s
  ) external;

  /**
    Execute a transfer with a signed authorization using a signature provided as
    combined bytes. Only the `_to` recipient may be `msg.sender`.

    @param _from The transfer authorizer's (payer's) address.
    @param _to The recipient's address.
    @param _amount The amount to be transferred.
    @param _validAfter The minimum timestamp after which the authorized transfer
      is valid.
    @param _validBefore The maximum timestamp before which the authorized
      transfer is valid.
    @param _nonce A unique nonce for this authorization.
    @param _signature The authorization signature.
  */
  function receiveWithAuthorization (
    address _from,
    address _to,
    uint256 _amount,
    uint256 _validAfter,
    uint256 _validBefore,
    bytes32 _nonce,
    bytes memory _signature
  ) external;

  /**
    Execute a transfer with a signed authorization using a signature split into
    its three component parts. Only the `_to` recipient may be `msg.sender`.

    @param _from The transfer authorizer's (payer's) address.
    @param _to The recipient's address.
    @param _amount The amount to be transferred.
    @param _validAfter The minimum timestamp after which the authorized transfer
      is valid.
    @param _validBefore The maximum timestamp before which the authorized
      transfer is valid.
    @param _nonce A unique nonce for this authorization.
    @param _v The "v" component of the authorizer's signature.
    @param _r The "r" component of the authorizer's signature.
    @param _s The "s" component of the authorizer's signature.
  */
  function receiveWithAuthorization (
    address _from,
    address _to,
    uint256 _amount,
    uint256 _validAfter,
    uint256 _validBefore,
    bytes32 _nonce,
    uint8 _v,
    bytes32 _r,
    bytes32 _s
  ) external;

  /**
    Attempt to cancel a signed authorization using a signature provided as
    combined bytes.

    @param _authorizer The transfer authorizer's (payer's) address.
    @param _nonce A unique nonce for this authorization.
    @param _signature The authorization signature.
  */
  function cancelAuthorization (
    address _authorizer,
    bytes32 _nonce,
    bytes memory _signature
  ) external;

  /**
    Attempt to cancel a signed authorization using a signature split into its
    three component parts.

    @param _authorizer The transfer authorizer's (payer's) address.
    @param _nonce A unique nonce for this authorization.
    @param _v The "v" component of the authorizer's signature.
    @param _r The "r" component of the authorizer's signature.
    @param _s The "s" component of the authorizer's signature.
  */
  function cancelAuthorization (
    address _authorizer,
    bytes32 _nonce,
    uint8 _v,
    bytes32 _r,
    bytes32 _s
  ) external;
}

