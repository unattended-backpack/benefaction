// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title An ERC-2612 Interface
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  This is an ERC-2612 implementation which extends the functionality of Solady
  to support smart contract signers for `permit` operations.

  @custom:date January 29th, 2026.
*/
interface IERC2612 {

  /**
    Returns the domain separator used in the encoding of the signature for
    `permit`, as defined by EIP-712.

    @return _ The EIP-712 domain separator.
  */
  function DOMAIN_SEPARATOR () external view returns (bytes32);

  /**
    Returns the current nonce for `_owner`. This value must be included whenever
    a signature is generated for `permit`.

    @param _owner The address to query the nonce for.

    @return _ The current nonce for `_owner`.
  */
  function nonces (
    address _owner
  ) external view returns (uint256);

  /**
    Use a valid signature by `_owner` to approve `_spender` to spend `_amount`
    tokens by `_deadline`.

    @param _owner The transfer authorizer's (payer's) address.
    @param _spender The approved spender.
    @param _amount The amount to be transferred.
    @param _deadline The maximum timestamp before which the authorized approval
      is valid.
    @param _signature The approval authorization signature.
  */
  function permit (
    address _owner,
    address _spender,
    uint256 _amount,
    uint256 _deadline,
    bytes memory _signature
  ) external;

  /**
    Use a valid signature by `_owner` to approve `_spender` to spend `_amount`
    tokens by `_deadline`. This function accepts an ECDSA signature split into
    its three component parts.

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
  ) external;
}

