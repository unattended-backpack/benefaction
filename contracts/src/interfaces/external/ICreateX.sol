// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity ^0.8.0;

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title CreateX Factory Interface
  @custom:blame Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"
  @custom:preserve

  This is a stylistically-modified version of CreateX, the phenomenal factory
  smart contract authored by `pcaversaccio`
  (https://web.archive.org/web/20230921103111/https://pcaversaccio.com/) and
  `Matt Solomon`
  (https://web.archive.org/web/20230921103335/https://mattsolomon.dev/). Do not
  blame or bother them, or upstream CreateX, regarding any issues you find with
  this contract. CreateX is an excellent option for safely creating smart
  contracts at predetermined addresses.

  @custom:date January 15th, 2026.
*/
interface ICreateX {

  /**
    An enum for representing the decoded message sender portion of the contract
    creation salt. This is used for checking for permissioned deploy protection.

    @param MsgSender The salt contains the message sender.
    @param ZeroAddress The salt contains the 0x0...0 zero address.
    @param Random The salt contains random bytes.
  */
  enum SenderBytes {
    MsgSender,
    ZeroAddress,
    Random
  }

  /**
    An enum for representing the decoded redeploy protection byte of the
    contract creation salt. This is used for checking cross-chain deployment
    protection. Protection must be specified explicitly by the caller, otherwise
    the transaction reverts. If enabled, the ID of the current chain is included
    in the final output address salt.

    @param True Redeploy protection is enabled.
    @param False Redeploy protection is disabled.
    @param Unspecified Protection settings have not been specified, so revert.
  */
  enum RedeployProtectionFlag {
    True,
    False,
    Unspecified
  }

  /**
    A struct encoding `payable` amounts in deploy-and-initialize calls.

    @param constructorAmount The amount of Ether sent to a payable constructor.
    @param initCallAmount The amount of Ether sent to a payable initialize call.
  */
  struct Values {
    uint256 constructorAmount;
    uint256 initCallAmount;
  }

  /// An error emitted when contract creation fails.
  error FailedContractCreation ();

  /**
    An error emitted when contract initialization fails.

    @param revertData The initialization call revert data.
  */
  error FailedContractinitialization (
    bytes revertData
  );

  /// An error emitted when an invalid salt is supplied.
  error InvalidSalt ();

  /// An error emitted when an invalid nonce is supplied for contract creation.
  error InvalidNonceValue ();

  /**
    An error emitted when transferring Ether has failed.

    @param revertData The Ether transfer call revert data.
  */
  error FailedEtherTransfer (
    bytes revertData
  );

  /**
    Compute the address where a contract will be stored if deployed via
    `deployer` using the `CREATE` opcode. For the specification of the Recursive
    Length Prefix (RLP) encoding scheme, please refer to p. 19 of the Ethereum
    Yellow Paper and the Ethereum Wiki. All contract accounts on Ethereum are
    initiated with `nonce = 1`. Thus, the first contract address created by
    another contract is calculated with a non-zero nonce.

    @param _deployer The 20-byte deployer address.
    @param _nonce The next 32-byte nonce of the deployer address.

    @return _ The 20-byte address where a contract will be stored.
  */
  function computeCreateAddress (
    address _deployer,
    uint256 _nonce
  ) external view returns (address);

  /**
    Compute the address where a contract will be stored if deployed via
    `deployer` using the `CREATE` opcode. For the specification of the Recursive
    Length Prefix (RLP) encoding scheme, please refer to p. 19 of the Ethereum
    Yellow Paper and the Ethereum Wiki. All contract accounts on Ethereum are
    initiated with `nonce = 1`. Thus, the first contract address created by
    another contract is calculated with a non-zero nonce.

    @param _nonce The next 32-byte nonce of the deployer address.

    @return _ The 20-byte address where a contract will be stored.
  */
  function computeCreateAddress (
    uint256 _nonce
  ) external view returns (address);

  /**
    Compute the address where a contract will be stored if deployed via
    `_deployer` using the `CREATE2` opcode. Any change in the `_initCodeHash` or
    `_salt` values will result in a new destination address. This implementation
    is based on OpenZeppelin.

    @param _salt The 32-byte value used to create the contract address.
    @param _initCodeHash The 32-byte bytecode digest of the contract creation
      bytecode.
    @param _deployer The 20-byte deployer address.

    @return _ The 20-byte address where a contract will be stored.
  */
  function computeCreate2Address (
    bytes32 _salt,
    bytes32 _initCodeHash,
    address _deployer
  ) external pure returns (address);

  /**
    Compute the address where a contract will be stored if deployed via this
    contract using the `CREATE2` opcode. Any change in the `_initCodeHash` or
    `_salt` values will result in a new destination address. This implementation
    is based on OpenZeppelin.

    @param _salt The 32-byte value used to create the contract address.
    @param _initCodeHash The 32-byte bytecode digest of the contract creation
      bytecode.

    @return _ The 20-byte address where a contract will be stored.
  */
  function computeCreate2Address (
    bytes32 _salt,
    bytes32 _initCodeHash
  ) external view returns (address);

  /**
    Compute the address where a contract will be stored if deployed via
    `_deployer` using the `CREATE3` pattern (i.e. without an initcode factor).
    Any change in the `_salt` value will result in a new destination address.
    This implementation is based on Solady.

    @param _salt The 32-byte value used to create the proxy contract address.
    @param _deployer The 20-byte deployer address.

    @return _ The 20-byte address where a contract will be stored.
  */
  function computeCreate3Address (
    bytes32 _salt,
    address _deployer
  ) external pure returns (address);

  /**
    Compute the address where a contract will be stored if deployed via this
    contract using the `CREATE3` pattern (i.e. without an initcode factor). Any
    change in the `_salt` value will result in a new destination address. This
    implementation is based on Solady.

    @param _salt The 32-byte value used to create the proxy contract address.

    @return _ The 20-byte address where a contract will be stored.
  */
  function computeCreate3Address (
    bytes32 _salt
  ) external view returns (address);

  /**
    Deploy a new contract via calling the `CREATE` opcode using the creation
    bytecode `_initCode` and `msg.value` as inputs. In order to save deployment
    costs, we do not sanity check the `_initCode` length. Note that if
    `msg.value` is non-zero, `_initCode` must have a `payable` constructor.

    @param _initCode The creation bytecode.

    @return _ The 20-byte address where the contract was deployed.
  */
  function deployCreate (
    bytes memory _initCode
  ) external payable returns (address);

  /**
    Deploy a new contract via calling the `CREATE2` opcode and using the salt
    value `_salt`, the creation bytecode `_initCode`, and `msg.value` as inputs.
    In order to save deployment costs, we do not sanity check the `_initCode`
    length. Note that if `msg.value` is non-zero, `initCode` must have a payable
    constructor.

    @param _salt The 32-byte value used to create the contract address.
    @param _initCode The creation bytecode.

    @return _ The 20-byte address where the contract was deployed.
  */
  function deployCreate2 (
    bytes32 _salt,
    bytes memory _initCode
  ) external payable returns (address);

  /**
    Deploy a new contract via the `CREATE3` pattern (i.e. without an initcode
    factor) and using the salt value `_salt`, the creation bytecode `_initCode`,
    and `msg.value` as inputs. In order to save deployment costs, we do not
    sanity check the `_initCode` length. Note that if `msg.value` is non-zero,
    `_initCode` must have a payable constructor. This implementation is based on
    Solmate. We strongly recommend implementing a permissioned deploy protection
    by setting the first 20 bytes equal to `msg.sender` in the `salt` to prevent
    maliciously-frontrun proxy deployments on other chains.

    @param _salt The 32-byte value used to create the proxy contract address.
    @param _initCode The creation bytecode.

    @return _ The 20-byte address where the contract was deployed.
  */
  function deployCreate3 (
    bytes32 _salt,
    bytes memory _initCode
  ) external payable returns (address);
}
