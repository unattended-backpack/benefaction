// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Proof Verification Interface
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  This is the interface for proof verification.

  @custom:date February 25th, 2026.
*/
interface IVerifier {

  /**
    Verify a proof against the given public inputs.

    @param _proof The serialized proof bytes.
    @param _publicInputs The public input values.

    @return _ Whether the proof is valid.
  */
  function verify (
    bytes calldata _proof,
    bytes32[] calldata _publicInputs
  ) external view returns (bool);
}

