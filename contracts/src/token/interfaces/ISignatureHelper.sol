// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title An interface for the simple signature verification helper.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  This is a simple signature helper which exposes a function to easily use the
  SignatureCheckerLib.

  @custom:date January 30th, 2026.
*/
interface ISignatureHelper {

  /// Thrown when a signature fails validation.
  error InvalidSignature ();
}
