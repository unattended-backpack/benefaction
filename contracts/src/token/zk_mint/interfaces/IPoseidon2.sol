// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity >=0.6.0;

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Poseidon2 Interface
  @author Soham <@zemse_>
  @custom:blame Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"
  @custom:preserve

  This is a Poseidon2 hash function optimized in Yul assembly. The
  implementation is originally by Zemse but it has been stylistically modifed by
  Tim Clancy. Blame Tim if anything is wrong with it.

  @custom:date February 24th, 2026.
*/
interface IPoseidon2 {

  /**
    Hash a single field element.

    @param _x The input field element.

    @return _ The Poseidon2 hash.
  */
  function hash (
    uint256 _x
  ) external pure returns (uint256);

  /**
    Hash two field elements.

    @param _x The first input field element.
    @param _y The second input field element.

    @return _ The Poseidon2 hash.
  */
  function hash (
    uint256 _x,
    uint256 _y
  ) external pure returns (uint256);

  /**
    Hash three field elements.

    @param _x The first input field element.
    @param _y The second input field element.
    @param _z The third input field element.

    @return _ The Poseidon2 hash.
  */
  function hash (
    uint256 _x,
    uint256 _y,
    uint256 _z
  ) external pure returns (uint256);
}

