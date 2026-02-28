// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity >=0.8.21;

using { add as + } for Fr global;
using { sub as - } for Fr global;
using { mul as * } for Fr global;
using { exp as ^ } for Fr global;
using { notEqual as != } for Fr global;
using { equal as == } for Fr global;

type Fr is uint256;

/**
  An enumeration of wire indices used to index into the array of polynomial
  evaluations in UltraHonk. These wires represent the selectors, permutation
  polynomials, identity polynomials, lookup tables, Lagrange basis polynomials,
  witness wire evaluations, and their shifted counterparts.

  @param Q_M The multiplication selector polynomial evaluation.
  @param Q_C The constant selector polynomial evaluation.
  @param Q_L The left wire selector polynomial evaluation.
  @param Q_R The right wire selector polynomial evaluation.
  @param Q_O The output wire selector polynomial evaluation.
  @param Q_4 The fourth wire selector polynomial evaluation.
  @param Q_LOOKUP The lookup table selector polynomial evaluation.
  @param Q_ARITH The arithmetic gate selector polynomial evaluation.
  @param Q_RANGE The delta range constraint selector polynomial evaluation.
  @param Q_ELLIPTIC The elliptic curve gate selector polynomial evaluation.
  @param Q_MEMORY The RAM/ROM memory gate selector polynomial evaluation.
  @param Q_NNF The non-native field arithmetic selector polynomial evaluation.
  @param Q_POSEIDON2_EXTERNAL The Poseidon2 external round selector polynomial
    evaluation.
  @param Q_POSEIDON2_INTERNAL The Poseidon2 internal round selector polynomial
    evaluation.
  @param SIGMA_1 The first copy constraint permutation polynomial evaluation.
  @param SIGMA_2 The second copy constraint permutation polynomial evaluation.
  @param SIGMA_3 The third copy constraint permutation polynomial evaluation.
  @param SIGMA_4 The fourth copy constraint permutation polynomial evaluation.
  @param ID_1 The first identity permutation polynomial evaluation.
  @param ID_2 The second identity permutation polynomial evaluation.
  @param ID_3 The third identity permutation polynomial evaluation.
  @param ID_4 The fourth identity permutation polynomial evaluation.
  @param TABLE_1 The first precomputed lookup table column evaluation.
  @param TABLE_2 The second precomputed lookup table column evaluation.
  @param TABLE_3 The third precomputed lookup table column evaluation.
  @param TABLE_4 The fourth precomputed lookup table column evaluation.
  @param LAGRANGE_FIRST The Lagrange basis polynomial evaluation at the first
    element.
  @param LAGRANGE_LAST The Lagrange basis polynomial evaluation at the last
    element.
  @param W_L The left witness wire polynomial evaluation.
  @param W_R The right witness wire polynomial evaluation.
  @param W_O The output witness wire polynomial evaluation.
  @param W_4 The fourth witness wire polynomial evaluation.
  @param Z_PERM The grand product permutation polynomial evaluation.
  @param LOOKUP_INVERSES The inverse values for log-derivative lookup
    evaluations.
  @param LOOKUP_READ_COUNTS The read counts for log-derivative lookup
    evaluations.
  @param LOOKUP_READ_TAGS The read tags for log-derivative lookup evaluations.
  @param W_L_SHIFT The left witness wire polynomial shifted evaluation.
  @param W_R_SHIFT The right witness wire polynomial shifted evaluation.
  @param W_O_SHIFT The output witness wire polynomial shifted evaluation.
  @param W_4_SHIFT The fourth witness wire polynomial shifted evaluation.
  @param Z_PERM_SHIFT The grand product permutation polynomial shifted
    evaluation.
*/
enum WIRE {
  Q_M,
  Q_C,
  Q_L,
  Q_R,
  Q_O,
  Q_4,
  Q_LOOKUP,
  Q_ARITH,
  Q_RANGE,
  Q_ELLIPTIC,
  Q_MEMORY,
  Q_NNF,
  Q_POSEIDON2_EXTERNAL,
  Q_POSEIDON2_INTERNAL,
  SIGMA_1,
  SIGMA_2,
  SIGMA_3,
  SIGMA_4,
  ID_1,
  ID_2,
  ID_3,
  ID_4,
  TABLE_1,
  TABLE_2,
  TABLE_3,
  TABLE_4,
  LAGRANGE_FIRST,
  LAGRANGE_LAST,
  W_L,
  W_R,
  W_O,
  W_4,
  Z_PERM,
  LOOKUP_INVERSES,
  LOOKUP_READ_COUNTS,
  LOOKUP_READ_TAGS,
  W_L_SHIFT,
  W_R_SHIFT,
  W_O_SHIFT,
  W_4_SHIFT,
  Z_PERM_SHIFT
}

// The total number of subrelations accumulated across all gate types.
uint256 constant NUMBER_OF_SUBRELATIONS = 28;

/*
  Powers of alpha used to batch subrelations (alpha, alpha^2, ...,
  alpha^(NUM_SUBRELATIONS-1))
*/
uint256 constant NUMBER_OF_ALPHAS = NUMBER_OF_SUBRELATIONS - 1;

// The maximum supported circuit depth as `log2(circuit_size)`.
uint256 constant CONST_PROOF_SIZE_LOG_N = 28;

/**
  The Fiat-Shamir transcript for the ZK-flavored UltraHonk protocol. Each
  field stores a challenge or set of challenges derived by hashing
  commitments and evaluations at each protocol phase.
  forge-lint: disable-next-item(pascal-case-struct)

  @param relationParameters The relation parameters derived during the Oink
    phase of the protocol.
  @param alphas Powers of alpha used to batch subrelations:
    `[alpha, alpha^2, ..., alpha^(NUM_SUBRELATIONS-1)]`.
  @param gateChallenges The gate challenges used to compute the perturbator
    polynomial.
  @param libraChallenge The challenge for the Libra masking protocol in the
    sumcheck phase.
  @param sumCheckUChallenges The challenges for each round of the sumcheck
    protocol.
  @param rho The batching challenge for the Shplemini opening scheme.
  @param geminiR The Gemini folding challenge.
  @param shplonkNu The Shplonk batching challenge.
  @param shplonkZ The Shplonk evaluation challenge.
  @param publicInputsDelta The public input contribution to the permutation
    grand product derived from beta and gamma.
*/
struct ZKTranscript {
  Honk.RelationParameters relationParameters;
  Fr[NUMBER_OF_ALPHAS] alphas;
  Fr[CONST_PROOF_SIZE_LOG_N] gateChallenges;
  Fr libraChallenge;
  Fr[CONST_PROOF_SIZE_LOG_N] sumCheckUChallenges;
  Fr rho;
  Fr geminiR;
  Fr shplonkNu;
  Fr shplonkZ;
  Fr publicInputsDelta;
}

// The circuit size; the number of gates in the arithmetized circuit.
uint256 constant N = 524288;

// The base-2 logarithm of the circuit size.
uint256 constant LOG_N = 19;

// The number of public inputs to the circuit.
uint256 constant NUMBER_OF_PUBLIC_INPUTS = 83;

// The Keccak256 hash of the serialized verification key.
uint256 constant VK_HASH =
  0x0bb276e9a9ffa9702ce4cb6b89823d859662f9f6c9d39d69313d9015898798fc;

// The size of the multiplicative subgroup used for Libra masking.
uint256 constant SUBGROUP_SIZE = 256;

uint256 constant MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617;

// An alias for `MODULUS`.
uint256 constant P = MODULUS;

// The generator of the multiplicative subgroup used for Libra masking.
Fr constant SUBGROUP_GENERATOR =
  Fr.wrap(0x07b0c561a6148404f086204a9f36ffb0617942546750f230c893619174a57a76);

// The multiplicative inverse of `SUBGROUP_GENERATOR`.
Fr constant SUBGROUP_GENERATOR_INVERSE =
  Fr.wrap(0x204bd3277422fad364751ad938e2b5e6a54cf8c68712848a692c553d0329f5d6);

// The field element representing `-1` modulo `MODULUS`.
Fr constant MINUS_ONE = Fr.wrap(MODULUS - 1);

// The multiplicative identity in the BN254 scalar field.
Fr constant ONE = Fr.wrap(1);

// The additive identity in the BN254 scalar field.
Fr constant ZERO = Fr.wrap(0);

// The degree of the batched relation polynomial in non-ZK mode.
uint256 constant BATCHED_RELATION_PARTIAL_LENGTH = 8;

// The degree of the batched relation polynomial in ZK mode.
uint256 constant ZK_BATCHED_RELATION_PARTIAL_LENGTH = 9;

// The total number of polynomial entities evaluated during sumcheck.
uint256 constant NUMBER_OF_ENTITIES = 41;

// The number of entities added for ZK (gemini_masking_poly)
uint256 constant NUM_MASKING_POLYNOMIALS = 1;

// The total number of polynomial entities in ZK mode.
uint256 constant NUMBER_OF_ENTITIES_ZK =
  NUMBER_OF_ENTITIES + NUM_MASKING_POLYNOMIALS;

// The number of unshifted polynomial commitments in non-ZK mode.
uint256 constant NUMBER_UNSHIFTED = 36;

// The number of unshifted polynomial commitments in ZK mode.
uint256 constant NUMBER_UNSHIFTED_ZK =
  NUMBER_UNSHIFTED + NUM_MASKING_POLYNOMIALS;

// The number of polynomial commitments requiring shifted evaluations.
uint256 constant NUMBER_TO_BE_SHIFTED = 5;

// The number of field elements encoding the recursive pairing points.
uint256 constant PAIRING_POINTS_SIZE = 16;

// The byte size of a single BN254 scalar field element.
uint256 constant FIELD_ELEMENT_SIZE = 0x20;

// The byte size of a single BN254 G1 group element.
uint256 constant GROUP_ELEMENT_SIZE = 0x40;

uint256 constant Q =
  21888242871839275222246405745257275088696311157297823662689037894645226208583;

/**
  Add two BN254 scalar field elements.

  @param _a The first operand.
  @param _b The second operand.

  @return _ The sum `(_a + _b) mod MODULUS`.
*/
function add (
  Fr _a,
  Fr _b
) pure returns (Fr) {
  unchecked {
    return Fr.wrap(addmod(Fr.unwrap(_a), Fr.unwrap(_b), MODULUS));
  }
}

/**
  Multiply two BN254 scalar field elements.

  @param _a The first operand.
  @param _b The second operand.

  @return _ The product `(_a * _b) mod MODULUS`.
*/
function mul (
  Fr _a,
  Fr _b
) pure returns (Fr) {
  unchecked {
    return Fr.wrap(mulmod(Fr.unwrap(_a), Fr.unwrap(_b), MODULUS));
  }
}

/**
  Subtract one BN254 scalar field element from another.

  @param _a The minuend.
  @param _b The subtrahend.

  @return _ The difference `(_a - _b) mod MODULUS`.
*/
function sub (
  Fr _a,
  Fr _b
) pure returns (Fr) {
  unchecked {
    return Fr.wrap(addmod(Fr.unwrap(_a), MODULUS - Fr.unwrap(_b), MODULUS));
  }
}

/**
  Raise a BN254 scalar field element to a power by repeated squaring.

  @param _base The base field element.
  @param _exponent The exponent.

  @return _ The result `_base ^ _exponent` in the field.
*/
function exp (
  Fr _base,
  Fr _exponent
) pure returns (Fr) {
  if (Fr.unwrap(_exponent) == 0) {
    return Fr.wrap(1);
  }

  // Implement exponent with a loop as we will overflow otherwise
  for (uint256 i = 1; i < Fr.unwrap(_exponent); i += i) {
    _base = _base * _base;
  }
  return _base;
}

/**
  Check whether two BN254 scalar field elements are not equal.

  @param _a The first field element.
  @param _b The second field element.

  @return _ Whether `_a` and `_b` differ.
*/
function notEqual (
  Fr _a,
  Fr _b
) pure returns (bool) {
  unchecked {
    return Fr.unwrap(_a) != Fr.unwrap(_b);
  }
}

/**
  Check whether two BN254 scalar field elements are equal.

  @param _a The first field element.
  @param _b The second field element.

  @return _ Whether `_a` and `_b` are identical.
*/
function equal (
  Fr _a,
  Fr _b
) pure returns (bool) {
  unchecked {
    return Fr.unwrap(_a) == Fr.unwrap(_b);
  }
}

/**
  Convert a `bytes32` value to its lowercase hexadecimal string
  representation, prefixed with `0x`.

  @param _value The raw bytes to convert.

  @return _ The hex string representation of `_value`.
*/
function bytes32ToString (
  bytes32 _value
) pure returns (string memory) {
  bytes memory _alphabet = "0123456789abcdef";
  bytes memory _str = new bytes(66);
  _str[0] = "0";
  _str[1] = "x";
  for (uint256 i = 0; i < 32; i++) {
    _str[2 + i * 2] = _alphabet[uint8(_value[i] >> 4)];
    _str[3 + i * 2] = _alphabet[uint8(_value[i] & 0x0f)];
  }
  return string(_str);
}

/**
  Decode a 32-byte section of a proof into a BN254 scalar field element.

  @param _proofSection The calldata slice to decode.

  @return _ The decoded field element.
*/
function bytesToFr (
  bytes calldata _proofSection
) pure returns (Fr) {
  return FrLib.fromBytes32(bytes32(_proofSection));
}

/**
  Decode a 64-byte section of a proof into a BN254 G1 point, reducing
  coordinates modulo the base field order.

  @param _proofSection The calldata slice containing the `(x, y)` coordinates.

  @return _ The decoded G1 point.
*/
function bytesToG1Point (
  bytes calldata _proofSection
) pure returns (Honk.G1Point memory) {
  return Honk.G1Point({
    x: uint256(bytes32(_proofSection[0x00:0x20])) % Q,
    y: uint256(bytes32(_proofSection[0x20:0x40])) % Q
  });
}

/**
  Negate a G1 point in place by reflecting its y-coordinate.

  @param _point The G1 point to negate.

  @return _ The negated point `(x, -y)`.
*/
function negateInplace (
  Honk.G1Point memory _point
) pure returns (Honk.G1Point memory) {
  _point.y = (Q - _point.y) % Q;
  return _point;
}

/**
  Convert the pairing points to G1 points. The pairing points are serialised as
  an array of 68 bit limbs representing two points The lhs of a pairing
  operation and the rhs of a pairing operation There are 4 fields for each group
  element, leaving 8 fields for each side of the pairing.

  @param _pairingPoints The pairing points to convert.

  @return _ The left-hand and right-hand G1 points for the pairing check.
*/
function convertPairingPointsToG1 (
  Fr[PAIRING_POINTS_SIZE] memory _pairingPoints
) pure returns (Honk.G1Point memory, Honk.G1Point memory) {
  Honk.G1Point memory _lhsOutput;
  Honk.G1Point memory _rhsOutput;
  uint256 _lhsX = Fr.unwrap(_pairingPoints[0]);
  _lhsX |= Fr.unwrap(_pairingPoints[1]) << 68;
  _lhsX |= Fr.unwrap(_pairingPoints[2]) << 136;
  _lhsX |= Fr.unwrap(_pairingPoints[3]) << 204;
  _lhsOutput.x = _lhsX;
  uint256 _lhsY = Fr.unwrap(_pairingPoints[4]);
  _lhsY |= Fr.unwrap(_pairingPoints[5]) << 68;
  _lhsY |= Fr.unwrap(_pairingPoints[6]) << 136;
  _lhsY |= Fr.unwrap(_pairingPoints[7]) << 204;
  _lhsOutput.y = _lhsY;
  uint256 _rhsX = Fr.unwrap(_pairingPoints[8]);
  _rhsX |= Fr.unwrap(_pairingPoints[9]) << 68;
  _rhsX |= Fr.unwrap(_pairingPoints[10]) << 136;
  _rhsX |= Fr.unwrap(_pairingPoints[11]) << 204;
  _rhsOutput.x = _rhsX;
  uint256 _rhsY = Fr.unwrap(_pairingPoints[12]);
  _rhsY |= Fr.unwrap(_pairingPoints[13]) << 68;
  _rhsY |= Fr.unwrap(_pairingPoints[14]) << 136;
  _rhsY |= Fr.unwrap(_pairingPoints[15]) << 204;
  _rhsOutput.y = _rhsY;
  return (_lhsOutput, _rhsOutput);
}

/**
  Hash the pairing inputs from the present verification context with those
  extracted from the public inputs.

  @param _proofPairingPoints Pairing points from the proof - (public inputs).
  @param _accLhs Accumulator point for the left side - result of shplemini.
  @param _accRhs Accumulator point for the right side - result of shplemini.

  @return _ The recursion separator - generated from hashing the above.
*/
function generateRecursionSeparator (
  Fr[PAIRING_POINTS_SIZE] memory _proofPairingPoints,
  Honk.G1Point memory _accLhs,
  Honk.G1Point memory _accRhs
) pure returns (Fr) {
  (Honk.G1Point memory _proofLhs, Honk.G1Point memory _proofRhs) =
  convertPairingPointsToG1(
    _proofPairingPoints
  );
  uint256[8] memory _recursionSeparatorElements;

  // Proof points
  _recursionSeparatorElements[0] = _proofLhs.x;
  _recursionSeparatorElements[1] = _proofLhs.y;
  _recursionSeparatorElements[2] = _proofRhs.x;
  _recursionSeparatorElements[3] = _proofRhs.y;

  // Accumulator points
  _recursionSeparatorElements[4] = _accLhs.x;
  _recursionSeparatorElements[5] = _accLhs.y;
  _recursionSeparatorElements[6] = _accRhs.x;
  _recursionSeparatorElements[7] = _accRhs.y;
  return FrLib.fromBytes32(
    keccak256(abi.encodePacked(_recursionSeparatorElements))
  );
}

/**
  G1 Mul with Separator Using the ecAdd and ecMul precompiles

  @param _basePoint The point to multiply.
  @param _other The other point to add.
  @param _recursionSeperator The separator to use for the multiplication.

  @return _ `(recursionSeperator * basePoint) + other`.
*/
function mulWithSeperator (
  Honk.G1Point memory _basePoint,
  Honk.G1Point memory _other,
  Fr _recursionSeperator
) view returns (Honk.G1Point memory) {
  Honk.G1Point memory _result;
  _result = ecMul(_recursionSeperator, _basePoint);
  _result = ecAdd(_result, _other);
  return _result;
}

/**
  G1 Mul Takes a Fr value and a G1 point and uses the ecMul precompile to return
  the result.

  @param _value The value to multiply the point by.
  @param _point The point to multiply.

  @return _ The result of the multiplication.
*/
function ecMul (
  Fr _value,
  Honk.G1Point memory _point
) view returns (Honk.G1Point memory) {
  Honk.G1Point memory _result;
  assembly {
    let _free := mload(0x40)

    /*
      Write the point into memory (two 32 byte words) Memory layout: Address |
      value free | point.x free + 0x20| point.y
    */
    mstore(_free, mload(_point))
    mstore(add(_free, 0x20), mload(add(_point, 0x20)))

    /*
      Write the scalar into memory (one 32 byte word) Memory layout: Address |
      value free + 0x40| value
    */
    mstore(add(_free, 0x40), _value)

    /*
      Call the ecMul precompile, it takes in the following [point.x, point.y,
      scalar], and returns the result back into the free memory location.
    */
    let _success := staticcall(gas(), 0x07, _free, 0x60, _free, 0x40)
    if iszero(_success) {
      revert(0, 0)
    }

    /*
      Copy the result of the multiplication back into the result memory
      location. Memory layout: Address | value result | result.x result + 0x20|
      result.y
    */
    mstore(_result, mload(_free))
    mstore(add(_result, 0x20), mload(add(_free, 0x20)))
    mstore(0x40, add(_free, 0x60))
  }
  return _result;
}

/**
  G1 Add Takes two G1 points and uses the ecAdd precompile to return the result.

  @param _lhs The left hand side of the addition.
  @param _rhs The right hand side of the addition.

  @return _ The result of the addition.
*/
function ecAdd (
  Honk.G1Point memory _lhs,
  Honk.G1Point memory _rhs
) view returns (Honk.G1Point memory) {
  Honk.G1Point memory _result;
  assembly {
    let _free := mload(0x40)

    /*
      Write lhs into memory (two 32 byte words) Memory layout: Address | value
      free | lhs.x free + 0x20| lhs.y
    */
    mstore(_free, mload(_lhs))
    mstore(add(_free, 0x20), mload(add(_lhs, 0x20)))

    /*
      Write rhs into memory (two 32 byte words) Memory layout: Address | value
      free + 0x40| rhs.x free + 0x60| rhs.y
    */
    mstore(add(_free, 0x40), mload(_rhs))
    mstore(add(_free, 0x60), mload(add(_rhs, 0x20)))

    /*
      Call the ecAdd precompile, it takes in the following [lhs.x, lhs.y, rhs.x,
      rhs.y], and returns their addition back into the free memory location.
    */
    let _success := staticcall(gas(), 0x06, _free, 0x80, _free, 0x40)
    if iszero(_success) {
      revert(0, 0)
    }

    /*
      Copy the result of the addition back into the result memory location.
      Memory layout: Address | value result | result.x result + 0x20| result.y
    */
    mstore(_result, mload(_free))
    mstore(add(_result, 0x20), mload(add(_free, 0x20)))
    mstore(0x40, add(_free, 0x80))
  }
  return _result;
}

/**
  Validate that a G1 point lies on the BN254 curve `y^2 = x^3 + 3`.

  @param _point The G1 point to validate.
*/
function validateOnCurve (
  Honk.G1Point memory _point
) pure {
  uint256 x = _point.x;
  uint256 y = _point.y;
  bool _success = false;
  assembly {
    let _xx := mulmod(x, x, Q)
    _success := eq(mulmod(y, y, Q), addmod(mulmod(x, _xx, Q), 3, Q))
  }
  require(_success, "point is not on the curve");
}

/**
  Perform a BN254 pairing check using the EIP-197 precompile. Returns
  `true` if `e(_rhs, G2_gen) * e(_lhs, G2_neg_gen) == 1`.

  @param _rhs The first G1 point input.
  @param _lhs The second G1 point input.

  @return _ Whether the pairing check succeeded.
*/
function pairing (
  Honk.G1Point memory _rhs,
  Honk.G1Point memory _lhs
) view returns (bool) {
  bytes memory _input =
    abi.encodePacked(
      _rhs.x, _rhs.y,
      uint256(
        0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2
      ),
      uint256(
        0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed
      ),
      uint256(
        0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b
      ),
      uint256(
        0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
      ), _lhs.x, _lhs.y,
      uint256(
        0x260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c1
      ),
      uint256(
        0x0118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b0
      ),
      uint256(
        0x04fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe4
      ),
      uint256(
        0x22febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e55
      )
    );
  (bool _success, bytes memory _result) = address(0x08).staticcall(_input);
  return _success && abi.decode(_result, (bool));
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title HonkVerificationKey
  @author Aztec
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  This library supplies the circuit-specific verification key for the ZK mint
  UltraHonk proof. The key contains precomputed polynomial commitment points
  that the verifier uses to validate proofs.

  @custom:date February 24th, 2026.
*/
library HonkVerificationKey {

  /**
    Load the hardcoded verification key for the ZK mint circuit.

    @return _ The verification key.
  */
  function loadVerificationKey () internal pure returns (
    Honk.VerificationKey memory
  ) {
    Honk.VerificationKey memory _vk = Honk.VerificationKey({
      circuitSize: uint256(524288),
      logCircuitSize: uint256(19),
      publicInputsSize: uint256(83),
      ql: Honk.G1Point({
        x: uint256(
          0x2c4c0eda1575922c0c65d786ff610487b96663b74098c48aa4b32fca49b2fad5
        ),
        y: uint256(
          0x0e180634d82284bfec9b1afe4a0702ce8dd3846cf368789aa5f69f0f4ac2182d
        )
      }),
      qr: Honk.G1Point({
        x: uint256(
          0x25f5186f927a47f42721c10a01fca867df00dbd0d7a48fce37d43d2a810c67d6
        ),
        y: uint256(
          0x093cfc4187260c3c75a8362c2fc883a72deecc65eb14d3246638cb356ac60bbb
        )
      }),
      qo: Honk.G1Point({
        x: uint256(
          0x080d82d0eb262bc958346170fcc8d115479d641122771a848bdf7ecb5cce4e7f
        ),
        y: uint256(
          0x09da3ce9771696b94df582a3079f1e8529634d862bf1a4efdba79a7421acf986
        )
      }),
      q4: Honk.G1Point({
        x: uint256(
          0x2a37820421e4338d0bb6734154c4a5f9cffdab3818350b5bf032663968a85275
        ),
        y: uint256(
          0x0a870facc392e539863231ac3c3a53440cd87cf5f8eb086ae91c7aad956ceaa1
        )
      }),
      qm: Honk.G1Point({
        x: uint256(
          0x1d1b5bb9f2a55c9ee2dc29728207f9f9a7bf6dd44ac4fd7dd96b2e3fc29aab8e
        ),
        y: uint256(
          0x28471b313b36dbd7449123335f612e2ada0bbb1d54e733df334f723065659d6b
        )
      }),
      qc: Honk.G1Point({
        x: uint256(
          0x2dda8d61840c2d68bdc018c30d1211c1b9c70f5a55e78c87d1d520ca2233ad42
        ),
        y: uint256(
          0x1292cbabb81e345733daab64235857c4736e6ac962cfc29bc251fffa3d00c3d8
        )
      }),
      qLookup: Honk.G1Point({
        x: uint256(
          0x2d1cd0edc00c78fe47607516a47096786ed9c24a36dcfaabe3bae0a4c6836754
        ),
        y: uint256(
          0x09fb8d4552f98b193a1126c87346dbb8a0c94d821fb523daa44e698252c41329
        )
      }),
      qArith: Honk.G1Point({
        x: uint256(
          0x277d801b8a9af7c5861fbabaa4e3194411ca6b110de9560ddd90ebfc75bcd027
        ),
        y: uint256(
          0x29f5bf1c3fc20c1d0b65c558eba856b4207411f03c545eb3df0dc82111dde99d
        )
      }),
      qDeltaRange: Honk.G1Point({
        x: uint256(
          0x17941e28d4482e0daa9d9455b0c871658fd44b3bafabec4ed3e464953f87b0da
        ),
        y: uint256(
          0x0a360c74149aee79325d28bd090166d80bd7938f010eefb7e28f03e6460e925e
        )
      }),
      qElliptic: Honk.G1Point({
        x: uint256(
          0x0232c1c2a7a0e9e21949422893b6de46c9065015064882a41577a949ec6a221c
        ),
        y: uint256(
          0x248192438f5644cb2db06bed8f93242104f8a2d03ec0c7b5adf0b375e225b4b6
        )
      }),
      qMemory: Honk.G1Point({
        x: uint256(
          0x0db0154b034f9221da68cb363db3bbc11a85ad7ac844e01ca279aabd416aff6c
        ),
        y: uint256(
          0x2c07da8a839a6f26333ea93a7774bbbc64edea252484bf8bb6e9ee9ae2117eaf
        )
      }),
      qNnf: Honk.G1Point({
        x: uint256(
          0x27a18c3d23251704a583192e3120939af0869f627e6df9524794a59729859ef3
        ),
        y: uint256(
          0x17bfde00f80a42521f0a80b9806dc54cb2e538086dcd9bd0c9eef36d8d2e59ed
        )
      }),
      qPoseidon2External: Honk.G1Point({
        x: uint256(
          0x0bb9400dbf5a0a84f97d4d09a4e8eae8cbe4f3b4f8b4c0033c2211782feecf07
        ),
        y: uint256(
          0x255400e9d29c7fbd2644b0a4bae65ff6fe4dff7b50bd731574cff7ee027867b3
        )
      }),
      qPoseidon2Internal: Honk.G1Point({
        x: uint256(
          0x16ec3472b77939538b83f44982813a04984eab4e646dd7d8650e2e9e6264cfd0
        ),
        y: uint256(
          0x148490f8abf1f0e44aa1f12a06909a3ec351b200aaf4636de3540d96f54bfa65
        )
      }),
      s1: Honk.G1Point({
        x: uint256(
          0x04bb1ead96d315b5189f84b60f907ae9697814c3023ecad86b2f76899b9598e4
        ),
        y: uint256(
          0x0e6085fff4c2b3fc673d6deccc16e8f820b825102d9855f9c4c007afb8393c68
        )
      }),
      s2: Honk.G1Point({
        x: uint256(
          0x2c932a1f3971f23bf66f37a585a33437d1ed99d86d8d574349201ce75665ec95
        ),
        y: uint256(
          0x1efac371fdae895296aee962c6b2255150b893da0e2d23770e0c2b15e9587c31
        )
      }),
      s3: Honk.G1Point({
        x: uint256(
          0x21e317ef225d29d2bf2eb65e3b62fcff1fd3ba9e1849cac13966affe63fcd61b
        ),
        y: uint256(
          0x2ef1e7904cb2541cfc281d5ec261d68296e70f01eadab32cd3a9a435ee4d8753
        )
      }),
      s4: Honk.G1Point({
        x: uint256(
          0x289d5e421193a9dc06cea8f16453df57bab455120c58c5bb4a8459ce75c82f06
        ),
        y: uint256(
          0x1b8bbc3679ab9154112f57af4939ce7360de42ca0825211a9a5fc395637a027a
        )
      }),
      t1: Honk.G1Point({
        x: uint256(
          0x099e3bd5a0a00ab7fe18040105b9b395b5d8b7b4a63b05df652b0d10ef146d26
        ),
        y: uint256(
          0x0015b8d2515d76e2ccec99dcd194592129af3a637f5a622a32440f860d1e2a7f
        )
      }),
      t2: Honk.G1Point({
        x: uint256(
          0x1b917517920bad3d8bc01c9595092a222b888108dc25d1aa450e0b4bc212c37e
        ),
        y: uint256(
          0x305e8992b148eedb22e6e992077a84482141c7ebe42000a1d58ccb74381f6d19
        )
      }),
      t3: Honk.G1Point({
        x: uint256(
          0x061f64497996e8915722501e9e367938ed8da2375186b518c7345c60b1134b2d
        ),
        y: uint256(
          0x1b84d38339321f405ebaf6a2f830842ad3d7cb59792e11c0d2691f317fd50e6e
        )
      }),
      t4: Honk.G1Point({
        x: uint256(
          0x043d063b130adfb37342af45d0155a28edd1a7e46c840d9c943fdf45521c64ce
        ),
        y: uint256(
          0x261522c4089330646aff96736194949330952ae74c573d1686d9cb4a00733854
        )
      }),
      id1: Honk.G1Point({
        x: uint256(
          0x24023c08b7e944a310e11c89b74ecf56326d2ef91f78dab32d0bf77e79ea5217
        ),
        y: uint256(
          0x02ac3cb2172d528923dfef6bfdc19c76b153f8c1f558817b2bf5e2ad7dd176cd
        )
      }),
      id2: Honk.G1Point({
        x: uint256(
          0x042ce7ad02f1c63a225e85c9f591e808dbe55fb8aa91eeb97dd7bd8efb711af8
        ),
        y: uint256(
          0x290d85f90d8ac6b12b12b1e5e4db3f363723e83f689264bfdc1ff8f8a8502cb4
        )
      }),
      id3: Honk.G1Point({
        x: uint256(
          0x25862dc3eb849c5db64c9bcae12e46632a14eb6a8248eb596eb8e6cf62f2c9a2
        ),
        y: uint256(
          0x0ae739c95f3c1aaed8c5529cd325846a92c0e61a8566d88ffcf1cfbb5caff499
        )
      }),
      id4: Honk.G1Point({
        x: uint256(
          0x06b24b7618798099c5f59497259c69f9b17f2d3073285b5bae04c87bb569a322
        ),
        y: uint256(
          0x2e751c72ca6f61321ea649f1d90d8dc8dfe0bff236c87aee13b52ea6227d3f02
        )
      }),
      lagrangeFirst: Honk.G1Point({
        x: uint256(
          0x0000000000000000000000000000000000000000000000000000000000000001
        ),
        y: uint256(
          0x0000000000000000000000000000000000000000000000000000000000000002
        )
      }),
      lagrangeLast: Honk.G1Point({
        x: uint256(
          0x112badc1f62da81d2d89f4fa9ab76b4bd3543d4c1d5d2f7506d69d7943267a71
        ),
        y: uint256(
          0x0bde0d8d0de61543db15ecb82a55bae40b4817563d0c24bb2feba438cb8847d4
        )
      })
    });
    return _vk;
  }
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title FrLib
  @author Aztec
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  This library provides utility functions for manipulating BN254 scalar field
  elements wrapped in the `Fr` user-defined value type. It includes
  conversions, modular arithmetic, inversion via the modexp precompile, and
  other field operations.

  @custom:date February 24th, 2026.
*/
library FrLib {

  /**
    Wrap a `uint256` as a field element, reducing it modulo `MODULUS`.

    @param _value The raw integer to convert.

    @return _ The reduced field element.
  */
  function from (
    uint256 _value
  ) internal pure returns (Fr) {
    unchecked {
      return Fr.wrap(_value % MODULUS);
    }
  }

  /**
    Convert a `bytes32` value to a field element, reducing modulo `MODULUS`.

    @param _value The raw bytes to convert.

    @return _ The reduced field element.
  */
  function fromBytes32 (
    bytes32 _value
  ) internal pure returns (Fr) {
    unchecked {
      return Fr.wrap(uint256(_value) % MODULUS);
    }
  }

  /**
    Convert a field element to its `bytes32` representation.

    @param _value The field element to convert.

    @return _ The raw `bytes32` encoding.
  */
  function toBytes32 (
    Fr _value
  ) internal pure returns (bytes32) {
    unchecked {
      return bytes32(Fr.unwrap(_value));
    }
  }

  /**
    Compute the modular multiplicative inverse of a field element using the
    EIP-198 modexp precompile with exponent `MODULUS - 2`.

    @param _value The field element to invert.

    @return _ The multiplicative inverse of `_value`.
  */
  function invert (
    Fr _value
  ) internal view returns (Fr) {
    uint256 v = Fr.unwrap(_value);
    uint256 _result;

    // Call the modexp precompile to invert in the field
    assembly {
      let _free := mload(0x40)
      mstore(_free, 0x20)
      mstore(add(_free, 0x20), 0x20)
      mstore(add(_free, 0x40), 0x20)
      mstore(add(_free, 0x60), v)
      mstore(add(_free, 0x80), sub(MODULUS, 2))
      mstore(add(_free, 0xa0), MODULUS)
      let _success := staticcall(gas(), 0x05, _free, 0xc0, 0x00, 0x20)
      if iszero(_success) {
        revert(0, 0)
      }
      _result := mload(0x00)
      mstore(0x40, add(_free, 0x80))
    }
    return Fr.wrap(_result);
  }

  /**
    Compute modular exponentiation using the EIP-198 modexp precompile.

    @param _base The base field element.
    @param _v The exponent as a raw `uint256`.

    @return _ The result `_base ^ _v` in the field.
  */
  function pow (
    Fr _base,
    uint256 _v
  ) internal view returns (Fr) {
    uint256 b = Fr.unwrap(_base);
    uint256 _result;

    // Call the modexp precompile to invert in the field
    assembly {
      let _free := mload(0x40)
      mstore(_free, 0x20)
      mstore(add(_free, 0x20), 0x20)
      mstore(add(_free, 0x40), 0x20)
      mstore(add(_free, 0x60), b)
      mstore(add(_free, 0x80), _v)
      mstore(add(_free, 0xa0), MODULUS)
      let _success := staticcall(gas(), 0x05, _free, 0xc0, 0x00, 0x20)
      if iszero(_success) {
        revert(0, 0)
      }
      _result := mload(0x00)
      mstore(0x40, add(_free, 0x80))
    }
    return Fr.wrap(_result);
  }

  /**
    Divide one field element by another via multiplication by the inverse.

    @param _numerator The dividend.
    @param _denominator The divisor.

    @return _ The quotient `_numerator / _denominator` in the field.
  */
  function div (
    Fr _numerator,
    Fr _denominator
  ) internal view returns (Fr) {
    unchecked {
      return _numerator * invert(_denominator);
    }
  }

  /**
    Compute the square of a field element.

    @param _value The field element to square.

    @return _ The result `_value * _value`.
  */
  function sqr (
    Fr _value
  ) internal pure returns (Fr) {
    unchecked {
      return _value * _value;
    }
  }

  /**
    Unwrap a field element to its underlying `uint256` representation.

    @param _value The field element to unwrap.

    @return _ The raw `uint256` value.
  */
  function unwrap (
    Fr _value
  ) internal pure returns (uint256) {
    unchecked {
      return Fr.unwrap(_value);
    }
  }

  /**
    Compute the additive inverse of a field element.

    @param _value The field element to negate.

    @return _ The negation `MODULUS - _value`.
  */
  function neg (
    Fr _value
  ) internal pure returns (Fr) {
    unchecked {
      return Fr.wrap(MODULUS - Fr.unwrap(_value));
    }
  }
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Honk
  @author Aztec
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  This library defines the data structures used in the UltraHonk proof
  system, including G1 points, verification keys, relation parameters, and
  proof objects for both standard and ZK-flavored protocols.

  @custom:date February 24th, 2026.
*/
library Honk {

  /**
    A point on the BN254 G1 elliptic curve.

    @param x The x-coordinate.
    @param y The y-coordinate.
  */
  struct G1Point {
    uint256 x;
    uint256 y;
  }

  /**
    The verification key containing all precomputed polynomial commitment
    points needed to verify an UltraHonk proof.

    @param circuitSize The number of gates in the arithmetized circuit.
    @param logCircuitSize The base-2 logarithm of `circuitSize`.
    @param publicInputsSize The number of public inputs to the circuit.
    @param qm The multiplication selector commitment.
    @param qc The constant selector commitment.
    @param ql The left wire selector commitment.
    @param qr The right wire selector commitment.
    @param qo The output wire selector commitment.
    @param q4 The fourth wire selector commitment.
    @param qLookup The lookup table selector commitment.
    @param qArith The arithmetic gate selector commitment.
    @param qDeltaRange The delta range constraint selector commitment.
    @param qMemory The RAM/ROM memory gate selector commitment.
    @param qNnf The non-native field gate selector commitment.
    @param qElliptic The elliptic curve gate selector commitment.
    @param qPoseidon2External The Poseidon2 external round selector
      commitment.
    @param qPoseidon2Internal The Poseidon2 internal round selector
      commitment.
    @param s1 The first copy constraint permutation commitment.
    @param s2 The second copy constraint permutation commitment.
    @param s3 The third copy constraint permutation commitment.
    @param s4 The fourth copy constraint permutation commitment.
    @param id1 The first identity permutation commitment.
    @param id2 The second identity permutation commitment.
    @param id3 The third identity permutation commitment.
    @param id4 The fourth identity permutation commitment.
    @param t1 The first precomputed lookup table commitment.
    @param t2 The second precomputed lookup table commitment.
    @param t3 The third precomputed lookup table commitment.
    @param t4 The fourth precomputed lookup table commitment.
    @param lagrangeFirst The Lagrange basis commitment for the first element.
    @param lagrangeLast The Lagrange basis commitment for the last element.
  */
  struct VerificationKey {
    uint256 circuitSize;
    uint256 logCircuitSize;
    uint256 publicInputsSize;
    G1Point qm;
    G1Point qc;
    G1Point ql;
    G1Point qr;
    G1Point qo;
    G1Point q4;
    G1Point qLookup;
    G1Point qArith;
    G1Point qDeltaRange;
    G1Point qMemory;
    G1Point qNnf;
    G1Point qElliptic;
    G1Point qPoseidon2External;
    G1Point qPoseidon2Internal;
    G1Point s1;
    G1Point s2;
    G1Point s3;
    G1Point s4;
    G1Point id1;
    G1Point id2;
    G1Point id3;
    G1Point id4;
    G1Point t1;
    G1Point t2;
    G1Point t3;
    G1Point t4;
    G1Point lagrangeFirst;
    G1Point lagrangeLast;
  }

  /**
    The relation parameters derived from Fiat-Shamir challenges during the
    Oink phase of the protocol.

    @param eta The first batching challenge for witness commitments.
    @param etaTwo The second batching challenge for witness commitments.
    @param etaThree The third batching challenge for witness commitments.
    @param beta The permutation challenge.
    @param gamma The permutation randomness challenge.
    @param publicInputsDelta The public input delta derived from beta and
      gamma.
  */
  struct RelationParameters {
    Fr eta;
    Fr etaTwo;
    Fr etaThree;
    Fr beta;
    Fr gamma;
    Fr publicInputsDelta;
  }

  /**
    A deserialized UltraHonk proof in non-ZK mode.

    @param pairingPointObject The recursive pairing point limbs carried as
      public inputs.
    @param w1 The first witness wire commitment.
    @param w2 The second witness wire commitment.
    @param w3 The third witness wire commitment.
    @param w4 The fourth witness wire commitment.
    @param zPerm The grand product permutation commitment.
    @param lookupReadCounts The log-derivative lookup read count commitment.
    @param lookupReadTags The log-derivative lookup read tag commitment.
    @param lookupInverses The log-derivative lookup inverse commitment.
    @param sumcheckUnivariates The sumcheck round univariate evaluations.
    @param sumcheckEvaluations The sumcheck polynomial evaluations.
    @param geminiFoldComms The Gemini fold polynomial commitments.
    @param geminiAEvaluations The Gemini polynomial evaluations.
    @param shplonkQ The Shplonk quotient commitment.
    @param kzgQuotient The KZG opening quotient commitment.
  */
  struct Proof {
    Fr[PAIRING_POINTS_SIZE] pairingPointObject;
    G1Point w1;
    G1Point w2;
    G1Point w3;
    G1Point w4;
    G1Point zPerm;
    G1Point lookupReadCounts;
    G1Point lookupReadTags;
    G1Point lookupInverses;
    Fr[BATCHED_RELATION_PARTIAL_LENGTH][CONST_PROOF_SIZE_LOG_N] sumcheckUnivariates;
    Fr[NUMBER_OF_ENTITIES] sumcheckEvaluations;
    G1Point[CONST_PROOF_SIZE_LOG_N - 1] geminiFoldComms;
    Fr[CONST_PROOF_SIZE_LOG_N] geminiAEvaluations;
    G1Point shplonkQ;
    G1Point kzgQuotient;
  }

  /**
    forge-lint: disable-next-item(pascal-case-struct)

    @param pairingPointObject Pairing point object
    @param geminiMaskingPoly ZK: Gemini masking polynomial commitment (sent
      first, right after public inputs)
    @param w1 Commitments to wire polynomials
    @param w2 The second witness wire commitment.
    @param w3 The third witness wire commitment.
    @param w4 The fourth witness wire commitment.
    @param lookupReadCounts The log-derivative lookup read count commitment.
    @param lookupReadTags The log-derivative lookup read tag commitment.
    @param lookupInverses The log-derivative lookup inverse commitment.
    @param zPerm The grand product permutation commitment.
    @param libraCommitments The Libra masking polynomial commitments.
    @param libraSum The claimed Libra sum for the sumcheck protocol.
    @param sumcheckUnivariates The sumcheck round univariate evaluations.
    @param libraEvaluation The Libra masking polynomial evaluation.
    @param sumcheckEvaluations The sumcheck polynomial evaluations; index 0
      holds the Gemini masking polynomial evaluation.
    @param geminiFoldComms The Gemini fold polynomial commitments.
    @param geminiAEvaluations The Gemini polynomial evaluations.
    @param libraPolyEvals The Libra polynomial evaluations.
    @param shplonkQ The Shplonk quotient commitment.
    @param kzgQuotient The KZG opening quotient commitment.
  */
  struct ZKProof {
    Fr[PAIRING_POINTS_SIZE] pairingPointObject;
    G1Point geminiMaskingPoly;
    G1Point w1;
    G1Point w2;
    G1Point w3;
    G1Point w4;
    G1Point lookupReadCounts;
    G1Point lookupReadTags;
    G1Point lookupInverses;
    G1Point zPerm;
    G1Point[3] libraCommitments;
    Fr libraSum;
    Fr[ZK_BATCHED_RELATION_PARTIAL_LENGTH][CONST_PROOF_SIZE_LOG_N] sumcheckUnivariates;
    Fr libraEvaluation;
    Fr[NUMBER_OF_ENTITIES_ZK] sumcheckEvaluations;
    G1Point[CONST_PROOF_SIZE_LOG_N - 1] geminiFoldComms;
    Fr[CONST_PROOF_SIZE_LOG_N] geminiAEvaluations;
    Fr[4] libraPolyEvals;
    G1Point shplonkQ;
    G1Point kzgQuotient;
  }
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title ZKTranscriptLib
  @author Aztec
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  This library generates the Fiat-Shamir transcript for the ZK-flavored
  UltraHonk protocol. It sequentially hashes proof elements to derive all
  verifier challenges in a deterministic, non-interactive manner.

  @custom:date February 24th, 2026.
*/
library ZKTranscriptLib {

  /**
    Generate the complete Fiat-Shamir transcript by deriving all challenges
    from the proof and public inputs.

    @param _proof The deserialized ZK proof.
    @param _publicInputs The public inputs to the circuit.
    @param _vkHash The hash of the verification key.
    @param _publicInputsSize The number of public inputs.
    @param _logN The base-2 logarithm of the circuit size.

    @return _ The fully-populated transcript.
  */
  function generateTranscript (
    Honk.ZKProof memory _proof,
    bytes32[] calldata _publicInputs,
    uint256 _vkHash,
    uint256 _publicInputsSize,
    uint256 _logN
  ) external pure returns (ZKTranscript memory) {
    ZKTranscript memory _tOutput;
    Fr _previousChallenge;
    (_tOutput.relationParameters, _previousChallenge) =
    generateRelationParametersChallenges(
      _proof, _publicInputs, _vkHash, _publicInputsSize, _previousChallenge
    );
    (_tOutput.alphas, _previousChallenge) = generateAlphaChallenges(
      _previousChallenge, _proof
    );
    (_tOutput.gateChallenges, _previousChallenge) = generateGateChallenges(
      _previousChallenge, _logN
    );
    (_tOutput.libraChallenge, _previousChallenge) = generateLibraChallenge(
      _previousChallenge, _proof
    );
    (_tOutput.sumCheckUChallenges, _previousChallenge) =
    generateSumcheckChallenges(
      _proof, _previousChallenge, _logN
    );
    (_tOutput.rho, _previousChallenge) = generateRhoChallenge(
      _proof, _previousChallenge
    );
    (_tOutput.geminiR, _previousChallenge) = generateGeminiRChallenge(
      _proof, _previousChallenge, _logN
    );
    (_tOutput.shplonkNu, _previousChallenge) = generateShplonkNuChallenge(
      _proof, _previousChallenge, _logN
    );
    (_tOutput.shplonkZ, _previousChallenge) = generateShplonkZChallenge(
      _proof, _previousChallenge
    );
    return _tOutput;
  }

  /**
    Split a 254-bit field element into two 127-bit challenges by taking the
    low and high halves.

    @param _challenge The field element to split.

    @return _ The low and high 127-bit challenges.
  */
  function splitChallenge (
    Fr _challenge
  ) internal pure returns (Fr, Fr) {
    uint256 _challengeU256 = uint256(Fr.unwrap(_challenge));

    // Split into two equal 127-bit chunks (254/2) 127 bits
    uint256 _lo = _challengeU256 & 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
    uint256 _hi = _challengeU256 >> 127;
    Fr _first = FrLib.fromBytes32(bytes32(_lo));
    Fr _second = FrLib.fromBytes32(bytes32(_hi));
    return (_first, _second);
  }

  /**
    Derive the relation parameter challenges (eta, beta, gamma) from the
    proof commitments and public inputs during the Oink phase.

    @param _proof The deserialized ZK proof.
    @param _publicInputs The public inputs to the circuit.
    @param _vkHash The hash of the verification key.
    @param _publicInputsSize The number of public inputs.
    @param _previousChallenge The running Fiat-Shamir challenge state.

    @return _ The relation parameters and the updated challenge state.
  */
  function generateRelationParametersChallenges (
    Honk.ZKProof memory _proof,
    bytes32[] calldata _publicInputs,
    uint256 _vkHash,
    uint256 _publicInputsSize,
    Fr _previousChallenge
  ) internal pure returns (Honk.RelationParameters memory, Fr) {
    Honk.RelationParameters memory _rpOutput;
    Fr _nextPreviousChallengeOutput;
    (_rpOutput.eta, _rpOutput.etaTwo, _rpOutput.etaThree, _previousChallenge) =
    generateEtaChallenge(
      _proof, _publicInputs, _vkHash, _publicInputsSize
    );
    (_rpOutput.beta, _rpOutput.gamma, _nextPreviousChallengeOutput) =
    generateBetaAndGammaChallenges(
      _previousChallenge, _proof
    );
    return (_rpOutput, _nextPreviousChallengeOutput);
  }

  /**
    Derive the eta challenges by hashing the verification key hash, public
    inputs, pairing points, the Gemini masking polynomial commitment, and the
    first three wire commitments.

    @param _proof The deserialized ZK proof.
    @param _publicInputs The public inputs to the circuit.
    @param _vkHash The hash of the verification key.
    @param _publicInputsSize The number of public inputs.

    @return _ The three eta challenges and the updated challenge state.
  */
  function generateEtaChallenge (
    Honk.ZKProof memory _proof,
    bytes32[] calldata _publicInputs,
    uint256 _vkHash,
    uint256 _publicInputsSize
  ) internal pure returns (Fr, Fr, Fr, Fr) {
    Fr _etaOutput;
    Fr _etaTwoOutput;
    Fr _etaThreeOutput;
    Fr _previousChallengeOutput;

    // Size: 1 (vkHash) + publicInputsSize + 8 (geminiMask(2) + 3 wires(6))
    bytes32[] memory _round0 = new bytes32[](1 + _publicInputsSize + 8);
    _round0[0] = bytes32(_vkHash);
    for (uint256 i = 0; i < _publicInputsSize - PAIRING_POINTS_SIZE; i++) {
      _round0[1 + i] = bytes32(_publicInputs[i]);
    }
    for (uint256 i = 0; i < PAIRING_POINTS_SIZE; i++) {
      _round0[1 + _publicInputsSize - PAIRING_POINTS_SIZE + i] = FrLib.toBytes32
      (
        _proof.pairingPointObject[i]
      );
    }

    /*
      For ZK flavors: hash the gemini masking poly commitment (sent right after
      public inputs)
    */
    _round0[1 + _publicInputsSize] = bytes32(_proof.geminiMaskingPoly.x);
    _round0[1 + _publicInputsSize + 1] = bytes32(_proof.geminiMaskingPoly.y);

    // Create the first challenge Note: w4 is added to the challenge later on
    _round0[1 + _publicInputsSize + 2] = bytes32(_proof.w1.x);
    _round0[1 + _publicInputsSize + 3] = bytes32(_proof.w1.y);
    _round0[1 + _publicInputsSize + 4] = bytes32(_proof.w2.x);
    _round0[1 + _publicInputsSize + 5] = bytes32(_proof.w2.y);
    _round0[1 + _publicInputsSize + 6] = bytes32(_proof.w3.x);
    _round0[1 + _publicInputsSize + 7] = bytes32(_proof.w3.y);
    _previousChallengeOutput = FrLib.fromBytes32(
      keccak256(abi.encodePacked(_round0))
    );
    (_etaOutput, _etaTwoOutput) = splitChallenge(_previousChallengeOutput);
    _previousChallengeOutput = FrLib.fromBytes32(
      keccak256(abi.encodePacked(Fr.unwrap(_previousChallengeOutput)))
    );
    (_etaThreeOutput, ) = splitChallenge(_previousChallengeOutput);
    return (_etaOutput, _etaTwoOutput, _etaThreeOutput, _previousChallengeOutput);
  }

  /**
    Derive the beta and gamma permutation challenges by hashing the lookup
    and fourth wire commitments with the running challenge state.

    @param _previousChallenge The running Fiat-Shamir challenge state.
    @param _proof The deserialized ZK proof.

    @return _ The beta challenge, gamma challenge, and updated state.
  */
  function generateBetaAndGammaChallenges (
    Fr _previousChallenge,
    Honk.ZKProof memory _proof
  ) internal pure returns (Fr, Fr, Fr) {
    Fr _betaOutput;
    Fr _gammaOutput;
    Fr _nextPreviousChallengeOutput;
    bytes32[7] memory _round1;
    _round1[0] = FrLib.toBytes32(_previousChallenge);
    _round1[1] = bytes32(_proof.lookupReadCounts.x);
    _round1[2] = bytes32(_proof.lookupReadCounts.y);
    _round1[3] = bytes32(_proof.lookupReadTags.x);
    _round1[4] = bytes32(_proof.lookupReadTags.y);
    _round1[5] = bytes32(_proof.w4.x);
    _round1[6] = bytes32(_proof.w4.y);
    _nextPreviousChallengeOutput = FrLib.fromBytes32(
      keccak256(abi.encodePacked(_round1))
    );
    (_betaOutput, _gammaOutput) = splitChallenge(_nextPreviousChallengeOutput);
    return (_betaOutput, _gammaOutput, _nextPreviousChallengeOutput);
  }

  /**
    Alpha challenges non-linearise the gate contributions

    @param _previousChallenge The running Fiat-Shamir challenge state.
    @param _proof The deserialized ZK proof.

    @return _ The alpha powers array and the updated challenge state.
  */
  function generateAlphaChallenges (
    Fr _previousChallenge,
    Honk.ZKProof memory _proof
  ) internal pure returns (Fr[NUMBER_OF_ALPHAS] memory, Fr) {
    Fr[NUMBER_OF_ALPHAS] memory _alphasOutput;
    Fr _nextPreviousChallengeOutput;

    // Generate the original sumcheck alpha 0 by hashing zPerm and zLookup
    uint256[5] memory _alpha0;
    _alpha0[0] = Fr.unwrap(_previousChallenge);
    _alpha0[1] = _proof.lookupInverses.x;
    _alpha0[2] = _proof.lookupInverses.y;
    _alpha0[3] = _proof.zPerm.x;
    _alpha0[4] = _proof.zPerm.y;
    _nextPreviousChallengeOutput = FrLib.fromBytes32(
      keccak256(abi.encodePacked(_alpha0))
    );
    Fr _alpha;
    (_alpha, ) = splitChallenge(_nextPreviousChallengeOutput);

    // Compute powers of alpha for batching subrelations
    _alphasOutput[0] = _alpha;
    for (uint256 i = 1; i < NUMBER_OF_ALPHAS; i++) {
      _alphasOutput[i] = _alphasOutput[i - 1] * _alpha;
    }
    return (_alphasOutput, _nextPreviousChallengeOutput);
  }

  /**
    Derive the gate challenges used to compute the perturbator
    polynomial by repeated squaring.

    @param _previousChallenge The running Fiat-Shamir challenge state.
    @param _logN The base-2 logarithm of the circuit size.

    @return _ The gate challenges array and the updated challenge state.
  */
  function generateGateChallenges (
    Fr _previousChallenge,
    uint256 _logN
  ) internal pure returns (Fr[CONST_PROOF_SIZE_LOG_N] memory, Fr) {
    Fr[CONST_PROOF_SIZE_LOG_N] memory _gateChallengesOutput;
    Fr _nextPreviousChallengeOutput;
    _previousChallenge = FrLib.fromBytes32(
      keccak256(abi.encodePacked(Fr.unwrap(_previousChallenge)))
    );
    (_gateChallengesOutput[0], ) = splitChallenge(_previousChallenge);
    for (uint256 i = 1; i < _logN; i++) {
      _gateChallengesOutput[i] = _gateChallengesOutput[i - 1] *
      _gateChallengesOutput[
        i - 1
      ];
    }
    _nextPreviousChallengeOutput = _previousChallenge;
    return (_gateChallengesOutput, _nextPreviousChallengeOutput);
  }

  /**
    Derive the Libra masking challenge by hashing the first Libra
    commitment and claimed sum.

    @param _previousChallenge The running Fiat-Shamir challenge state.
    @param _proof The deserialized ZK proof.

    @return _ The Libra challenge and the updated challenge state.
  */
  function generateLibraChallenge (
    Fr _previousChallenge,
    Honk.ZKProof memory _proof
  ) internal pure returns (Fr, Fr) {
    Fr _libraChallengeOutput;
    Fr _nextPreviousChallengeOutput;

    // 2 comm, 1 sum, 1 challenge
    uint256[4] memory _challengeData;
    _challengeData[0] = Fr.unwrap(_previousChallenge);
    _challengeData[1] = _proof.libraCommitments[0].x;
    _challengeData[2] = _proof.libraCommitments[0].y;
    _challengeData[3] = Fr.unwrap(_proof.libraSum);
    _nextPreviousChallengeOutput = FrLib.fromBytes32(
      keccak256(abi.encodePacked(_challengeData))
    );
    (_libraChallengeOutput, ) = splitChallenge(_nextPreviousChallengeOutput);
    return (_libraChallengeOutput, _nextPreviousChallengeOutput);
  }

  /**
    Derive the sumcheck round challenges by hashing each round's univariate
    evaluations with the running challenge state.

    @param _proof The deserialized ZK proof.
    @param _prevChallenge The running Fiat-Shamir challenge state.
    @param _logN The base-2 logarithm of the circuit size.

    @return _ The sumcheck challenges and the updated challenge state.
  */
  function generateSumcheckChallenges (
    Honk.ZKProof memory _proof,
    Fr _prevChallenge,
    uint256 _logN
  ) internal pure returns (Fr[CONST_PROOF_SIZE_LOG_N] memory, Fr) {
    Fr[CONST_PROOF_SIZE_LOG_N] memory _sumcheckChallengesOutput;
    Fr _nextPreviousChallengeOutput;
    for (uint256 i = 0; i < _logN; i++) {
      Fr[ZK_BATCHED_RELATION_PARTIAL_LENGTH + 1] memory _univariateChal;
      _univariateChal[0] = _prevChallenge;
      for (uint256 j = 0; j < ZK_BATCHED_RELATION_PARTIAL_LENGTH; j++) {
        _univariateChal[j + 1] = _proof.sumcheckUnivariates[i][j];
      }
      _prevChallenge = FrLib.fromBytes32(
        keccak256(abi.encodePacked(_univariateChal))
      );
      (_sumcheckChallengesOutput[i], ) = splitChallenge(_prevChallenge);
    }
    _nextPreviousChallengeOutput = _prevChallenge;
    return (_sumcheckChallengesOutput, _nextPreviousChallengeOutput);
  }

  /**
    We add Libra claimed eval + 2 libra commitments (grand_sum, quotient)

    @param _proof The deserialized ZK proof.
    @param _prevChallenge The running Fiat-Shamir challenge state.

    @return _ The rho challenge and the updated challenge state.
  */
  function generateRhoChallenge (
    Honk.ZKProof memory _proof,
    Fr _prevChallenge
  ) internal pure returns (Fr, Fr) {
    Fr _rhoOutput;
    Fr _nextPreviousChallengeOutput;
    uint256[NUMBER_OF_ENTITIES_ZK + 6] memory _rhoChallengeElements;
    _rhoChallengeElements[0] = Fr.unwrap(_prevChallenge);
    uint256 i;
    for (i = 1; i <= NUMBER_OF_ENTITIES_ZK; i++) {
      _rhoChallengeElements[i] = Fr.unwrap(_proof.sumcheckEvaluations[i - 1]);
    }
    _rhoChallengeElements[i] = Fr.unwrap(_proof.libraEvaluation);
    i += 1;
    _rhoChallengeElements[i] = _proof.libraCommitments[1].x;
    _rhoChallengeElements[i + 1] = _proof.libraCommitments[1].y;
    i += 2;
    _rhoChallengeElements[i] = _proof.libraCommitments[2].x;
    _rhoChallengeElements[i + 1] = _proof.libraCommitments[2].y;
    _nextPreviousChallengeOutput = FrLib.fromBytes32(
      keccak256(abi.encodePacked(_rhoChallengeElements))
    );
    (_rhoOutput, ) = splitChallenge(_nextPreviousChallengeOutput);
    return (_rhoOutput, _nextPreviousChallengeOutput);
  }

  /**
    Derive the Gemini folding challenge by hashing the Gemini fold
    commitments with the running challenge state.

    @param _proof The deserialized ZK proof.
    @param _prevChallenge The running Fiat-Shamir challenge state.
    @param _logN The base-2 logarithm of the circuit size.

    @return _ The Gemini-r challenge and the updated challenge state.
  */
  function generateGeminiRChallenge (
    Honk.ZKProof memory _proof,
    Fr _prevChallenge,
    uint256 _logN
  ) internal pure returns (Fr, Fr) {
    Fr _geminiROutput;
    Fr _nextPreviousChallengeOutput;
    uint256[] memory _gR = new uint256[]((_logN - 1) * 2 + 1);
    _gR[0] = Fr.unwrap(_prevChallenge);
    for (uint256 i = 0; i < _logN - 1; i++) {
      _gR[1 + i * 2] = _proof.geminiFoldComms[i].x;
      _gR[2 + i * 2] = _proof.geminiFoldComms[i].y;
    }
    _nextPreviousChallengeOutput = FrLib.fromBytes32(
      keccak256(abi.encodePacked(_gR))
    );
    (_geminiROutput, ) = splitChallenge(_nextPreviousChallengeOutput);
    return (_geminiROutput, _nextPreviousChallengeOutput);
  }

  /**
    Derive the Shplonk batching challenge by hashing the Gemini evaluations
    and Libra polynomial evaluations.

    @param _proof The deserialized ZK proof.
    @param _prevChallenge The running Fiat-Shamir challenge state.
    @param _logN The base-2 logarithm of the circuit size.

    @return _ The Shplonk-nu challenge and the updated challenge state.
  */
  function generateShplonkNuChallenge (
    Honk.ZKProof memory _proof,
    Fr _prevChallenge,
    uint256 _logN
  ) internal pure returns (Fr, Fr) {
    Fr _shplonkNuOutput;
    Fr _nextPreviousChallengeOutput;
    uint256[] memory _shplonkNuChallengeElements =
      new uint256[](_logN + 1 + 4);
    _shplonkNuChallengeElements[0] = Fr.unwrap(_prevChallenge);
    for (uint256 i = 1; i <= _logN; i++) {
      _shplonkNuChallengeElements[i] = Fr.unwrap(
        _proof.geminiAEvaluations[i - 1]
      );
    }
    uint256 _libraIdx = 0;
    for (uint256 i = _logN + 1; i <= _logN + 4; i++) {
      _shplonkNuChallengeElements[i] = Fr.unwrap(
        _proof.libraPolyEvals[_libraIdx]
      );
      _libraIdx++;
    }
    _nextPreviousChallengeOutput = FrLib.fromBytes32(
      keccak256(abi.encodePacked(_shplonkNuChallengeElements))
    );
    (_shplonkNuOutput, ) = splitChallenge(_nextPreviousChallengeOutput);
    return (_shplonkNuOutput, _nextPreviousChallengeOutput);
  }

  /**
    Derive the Shplonk evaluation challenge by hashing the Shplonk quotient
    commitment.

    @param _proof The deserialized ZK proof.
    @param _prevChallenge The running Fiat-Shamir challenge state.

    @return _ The Shplonk-z challenge and the updated challenge state.
  */
  function generateShplonkZChallenge (
    Honk.ZKProof memory _proof,
    Fr _prevChallenge
  ) internal pure returns (Fr, Fr) {
    Fr _shplonkZOutput;
    Fr _nextPreviousChallengeOutput;
    uint256[3] memory _shplonkZChallengeElements;
    _shplonkZChallengeElements[0] = Fr.unwrap(_prevChallenge);
    _shplonkZChallengeElements[1] = _proof.shplonkQ.x;
    _shplonkZChallengeElements[2] = _proof.shplonkQ.y;
    _nextPreviousChallengeOutput = FrLib.fromBytes32(
      keccak256(abi.encodePacked(_shplonkZChallengeElements))
    );
    (_shplonkZOutput, ) = splitChallenge(_nextPreviousChallengeOutput);
    return (_shplonkZOutput, _nextPreviousChallengeOutput);
  }

  /**
    Deserialize a raw proof byte array into a structured `ZKProof` object by
    sequentially decoding field elements and group elements.

    @param _proof The raw proof bytes from calldata.
    @param _logN The base-2 logarithm of the circuit size.

    @return _ The deserialized proof object.
  */
  function loadProof (
    bytes calldata _proof,
    uint256 _logN
  ) internal pure returns (Honk.ZKProof memory) {
    Honk.ZKProof memory _pOutput;
    uint256 _boundary = 0x0;

    // Pairing point object
    for (uint256 i = 0; i < PAIRING_POINTS_SIZE; i++) {
      _pOutput.pairingPointObject[i] = bytesToFr(
        _proof[_boundary:_boundary + FIELD_ELEMENT_SIZE]
      );
      _boundary += FIELD_ELEMENT_SIZE;
    }

    /*
      Gemini masking polynomial commitment (sent first in ZK flavors, right
      after pairing points)
    */
    _pOutput.geminiMaskingPoly = bytesToG1Point(
      _proof[_boundary:_boundary + GROUP_ELEMENT_SIZE]
    );
    _boundary += GROUP_ELEMENT_SIZE;

    // Commitments
    _pOutput.w1 = bytesToG1Point(
      _proof[_boundary:_boundary + GROUP_ELEMENT_SIZE]
    );
    _boundary += GROUP_ELEMENT_SIZE;
    _pOutput.w2 = bytesToG1Point(
      _proof[_boundary:_boundary + GROUP_ELEMENT_SIZE]
    );
    _boundary += GROUP_ELEMENT_SIZE;
    _pOutput.w3 = bytesToG1Point(
      _proof[_boundary:_boundary + GROUP_ELEMENT_SIZE]
    );
    _boundary += GROUP_ELEMENT_SIZE;

    // Lookup / Permutation Helper Commitments
    _pOutput.lookupReadCounts = bytesToG1Point(
      _proof[_boundary:_boundary + GROUP_ELEMENT_SIZE]
    );
    _boundary += GROUP_ELEMENT_SIZE;
    _pOutput.lookupReadTags = bytesToG1Point(
      _proof[_boundary:_boundary + GROUP_ELEMENT_SIZE]
    );
    _boundary += GROUP_ELEMENT_SIZE;
    _pOutput.w4 = bytesToG1Point(
      _proof[_boundary:_boundary + GROUP_ELEMENT_SIZE]
    );
    _boundary += GROUP_ELEMENT_SIZE;
    _pOutput.lookupInverses = bytesToG1Point(
      _proof[_boundary:_boundary + GROUP_ELEMENT_SIZE]
    );
    _boundary += GROUP_ELEMENT_SIZE;
    _pOutput.zPerm = bytesToG1Point(
      _proof[_boundary:_boundary + GROUP_ELEMENT_SIZE]
    );
    _boundary += GROUP_ELEMENT_SIZE;
    _pOutput.libraCommitments[0] = bytesToG1Point(
      _proof[_boundary:_boundary + GROUP_ELEMENT_SIZE]
    );
    _boundary += GROUP_ELEMENT_SIZE;
    _pOutput.libraSum = bytesToFr(
      _proof[_boundary:_boundary + FIELD_ELEMENT_SIZE]
    );
    _boundary += FIELD_ELEMENT_SIZE;

    // Sumcheck univariates
    for (uint256 i = 0; i < _logN; i++) {
      for (uint256 j = 0; j < ZK_BATCHED_RELATION_PARTIAL_LENGTH; j++) {
        _pOutput.sumcheckUnivariates[i][j] = bytesToFr(
          _proof[_boundary:_boundary + FIELD_ELEMENT_SIZE]
        );
        _boundary += FIELD_ELEMENT_SIZE;
      }
    }

    /*
      Sumcheck evaluations (includes gemini_masking_poly eval at index 0 for ZK
      flavors)
    */
    for (uint256 i = 0; i < NUMBER_OF_ENTITIES_ZK; i++) {
      _pOutput.sumcheckEvaluations[i] = bytesToFr(
        _proof[_boundary:_boundary + FIELD_ELEMENT_SIZE]
      );
      _boundary += FIELD_ELEMENT_SIZE;
    }
    _pOutput.libraEvaluation = bytesToFr(
      _proof[_boundary:_boundary + FIELD_ELEMENT_SIZE]
    );
    _boundary += FIELD_ELEMENT_SIZE;
    _pOutput.libraCommitments[1] = bytesToG1Point(
      _proof[_boundary:_boundary + GROUP_ELEMENT_SIZE]
    );
    _boundary += GROUP_ELEMENT_SIZE;
    _pOutput.libraCommitments[2] = bytesToG1Point(
      _proof[_boundary:_boundary + GROUP_ELEMENT_SIZE]
    );
    _boundary += GROUP_ELEMENT_SIZE;

    // Gemini Read gemini fold univariates
    for (uint256 i = 0; i < _logN - 1; i++) {
      _pOutput.geminiFoldComms[i] = bytesToG1Point(
        _proof[_boundary:_boundary + GROUP_ELEMENT_SIZE]
      );
      _boundary += GROUP_ELEMENT_SIZE;
    }

    // Read gemini a evaluations
    for (uint256 i = 0; i < _logN; i++) {
      _pOutput.geminiAEvaluations[i] = bytesToFr(
        _proof[_boundary:_boundary + FIELD_ELEMENT_SIZE]
      );
      _boundary += FIELD_ELEMENT_SIZE;
    }
    for (uint256 i = 0; i < 4; i++) {
      _pOutput.libraPolyEvals[i] = bytesToFr(
        _proof[_boundary:_boundary + FIELD_ELEMENT_SIZE]
      );
      _boundary += FIELD_ELEMENT_SIZE;
    }

    // Shplonk
    _pOutput.shplonkQ = bytesToG1Point(
      _proof[_boundary:_boundary + GROUP_ELEMENT_SIZE]
    );
    _boundary += GROUP_ELEMENT_SIZE;

    // KZG
    _pOutput.kzgQuotient = bytesToG1Point(
      _proof[_boundary:_boundary + GROUP_ELEMENT_SIZE]
    );
    return _pOutput;
  }
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title RelationsLib
  @author Aztec
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  This library evaluates the UltraHonk gate relations. Each relation
  contributes one or more subrelation evaluations that are batched together
  with powers of alpha to produce the full Honk relation sum.

  @custom:date February 24th, 2026.
*/
library RelationsLib {

  /**
    Intermediate values for the elliptic curve addition gate relation.

    @param x_1 The x-coordinate of the first input point.
    @param y_1 The y-coordinate of the first input point.
    @param x_2 The x-coordinate of the second input point.
    @param y_2 The y-coordinate of the second input point.
    @param y_3 The y-coordinate of the output point.
    @param x_3 The x-coordinate of the output point.
    @param x_double_identity The accumulator for the point doubling identity.
  */
  struct EllipticParams {
    Fr x_1;
    Fr y_1;
    Fr x_2;
    Fr y_2;
    Fr y_3;
    Fr x_3;
    Fr x_double_identity;
  }

  /**
    Parameters used within the Memory Relation A struct is used to work around
    stack too deep. This relation has alot of variables

    @param memory_record_check The full record consistency check.
    @param partial_record_check The partial record consistency check.
    @param next_gate_access_type The access type of the next gate.
    @param record_delta The difference between adjacent records.
    @param index_delta The difference between adjacent indices.
    @param adjacent_values_match_if_adjacent_indices_match Whether adjacent
      values match when their indices are equal.
    @param adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation
      Whether adjacent values match when indices are equal and the next access
      is a read.
    @param access_check The access type consistency check.
    @param next_gate_access_type_is_boolean Whether the next gate access type
      is boolean.
    @param ROM_consistency_check_identity The ROM consistency identity.
    @param RAM_consistency_check_identity The RAM consistency identity.
    @param timestamp_delta The difference between adjacent timestamps.
    @param RAM_timestamp_check_identity The RAM timestamp ordering identity.
    @param memory_identity The combined memory gate identity.
    @param index_is_monotonically_increasing Whether indices increase
      monotonically.
  */
  struct MemParams {
    Fr memory_record_check;
    Fr partial_record_check;
    Fr next_gate_access_type;
    Fr record_delta;
    Fr index_delta;
    Fr adjacent_values_match_if_adjacent_indices_match;
    Fr adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation;
    Fr access_check;
    Fr next_gate_access_type_is_boolean;
    Fr ROM_consistency_check_identity;
    Fr RAM_consistency_check_identity;
    Fr timestamp_delta;
    Fr RAM_timestamp_check_identity;
    Fr memory_identity;
    Fr index_is_monotonically_increasing;
  }

  /**
    Parameters used within the Non-Native Field Relation A struct is used to
    work around stack too deep. This relation has alot of variables

    @param limb_subproduct The product of limb cross-terms.
    @param non_native_field_gate_1 The first non-native field gate identity.
    @param non_native_field_gate_2 The second non-native field gate identity.
    @param non_native_field_gate_3 The third non-native field gate identity.
    @param limb_accumulator_1 The first limb accumulator identity.
    @param limb_accumulator_2 The second limb accumulator identity.
    @param nnf_identity The combined non-native field identity.
  */
  struct NnfParams {
    Fr limb_subproduct;
    Fr non_native_field_gate_1;
    Fr non_native_field_gate_2;
    Fr non_native_field_gate_3;
    Fr limb_accumulator_1;
    Fr limb_accumulator_2;
    Fr nnf_identity;
  }

  /**
    Intermediate values for the Poseidon2 external round relation.

    @param s1 The first state element after round constant addition.
    @param s2 The second state element after round constant addition.
    @param s3 The third state element after round constant addition.
    @param s4 The fourth state element after round constant addition.
    @param u1 The first state element after the S-box.
    @param u2 The second state element after the S-box.
    @param u3 The third state element after the S-box.
    @param u4 The fourth state element after the S-box.
    @param t0 The first MDS matrix intermediate.
    @param t1 The second MDS matrix intermediate.
    @param t2 The third MDS matrix intermediate.
    @param t3 The fourth MDS matrix intermediate.
    @param v1 The first state element after the MDS matrix.
    @param v2 The second state element after the MDS matrix.
    @param v3 The third state element after the MDS matrix.
    @param v4 The fourth state element after the MDS matrix.
    @param q_pos_by_scaling The Poseidon2 external selector scaled by the
      domain separator.
  */
  struct PoseidonExternalParams {
    Fr s1;
    Fr s2;
    Fr s3;
    Fr s4;
    Fr u1;
    Fr u2;
    Fr u3;
    Fr u4;
    Fr t0;
    Fr t1;
    Fr t2;
    Fr t3;
    Fr v1;
    Fr v2;
    Fr v3;
    Fr v4;
    Fr q_pos_by_scaling;
  }

  /**
    Intermediate values for the Poseidon2 internal round relation.

    @param u1 The first state element after the S-box.
    @param u2 The second state element (unchanged).
    @param u3 The third state element (unchanged).
    @param u4 The fourth state element (unchanged).
    @param u_sum The sum of all state elements after the S-box.
    @param v1 The first state element after the internal matrix.
    @param v2 The second state element after the internal matrix.
    @param v3 The third state element after the internal matrix.
    @param v4 The fourth state element after the internal matrix.
    @param s1 The first state element after round constant addition.
    @param q_pos_by_scaling The Poseidon2 internal selector scaled by the
      domain separator.
  */
  struct PoseidonInternalParams {
    Fr u1;
    Fr u2;
    Fr u3;
    Fr u4;
    Fr u_sum;
    Fr v1;
    Fr v2;
    Fr v3;
    Fr v4;
    Fr s1;
    Fr q_pos_by_scaling;
  }

  Fr internal constant GRUMPKIN_CURVE_B_PARAMETER_NEGATED = Fr.wrap(17);

  // The additive inverse of `2^(-1)` in the BN254 scalar field.
  uint256 internal constant NEG_HALF_MODULO_P =
    0x183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000000;

  // Constants for the Non-native Field relation
  Fr constant LIMB_SIZE = Fr.wrap(uint256(1) << 68);

  // The shift between sub-limbs in the non-native field decomposition.
  Fr constant SUBLIMB_SHIFT = Fr.wrap(uint256(1) << 14);

  /**
    Accumulate evaluations of all UltraHonk gate relations and batch them
    using powers of alpha to produce the full Honk relation sum.

    @param _purportedEvaluations The polynomial evaluations from the proof.
    @param _rp The relation parameters from the transcript.
    @param _subrelationChallenges The alpha powers for batching subrelations.
    @param _powPartialEval The partial evaluation of the pow polynomial.

    @return _ The batched relation evaluation.
  */
  function accumulateRelationEvaluations (
    Fr[NUMBER_OF_ENTITIES] memory _purportedEvaluations,
    Honk.RelationParameters memory _rp,
    Fr[NUMBER_OF_ALPHAS] memory _subrelationChallenges,
    Fr _powPartialEval
  ) internal pure returns (Fr) {
    Fr[NUMBER_OF_SUBRELATIONS] memory _evaluations;

    /*
      Accumulate all relations in Ultra Honk - each with varying number of
      subrelations
    */
    accumulateArithmeticRelation(
      _purportedEvaluations, _evaluations, _powPartialEval
    );
    accumulatePermutationRelation(
      _purportedEvaluations, _rp, _evaluations, _powPartialEval
    );
    accumulateLogDerivativeLookupRelation(
      _purportedEvaluations, _rp, _evaluations, _powPartialEval
    );
    accumulateDeltaRangeRelation(
      _purportedEvaluations, _evaluations, _powPartialEval
    );
    accumulateEllipticRelation(
      _purportedEvaluations, _evaluations, _powPartialEval
    );
    accumulateMemoryRelation(
      _purportedEvaluations, _rp, _evaluations, _powPartialEval
    );
    accumulateNnfRelation(_purportedEvaluations, _evaluations, _powPartialEval);
    accumulatePoseidonExternalRelation(
      _purportedEvaluations, _evaluations, _powPartialEval
    );
    accumulatePoseidonInternalRelation(
      _purportedEvaluations, _evaluations, _powPartialEval
    );

    /*
      batch the subrelations with the precomputed alpha powers to obtain the
      full honk relation
    */
    return scaleAndBatchSubrelations(_evaluations, _subrelationChallenges);
  }

  /**
    Aesthetic helper function that is used to index by enum into
    proof.sumcheckEvaluations, it avoids the relation checking code being
    cluttered with uint256 type casting, which is often a different colour in
    code editors, and thus is noisy.

    @param _p The array of polynomial evaluations.
    @param _wire The wire index to look up.

    @return _ The evaluation at the specified wire index.
  */
  function wire (
    Fr[NUMBER_OF_ENTITIES] memory _p,
    WIRE _wire
  ) internal pure returns (Fr) {
    return _p[uint256(_wire)];
  }

  /**
    Evaluate the arithmetic gate relation and accumulate its two
    subrelation contributions.

    @param _p The array of polynomial evaluations.
    @param _evals The subrelation accumulator array.
    @param _domainSep The domain separator (pow partial evaluation).
  */
  function accumulateArithmeticRelation (
    Fr[NUMBER_OF_ENTITIES] memory _p,
    Fr[NUMBER_OF_SUBRELATIONS] memory _evals,
    Fr _domainSep
  ) internal pure {

    // Relation 0
    Fr _q_arith = wire(_p, WIRE.Q_ARITH);
    {
      Fr _neg_half = Fr.wrap(NEG_HALF_MODULO_P);
      Fr _accum =
        (_q_arith - Fr.wrap(3)) * (
          wire(_p, WIRE.Q_M) * wire(_p, WIRE.W_R) * wire(_p, WIRE.W_L)
        ) * _neg_half;
      _accum = _accum + (wire(_p, WIRE.Q_L) * wire(_p, WIRE.W_L)) + (
        wire(_p, WIRE.Q_R) * wire(_p, WIRE.W_R)
      ) + (wire(_p, WIRE.Q_O) * wire(_p, WIRE.W_O)) + (
        wire(_p, WIRE.Q_4) * wire(_p, WIRE.W_4)
      ) + wire(_p, WIRE.Q_C);
      _accum = _accum + (_q_arith - ONE) * wire(_p, WIRE.W_4_SHIFT);
      _accum = _accum * _q_arith;
      _accum = _accum * _domainSep;
      _evals[0] = _accum;
    }

    // Relation 1
    {
      Fr _accum =
        wire(_p, WIRE.W_L) + wire(_p, WIRE.W_4) - wire(_p, WIRE.W_L_SHIFT) +
        wire(
          _p, WIRE.Q_M
        );
      _accum = _accum * (_q_arith - Fr.wrap(2));
      _accum = _accum * (_q_arith - ONE);
      _accum = _accum * _q_arith;
      _accum = _accum * _domainSep;
      _evals[1] = _accum;
    }
  }

  /**
    Evaluate the grand product permutation relation and accumulate its
    subrelation contributions.

    @param _p The array of polynomial evaluations.
    @param _rp The relation parameters containing beta and gamma.
    @param _evals The subrelation accumulator array.
    @param _domainSep The domain separator (pow partial evaluation).
  */
  function accumulatePermutationRelation (
    Fr[NUMBER_OF_ENTITIES] memory _p,
    Honk.RelationParameters memory _rp,
    Fr[NUMBER_OF_SUBRELATIONS] memory _evals,
    Fr _domainSep
  ) internal pure {
    Fr _grand_product_numerator;
    Fr _grand_product_denominator;
    {
      Fr _num =
        wire(_p, WIRE.W_L) + wire(_p, WIRE.ID_1) * _rp.beta + _rp.gamma;
      _num = _num * (
        wire(_p, WIRE.W_R) + wire(_p, WIRE.ID_2) * _rp.beta + _rp.gamma
      );
      _num = _num * (
        wire(_p, WIRE.W_O) + wire(_p, WIRE.ID_3) * _rp.beta + _rp.gamma
      );
      _num = _num * (
        wire(_p, WIRE.W_4) + wire(_p, WIRE.ID_4) * _rp.beta + _rp.gamma
      );
      _grand_product_numerator = _num;
    }
    {
      Fr _den =
        wire(_p, WIRE.W_L) + wire(_p, WIRE.SIGMA_1) * _rp.beta + _rp.gamma;
      _den = _den * (
        wire(_p, WIRE.W_R) + wire(_p, WIRE.SIGMA_2) * _rp.beta + _rp.gamma
      );
      _den = _den * (
        wire(_p, WIRE.W_O) + wire(_p, WIRE.SIGMA_3) * _rp.beta + _rp.gamma
      );
      _den = _den * (
        wire(_p, WIRE.W_4) + wire(_p, WIRE.SIGMA_4) * _rp.beta + _rp.gamma
      );
      _grand_product_denominator = _den;
    }

    // Contribution 2
    {
      Fr _acc =
        (wire(_p, WIRE.Z_PERM) + wire(_p, WIRE.LAGRANGE_FIRST)) *
        _grand_product_numerator;
      _acc = _acc - (
        (
          wire(_p, WIRE.Z_PERM_SHIFT) + (
            wire(_p, WIRE.LAGRANGE_LAST) * _rp.publicInputsDelta
          )
        ) * _grand_product_denominator
      );
      _acc = _acc * _domainSep;
      _evals[2] = _acc;
    }

    // Contribution 3
    {
      Fr _acc =
        (wire(_p, WIRE.LAGRANGE_LAST) * wire(_p, WIRE.Z_PERM_SHIFT)) *
        _domainSep;
      _evals[3] = _acc;
    }
  }

  /**
    Evaluate the log-derivative lookup relation and accumulate its
    subrelation contributions.

    @param _p The array of polynomial evaluations.
    @param _rp The relation parameters containing eta and gamma.
    @param _evals The subrelation accumulator array.
    @param _domainSep The domain separator (pow partial evaluation).
  */
  function accumulateLogDerivativeLookupRelation (
    Fr[NUMBER_OF_ENTITIES] memory _p,
    Honk.RelationParameters memory _rp,
    Fr[NUMBER_OF_SUBRELATIONS] memory _evals,
    Fr _domainSep
  ) internal pure {
    Fr _write_term;
    Fr _read_term;

    // Calculate the write term (the table accumulation)
    {
      _write_term = wire(_p, WIRE.TABLE_1) + _rp.gamma + (
        wire(_p, WIRE.TABLE_2) * _rp.eta
      ) + (wire(_p, WIRE.TABLE_3) * _rp.etaTwo) + (
        wire(_p, WIRE.TABLE_4) * _rp.etaThree
      );
    }

    // Calculate the write term
    {
      Fr _derived_entry_1 =
        wire(_p, WIRE.W_L) + _rp.gamma + (
          wire(_p, WIRE.Q_R) * wire(_p, WIRE.W_L_SHIFT)
        );
      Fr _derived_entry_2 =
        wire(_p, WIRE.W_R) + wire(_p, WIRE.Q_M) * wire(_p, WIRE.W_R_SHIFT);
      Fr _derived_entry_3 =
        wire(_p, WIRE.W_O) + wire(_p, WIRE.Q_C) * wire(_p, WIRE.W_O_SHIFT);
      _read_term = _derived_entry_1 + (_derived_entry_2 * _rp.eta) + (
        _derived_entry_3 * _rp.etaTwo
      ) + (wire(_p, WIRE.Q_O) * _rp.etaThree);
    }
    Fr _read_inverse = wire(_p, WIRE.LOOKUP_INVERSES) * _write_term;
    Fr _write_inverse = wire(_p, WIRE.LOOKUP_INVERSES) * _read_term;
    Fr _inverse_exists_xor =
      wire(_p, WIRE.LOOKUP_READ_TAGS) + wire(_p, WIRE.Q_LOOKUP) - (
        wire(_p, WIRE.LOOKUP_READ_TAGS) * wire(_p, WIRE.Q_LOOKUP)
      );

    // Inverse calculated correctly relation
    Fr _accumulatorNone =
      _read_term * _write_term * wire(_p, WIRE.LOOKUP_INVERSES) -
      _inverse_exists_xor;
    _accumulatorNone = _accumulatorNone * _domainSep;

    // Inverse
    Fr _accumulatorOne =
      wire(_p, WIRE.Q_LOOKUP) * _read_inverse - wire(
        _p, WIRE.LOOKUP_READ_COUNTS
      ) * _write_inverse;
    Fr _read_tag = wire(_p, WIRE.LOOKUP_READ_TAGS);
    Fr _read_tag_boolean_relation = _read_tag * _read_tag - _read_tag;
    _evals[4] = _accumulatorNone;
    _evals[5] = _accumulatorOne;
    _evals[6] = _read_tag_boolean_relation * _domainSep;
  }

  /**
    Evaluate the delta range constraint relation, which enforces that
    consecutive wire differences are in `{0, 1, 2, 3}`.

    @param _p The array of polynomial evaluations.
    @param _evals The subrelation accumulator array.
    @param _domainSep The domain separator (pow partial evaluation).
  */
  function accumulateDeltaRangeRelation (
    Fr[NUMBER_OF_ENTITIES] memory _p,
    Fr[NUMBER_OF_SUBRELATIONS] memory _evals,
    Fr _domainSep
  ) internal pure {
    Fr _minus_one = ZERO - ONE;
    Fr _minus_two = ZERO - Fr.wrap(2);
    Fr _minus_three = ZERO - Fr.wrap(3);

    // Compute wire differences
    Fr _delta_1 = wire(_p, WIRE.W_R) - wire(_p, WIRE.W_L);
    Fr _delta_2 = wire(_p, WIRE.W_O) - wire(_p, WIRE.W_R);
    Fr _delta_3 = wire(_p, WIRE.W_4) - wire(_p, WIRE.W_O);
    Fr _delta_4 = wire(_p, WIRE.W_L_SHIFT) - wire(_p, WIRE.W_4);

    // Contribution 6
    {
      Fr _acc = _delta_1;
      _acc = _acc * (_delta_1 + _minus_one);
      _acc = _acc * (_delta_1 + _minus_two);
      _acc = _acc * (_delta_1 + _minus_three);
      _acc = _acc * wire(_p, WIRE.Q_RANGE);
      _acc = _acc * _domainSep;
      _evals[7] = _acc;
    }

    // Contribution 7
    {
      Fr _acc = _delta_2;
      _acc = _acc * (_delta_2 + _minus_one);
      _acc = _acc * (_delta_2 + _minus_two);
      _acc = _acc * (_delta_2 + _minus_three);
      _acc = _acc * wire(_p, WIRE.Q_RANGE);
      _acc = _acc * _domainSep;
      _evals[8] = _acc;
    }

    // Contribution 8
    {
      Fr _acc = _delta_3;
      _acc = _acc * (_delta_3 + _minus_one);
      _acc = _acc * (_delta_3 + _minus_two);
      _acc = _acc * (_delta_3 + _minus_three);
      _acc = _acc * wire(_p, WIRE.Q_RANGE);
      _acc = _acc * _domainSep;
      _evals[9] = _acc;
    }

    // Contribution 9
    {
      Fr _acc = _delta_4;
      _acc = _acc * (_delta_4 + _minus_one);
      _acc = _acc * (_delta_4 + _minus_two);
      _acc = _acc * (_delta_4 + _minus_three);
      _acc = _acc * wire(_p, WIRE.Q_RANGE);
      _acc = _acc * _domainSep;
      _evals[10] = _acc;
    }
  }

  /**
    Evaluate the elliptic curve point addition and doubling gate relation.

    @param _p The array of polynomial evaluations.
    @param _evals The subrelation accumulator array.
    @param _domainSep The domain separator (pow partial evaluation).
  */
  function accumulateEllipticRelation (
    Fr[NUMBER_OF_ENTITIES] memory _p,
    Fr[NUMBER_OF_SUBRELATIONS] memory _evals,
    Fr _domainSep
  ) internal pure {
    EllipticParams memory _ep;
    _ep.x_1 = wire(_p, WIRE.W_R);
    _ep.y_1 = wire(_p, WIRE.W_O);
    _ep.x_2 = wire(_p, WIRE.W_L_SHIFT);
    _ep.y_2 = wire(_p, WIRE.W_4_SHIFT);
    _ep.y_3 = wire(_p, WIRE.W_O_SHIFT);
    _ep.x_3 = wire(_p, WIRE.W_R_SHIFT);
    Fr _q_sign = wire(_p, WIRE.Q_L);
    Fr _q_is_double = wire(_p, WIRE.Q_M);

    /*
      Contribution 10 point addition, x-coordinate check q_elliptic * (x3 + x2 +
      x1)(x2 - x1)(x2 - x1) - y2^2 - y1^2 + 2(y2y1)*q_sign = 0
    */
    Fr _x_diff = (_ep.x_2 - _ep.x_1);
    Fr _y1_sqr = (_ep.y_1 * _ep.y_1);
    {
      // Move to top
      Fr _partialEval = _domainSep;
      Fr _y2_sqr = (_ep.y_2 * _ep.y_2);
      Fr _y1y2 = _ep.y_1 * _ep.y_2 * _q_sign;
      Fr _x_add_identity = (_ep.x_3 + _ep.x_2 + _ep.x_1);
      _x_add_identity = _x_add_identity * _x_diff * _x_diff;
      _x_add_identity = _x_add_identity - _y2_sqr - _y1_sqr + _y1y2 + _y1y2;
      _evals[11] = _x_add_identity * _partialEval * wire(_p, WIRE.Q_ELLIPTIC) *
      (
        ONE - _q_is_double
      );
    }

    /*
      Contribution 11 point addition, x-coordinate check q_elliptic * (q_sign *
      y1 + y3)(x2 - x1) + (x3 - x1)(y2 - q_sign * y1) = 0
    */
    {
      Fr _y1_plus_y3 = _ep.y_1 + _ep.y_3;
      Fr _y_diff = _ep.y_2 * _q_sign - _ep.y_1;
      Fr _y_add_identity =
        _y1_plus_y3 * _x_diff + (_ep.x_3 - _ep.x_1) * _y_diff;
      _evals[12] = _y_add_identity * _domainSep * wire(_p, WIRE.Q_ELLIPTIC) * (
        ONE - _q_is_double
      );
    }

    /*
      Contribution 10 point doubling, x-coordinate check (x3 + x1 + x1) (4y1*y1)
      - 9 * x1 * x1 * x1 * x1 = 0 N.B. we're using the equivalence x1*x1*x1 ===
      y1*y1 - curve_b to reduce degree by 1
    */
    {
      Fr _x_pow_4 = (_y1_sqr + GRUMPKIN_CURVE_B_PARAMETER_NEGATED) * _ep.x_1;
      Fr _y1_sqr_mul_4 = _y1_sqr + _y1_sqr;
      _y1_sqr_mul_4 = _y1_sqr_mul_4 + _y1_sqr_mul_4;
      Fr _x1_pow_4_mul_9 = _x_pow_4 * Fr.wrap(9);
      // NOTE: pushed into memory (stack >:'( )
      _ep.x_double_identity = (_ep.x_3 + _ep.x_1 + _ep.x_1) * _y1_sqr_mul_4 -
      _x1_pow_4_mul_9;
      Fr _acc =
        _ep.x_double_identity * _domainSep * wire(_p, WIRE.Q_ELLIPTIC) *
        _q_is_double;
      _evals[11] = _evals[11] + _acc;
    }

    /*
      Contribution 11 point doubling, y-coordinate check (y1 + y1) (2y1) - (3 *
      x1 * x1)(x1 - x3) = 0
    */
    {
      Fr _x1_sqr_mul_3 = (_ep.x_1 + _ep.x_1 + _ep.x_1) * _ep.x_1;
      Fr _y_double_identity =
        _x1_sqr_mul_3 * (_ep.x_1 - _ep.x_3) - (_ep.y_1 + _ep.y_1) * (
          _ep.y_1 + _ep.y_3
        );
      _evals[12] = _evals[12] + _y_double_identity * _domainSep * wire(
        _p, WIRE.Q_ELLIPTIC
      ) * _q_is_double;
    }
  }

  /**
    Evaluate the RAM/ROM memory gate relation and accumulate its
    subrelation contributions.

    @param _p The array of polynomial evaluations.
    @param _rp The relation parameters containing eta challenges.
    @param _evals The subrelation accumulator array.
    @param _domainSep The domain separator (pow partial evaluation).
  */
  function accumulateMemoryRelation (
    Fr[NUMBER_OF_ENTITIES] memory _p,
    Honk.RelationParameters memory _rp,
    Fr[NUMBER_OF_SUBRELATIONS] memory _evals,
    Fr _domainSep
  ) internal pure {
    MemParams memory _ap;

    /**
      * Memory Record Check
      * Partial degree: 1
      * Total degree: 4
      *
      * A ROM/ROM access gate can be evaluated with the identity:
      *
      * qc + w1 \eta + w2 \eta_two + w3 \eta_three - w4 = 0
      *
      * For ROM gates, qc = 0
    */
    _ap.memory_record_check = wire(_p, WIRE.W_O) * _rp.etaThree;
    _ap.memory_record_check = _ap.memory_record_check + (
      wire(_p, WIRE.W_R) * _rp.etaTwo
    );
    _ap.memory_record_check = _ap.memory_record_check + (
      wire(_p, WIRE.W_L) * _rp.eta
    );
    _ap.memory_record_check = _ap.memory_record_check + wire(_p, WIRE.Q_C);

    // used in RAM consistency check; deg 1 or 4
    _ap.partial_record_check = _ap.memory_record_check;
    _ap.memory_record_check = _ap.memory_record_check - wire(_p, WIRE.W_4);

    /**
      * Contribution 13 & 14
      * ROM Consistency Check
      * Partial degree: 1
      * Total degree: 4
      *
      * For every ROM read, a set equivalence check is applied between the record witnesses, and a second set of
      * records that are sorted.
      *
      * We apply the following checks for the sorted records:
      *
      * 1. w1, w2, w3 correctly map to 'index', 'v1, 'v2' for a given record value at w4
      * 2. index values for adjacent records are monotonically increasing
      * 3. if, at gate i, index_i == index_{i + 1}, then value1_i == value1_{i + 1} and value2_i == value2_{i + 1}
      *
    */
    _ap.index_delta = wire(_p, WIRE.W_L_SHIFT) - wire(_p, WIRE.W_L);
    _ap.record_delta = wire(_p, WIRE.W_4_SHIFT) - wire(_p, WIRE.W_4);

    // deg 2
    _ap.index_is_monotonically_increasing = _ap.index_delta * (
      _ap.index_delta - Fr.wrap(1)
    );

    // deg 2
    _ap.adjacent_values_match_if_adjacent_indices_match = (
      _ap.index_delta * MINUS_ONE + ONE
    ) * _ap.record_delta;

    // deg 5
    _evals[14] = _ap.adjacent_values_match_if_adjacent_indices_match * (
      wire(_p, WIRE.Q_L) * wire(_p, WIRE.Q_R)
    ) * (wire(_p, WIRE.Q_MEMORY) * _domainSep);

    // deg 5
    _evals[15] = _ap.index_is_monotonically_increasing * (
      wire(_p, WIRE.Q_L) * wire(_p, WIRE.Q_R)
    ) * (wire(_p, WIRE.Q_MEMORY) * _domainSep);

    // deg 3 or 7
    _ap.ROM_consistency_check_identity = _ap.memory_record_check * (
      wire(_p, WIRE.Q_L) * wire(_p, WIRE.Q_R)
    );

    /**
      * Contributions 15,16,17
      * RAM Consistency Check
      *
      * The 'access' type of the record is extracted with the expression `w_4 - ap.partial_record_check`
      * (i.e. for an honest Prover `w1 * eta + w2 * eta^2 + w3 * eta^3 - w4 = access`.
      * This is validated by requiring `access` to be boolean
      *
      * For two adjacent entries in the sorted list if _both_
      *  A) index values match
      *  B) adjacent access value is 0 (i.e. next gate is a READ)
      * then
      *  C) both values must match.
      * The gate boolean check is
      * (A && B) => C  === !(A && B) || C ===  !A || !B || C
      *
      * N.B. it is the responsibility of the circuit writer to ensure that every RAM cell is initialized
      * with a WRITE operation.
    */

    // will be 0 or 1 for honest Prover; deg 1 or 4
    Fr _access_type = (wire(_p, WIRE.W_4) - _ap.partial_record_check);

    // check value is 0 or 1; deg 2 or 8
    _ap.access_check = _access_type * (_access_type - Fr.wrap(1));

    /*
      reverse order we could re-use `ap.partial_record_check` 1 - ((w3' * eta +
      w2') * eta + w1') * eta deg 1 or 4
    */
    _ap.next_gate_access_type = wire(_p, WIRE.W_O_SHIFT) * _rp.etaThree;
    _ap.next_gate_access_type = _ap.next_gate_access_type + (
      wire(_p, WIRE.W_R_SHIFT) * _rp.etaTwo
    );
    _ap.next_gate_access_type = _ap.next_gate_access_type + (
      wire(_p, WIRE.W_L_SHIFT) * _rp.eta
    );
    _ap.next_gate_access_type = wire(_p, WIRE.W_4_SHIFT) -
    _ap.next_gate_access_type;
    Fr _value_delta = wire(_p, WIRE.W_O_SHIFT) - wire(_p, WIRE.W_O);

    // deg 3 or 6
    _ap.adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation
     = (_ap.index_delta * MINUS_ONE + ONE) * _value_delta * (
      _ap.next_gate_access_type * MINUS_ONE + ONE
    );

    /*
      We can't apply the RAM consistency check identity on the final entry in
      the sorted list (the wires in the next gate would make the identity fail).
      We need to validate that its 'access type' bool is correct. Can't do with
      an arithmetic gate because of the `eta` factors. We need to check that the
      *next* gate's access type is correct, to cover this edge case deg 2 or 4
    */
    _ap.next_gate_access_type_is_boolean = _ap.next_gate_access_type *
    _ap.next_gate_access_type - _ap.next_gate_access_type;

    // Putting it all together... deg 5 or 8
    _evals[16] =
    _ap.adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation
     * (wire(_p, WIRE.Q_O)) * (wire(_p, WIRE.Q_MEMORY) * _domainSep);

    // deg 4
    _evals[17] = _ap.index_is_monotonically_increasing * (wire(_p, WIRE.Q_O)) *
    (
      wire(_p, WIRE.Q_MEMORY) * _domainSep
    );

    // deg 4 or 6
    _evals[18] = _ap.next_gate_access_type_is_boolean * (wire(_p, WIRE.Q_O)) * (
      wire(_p, WIRE.Q_MEMORY) * _domainSep
    );

    // deg 3 or 9
    _ap.RAM_consistency_check_identity = _ap.access_check * (
      wire(_p, WIRE.Q_O)
    );

    /**
      * RAM Timestamp Consistency Check
      *
      * | w1 | w2 | w3 | w4 |
      * | index | timestamp | timestamp_check | -- |
      *
      * Let delta_index = index_{i + 1} - index_{i}
      *
      * Iff delta_index == 0, timestamp_check = timestamp_{i + 1} - timestamp_i
      * Else timestamp_check = 0
    */
    _ap.timestamp_delta = wire(_p, WIRE.W_R_SHIFT) - wire(_p, WIRE.W_R);

    // deg 3
    _ap.RAM_timestamp_check_identity = (_ap.index_delta * MINUS_ONE + ONE) *
    _ap.timestamp_delta - wire(_p, WIRE.W_O);

    /**
      * Complete Contribution 12
      * The complete RAM/ROM memory identity
      * Partial degree:
    */

    // deg 3 or 6
    _ap.memory_identity = _ap.ROM_consistency_check_identity;

    // deg 4
    _ap.memory_identity = _ap.memory_identity + _ap.RAM_timestamp_check_identity
     * (wire(_p, WIRE.Q_4) * wire(_p, WIRE.Q_L));

    // deg 3 or 6
    _ap.memory_identity = _ap.memory_identity + _ap.memory_record_check * (
      wire(_p, WIRE.Q_M) * wire(_p, WIRE.Q_L)
    );

    // deg 3 or 9
    _ap.memory_identity = _ap.memory_identity +
    _ap.RAM_consistency_check_identity;

    // (deg 3 or 9) + (deg 4) + (deg 3) deg 4 or 10
    _ap.memory_identity = _ap.memory_identity * (
      wire(_p, WIRE.Q_MEMORY) * _domainSep
    );
    _evals[13] = _ap.memory_identity;
  }

  /**
    Evaluate the non-native field arithmetic gate relation and accumulate
    its subrelation contributions.

    @param _p The array of polynomial evaluations.
    @param _evals The subrelation accumulator array.
    @param _domainSep The domain separator (pow partial evaluation).
  */
  function accumulateNnfRelation (
    Fr[NUMBER_OF_ENTITIES] memory _p,
    Fr[NUMBER_OF_SUBRELATIONS] memory _evals,
    Fr _domainSep
  ) internal pure {
    NnfParams memory _ap;

    /**
      * Contribution 12
      * Non native field arithmetic gate 2
      * deg 4
      *
      *             _                                                                               _
      *            /   _                   _                               _       14                \
      * q_2 . q_4 |   (w_1 . w_2) + (w_1 . w_2) + (w_1 . w_4 + w_2 . w_3 - w_3) . 2    - w_3 - w_4   |
      *            \_                                                                               _/
      *
      *
    */
    _ap.limb_subproduct = wire(_p, WIRE.W_L) * wire(_p, WIRE.W_R_SHIFT) + wire(
      _p, WIRE.W_L_SHIFT
    ) * wire(_p, WIRE.W_R);
    _ap.non_native_field_gate_2 = (
      wire(_p, WIRE.W_L) * wire(_p, WIRE.W_4) + wire(_p, WIRE.W_R) * wire(
        _p, WIRE.W_O
      ) - wire(_p, WIRE.W_O_SHIFT)
    );
    _ap.non_native_field_gate_2 = _ap.non_native_field_gate_2 * LIMB_SIZE;
    _ap.non_native_field_gate_2 = _ap.non_native_field_gate_2 - wire(
      _p, WIRE.W_4_SHIFT
    );
    _ap.non_native_field_gate_2 = _ap.non_native_field_gate_2 +
    _ap.limb_subproduct;
    _ap.non_native_field_gate_2 = _ap.non_native_field_gate_2 * wire(
      _p, WIRE.Q_4
    );
    _ap.limb_subproduct = _ap.limb_subproduct * LIMB_SIZE;
    _ap.limb_subproduct = _ap.limb_subproduct + (
      wire(_p, WIRE.W_L_SHIFT) * wire(_p, WIRE.W_R_SHIFT)
    );
    _ap.non_native_field_gate_1 = _ap.limb_subproduct;
    _ap.non_native_field_gate_1 = _ap.non_native_field_gate_1 - (
      wire(_p, WIRE.W_O) + wire(_p, WIRE.W_4)
    );
    _ap.non_native_field_gate_1 = _ap.non_native_field_gate_1 * wire(
      _p, WIRE.Q_O
    );
    _ap.non_native_field_gate_3 = _ap.limb_subproduct;
    _ap.non_native_field_gate_3 = _ap.non_native_field_gate_3 + wire(
      _p, WIRE.W_4
    );
    _ap.non_native_field_gate_3 = _ap.non_native_field_gate_3 - (
      wire(_p, WIRE.W_O_SHIFT) + wire(_p, WIRE.W_4_SHIFT)
    );
    _ap.non_native_field_gate_3 = _ap.non_native_field_gate_3 * wire(
      _p, WIRE.Q_M
    );
    Fr _non_native_field_identity =
      _ap.non_native_field_gate_1 + _ap.non_native_field_gate_2 +
      _ap.non_native_field_gate_3;
    _non_native_field_identity = _non_native_field_identity * wire(
      _p, WIRE.Q_R
    );

    /*
      ((((w2' * 2^14 + w1') * 2^14 + w3) * 2^14 + w2) * 2^14 + w1 - w4) * qm deg
      2
    */
    _ap.limb_accumulator_1 = wire(_p, WIRE.W_R_SHIFT) * SUBLIMB_SHIFT;
    _ap.limb_accumulator_1 = _ap.limb_accumulator_1 + wire(_p, WIRE.W_L_SHIFT);
    _ap.limb_accumulator_1 = _ap.limb_accumulator_1 * SUBLIMB_SHIFT;
    _ap.limb_accumulator_1 = _ap.limb_accumulator_1 + wire(_p, WIRE.W_O);
    _ap.limb_accumulator_1 = _ap.limb_accumulator_1 * SUBLIMB_SHIFT;
    _ap.limb_accumulator_1 = _ap.limb_accumulator_1 + wire(_p, WIRE.W_R);
    _ap.limb_accumulator_1 = _ap.limb_accumulator_1 * SUBLIMB_SHIFT;
    _ap.limb_accumulator_1 = _ap.limb_accumulator_1 + wire(_p, WIRE.W_L);
    _ap.limb_accumulator_1 = _ap.limb_accumulator_1 - wire(_p, WIRE.W_4);
    _ap.limb_accumulator_1 = _ap.limb_accumulator_1 * wire(_p, WIRE.Q_4);

    /*
      ((((w3' * 2^14 + w2') * 2^14 + w1') * 2^14 + w4) * 2^14 + w3 - w4') * qm
      deg 2
    */
    _ap.limb_accumulator_2 = wire(_p, WIRE.W_O_SHIFT) * SUBLIMB_SHIFT;
    _ap.limb_accumulator_2 = _ap.limb_accumulator_2 + wire(_p, WIRE.W_R_SHIFT);
    _ap.limb_accumulator_2 = _ap.limb_accumulator_2 * SUBLIMB_SHIFT;
    _ap.limb_accumulator_2 = _ap.limb_accumulator_2 + wire(_p, WIRE.W_L_SHIFT);
    _ap.limb_accumulator_2 = _ap.limb_accumulator_2 * SUBLIMB_SHIFT;
    _ap.limb_accumulator_2 = _ap.limb_accumulator_2 + wire(_p, WIRE.W_4);
    _ap.limb_accumulator_2 = _ap.limb_accumulator_2 * SUBLIMB_SHIFT;
    _ap.limb_accumulator_2 = _ap.limb_accumulator_2 + wire(_p, WIRE.W_O);
    _ap.limb_accumulator_2 = _ap.limb_accumulator_2 - wire(_p, WIRE.W_4_SHIFT);
    _ap.limb_accumulator_2 = _ap.limb_accumulator_2 * wire(_p, WIRE.Q_M);
    Fr _limb_accumulator_identity =
      _ap.limb_accumulator_1 + _ap.limb_accumulator_2;

    // deg 3
    _limb_accumulator_identity = _limb_accumulator_identity * wire(
      _p, WIRE.Q_O
    );
    _ap.nnf_identity = _non_native_field_identity + _limb_accumulator_identity;
    _ap.nnf_identity = _ap.nnf_identity * (wire(_p, WIRE.Q_NNF) * _domainSep);
    _evals[19] = _ap.nnf_identity;
  }

  /**
    Evaluate the Poseidon2 external round gate relation and accumulate its
    subrelation contributions.

    @param _p The array of polynomial evaluations.
    @param _evals The subrelation accumulator array.
    @param _domainSep The domain separator (pow partial evaluation).
  */
  function accumulatePoseidonExternalRelation (
    Fr[NUMBER_OF_ENTITIES] memory _p,
    Fr[NUMBER_OF_SUBRELATIONS] memory _evals,
    Fr _domainSep
  ) internal pure {
    PoseidonExternalParams memory _ep;
    _ep.s1 = wire(_p, WIRE.W_L) + wire(_p, WIRE.Q_L);
    _ep.s2 = wire(_p, WIRE.W_R) + wire(_p, WIRE.Q_R);
    _ep.s3 = wire(_p, WIRE.W_O) + wire(_p, WIRE.Q_O);
    _ep.s4 = wire(_p, WIRE.W_4) + wire(_p, WIRE.Q_4);
    _ep.u1 = _ep.s1 * _ep.s1 * _ep.s1 * _ep.s1 * _ep.s1;
    _ep.u2 = _ep.s2 * _ep.s2 * _ep.s2 * _ep.s2 * _ep.s2;
    _ep.u3 = _ep.s3 * _ep.s3 * _ep.s3 * _ep.s3 * _ep.s3;
    _ep.u4 = _ep.s4 * _ep.s4 * _ep.s4 * _ep.s4 * _ep.s4;

    // matrix mul v = M_E * u with 14 additions u_1 + u_2
    _ep.t0 = _ep.u1 + _ep.u2;

    // u_3 + u_4
    _ep.t1 = _ep.u3 + _ep.u4;

    // 2u_2
    _ep.t2 = _ep.u2 + _ep.u2 + _ep.t1;

    // ep.t2 += ep.t1; // 2u_2 + u_3 + u_4 2u_4
    _ep.t3 = _ep.u4 + _ep.u4 + _ep.t0;

    // ep.t3 += ep.t0; // u_1 + u_2 + 2u_4
    _ep.v4 = _ep.t1 + _ep.t1;
    _ep.v4 = _ep.v4 + _ep.v4 + _ep.t3;

    // ep.v4 += ep.t3; // u_1 + u_2 + 4u_3 + 6u_4
    _ep.v2 = _ep.t0 + _ep.t0;
    _ep.v2 = _ep.v2 + _ep.v2 + _ep.t2;

    // ep.v2 += ep.t2; // 4u_1 + 6u_2 + u_3 + u_4 5u_1 + 7u_2 + u_3 + 3u_4
    _ep.v1 = _ep.t3 + _ep.v2;

    // u_1 + 3u_2 + 5u_3 + 7u_4
    _ep.v3 = _ep.t2 + _ep.v4;
    _ep.q_pos_by_scaling = wire(_p, WIRE.Q_POSEIDON2_EXTERNAL) * _domainSep;
    _evals[20] = _evals[20] + _ep.q_pos_by_scaling * (
      _ep.v1 - wire(_p, WIRE.W_L_SHIFT)
    );
    _evals[21] = _evals[21] + _ep.q_pos_by_scaling * (
      _ep.v2 - wire(_p, WIRE.W_R_SHIFT)
    );
    _evals[22] = _evals[22] + _ep.q_pos_by_scaling * (
      _ep.v3 - wire(_p, WIRE.W_O_SHIFT)
    );
    _evals[23] = _evals[23] + _ep.q_pos_by_scaling * (
      _ep.v4 - wire(_p, WIRE.W_4_SHIFT)
    );
  }

  /**
    Evaluate the Poseidon2 internal round gate relation and accumulate its
    subrelation contributions.

    @param _p The array of polynomial evaluations.
    @param _evals The subrelation accumulator array.
    @param _domainSep The domain separator (pow partial evaluation).
  */
  function accumulatePoseidonInternalRelation (
    Fr[NUMBER_OF_ENTITIES] memory _p,
    Fr[NUMBER_OF_SUBRELATIONS] memory _evals,
    Fr _domainSep
  ) internal pure {
    PoseidonInternalParams memory _ip;
    Fr[4] memory _INTERNAL_MATRIX_DIAGONAL =
      [FrLib.from(
        0x10dc6e9c006ea38b04b1e03b4bd9490c0d03f98929ca1d7fb56821fd19d3b6e7
      ),
      FrLib.from(
        0x0c28145b6a44df3e0149b3d0a30b3bb599df9756d4dd9b84a86b38cfb45a740b
      ),
      FrLib.from(
        0x00544b8338791518b2c7645a50392798b21f75bb60e3596170067d00141cac15
      ),
      FrLib.from(
        0x222c01175718386f2e2e82eb122789e352e105a3b8fa852613bc534433ee428b
      )];

    // add round constants
    _ip.s1 = wire(_p, WIRE.W_L) + wire(_p, WIRE.Q_L);

    // apply s-box round
    _ip.u1 = _ip.s1 * _ip.s1 * _ip.s1 * _ip.s1 * _ip.s1;
    _ip.u2 = wire(_p, WIRE.W_R);
    _ip.u3 = wire(_p, WIRE.W_O);
    _ip.u4 = wire(_p, WIRE.W_4);

    // matrix mul with v = M_I * u 4 muls and 7 additions
    _ip.u_sum = _ip.u1 + _ip.u2 + _ip.u3 + _ip.u4;
    _ip.q_pos_by_scaling = wire(_p, WIRE.Q_POSEIDON2_INTERNAL) * _domainSep;
    _ip.v1 = _ip.u1 * _INTERNAL_MATRIX_DIAGONAL[0] + _ip.u_sum;
    _evals[24] = _evals[24] + _ip.q_pos_by_scaling * (
      _ip.v1 - wire(_p, WIRE.W_L_SHIFT)
    );
    _ip.v2 = _ip.u2 * _INTERNAL_MATRIX_DIAGONAL[1] + _ip.u_sum;
    _evals[25] = _evals[25] + _ip.q_pos_by_scaling * (
      _ip.v2 - wire(_p, WIRE.W_R_SHIFT)
    );
    _ip.v3 = _ip.u3 * _INTERNAL_MATRIX_DIAGONAL[2] + _ip.u_sum;
    _evals[26] = _evals[26] + _ip.q_pos_by_scaling * (
      _ip.v3 - wire(_p, WIRE.W_O_SHIFT)
    );
    _ip.v4 = _ip.u4 * _INTERNAL_MATRIX_DIAGONAL[3] + _ip.u_sum;
    _evals[27] = _evals[27] + _ip.q_pos_by_scaling * (
      _ip.v4 - wire(_p, WIRE.W_4_SHIFT)
    );
  }

  /**
    Batch subrelation evaluations using precomputed powers of alpha First subrelation is implicitly scaled by 1, subsequent ones use powers from the subrelationChallenges array

    @param _evaluations The per-subrelation evaluation results.
    @param _subrelationChallenges The alpha powers for batching.

    @return _ The linearly combined relation evaluation.
  */
  function scaleAndBatchSubrelations (
    Fr[NUMBER_OF_SUBRELATIONS] memory _evaluations,
    Fr[NUMBER_OF_ALPHAS] memory _subrelationChallenges
  ) internal pure returns (Fr) {
    Fr _accumulator = _evaluations[0];
    for (uint256 i = 1; i < NUMBER_OF_SUBRELATIONS; ++i) {
      _accumulator = _accumulator + _evaluations[i] * _subrelationChallenges[
        i - 1
      ];
    }
    return _accumulator;
  }
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title CommitmentSchemeLib
  @author Aztec
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  This library implements the Shplemini polynomial commitment scheme used to
  batch-verify multilinear polynomial openings. It computes the scalar
  multipliers and constant term accumulator needed for the final KZG pairing
  check.

  @custom:date February 24th, 2026.
*/
library CommitmentSchemeLib {

  using FrLib for Fr;

  /**
    Avoid stack too deep

    @param unshiftedScalar The scalar for unshifted polynomial commitments.
    @param shiftedScalar The scalar for shifted polynomial commitments.
    @param unshiftedScalarNeg The negation of `unshiftedScalar`.
    @param shiftedScalarNeg The negation of `shiftedScalar`.
    @param constantTermAccumulator Scalar to be multiplied by [1]₁
    @param batchingChallenge Accumulator for powers of rho
    @param batchedEvaluation Linear combination of multilinear (sumcheck)
      evaluations and powers of rho
    @param denominators The inverted denominators for the Libra evaluations.
    @param batchingScalars The scaled batching coefficients for the Libra
      commitments.
    @param posInvertedDenominator 1/(z - r^{2^i}) for i = 0, ..., logSize,
      dynamically updated
    @param negInvertedDenominator 1/(z + r^{2^i}) for i = 0, ..., logSize,
      dynamically updated
    @param scalingFactorPos ν^{2i} * 1/(z - r^{2^i})
    @param scalingFactorNeg ν^{2i+1} * 1/(z + r^{2^i})
    @param foldPosEvaluations Fold_i(r^{2^i}) reconstructed by Verifier
  */
  struct ShpleminiIntermediates {
    Fr unshiftedScalar;
    Fr shiftedScalar;
    Fr unshiftedScalarNeg;
    Fr shiftedScalarNeg;
    Fr constantTermAccumulator;
    Fr batchingChallenge;
    Fr batchedEvaluation;
    Fr[4] denominators;
    Fr[4] batchingScalars;
    Fr posInvertedDenominator;
    Fr negInvertedDenominator;
    Fr scalingFactorPos;
    Fr scalingFactorNeg;
    Fr[] foldPosEvaluations;
  }

  /**
    Compute the vector of successive squares `[r, r^2, r^4, ..., r^(2^(n-1))]`
    needed for the Gemini folding scheme.

    @param _r The Gemini challenge.
    @param _logN The base-2 logarithm of the circuit size.

    @return _ The array of squared challenge powers.
  */
  function computeSquares (
    Fr _r,
    uint256 _logN
  ) internal pure returns (Fr[] memory) {
    Fr[] memory _squares = new Fr[](_logN);
    _squares[0] = _r;
    for (uint256 i = 1; i < _logN; ++i) {
      _squares[i] = _squares[i - 1].sqr();
    }
    return _squares;
  }

  /**
    Reconstruct the Gemini fold polynomial positive evaluations
    `A_l(r^(2^l))` from the sumcheck challenges and Gemini evaluations.

    @param _sumcheckUChallenges The sumcheck round challenges.
    @param _batchedEvalAccumulator The batched multilinear evaluation.
    @param _geminiEvaluations The Gemini polynomial evaluations from the proof.
    @param _geminiEvalChallengePowers The squared powers of the Gemini
      challenge.
    @param _logSize The base-2 logarithm of the circuit size.

    @return _ The reconstructed fold positive evaluations.
  */
  function computeFoldPosEvaluations (
    Fr[CONST_PROOF_SIZE_LOG_N] memory _sumcheckUChallenges,
    Fr _batchedEvalAccumulator,
    Fr[CONST_PROOF_SIZE_LOG_N] memory _geminiEvaluations,
    Fr[] memory _geminiEvalChallengePowers,
    uint256 _logSize
  ) internal view returns (Fr[] memory) {
    Fr[] memory _foldPosEvaluations = new Fr[](_logSize);
    for (uint256 i = _logSize; i > 0; --i) {
      Fr _challengePower = _geminiEvalChallengePowers[i - 1];
      Fr u = _sumcheckUChallenges[i - 1];
      Fr _batchedEvalRoundAcc =
        (
          (_challengePower * _batchedEvalAccumulator * Fr.wrap(2)) -
          _geminiEvaluations[
            i - 1
          ] * (_challengePower * (ONE - u) - u)
        );

      // Divide by the denominator
      _batchedEvalRoundAcc = _batchedEvalRoundAcc * (
        _challengePower * (ONE - u) + u
      ).invert();
      _batchedEvalAccumulator = _batchedEvalRoundAcc;
      _foldPosEvaluations[i - 1] = _batchedEvalRoundAcc;
    }
    return _foldPosEvaluations;
  }
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title IVerifier
  @author Aztec
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  An interface for UltraHonk proof verifiers.

  @custom:date February 24th, 2026.
*/
interface IVerifier {

  /**
    Verify an UltraHonk proof against the given public inputs.

    @param _proof The serialized proof bytes.
    @param _publicInputs The public inputs to the circuit.

    @return _ Whether the proof is valid.
  */
  function verify (
    bytes calldata _proof,
    bytes32[] calldata _publicInputs
  ) external returns (bool);
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title BaseZKHonkVerifier
  @author Aztec
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  This abstract contract implements the core ZK-flavored UltraHonk verifier
  logic including sumcheck verification, the Shplemini opening scheme, and
  the final KZG pairing check. Concrete verifiers inherit from this and
  supply a circuit-specific verification key.

  @custom:date February 24th, 2026.
*/
abstract contract BaseZKHonkVerifier is
  IVerifier {

  using FrLib for Fr;

  /**
    The two G1 points that form the inputs to the final pairing check.

    @param P_0 The first pairing input point.
    @param P_1 The second pairing input point.
  */
  struct PairingInputs {
    Honk.G1Point P_0;
    Honk.G1Point P_1;
  }

  /**
    Intermediate values used during the small subgroup IPA consistency
    check for Libra polynomial evaluations.

    @param challengePolyLagrange The challenge polynomial in Lagrange basis.
    @param challengePolyEval The evaluation of the challenge polynomial.
    @param lagrangeFirst The Lagrange basis evaluation at the first element.
    @param lagrangeLast The Lagrange basis evaluation at the last element.
    @param rootPower The running power of the subgroup generator inverse.
    @param denominators The inverted Lagrange denominators.
    @param diff The consistency check residual.
  */
  struct SmallSubgroupIpaIntermediates {
    Fr[SUBGROUP_SIZE] challengePolyLagrange;
    Fr challengePolyEval;
    Fr lagrangeFirst;
    Fr lagrangeLast;
    Fr rootPower;
    Fr[SUBGROUP_SIZE] denominators;
    Fr diff;
  }

  /// An error emitted when the proof length does not match the expected size.
  error ProofLengthWrong ();

  /**
    An error emitted when the proof length does not match the expected size,
    providing diagnostic details.

    @param logN The base-2 logarithm of the circuit size.
    @param actualLength The actual byte length of the proof.
    @param expectedLength The expected byte length of the proof.
  */
  error ProofLengthWrongWithLogN (
    uint256 logN,
    uint256 actualLength,
    uint256 expectedLength
  );

  /**
    An error emitted when the number of public inputs does not match the
    verification key.
  */
  error PublicInputsLengthWrong ();

  /**
    An error emitted when the sumcheck verification fails.
  */
  error SumcheckFailed ();

  /**
    An error emitted when the Shplemini opening verification fails.
  */
  error ShpleminiFailed ();

  /**
    An error emitted when the Gemini challenge falls within the
    multiplicative subgroup, which would cause a division by zero.
  */
  error GeminiChallengeInSubgroup ();

  /**
    An error emitted when the Libra evaluation consistency check fails.
  */
  error ConsistencyCheckFailed ();

  /// The circuit size.
  uint256 immutable $N;

  /// The base-2 logarithm of the circuit size.
  uint256 immutable $LOG_N;

  /// The hash of the verification key.
  uint256 immutable $VK_HASH;

  /// The number of public inputs to the circuit.
  uint256 immutable $NUM_PUBLIC_INPUTS;

  /// The number of points in the multi-scalar multiplication.
  uint256 immutable $MSMSize;

  // Constants for proof length calculation (matching UltraKeccakZKFlavor)
  uint256 constant NUM_WITNESS_ENTITIES = 8 + NUM_MASKING_POLYNOMIALS;

  uint256 constant NUM_ELEMENTS_COMM = 2;

  uint256 constant NUM_ELEMENTS_FR = 1;

  uint256 constant NUM_LIBRA_EVALUATIONS = 4;

  // The index in the commitments array where shifted commitments begin.
  uint256 constant SHIFTED_COMMITMENTS_START = 30;

  // The offset separating sigma and identity permutation domains.
  uint256 constant PERMUTATION_ARGUMENT_VALUE_SEPARATOR = 1 << 28;

  // The number of Libra masking polynomial commitments.
  uint256 constant LIBRA_COMMITMENTS = 3;

  // The number of Libra polynomial evaluations.
  uint256 constant LIBRA_EVALUATIONS = 4;

  // The degree of Libra univariate polynomials.
  uint256 constant LIBRA_UNIVARIATES_LENGTH = 9;

  /**
    Initialize the verifier with circuit parameters.

    @param _N The circuit size.
    @param _logN The base-2 logarithm of the circuit size.
    @param _vkHash The hash of the verification key.
    @param _numPublicInputs The number of public inputs to the circuit.
  */
  constructor (
    uint256 _N,
    uint256 _logN,
    uint256 _vkHash,
    uint256 _numPublicInputs
  ) {
    $N = _N;
    $LOG_N = _logN;
    $VK_HASH = _vkHash;
    $NUM_PUBLIC_INPUTS = _numPublicInputs;
    $MSMSize = NUMBER_UNSHIFTED_ZK + _logN + LIBRA_COMMITMENTS + 2;
  }

  /**
    Calculate proof size based on log_n (matching UltraKeccakZKFlavor formula)

    @param _logN The base-2 logarithm of the circuit size.

    @return _ The expected number of 32-byte elements in the proof.
  */
  function calculateProofSize (
    uint256 _logN
  ) internal pure returns (uint256) {

    // Witness and Libra commitments witness commitments
    uint256 _proofLength = NUM_WITNESS_ENTITIES * NUM_ELEMENTS_COMM;

    // Libra concat, grand sum, quotient comms + Gemini masking
    _proofLength += NUM_ELEMENTS_COMM * 3;

    // Sumcheck sumcheck univariates
    _proofLength += _logN * ZK_BATCHED_RELATION_PARTIAL_LENGTH * NUM_ELEMENTS_FR;

    // sumcheck evaluations
    _proofLength += NUMBER_OF_ENTITIES_ZK * NUM_ELEMENTS_FR;

    // Libra and Gemini Libra sum, claimed eval
    _proofLength += NUM_ELEMENTS_FR * 2;

    // Gemini a evaluations
    _proofLength += _logN * NUM_ELEMENTS_FR;

    // libra evaluations
    _proofLength += NUM_LIBRA_EVALUATIONS * NUM_ELEMENTS_FR;

    // PCS commitments Gemini Fold commitments
    _proofLength += (_logN - 1) * NUM_ELEMENTS_COMM;

    // Shplonk Q and KZG W commitments
    _proofLength += NUM_ELEMENTS_COMM * 2;

    // Pairing points pairing inputs carried on public inputs
    _proofLength += PAIRING_POINTS_SIZE;
    return _proofLength;
  }

  /**
    Load the circuit-specific verification key. Must be overridden by
    concrete verifier implementations.

    @return _ The verification key.
  */
  function loadVerificationKey () internal pure virtual returns (
    Honk.VerificationKey memory
  );

  /**
    Verify a ZK-flavored UltraHonk proof by generating the Fiat-Shamir
    transcript, running sumcheck verification, and performing the Shplemini
    opening check with a final KZG pairing.

    @param _proof The serialized proof bytes.
    @param _publicInputs The public inputs to the circuit.

    @return _ Whether the proof is valid.
  */
  function verify (
    bytes calldata _proof,
    bytes32[] calldata _publicInputs
  ) public view override returns (bool) {

    // Calculate expected proof size based on $LOG_N
    uint256 _expectedProofSize = calculateProofSize($LOG_N);

    /*
      Check the received proof is the expected size where each field element is
      32 bytes
    */
    if (_proof.length != _expectedProofSize * 32) {
      revert ProofLengthWrongWithLogN(
        $LOG_N, _proof.length, _expectedProofSize * 32
      );
    }
    Honk.VerificationKey memory _vk = loadVerificationKey();
    Honk.ZKProof memory p = ZKTranscriptLib.loadProof(_proof, $LOG_N);
    if (_publicInputs.length != _vk.publicInputsSize - PAIRING_POINTS_SIZE) {
      revert PublicInputsLengthWrong();
    }

    // Generate the fiat shamir challenges for the whole protocol
    ZKTranscript memory t =
      ZKTranscriptLib.generateTranscript(
        p, _publicInputs, $VK_HASH, $NUM_PUBLIC_INPUTS, $LOG_N
      );

    // Derive public input delta
    t.relationParameters.publicInputsDelta = computePublicInputDelta(
      _publicInputs, p.pairingPointObject, t.relationParameters.beta,
      t.relationParameters.gamma, 1
    );

    // Sumcheck
    if (!verifySumcheck(p, t)) {
      revert SumcheckFailed();
    }

    if (!verifyShplemini(p, _vk, t)) {
      revert ShpleminiFailed();
    }
    return true;
  }

  /**
    Compute the public input contribution to the permutation grand product.
    This is the ratio of the numerator and denominator terms formed from the
    public inputs, beta, and gamma challenges.

    @param _publicInputs The public inputs to the circuit.
    @param _pairingPointObject The recursive pairing point limbs.
    @param _beta The permutation challenge.
    @param _gamma The permutation randomness challenge.
    @param _offset The starting offset for the permutation argument.

    @return _ The public input delta.
  */
  function computePublicInputDelta (
    bytes32[] memory _publicInputs,
    Fr[PAIRING_POINTS_SIZE] memory _pairingPointObject,
    Fr _beta,
    Fr _gamma,
    uint256 _offset
  ) internal view returns (Fr) {
    Fr _numerator = Fr.wrap(1);
    Fr _denominator = Fr.wrap(1);
    Fr _numeratorAcc =
      _gamma + (
        _beta * FrLib.from(PERMUTATION_ARGUMENT_VALUE_SEPARATOR + _offset)
      );
    Fr _denominatorAcc = _gamma - (_beta * FrLib.from(_offset + 1));
    {
      for (uint256 i = 0; i < $NUM_PUBLIC_INPUTS - PAIRING_POINTS_SIZE; i++) {
        Fr _pubInput = FrLib.fromBytes32(_publicInputs[i]);
        _numerator = _numerator * (_numeratorAcc + _pubInput);
        _denominator = _denominator * (_denominatorAcc + _pubInput);
        _numeratorAcc = _numeratorAcc + _beta;
        _denominatorAcc = _denominatorAcc - _beta;
      }
      for (uint256 i = 0; i < PAIRING_POINTS_SIZE; i++) {
        Fr _pubInput = _pairingPointObject[i];
        _numerator = _numerator * (_numeratorAcc + _pubInput);
        _denominator = _denominator * (_denominatorAcc + _pubInput);
        _numeratorAcc = _numeratorAcc + _beta;
        _denominatorAcc = _denominatorAcc - _beta;
      }
    }

    // Fr delta = numerator / denominator; // TOOO: batch invert later?
    return FrLib.div(_numerator, _denominator);
  }

  /**
    Verify the sumcheck protocol by checking each round's univariate sum
    and confirming the final relation evaluation matches the target.

    @param _proof The deserialized ZK proof.
    @param _tp The Fiat-Shamir transcript.

    @return _ Whether the sumcheck verification succeeded.
  */
  function verifySumcheck (
    Honk.ZKProof memory _proof,
    ZKTranscript memory _tp
  ) internal view returns (bool) {

    // default 0
    Fr _roundTargetSum = _tp.libraChallenge * _proof.libraSum;
    Fr _powPartialEvaluation = Fr.wrap(1);

    /*
      We perform sumcheck reductions over log n rounds ( the multivariate degree
      )
    */
    for (uint256 _round; _round < $LOG_N; ++_round) {
      Fr[ZK_BATCHED_RELATION_PARTIAL_LENGTH] memory _roundUnivariate =
        _proof.sumcheckUnivariates[_round];
      Fr _totalSum = _roundUnivariate[0] + _roundUnivariate[1];
      if (_totalSum != _roundTargetSum) {
        revert SumcheckFailed();
      }
      Fr _roundChallenge = _tp.sumCheckUChallenges[_round];

      // Update the round target for the next rounf
      _roundTargetSum = computeNextTargetSum(_roundUnivariate, _roundChallenge);
      _powPartialEvaluation = _powPartialEvaluation * (
        Fr.wrap(1) + _roundChallenge * (
          _tp.gateChallenges[_round] - Fr.wrap(1)
        )
      );
    }

    /*
      Last round For ZK flavors: sumcheckEvaluations has 42 elements Index 0 is
      gemini_masking_poly, indices 1-41 are the regular entities used in
      relations
    */
    Fr[NUMBER_OF_ENTITIES] memory _relationsEvaluations;
    for (uint256 i = 0; i < NUMBER_OF_ENTITIES; i++) {

      // Skip gemini_masking_poly at index 0
      _relationsEvaluations[i] = _proof.sumcheckEvaluations[
        i + NUM_MASKING_POLYNOMIALS
      ];
    }
    Fr _grandHonkRelationSum =
      RelationsLib.accumulateRelationEvaluations(
        _relationsEvaluations, _tp.relationParameters, _tp.alphas,
        _powPartialEvaluation
      );
    Fr _evaluation = Fr.wrap(1);
    for (uint256 i = 2; i < $LOG_N; i++) {
      _evaluation = _evaluation * _tp.sumCheckUChallenges[i];
    }
    _grandHonkRelationSum = _grandHonkRelationSum * (Fr.wrap(1) - _evaluation)
     + _proof.libraEvaluation * _tp.libraChallenge;
    return (_grandHonkRelationSum == _roundTargetSum);
  }

  /**
    Return the new target sum for the next sumcheck round

    @param _roundUnivariates The univariate evaluations for this round.
    @param _roundChallenge The Fiat-Shamir challenge for this round.

    @return _ The target sum for the next round.
  */
  function computeNextTargetSum (
    Fr[ZK_BATCHED_RELATION_PARTIAL_LENGTH] memory _roundUnivariates,
    Fr _roundChallenge
  ) internal view returns (Fr) {
    Fr _targetSumOutput;
    Fr[ZK_BATCHED_RELATION_PARTIAL_LENGTH] memory
    _BARYCENTRIC_LAGRANGE_DENOMINATORS =
      [Fr.wrap(
        0x0000000000000000000000000000000000000000000000000000000000009d80
      ),
      Fr.wrap(
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffec51
      ),
      Fr.wrap(
        0x00000000000000000000000000000000000000000000000000000000000005a0
      ),
      Fr.wrap(
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffd31
      ),
      Fr.wrap(
        0x0000000000000000000000000000000000000000000000000000000000000240
      ),
      Fr.wrap(
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffd31
      ),
      Fr.wrap(
        0x00000000000000000000000000000000000000000000000000000000000005a0
      ),
      Fr.wrap(
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffec51
      ),
      Fr.wrap(
        0x0000000000000000000000000000000000000000000000000000000000009d80
      )];

    // Performing Barycentric evaluations Compute B(x)
    Fr _numeratorValue = Fr.wrap(1);
    for (uint256 i = 0; i < ZK_BATCHED_RELATION_PARTIAL_LENGTH; ++i) {
      _numeratorValue = _numeratorValue * (_roundChallenge - Fr.wrap(i));
    }
    Fr[ZK_BATCHED_RELATION_PARTIAL_LENGTH] memory _denominatorInverses;
    for (uint256 i = 0; i < ZK_BATCHED_RELATION_PARTIAL_LENGTH; ++i) {
      _denominatorInverses[i] = FrLib.invert(
        _BARYCENTRIC_LAGRANGE_DENOMINATORS[i] * (_roundChallenge - Fr.wrap(i))
      );
    }
    for (uint256 i = 0; i < ZK_BATCHED_RELATION_PARTIAL_LENGTH; ++i) {
      _targetSumOutput = _targetSumOutput + _roundUnivariates[i] *
      _denominatorInverses[i];
    }

    // Scale the sum by the value of B(x)
    _targetSumOutput = _targetSumOutput * _numeratorValue;
    return _targetSumOutput;
  }

  /**
    Verify the Shplemini polynomial commitment opening scheme by computing
    the batched scalar multipliers, accumulating commitment points, and
    performing the final KZG pairing check.

    @param _proof The deserialized ZK proof.
    @param _vk The circuit verification key.
    @param _tp The Fiat-Shamir transcript.

    @return _ Whether the Shplemini verification succeeded.
  */
  function verifyShplemini (
    Honk.ZKProof memory _proof,
    Honk.VerificationKey memory _vk,
    ZKTranscript memory _tp
  ) internal view returns (bool) {

    // stack
    CommitmentSchemeLib.ShpleminiIntermediates memory _mem;

    /*
      - Compute vector (r, r², ... , r²⁽ⁿ⁻¹⁾), where n = log_circuit_size
    */
    Fr[] memory _powers_of_evaluation_challenge =
      CommitmentSchemeLib.computeSquares(_tp.geminiR, $LOG_N);

    /*
      Arrays hold values that will be linearly combined for the gemini and
      shplonk batch openings
    */
    Fr[] memory _scalars = new Fr[]($MSMSize);
    Honk.G1Point[] memory _commitments = new Honk.G1Point[]($MSMSize);
    _mem.posInvertedDenominator = (
      _tp.shplonkZ - _powers_of_evaluation_challenge[0]
    ).invert();
    _mem.negInvertedDenominator = (
      _tp.shplonkZ + _powers_of_evaluation_challenge[0]
    ).invert();
    _mem.unshiftedScalar = _mem.posInvertedDenominator + (
      _tp.shplonkNu * _mem.negInvertedDenominator
    );
    _mem.shiftedScalar = _tp.geminiR.invert() * (
      _mem.posInvertedDenominator - (
        _tp.shplonkNu * _mem.negInvertedDenominator
      )
    );
    _scalars[0] = Fr.wrap(1);
    _commitments[0] = _proof.shplonkQ;

    /*
      Batch multivariate opening claims, shifted and unshifted
      * The vector of scalars is populated as follows:
      * \f[
      * \left(
      * - \left(\frac{1}{z-r} + \nu \times \frac{1}{z+r}\right),
      * \ldots,
      * - \rho^{i+k-1} \times \left(\frac{1}{z-r} + \nu \times \frac{1}{z+r}\right),
      * - \rho^{i+k} \times \frac{1}{r} \times \left(\frac{1}{z-r} - \nu \times \frac{1}{z+r}\right),
      * \ldots,
      * - \rho^{k+m-1} \times \frac{1}{r} \times \left(\frac{1}{z-r} - \nu \times \frac{1}{z+r}\right)
      * \right)
      * \f]
      *
      * The following vector is concatenated to the vector of commitments:
      * \f[
      * f_0, \ldots, f_{m-1}, f_{\text{shift}, 0}, \ldots, f_{\text{shift}, k-1}
      * \f]
      *
      * Simultaneously, the evaluation of the multilinear polynomial
      * \f[
      * \sum \rho^i \cdot f_i + \sum \rho^{i+k} \cdot f_{\text{shift}, i}
      * \f]
      * at the challenge point \f$ (u_0,\ldots, u_{n-1}) \f$ is computed.
      *
      * This approach minimizes the number of iterations over the commitments to multilinear polynomials
      * and eliminates the need to store the powers of \f$ \rho \f$.
    */
    /*
      For ZK flavors: evaluations array is [gemini_masking_poly, qm, qc, ql, qr,
      ...] Start batching challenge at 1, not rho, to match non-ZK pattern
    */
    _mem.batchingChallenge = Fr.wrap(1);
    _mem.batchedEvaluation = Fr.wrap(0);
    _mem.unshiftedScalarNeg = _mem.unshiftedScalar.neg();
    _mem.shiftedScalarNeg = _mem.shiftedScalar.neg();

    /*
      Process all NUMBER_UNSHIFTED_ZK evaluations (includes gemini_masking_poly
      at index 0)
    */
    for (uint256 i = 1; i <= NUMBER_UNSHIFTED_ZK; ++i) {
      _scalars[i] = _mem.unshiftedScalarNeg * _mem.batchingChallenge;
      _mem.batchedEvaluation = _mem.batchedEvaluation + (
        _proof.sumcheckEvaluations[i - NUM_MASKING_POLYNOMIALS] *
        _mem.batchingChallenge
      );
      _mem.batchingChallenge = _mem.batchingChallenge * _tp.rho;
    }

    /*
      g commitments are accumulated at r For each of the to be shifted
      commitments perform the shift in place by adding to the unshifted value.
      We do so, as the values are to be used in batchMul later, and as `a * c +
      b * c = (a + b) * c` this will allow us to reduce memory and compute.
      Applied to w1, w2, w3, w4 and zPerm
    */
    for (uint256 i = 0; i < NUMBER_TO_BE_SHIFTED; ++i) {
      uint256 _scalarOff = i + SHIFTED_COMMITMENTS_START;
      uint256 _evaluationOff = i + NUMBER_UNSHIFTED_ZK;
      _scalars[_scalarOff] = _scalars[_scalarOff] + (
        _mem.shiftedScalarNeg * _mem.batchingChallenge
      );
      _mem.batchedEvaluation = _mem.batchedEvaluation + (
        _proof.sumcheckEvaluations[_evaluationOff] * _mem.batchingChallenge
      );
      _mem.batchingChallenge = _mem.batchingChallenge * _tp.rho;
    }
    _commitments[1] = _proof.geminiMaskingPoly;
    _commitments[2] = _vk.qm;
    _commitments[3] = _vk.qc;
    _commitments[4] = _vk.ql;
    _commitments[5] = _vk.qr;
    _commitments[6] = _vk.qo;
    _commitments[7] = _vk.q4;
    _commitments[8] = _vk.qLookup;
    _commitments[9] = _vk.qArith;
    _commitments[10] = _vk.qDeltaRange;
    _commitments[11] = _vk.qElliptic;
    _commitments[12] = _vk.qMemory;
    _commitments[13] = _vk.qNnf;
    _commitments[14] = _vk.qPoseidon2External;
    _commitments[15] = _vk.qPoseidon2Internal;
    _commitments[16] = _vk.s1;
    _commitments[17] = _vk.s2;
    _commitments[18] = _vk.s3;
    _commitments[19] = _vk.s4;
    _commitments[20] = _vk.id1;
    _commitments[21] = _vk.id2;
    _commitments[22] = _vk.id3;
    _commitments[23] = _vk.id4;
    _commitments[24] = _vk.t1;
    _commitments[25] = _vk.t2;
    _commitments[26] = _vk.t3;
    _commitments[27] = _vk.t4;
    _commitments[28] = _vk.lagrangeFirst;
    _commitments[29] = _vk.lagrangeLast;

    // Accumulate proof points
    _commitments[30] = _proof.w1;
    _commitments[31] = _proof.w2;
    _commitments[32] = _proof.w3;
    _commitments[33] = _proof.w4;
    _commitments[34] = _proof.zPerm;
    _commitments[35] = _proof.lookupInverses;
    _commitments[36] = _proof.lookupReadCounts;
    _commitments[37] = _proof.lookupReadTags;

    /*
      Add contributions from A₀(r) and A₀(-r) to constant_term_accumulator:
      Compute the evaluations Aₗ(r^{2ˡ}) for l = 0, ..., $LOG_N - 1
    */
    Fr[] memory _foldPosEvaluations =
      CommitmentSchemeLib.computeFoldPosEvaluations(
        _tp.sumCheckUChallenges, _mem.batchedEvaluation,
        _proof.geminiAEvaluations, _powers_of_evaluation_challenge, $LOG_N
      );
    _mem.constantTermAccumulator = _foldPosEvaluations[0] *
    _mem.posInvertedDenominator;
    _mem.constantTermAccumulator = _mem.constantTermAccumulator + (
      _proof.geminiAEvaluations[0] * _tp.shplonkNu * _mem.negInvertedDenominator
    );
    _mem.batchingChallenge = _tp.shplonkNu.sqr();
    uint256 _boundary = NUMBER_UNSHIFTED_ZK + 1;

    /*
      Compute Shplonk constant term contributions from Aₗ(± r^{2ˡ}) for l = 1,
      ..., m-1; Compute scalar multipliers for each fold commitment
    */
    for (uint256 i = 0; i < $LOG_N - 1; ++i) {
      bool _dummy_round = i >= ($LOG_N - 1);
      if (!_dummy_round) {

        // Update inverted denominators
        _mem.posInvertedDenominator = (
          _tp.shplonkZ - _powers_of_evaluation_challenge[i + 1]
        ).invert();
        _mem.negInvertedDenominator = (
          _tp.shplonkZ + _powers_of_evaluation_challenge[i + 1]
        ).invert();

        // Compute the scalar multipliers for Aₗ(± r^{2ˡ}) and [Aₗ]
        _mem.scalingFactorPos = _mem.batchingChallenge *
        _mem.posInvertedDenominator;
        _mem.scalingFactorNeg = _mem.batchingChallenge * _tp.shplonkNu *
        _mem.negInvertedDenominator;
        _scalars[_boundary + i] = _mem.scalingFactorNeg.neg() +
        _mem.scalingFactorPos.neg();

        /*
          Accumulate the const term contribution given by v^{2l} * Aₗ(r^{2ˡ})
          /(z-r^{2^l}) + v^{2l+1} * Aₗ(-r^{2ˡ}) /(z+ r^{2^l})
        */
        Fr _accumContribution =
          _mem.scalingFactorNeg * _proof.geminiAEvaluations[i + 1];
        _accumContribution = _accumContribution + _mem.scalingFactorPos *
        _foldPosEvaluations[
          i + 1
        ];
        _mem.constantTermAccumulator = _mem.constantTermAccumulator +
        _accumContribution;
      }

      // Update the running power of v
      _mem.batchingChallenge = _mem.batchingChallenge * _tp.shplonkNu *
      _tp.shplonkNu;
      _commitments[_boundary + i] = _proof.geminiFoldComms[i];
    }
    _boundary += $LOG_N - 1;

    // Finalize the batch opening claim
    _mem.denominators[0] = Fr.wrap(1).div(_tp.shplonkZ - _tp.geminiR);
    _mem.denominators[1] = Fr.wrap(1).div(
      _tp.shplonkZ - SUBGROUP_GENERATOR * _tp.geminiR
    );
    _mem.denominators[2] = _mem.denominators[0];
    _mem.denominators[3] = _mem.denominators[0];
    _mem.batchingChallenge = _mem.batchingChallenge * _tp.shplonkNu *
    _tp.shplonkNu;
    for (uint256 i = 0; i < LIBRA_EVALUATIONS; i++) {
      Fr _scalingFactor = _mem.denominators[i] * _mem.batchingChallenge;
      _mem.batchingScalars[i] = _scalingFactor.neg();
      _mem.batchingChallenge = _mem.batchingChallenge * _tp.shplonkNu;
      _mem.constantTermAccumulator = _mem.constantTermAccumulator +
      _scalingFactor * _proof.libraPolyEvals[i];
    }
    _scalars[_boundary] = _mem.batchingScalars[0];
    _scalars[_boundary + 1] = _mem.batchingScalars[1] + _mem.batchingScalars[2];
    _scalars[_boundary + 2] = _mem.batchingScalars[3];
    for (uint256 i = 0; i < LIBRA_COMMITMENTS; i++) {
      _commitments[_boundary++] = _proof.libraCommitments[i];
    }
    _commitments[_boundary] = Honk.G1Point({
      x: 1,
      y: 2
    });
    _scalars[_boundary++] = _mem.constantTermAccumulator;
    if (
      !checkEvalsConsistency(
        _proof.libraPolyEvals, _tp.geminiR, _tp.sumCheckUChallenges,
        _proof.libraEvaluation
      )
    ) {
      revert ConsistencyCheckFailed();
    }
    Honk.G1Point memory _quotient_commitment = _proof.kzgQuotient;
    _commitments[_boundary] = _quotient_commitment;

    // evaluation challenge
    _scalars[_boundary] = _tp.shplonkZ;
    PairingInputs memory _pair;
    _pair.P_0 = batchMul(_commitments, _scalars);
    _pair.P_1 = negateInplace(_quotient_commitment);

    // Aggregate pairing points
    Fr _recursionSeparator =
      generateRecursionSeparator(
        _proof.pairingPointObject, _pair.P_0, _pair.P_1
      );
    (Honk.G1Point memory _P_0_other, Honk.G1Point memory _P_1_other) =
    convertPairingPointsToG1(
      _proof.pairingPointObject
    );

    // Validate the points from the proof are on the curve
    validateOnCurve(_P_0_other);
    validateOnCurve(_P_1_other);

    // accumulate with aggregate points in proof
    _pair.P_0 = mulWithSeperator(_pair.P_0, _P_0_other, _recursionSeparator);
    _pair.P_1 = mulWithSeperator(_pair.P_1, _P_1_other, _recursionSeparator);
    return pairing(_pair.P_0, _pair.P_1);
  }

  /**
    Check the consistency of the Libra polynomial evaluations against the
    claimed Libra evaluation using a small subgroup IPA argument.

    @param _libraPolyEvals The four Libra polynomial evaluations.
    @param _geminiR The Gemini folding challenge.
    @param _uChallenges The sumcheck round challenges.
    @param _libraEval The claimed Libra masking polynomial evaluation.

    @return _ Whether the consistency check passed.
  */
  function checkEvalsConsistency (
    Fr[LIBRA_EVALUATIONS] memory _libraPolyEvals,
    Fr _geminiR,
    Fr[CONST_PROOF_SIZE_LOG_N] memory _uChallenges,
    Fr _libraEval
  ) internal view returns (bool) {
    Fr _one = Fr.wrap(1);
    Fr _vanishingPolyEval = _geminiR.pow(SUBGROUP_SIZE) - _one;
    if (_vanishingPolyEval == Fr.wrap(0)) {
      revert GeminiChallengeInSubgroup();
    }
    SmallSubgroupIpaIntermediates memory _mem;
    _mem.challengePolyLagrange[0] = _one;
    for (uint256 _round = 0; _round < $LOG_N; _round++) {
      uint256 _currIdx = 1 + LIBRA_UNIVARIATES_LENGTH * _round;
      _mem.challengePolyLagrange[_currIdx] = _one;
      for (uint256 _idx = _currIdx + 1; _idx < _currIdx +
      LIBRA_UNIVARIATES_LENGTH; _idx++) {
        _mem.challengePolyLagrange[_idx] = _mem.challengePolyLagrange[_idx - 1]
         * _uChallenges[_round];
      }
    }
    _mem.rootPower = _one;
    _mem.challengePolyEval = Fr.wrap(0);
    for (uint256 _idx = 0; _idx < SUBGROUP_SIZE; _idx++) {
      _mem.denominators[_idx] = _mem.rootPower * _geminiR - _one;
      _mem.denominators[_idx] = _mem.denominators[_idx].invert();
      _mem.challengePolyEval = _mem.challengePolyEval +
      _mem.challengePolyLagrange[_idx] * _mem.denominators[_idx];
      _mem.rootPower = _mem.rootPower * SUBGROUP_GENERATOR_INVERSE;
    }
    Fr _numerator = _vanishingPolyEval * Fr.wrap(SUBGROUP_SIZE).invert();
    _mem.challengePolyEval = _mem.challengePolyEval * _numerator;
    _mem.lagrangeFirst = _mem.denominators[0] * _numerator;
    _mem.lagrangeLast = _mem.denominators[SUBGROUP_SIZE - 1] * _numerator;
    _mem.diff = _mem.lagrangeFirst * _libraPolyEvals[2];
    _mem.diff = _mem.diff + (_geminiR - SUBGROUP_GENERATOR_INVERSE) * (
      _libraPolyEvals[1] - _libraPolyEvals[2] - _libraPolyEvals[0] *
      _mem.challengePolyEval
    );
    _mem.diff = _mem.diff + _mem.lagrangeLast * (
      _libraPolyEvals[2] - _libraEval
    ) - _vanishingPolyEval * _libraPolyEvals[3];
    return _mem.diff == Fr.wrap(0);
  }

  /**
    This implementation is the same as above with different constants

    @param _base The array of G1 commitment points.
    @param _scalars The array of scalar multipliers.

    @return _ The accumulated multi-scalar multiplication result.
  */
  function batchMul (
    Honk.G1Point[] memory _base,
    Fr[] memory _scalars
  ) internal view returns (Honk.G1Point memory) {
    Honk.G1Point memory _resultOutput;
    uint256 _limit = $MSMSize;

    // Validate all points are on the curve
    for (uint256 i = 0; i < _limit; ++i) {
      validateOnCurve(_base[i]);
    }
    bool _success = true;
    assembly {
      let _free := mload(0x40)
      let _count := 0x01
      for {} lt(_count, add(_limit, 1)) {
        _count := add(_count, 1)
      } {

        // Get loop offsets
        let _base_base := add(_base, mul(_count, 0x20))
        let _scalar_base := add(_scalars, mul(_count, 0x20))
        mstore(add(_free, 0x40), mload(mload(_base_base)))
        mstore(add(_free, 0x60), mload(add(0x20, mload(_base_base))))

        // Add scalar
        mstore(add(_free, 0x80), mload(_scalar_base))
        _success := and(
          _success,
          staticcall(gas(), 7, add(_free, 0x40), 0x60, add(_free, 0x40), 0x40)
        )

        // accumulator = accumulator + accumulator_2
        _success := and(
          _success, staticcall(gas(), 6, _free, 0x80, _free, 0x40)
        )
      }

      // Return the result
      mstore(_resultOutput, mload(_free))
      mstore(add(_resultOutput, 0x20), mload(add(_free, 0x20)))
    }
    if (!_success) {
      revert ShpleminiFailed();
    }
    return _resultOutput;
  }
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title HonkVerifier
  @author Aztec
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A concrete UltraHonk verifier parameterized with the ZK mint circuit
  constants and verification key.

  @custom:date February 24th, 2026.
*/
contract HonkVerifier is
  BaseZKHonkVerifier(N, LOG_N, VK_HASH, NUMBER_OF_PUBLIC_INPUTS) {

  /**
    Load the ZK mint circuit verification key.

    @return _ The verification key.
  */
  function loadVerificationKey () internal pure override returns (
    Honk.VerificationKey memory
  ) {
    return HonkVerificationKey.loadVerificationKey();
  }
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title ZKMintVerifier
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  The deployed ZK mint proof verifier contract. This is a thin wrapper
  around `HonkVerifier` that exists to provide a stable deployment identity.

  @custom:date February 24th, 2026.
*/
contract ZKMintVerifier is
  HonkVerifier { }

