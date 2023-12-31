// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

contract Bn254 {
    // Field order
    uint256 constant N = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Negated genarator of G2
    uint256 constant nG2x1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant nG2x0 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant nG2y1 = 17805874995975841540914202342111839520379459829704422454583296818431106115052;
    uint256 constant nG2y0 = 13392588948715843804641432497768002650278120570034223513918757245338268106653;

    function verifySingle(
      uint256[2] memory signature,
      uint256[4] memory pubkey,
      uint256[2] memory message
  ) public view returns (bool) {
      uint256[12] memory input = [signature[0], signature[1], nG2x1, nG2x0, nG2y1, nG2y0, message[0], message[1], pubkey[1], pubkey[0], pubkey[3], pubkey[2]];
      uint256[1] memory out;
      bool success;
      // solium-disable-next-line security/no-inline-assembly
      assembly {
        success := staticcall(sub(gas(), 2000), 8, input, 384, out, 32)
        switch success
          case 0 {
            invalid()
          }
      }
      require(success, "");
      return out[0] != 0;
    }
}