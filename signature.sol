// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SignatureVerifier {
    function verifySingleSignature(address signer, string memory data, bytes memory signature) public pure returns (bool) {
        bytes32 hash = keccak256(abi.encodePacked(data));
        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        address signatureAddress = ecrecover(hash, v, r, s);
        return signer == signatureAddress;
    }

    function verifyMultidataSignature(address signer, address addr,uint num1, uint num2, string memory memo, bytes memory signature) public pure returns (bool) {
        bytes32 hash = keccak256(abi.encodePacked(addr,num1,num2,memo));
        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        address signatureAddress = ecrecover(hash, v, r, s);
        return signer == signatureAddress;
    }
}
