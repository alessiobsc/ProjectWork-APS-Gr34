// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RevocationRegistry {
    address public admin;
    mapping(bytes32 => bool) public revoked;

    constructor() {
        admin = msg.sender;
    }

    function revokeRoot(bytes32 rootHash) public {
        require(msg.sender == admin, "Only admin can revoke");
        revoked[rootHash] = true;
    }

    function isRevoked(bytes32 rootHash) public view returns (bool) {
        return revoked[rootHash];
    }
}
