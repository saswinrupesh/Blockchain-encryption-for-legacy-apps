// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AccessRegistry {
    struct DataMeta {
        bytes32 dataHash;
        address owner;
        bool exists;
    }
    mapping(bytes32 => DataMeta) public data;
    mapping(bytes32 => mapping(address => bool)) public isAllowed;
    mapping(bytes32 => mapping(address => string)) private encKeys;

    event DataRegistered(bytes32 indexed dataId, bytes32 dataHash, address indexed owner);
    event PermissionSet(bytes32 indexed dataId, address indexed user, bool allowed);
    event EncryptedKeySet(bytes32 indexed dataId, address indexed user);

    modifier onlyOwner(bytes32 dataId) {
        require(data[dataId].owner == msg.sender, "not owner");
        _;
    }

    function registerData(bytes32 dataId, bytes32 dataHash) external {
        require(!data[dataId].exists, "already exists");
        data[dataId] = DataMeta({dataHash: dataHash, owner: msg.sender, exists: true});
        emit DataRegistered(dataId, dataHash, msg.sender);
    }

    function setPermission(bytes32 dataId, address user, bool allowed) external onlyOwner(dataId) {
        require(data[dataId].exists, "no data");
        isAllowed[dataId][user] = allowed;
        emit PermissionSet(dataId, user, allowed);
    }

    function setEncryptedKey(bytes32 dataId, address user, string calldata encryptedKeyB64) external onlyOwner(dataId) {
        require(isAllowed[dataId][user], "user not allowed");
        encKeys[dataId][user] = encryptedKeyB64;
        emit EncryptedKeySet(dataId, user);
    }

    function getEncryptedKey(bytes32 dataId) external view returns (string memory) {
        require(isAllowed[dataId][msg.sender], "not allowed");
        return encKeys[dataId][msg.sender];
    }
}
