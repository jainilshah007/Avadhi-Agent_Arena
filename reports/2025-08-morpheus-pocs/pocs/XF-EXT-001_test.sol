// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Mock interface for the endpoint
interface IEndpoint {
    function send(address to, uint256 amount) external returns (bool);
}

// Mock OAppSender contract
contract OAppSender {
    IEndpoint public endpoint;

    constructor(address _endpoint) {
        endpoint = IEndpoint(_endpoint);
    }

    function _lzSend(address to, uint256 amount) external {
        // Unchecked return value vulnerability
        endpoint.send(to, amount);
    }
}

contract ExploitTest is Test {
    OAppSender oAppSender;
    IEndpoint endpoint;
    address attacker = address(0xdeadbeef);
    address victim = address(0x123456);

    function setUp() public {
        // Deploy a mock endpoint contract
        endpoint = new MockEndpoint();
        // Deploy the OAppSender contract with the mock endpoint
        oAppSender = new OAppSender(address(endpoint));
        // Fund the victim with some ETH
        vm.deal(victim, 10 ether);
    }

    function test_exploit() public {
        // Step 1: Attacker impersonates the victim
        vm.prank(victim);

        // Step 2: Attacker calls _lzSend with parameters that cause the send to fail
        oAppSender._lzSend(attacker, 10 ether);

        // Step 3: Assert that the victim's balance is reduced despite the send failing
        assertEq(victim.balance, 0 ether);
        // Assert that the attacker's balance did not increase (send failed)
        assertEq(attacker.balance, 0 ether);
    }
}

// Mock endpoint contract that always fails
contract MockEndpoint is IEndpoint {
    function send(address, uint256) external pure returns (bool) {
        return false; // Always fail
    }
}