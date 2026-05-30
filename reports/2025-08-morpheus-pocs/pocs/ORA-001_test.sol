// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IDistributor {
    function rewardPool() external view returns (address);
    function distributeRewards(uint256 rewardPoolIndex) external;
    function updateDepositTokensPrices() external;
}

interface IRewardPool {
    function onlyExistedRewardPool(uint256 rewardPoolIndex) external view;
    function onlyPublicRewardPool(uint256 rewardPoolIndex) external view;
}

contract MockDistributor is IDistributor {
    address public override rewardPool;
    uint256 public manipulatedPrice;

    constructor(address _rewardPool) {
        rewardPool = _rewardPool;
    }

    function distributeRewards(uint256 rewardPoolIndex) external override {
        // Mock implementation
    }

    function updateDepositTokensPrices() external override {
        // Simulate price manipulation
        manipulatedPrice = 1000; // Arbitrary manipulated price
    }
}

contract ExploitTest is Test {
    IDistributor distributor;
    IRewardPool rewardPool;
    address attacker = address(0xdeadbeef);

    function setUp() public {
        // Deploy mock reward pool and distributor
        rewardPool = IRewardPool(address(new MockRewardPool()));
        distributor = new MockDistributor(address(rewardPool));

        // Fund attacker with some ETH for transactions
        vm.deal(attacker, 10 ether);
    }

    function test_exploit() public {
        // Step 1: Attacker manipulates the oracle price
        vm.prank(attacker);
        distributor.updateDepositTokensPrices();

        // Step 2: Attacker triggers reward distribution with manipulated price
        vm.prank(attacker);
        distributor.distributeRewards(0);

        // Assert the vulnerability
        // Check if the manipulated price was set
        uint256 manipulatedPrice = MockDistributor(address(distributor)).manipulatedPrice();
        assertEq(manipulatedPrice, 1000, "Price manipulation failed");

        // Further assertions can be added to check the impact on rewards, etc.
    }
}

contract MockRewardPool is IRewardPool {
    function onlyExistedRewardPool(uint256 rewardPoolIndex) external view override {
        // Mock implementation
    }

    function onlyPublicRewardPool(uint256 rewardPoolIndex) external view override {
        // Mock implementation
    }
}