// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract BuildersV3 {
    bool public pauseForMigration;
    mapping(address => uint256) public pendingRewards;

    modifier whenNotPausedForMigration() {
        require(!pauseForMigration, "Paused for migration");
        _;
    }

    function claim() external whenNotPausedForMigration {
        uint256 reward = pendingRewards[msg.sender];
        require(reward > 0, "No rewards to claim");
        pendingRewards[msg.sender] = 0;
        payable(msg.sender).transfer(reward);
    }

    function activatePauseForMigration() external {
        pauseForMigration = true;
    }

    function depositRewards(address user, uint256 amount) external payable {
        require(msg.value == amount, "Incorrect ETH sent");
        pendingRewards[user] += amount;
    }
}

contract ExploitTest is Test {
    BuildersV3 buildersV3;
    address admin = address(0x1);
    address user = address(0x2);

    function setUp() public {
        // Deploy the BuildersV3 contract
        buildersV3 = new BuildersV3();

        // Fund the user with some ETH
        vm.deal(user, 1 ether);

        // Deposit rewards for the user
        vm.prank(user);
        buildersV3.depositRewards{value: 1 ether}(user, 1 ether);
    }

    function test_exploit() public {
        // Step 1: Admin activates pauseForMigration
        vm.prank(admin);
        buildersV3.activatePauseForMigration();

        // Step 2: User attempts to claim rewards
        vm.prank(user);
        vm.expectRevert("Paused for migration");
        buildersV3.claim();

        // Assert the vulnerability: User's rewards remain locked
        assertEq(buildersV3.pendingRewards(user), 1 ether);
    }
}