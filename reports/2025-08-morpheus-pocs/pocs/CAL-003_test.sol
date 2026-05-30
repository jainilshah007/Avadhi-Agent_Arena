// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Mock interface for L1Sender
interface IL1Sender {
    function sendMintMessage(address receiver, uint256 amount, address user) external payable;
}

// Mock L1Sender contract that always reverts
contract MaliciousL1Sender is IL1Sender {
    function sendMintMessage(address, uint256, address) external payable override {
        revert("Malicious revert");
    }
}

// Mock DistributionV2 contract
contract DistributionV2 {
    struct Pool {
        uint256 payoutStart;
        uint256 claimLockPeriod;
    }

    struct PoolData {
        uint128 lastUpdate;
        uint256 rate;
        uint256 totalVirtualDeposited;
    }

    struct UserData {
        uint256 deposited;
        uint256 virtualDeposited;
        uint256 pendingRewards;
        uint256 rate;
        uint128 claimLockStart;
        uint128 claimLockEnd;
    }

    mapping(uint256 => Pool) public pools;
    mapping(uint256 => PoolData) public poolsData;
    mapping(address => mapping(uint256 => UserData)) public usersData;
    address public l1Sender;

    event UserClaimed(uint256 poolId, address user, address receiver, uint256 pendingRewards);

    constructor(address _l1Sender) {
        l1Sender = _l1Sender;
    }

    function claim(uint256 poolId_, address receiver_) external payable {
        address user_ = msg.sender;

        Pool storage pool = pools[poolId_];
        PoolData storage poolData = poolsData[poolId_];
        UserData storage userData = usersData[user_][poolId_];

        require(block.timestamp > pool.payoutStart + pool.claimLockPeriod, "DS: pool claim is locked");
        require(block.timestamp > userData.claimLockEnd, "DS: user claim is locked");

        uint256 currentPoolRate_ = 1; // Mocked value
        uint256 pendingRewards_ = 1; // Mocked value
        require(pendingRewards_ > 0, "DS: nothing to claim");

        if (userData.virtualDeposited == 0) {
            userData.virtualDeposited = userData.deposited;
        }

        poolData.lastUpdate = uint128(block.timestamp);
        poolData.rate = currentPoolRate_;
        poolData.totalVirtualDeposited =
            poolData.totalVirtualDeposited +
            userData.deposited -
            userData.virtualDeposited;

        userData.rate = currentPoolRate_;
        userData.pendingRewards = 0;
        userData.virtualDeposited = userData.deposited;
        userData.claimLockStart = 0;
        userData.claimLockEnd = 0;

        IL1Sender(l1Sender).sendMintMessage{value: msg.value}(receiver_, pendingRewards_, user_);

        emit UserClaimed(poolId_, user_, receiver_, pendingRewards_);
    }
}

contract ExploitTest is Test {
    DistributionV2 distribution;
    MaliciousL1Sender maliciousL1Sender;

    function setUp() public {
        // Deploy the malicious L1Sender contract
        maliciousL1Sender = new MaliciousL1Sender();

        // Deploy the DistributionV2 contract with the malicious L1Sender
        distribution = new DistributionV2(address(maliciousL1Sender));

        // Set up initial state
        distribution.pools(1).payoutStart = block.timestamp - 1 days;
        distribution.pools(1).claimLockPeriod = 1 days;
        distribution.usersData(address(this), 1).deposited = 100;
        distribution.usersData(address(this), 1).claimLockEnd = block.timestamp - 1 days;
    }

    function test_exploit() public {
        // Attempt to claim rewards
        vm.expectRevert("Malicious revert");
        distribution.claim{value: 1 ether}(1, address(this));

        // Assert that the claim was not successful
        assertEq(distribution.usersData(address(this), 1).pendingRewards, 1);
    }
}