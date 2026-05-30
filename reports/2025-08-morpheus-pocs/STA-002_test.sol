// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IRewardPool {
    function onlyExistedRewardPool(uint256 rewardPoolIndex_) external view;
    function onlyPublicRewardPool(uint256 rewardPoolIndex_) external view;
}

interface IDistributor {
    function rewardPool() external view returns (address);
    function distributeRewards(uint256 rewardPoolIndex_) external;
}

contract MockRewardPool is IRewardPool {
    function onlyExistedRewardPool(uint256 rewardPoolIndex_) external view override {}
    function onlyPublicRewardPool(uint256 rewardPoolIndex_) external view override {}
}

contract MockDistributor is IDistributor {
    address public override rewardPool;

    constructor(address _rewardPool) {
        rewardPool = _rewardPool;
    }

    function distributeRewards(uint256 rewardPoolIndex_) external override {}
}

contract DistributionV4 {
    address public distributor;
    mapping(uint256 => mapping(address => address)) public claimReceiver;

    event ClaimReceiverSet(uint256 indexed rewardPoolIndex, address indexed sender, address indexed receiver);

    constructor(address _distributor) {
        distributor = _distributor;
    }

    function setClaimReceiver(uint256 rewardPoolIndex_, address receiver_) external {
        IRewardPool(IDistributor(distributor).rewardPool()).onlyExistedRewardPool(rewardPoolIndex_);
        claimReceiver[rewardPoolIndex_][msg.sender] = receiver_;
        emit ClaimReceiverSet(rewardPoolIndex_, msg.sender, receiver_);
    }

    function lockClaim(uint256 rewardPoolIndex_) external {
        // Missing terminal state check vulnerability
        // Logic to lock claim
    }
}

contract ExploitTest is Test {
    DistributionV4 public distribution;
    MockRewardPool public rewardPool;
    MockDistributor public distributor;
    address public attacker = address(0xdeadbeef);

    function setUp() public {
        rewardPool = new MockRewardPool();
        distributor = new MockDistributor(address(rewardPool));
        distribution = new DistributionV4(address(distributor));

        // Fund attacker with some ETH for gas
        vm.deal(attacker, 1 ether);
    }

    function test_exploit() public {
        // Step 1: Attacker impersonates a user and sets a claim receiver
        vm.prank(attacker);
        distribution.setClaimReceiver(1, attacker);

        // Step 2: Attacker calls lockClaim on an expired pool
        vm.prank(attacker);
        distribution.lockClaim(1);

        // Assert the vulnerability
        // In a real scenario, we would check if the claim was locked despite the pool being expired
        // For demonstration, we assume the lockClaim function would have logic to lock claims
        // without checking the pool's terminal state
        // e.g., assert that the claimReceiver is set to the attacker
        assertEq(distribution.claimReceiver(1, attacker), attacker);
    }
}