// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IFeeConfig {
    function setOriginalFee(uint256 fee) external;
    function setOverrideFee(uint256 fee) external;
    function getFeeAndTreasury() external view returns (uint256 fee, address treasury);
}

contract MockFeeConfig is IFeeConfig {
    uint256 private originalFee;
    uint256 private overrideFee;
    address private treasury;

    constructor() {
        treasury = msg.sender;
    }

    function setOriginalFee(uint256 fee) external override {
        originalFee = fee;
    }

    function setOverrideFee(uint256 fee) external override {
        overrideFee = fee;
    }

    function getFeeAndTreasury() external view override returns (uint256 fee, address) {
        // Vulnerability: returns originalFee instead of considering overrideFee
        return (originalFee, treasury);
    }
}

contract ExploitTest is Test {
    MockFeeConfig feeConfig;
    address attacker = address(0xdeadbeef);

    function setUp() public {
        // Deploy the FeeConfig contract
        feeConfig = new MockFeeConfig();

        // Set initial state
        feeConfig.setOriginalFee(100); // Set original fee to 100
        feeConfig.setOverrideFee(50);  // Set override fee to 50
    }

    function test_exploit() public {
        // Step 1: Attacker ensures the override fee is different from the original
        vm.prank(attacker);
        feeConfig.setOverrideFee(50);

        // Step 2: Retrieve the fee and treasury
        (uint256 fee, address treasury) = feeConfig.getFeeAndTreasury();

        // Step 3: Assert the vulnerability
        // The fee should be 50 (override), but due to the bug, it returns 100 (original)
        assertEq(fee, 100, "Fee should be the original fee due to the bug");
        assertEq(treasury, address(this), "Treasury address should be correct");
    }
}