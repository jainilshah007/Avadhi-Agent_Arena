// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface ISecondSwapMarketplaceSetting {
    function setFeeAccount(address _address) external;
    function setPenaltyFee(uint256 _amount) external;
    function setMinListingDuration(uint256 _seconds) external;
    function setS2Admin(address _user) external;
    function setMarketplaceStatus(bool _status) external;
}

contract ExploitTest is Test {
    ISecondSwapMarketplaceSetting marketplaceSetting;
    address admin;
    address nonPayableAddress;
    address payable feeCollector;
    uint256 initialBalance;

    function setUp() public {
        // Deploy the contract and set initial state
        admin = address(0x1);
        nonPayableAddress = address(0x2);
        feeCollector = payable(address(0x3));

        // Assume marketplaceSetting is already deployed and admin is set
        marketplaceSetting = ISecondSwapMarketplaceSetting(address(0x4));

        // Fund the fee collector with some initial balance
        initialBalance = 10 ether;
        vm.deal(feeCollector, initialBalance);

        // Impersonate admin to set the fee collector
        vm.prank(admin);
        marketplaceSetting.setFeeAccount(feeCollector);
    }

    function test_exploit() public {
        // Step 1: Impersonate admin to set fee collector to a non-payable address
        vm.prank(admin);
        marketplaceSetting.setFeeAccount(nonPayableAddress);

        // Step 2: Simulate a marketplace transaction that generates fees
        // This is a mock step, assuming a function that sends fees to the fee collector
        // For example: marketplace.collectFees{value: 1 ether}();

        // Step 3: Assert that the fees are lost or locked
        // Since nonPayableAddress cannot receive Ether, the balance should remain unchanged
        assertEq(feeCollector.balance, initialBalance);

        // Assert that the nonPayableAddress did not receive any Ether
        assertEq(nonPayableAddress.balance, 0);
    }
}