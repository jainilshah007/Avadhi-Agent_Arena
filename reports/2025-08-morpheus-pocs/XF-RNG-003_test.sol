// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IScaledEntropyReceiver {
    function scaledEntropyCallback(uint256 requestId, uint256 randomNumber) external;
}

contract MockUnderlyingEntropyProvider {
    uint256 public nextRequestId;
    mapping(uint256 => address) public requester;

    function requestRandomness() external returns (uint256 requestId) {
        requestId = ++nextRequestId;
        requester[requestId] = msg.sender;
    }

    function fulfill(uint256 requestId, uint256 randomNumber) external {
        address target = requester[requestId];
        require(target != address(0), "no requester");
        MockScaledEntropyProvider(target).rawEntropyCallback(requestId, randomNumber);
    }
}

contract MockScaledEntropyProvider {
    address public owner;
    MockUnderlyingEntropyProvider public entropyProvider;
    uint256 public nextScaledRequestId;

    struct PendingRequest {
        address callback;
        uint256 underlyingRequestId;
        bool exists;
    }

    mapping(uint256 => PendingRequest) public pendingByScaledId;
    mapping(uint256 => uint256) public scaledIdByUnderlyingId;

    modifier onlyOwner() {
        require(msg.sender == owner, "only owner");
        _;
    }

    constructor(address _owner, MockUnderlyingEntropyProvider _entropyProvider) {
        owner = _owner;
        entropyProvider = _entropyProvider;
    }

    function setEntropyProvider(MockUnderlyingEntropyProvider _newProvider) external onlyOwner {
        entropyProvider = _newProvider;
    }

    function requestAndCallbackScaledRandomness() external returns (uint256 scaledRequestId) {
        uint256 underlyingRequestId = entropyProvider.requestRandomness();
        scaledRequestId = ++nextScaledRequestId;

        pendingByScaledId[scaledRequestId] = PendingRequest({
            callback: msg.sender,
            underlyingRequestId: underlyingRequestId,
            exists: true
        });

        scaledIdByUnderlyingId[underlyingRequestId] = scaledRequestId;
    }

    function rawEntropyCallback(uint256 underlyingRequestId, uint256 randomNumber) external {
        require(msg.sender == address(entropyProvider), "wrong underlying provider");

        uint256 scaledRequestId = scaledIdByUnderlyingId[underlyingRequestId];
        PendingRequest memory p = pendingByScaledId[scaledRequestId];
        require(p.exists, "no pending");

        IScaledEntropyReceiver(p.callback).scaledEntropyCallback(scaledRequestId, randomNumber);

        delete pendingByScaledId[scaledRequestId];
        delete scaledIdByUnderlyingId[underlyingRequestId];
    }

    function hasPending(uint256 scaledRequestId) external view returns (bool) {
        return pendingByScaledId[scaledRequestId].exists;
    }
}

contract MockJackpot is IScaledEntropyReceiver {
    address public owner;
    MockScaledEntropyProvider public entropy;

    uint256 public currentDrawingId;
    bool public drawingLocked;
    uint256 public pendingRequestId;
    uint256 public resolvedRandomness;

    modifier onlyOwner() {
        require(msg.sender == owner, "only owner");
        _;
    }

    modifier onlyEntropy() {
        require(msg.sender == address(entropy), "only entropy");
        _;
    }

    constructor(address _owner, MockScaledEntropyProvider _entropy) {
        owner = _owner;
        entropy = _entropy;
    }

    function setEntropy(MockScaledEntropyProvider _newEntropy) external onlyOwner {
        entropy = _newEntropy;
    }

    function startSettlement(uint256 drawingId) external onlyOwner {
        require(!drawingLocked, "already locked");
        currentDrawingId = drawingId;
        drawingLocked = true;
        pendingRequestId = entropy.requestAndCallbackScaledRandomness();
    }

    function scaledEntropyCallback(uint256 requestId, uint256 randomNumber) external override onlyEntropy {
        require(drawingLocked, "drawing not locked");
        require(requestId == pendingRequestId, "wrong request");

        resolvedRandomness = randomNumber;
        drawingLocked = false;
        pendingRequestId = 0;
    }
}

contract ExploitTest is Test {
    address internal owner = address(0xABCD);
    address internal attacker = address(0xBEEF);

    MockUnderlyingEntropyProvider internal underlying1;
    MockUnderlyingEntropyProvider internal underlying2;
    MockScaledEntropyProvider internal scaled1;
    MockScaledEntropyProvider internal scaled2;
    MockJackpot internal jackpot;

    function setUp() public {
        underlying1 = new MockUnderlyingEntropyProvider();
        underlying2 = new MockUnderlyingEntropyProvider();

        scaled1 = new MockScaledEntropyProvider(owner, underlying1);
        scaled2 = new MockScaledEntropyProvider(owner, underlying2);

        jackpot = new MockJackpot(owner, scaled1);

        vm.deal(owner, 10 ether);
        vm.deal(attacker, 10 ether);
    }

    function test_exploit() public {
        // Step 1: owner starts settlement using the original entropy stack.
        vm.prank(owner);
        jackpot.startSettlement(1);

        uint256 pendingScaledRequestId = jackpot.pendingRequestId();
        assertTrue(jackpot.drawingLocked(), "drawing should be locked after randomness request");
        assertTrue(scaled1.hasPending(pendingScaledRequestId), "old scaled provider should hold pending request");

        // Step 2: before fulfillment arrives, owner swaps Jackpot.entropy to a different scaled provider.
        vm.prank(owner);
        jackpot.setEntropy(scaled2);

        // Step 3: original underlying provider fulfills through the old provider stack.
        // The callback reaches Jackpot from scaled1, but Jackpot now only accepts scaled2.
        uint256 oldUnderlyingRequestId = 1;
        vm.expectRevert(bytes("only entropy"));
        underlying1.fulfill(oldUnderlyingRequestId, 777);

        // Step 4: prove the draw is still locked and the pending request remains stranded in the old provider.
        assertTrue(jackpot.drawingLocked(), "drawing remains permanently locked");
        assertEq(jackpot.pendingRequestId(), pendingScaledRequestId, "pending request id unchanged");
        assertEq(jackpot.resolvedRandomness(), 0, "randomness was never applied");
        assertTrue(scaled1.hasPending(pendingScaledRequestId), "pending request is stranded in old provider");

        // Step 5: normal progression is frozen; starting another settlement is blocked by the lock.
        vm.prank(owner);
        vm.expectRevert(bytes("already locked"));
        jackpot.startSettlement(2);
    }
}