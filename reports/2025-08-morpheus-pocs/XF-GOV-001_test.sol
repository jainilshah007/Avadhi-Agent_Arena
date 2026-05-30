// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IRankedBattle {
    function setBpsLostPerLoss(uint256 newBps) external;
    function startBattle(uint256 fighterId) external;
    function completeBattle(uint256 fighterId) external returns (uint256 nrnAtRisk);
    function getBpsLostPerLoss() external view returns (uint256);
}

contract MockRankedBattle is IRankedBattle {
    uint256 public bpsLostPerLoss = 100; // Initial value
    mapping(uint256 => uint256) public battleNRNAtRisk;

    function setBpsLostPerLoss(uint256 newBps) external override {
        bpsLostPerLoss = newBps;
    }

    function startBattle(uint256 fighterId) external override {
        // Simulate starting a battle
        battleNRNAtRisk[fighterId] = bpsLostPerLoss;
    }

    function completeBattle(uint256 fighterId) external override returns (uint256 nrnAtRisk) {
        // Simulate completing a battle
        nrnAtRisk = battleNRNAtRisk[fighterId];
    }

    function getBpsLostPerLoss() external view override returns (uint256) {
        return bpsLostPerLoss;
    }
}

contract ExploitTest is Test {
    MockRankedBattle rankedBattle;
    address admin = address(0x1);
    address player = address(0x2);

    function setUp() public {
        // Deploy the mock contract
        rankedBattle = new MockRankedBattle();

        // Fund the admin and player accounts
        vm.deal(admin, 1 ether);
        vm.deal(player, 1 ether);
    }

    function test_exploit() public {
        uint256 initialBps = rankedBattle.getBpsLostPerLoss();
        uint256 fighterId = 1;

        // Step 1: Player starts a battle
        vm.prank(player);
        rankedBattle.startBattle(fighterId);

        // Step 2: Admin changes the bpsLostPerLoss mid-operation
        uint256 newBps = 200;
        vm.prank(admin);
        rankedBattle.setBpsLostPerLoss(newBps);

        // Step 3: Player completes the battle
        vm.prank(player);
        uint256 nrnAtRisk = rankedBattle.completeBattle(fighterId);

        // Assert the vulnerability: NRN at risk should be calculated with the initial bps
        assertEq(nrnAtRisk, initialBps, "NRN at risk should be calculated with the initial bpsLostPerLoss");
    }
}