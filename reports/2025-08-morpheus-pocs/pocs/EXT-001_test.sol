// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface ISafeERC20Namer {
    function callAndParseStringReturn(address token, bytes4 selector) external view returns (string memory);
}

contract MaliciousContract {
    string private secret = "Sensitive Information";

    function getSecret() external view returns (string memory) {
        return secret;
    }
}

contract SafeERC20NamerExploitTest is Test {
    ISafeERC20Namer safeERC20Namer;
    MaliciousContract maliciousContract;
    address attacker = address(0xdeadbeef);

    function setUp() public {
        // Deploy the malicious contract
        maliciousContract = new MaliciousContract();

        // Assume safeERC20Namer is already deployed and we have its address
        // For the purpose of this test, we will mock its interface
        safeERC20Namer = ISafeERC20Namer(address(maliciousContract));

        // Fund the attacker with some ETH for transaction fees
        vm.deal(attacker, 1 ether);
    }

    function test_exploit() public {
        // Step 1: Attacker impersonates their address
        vm.prank(attacker);

        // Step 2: Attacker calls callAndParseStringReturn with the malicious contract address
        // and the selector for the getSecret function
        bytes4 selector = bytes4(keccak256("getSecret()"));
        string memory extractedSecret = safeERC20Namer.callAndParseStringReturn(address(maliciousContract), selector);

        // Step 3: Assert that the attacker was able to extract the sensitive information
        assertEq(extractedSecret, "Sensitive Information");
    }
}