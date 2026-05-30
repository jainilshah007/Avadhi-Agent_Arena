// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract MockERC20 is IERC20 {
    using SafeERC20 for IERC20;

    string public name = "MockERC20";
    string public symbol = "MERC20";
    uint8 public decimals = 18;
    uint256 public totalSupply = 1_000_000 * 10**18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor() {
        balanceOf[msg.sender] = totalSupply;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Allowance exceeded");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        allowance[from][msg.sender] -= amount;
        emit Transfer(from, to, amount);
        return true;
    }
}

contract BuilderSubnets {
    using SafeERC20 for IERC20;

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

    address public owner;
    bool public isMigrationOver;
    uint256 public subnetCreationFeeAmount;
    address public subnetCreationFeeTreasury;
    IERC20 public token;
    mapping(bytes32 => Subnet) public subnets;
    mapping(bytes32 => SubnetMetadata) public subnetsMetadata;

    event SubnetEdited(bytes32 indexed subnetId, Subnet subnet);
    event SubnetMetadataEdited(bytes32 indexed subnetId, SubnetMetadata metadata);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor(address _token) {
        owner = msg.sender;
        token = IERC20(_token);
    }

    function setSubnetCreationFeeAmount(uint256 amount) external onlyOwner {
        subnetCreationFeeAmount = amount;
    }

    function createSubnet(Subnet calldata subnet_, SubnetMetadata calldata metadata_) external {
        bytes32 subnetId_ = keccak256(abi.encodePacked(subnet_.name));
        require(subnet_.owner != address(0), "Invalid owner address");
        require(subnetCreationFeeAmount <= token.balanceOf(msg.sender), "Insufficient funds for fee");

        if (subnetCreationFeeAmount > 0) {
            token.safeTransferFrom(msg.sender, subnetCreationFeeTreasury, subnetCreationFeeAmount);
        }

        subnets[subnetId_] = subnet_;
        subnetsMetadata[subnetId_] = metadata_;

        emit SubnetEdited(subnetId_, subnet_);
        emit SubnetMetadataEdited(subnetId_, metadata_);
    }
}

contract ExploitTest is Test {
    BuilderSubnets builderSubnets;
    MockERC20 mockToken;
    address admin = address(0x1);
    address user = address(0x2);

    function setUp() public {
        mockToken = new MockERC20();
        builderSubnets = new BuilderSubnets(address(mockToken));

        // Set initial balances
        deal(address(mockToken), user, 100 * 10**18);
        deal(address(mockToken), admin, 100 * 10**18);

        // Set roles
        vm.prank(admin);
        builderSubnets.setSubnetCreationFeeAmount(10 * 10**18);
    }

    function test_exploit() public {
        // Step 1: Admin sets a high subnet creation fee
        vm.prank(admin);
        builderSubnets.setSubnetCreationFeeAmount(200 * 10**18);

        // Step 2: User attempts to create a subnet without sufficient funds
        BuilderSubnets.Subnet memory subnet = BuilderSubnets.Subnet({
            name: "TestSubnet",
            owner: user,
            withdrawLockPeriodAfterStake: 1,
            fee: 1,
            feeTreasury: user,
            startsAt: block.timestamp + 1 days
        });

        BuilderSubnets.SubnetMetadata memory metadata = BuilderSubnets.SubnetMetadata({
            description: "Test Subnet Metadata"
        });

        vm.prank(user);
        vm.expectRevert("Insufficient funds for fee");
        builderSubnets.createSubnet(subnet, metadata);

        // Assert the DoS condition
        bytes32 subnetId = keccak256(abi.encodePacked(subnet.name));
        assertEq(builderSubnets.subnets(subnetId).owner, address(0), "Subnet should not be created");
    }
}