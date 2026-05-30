// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

interface ITrailsIntentEntrypoint {
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

contract FeeOnTransferToken is IERC20 {
    using SafeERC20 for IERC20;

    string public constant name = "FeeOnTransferToken";
    string public constant symbol = "FOT";
    uint8 public constant decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    uint256 public feePercentage = 1; // 1% fee on transfer

    constructor(uint256 initialSupply) {
        balanceOf[msg.sender] = initialSupply;
        totalSupply = initialSupply;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        uint256 fee = (amount * feePercentage) / 100;
        uint256 amountAfterFee = amount - fee;
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amountAfterFee;
        balanceOf[address(this)] += fee;
        emit Transfer(msg.sender, to, amountAfterFee);
        emit Transfer(msg.sender, address(this), fee);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 fee = (amount * feePercentage) / 100;
        uint256 amountAfterFee = amount - fee;
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amountAfterFee;
        balanceOf[address(this)] += fee;
        emit Transfer(from, to, amountAfterFee);
        emit Transfer(from, address(this), fee);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }
}

contract ExploitTest is Test {
    ITrailsIntentEntrypoint public trailsIntentEntrypoint;
    FeeOnTransferToken public feeOnTransferToken;
    address public user = address(0x1);
    address public intentAddress = address(0x2);
    address public feeCollector = address(0x3);

    function setUp() public {
        // Deploy the fee-on-transfer token
        feeOnTransferToken = new FeeOnTransferToken(1000 ether);

        // Deploy the TrailsIntentEntrypoint contract (mocked for this test)
        trailsIntentEntrypoint = ITrailsIntentEntrypoint(address(new MockTrailsIntentEntrypoint()));

        // Fund the user with tokens
        feeOnTransferToken.transfer(user, 100 ether);

        // Approve the TrailsIntentEntrypoint contract to spend user's tokens
        vm.prank(user);
        feeOnTransferToken.approve(address(trailsIntentEntrypoint), type(uint256).max);
    }

    function test_exploit() public {
        // Initial balances
        uint256 initialIntentBalance = feeOnTransferToken.balanceOf(intentAddress);

        // Step 1: User deposits fee-on-transfer token to intent
        vm.prank(user);
        trailsIntentEntrypoint.depositToIntent(
            user,
            address(feeOnTransferToken),
            100 ether,
            intentAddress,
            block.timestamp + 1 days,
            0,
            0,
            address(0),
            0,
            bytes32(0),
            bytes32(0)
        );

        // Step 2: Check the balance of the intent address
        uint256 finalIntentBalance = feeOnTransferToken.balanceOf(intentAddress);

        // Assert the vulnerability: The intent address received less than expected
        assertLt(finalIntentBalance, initialIntentBalance + 100 ether);
    }
}

contract MockTrailsIntentEntrypoint is ITrailsIntentEntrypoint {
    using SafeERC20 for IERC20;

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
    ) external override {
        IERC20(token).safeTransferFrom(user, intentAddress, amount);
    }
}