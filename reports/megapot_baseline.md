# Megapot Audit Baseline — Code4rena (Nov 2025)

Source: https://code4rena.com/reports/2025-11-megapot

This is the ground truth we compare our `avadhi hunt` output against.

---

## High Severity (3)

### H-01: Attacker can steal JackpotTicketNFTs from JackpotBridgeManager
- **Location:** `JackpotBridgeManager._bridgeFunds()` (L345-362)
- **Root Cause:** `_bridgeDetails.to.call(_bridgeDetails.data)` — user-controlled external call target and data. Attacker crafts malicious `RelayTxData` to call `safeTransferFrom` on the NFT contract, stealing victim NFTs held in custody.
- **Category:** Arbitrary External Call / Access Control
- **Impact:** Theft of NFTs + USDC drain via `onERC721Received` callback

### H-02: Unoptimized subset matches counting exceeds tx gas limit
- **Location:** `TicketComboTracker._countSubsetMatches()` (L157-160)
- **Root Cause:** Nested loop generates subsets `bonusballMax * normalTiers` times. For large `bonusballMax` (e.g., 129), gas exceeds Base chain's 25M limit.
- **Category:** DoS / Gas Griefing
- **Impact:** Drawing can never be settled; permanent protocol lock

### H-03: LP pool cap may be exceeded on drawing settlement
- **Location:** `JackpotLPManager.processDrawingSettlement()` (L378, L391)
- **Root Cause:** New LP value calculation doesn't enforce the pool cap, allowing `lpPoolTotal > governancePoolCap` after settlement. Breaks bitpacking invariant (`bonusBallMax + normalBallMax <= 255`).
- **Category:** Invariant Violation / Math
- **Impact:** DoS on ticket purchases, unfair betting

---

## Medium Severity (8)

### M-01: Global Variable Manipulation During Active Draw
- **Category:** Admin Privilege / State Inconsistency
- **Impact:** Owner can change `protocolFee`, `referralFee`, `payoutCalculator`, `entropy`, `jackpotLPManager` mid-draw

### M-02: Incorrect ticket price reference in JackpotBridgeManager
- **Category:** Stale State / Value Flow
- **Impact:** User overpayment after price updates

### M-03: Deliberately increasing liquidity can DoS governance parameter updates
- **Category:** DoS / Governance
- **Impact:** LP cap manipulation blocks admin updates

### M-04: lpEarnings generated in emergency mode become stuck
- **Category:** Locked Funds
- **Impact:** LP earnings inaccessible after emergency

### M-05: Randomness can be exploited in some cases
- **Category:** Randomness / VRF
- **Impact:** Predictable outcomes

### M-06: Changes to Pyth entropy provider allow attacker to fix jackpot result
- **Category:** Randomness Manipulation
- **Impact:** Attacker controls draw outcome

### M-07: Changing Entropy Provider During Active Drawing Causes Protocol Lock
- **Category:** DoS / State Machine
- **Impact:** Permanent protocol lock, callback failure

### M-08: Changing Payout Calculator During Active Drawing Causes Loss of Winnings
- **Category:** State Inconsistency / Value Flow
- **Impact:** Unclaimed winnings lost

---

## Low Severity (8)
- L-01: LP Earnings can exceed maximum capacity
- L-02: Pool cap check restricts future round deposits
- L-03: Missing validation for ball sum exceeding bit vector capacity
- L-04: Missing validation for normal ball max range
- L-05: Unbounded bonus ball max causes DoS
- L-06: Drawing time uses scheduled end instead of actual settlement
- L-07: Missing user tickets mapping update in claimTickets
- L-08: Pending deposits cannot be withdrawn until converted to shares

---

## Summary Stats
| Metric | Count |
|--------|-------|
| High | 3 |
| Medium | 8 |
| Low | 8 |
| Total | 19 |
| Unique Wardens | 65+ |
| Prize Pool | $30,000 USDC |
