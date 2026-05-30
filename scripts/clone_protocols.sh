#!/bin/bash
# Clone all 36 DeFi protocol repos (shallow clones)
set -e

BASE_DIR="/Users/jainilshah/codenstuff/Avadhi/data/protocols/git_repos"
mkdir -p "$BASE_DIR"
cd "$BASE_DIR"

echo "=== Cloning Protocol Git Repos ==="

clone_if_needed() {
    local repo_url="$1"
    local dir_name="$2"
    if [ -d "$dir_name" ]; then
        echo "SKIP: $dir_name already exists"
    else
        echo "CLONE: $repo_url → $dir_name"
        git clone --depth 1 "$repo_url" "$dir_name" 2>&1 || echo "FAIL: $repo_url"
    fi
}

# 1. Uniswap v3
clone_if_needed "https://github.com/Uniswap/v3-core.git" "uniswap-v3-core"
clone_if_needed "https://github.com/Uniswap/v3-periphery.git" "uniswap-v3-periphery"

# 2. Curve Finance
clone_if_needed "https://github.com/curvefi/curve-contract.git" "curve-contract"
clone_if_needed "https://github.com/curvefi/stableswap-ng.git" "curve-stableswap-ng"

# 3. Balancer v2
clone_if_needed "https://github.com/balancer/balancer-v2-monorepo.git" "balancer-v2-monorepo"

# 4. Aave v3
clone_if_needed "https://github.com/aave/aave-v3-core.git" "aave-v3-core"
clone_if_needed "https://github.com/aave-dao/aave-v3-origin.git" "aave-v3-origin"

# 5. Morpho Blue
clone_if_needed "https://github.com/morpho-org/morpho-blue.git" "morpho-blue"

# 6. Compound v3
clone_if_needed "https://github.com/compound-finance/comet.git" "compound-comet"

# 7. MakerDAO
clone_if_needed "https://github.com/makerdao/dss.git" "makerdao-dss"
clone_if_needed "https://github.com/makerdao/sky.git" "makerdao-sky"

# 8. Lido
clone_if_needed "https://github.com/lidofinance/core.git" "lido-core"

# 9. EigenLayer
clone_if_needed "https://github.com/Layr-Labs/eigenlayer-contracts.git" "eigenlayer-contracts"

# 10. GMX v2
clone_if_needed "https://github.com/gmx-io/gmx-synthetics.git" "gmx-synthetics"

# 11. Synthetix v3
clone_if_needed "https://github.com/Synthetixio/synthetix-v3.git" "synthetix-v3"

# 12. Yearn v3
clone_if_needed "https://github.com/yearn/yearn-vaults-v3.git" "yearn-vaults-v3"
clone_if_needed "https://github.com/yearn/tokenized-strategy-foundry-mix.git" "yearn-tokenized-strategy"

# 13. LayerZero
clone_if_needed "https://github.com/LayerZero-Labs/LayerZero-v2.git" "layerzero-v2"

# 14. Across Protocol
clone_if_needed "https://github.com/across-protocol/contracts.git" "across-contracts"

# 15. Chainlink
clone_if_needed "https://github.com/smartcontractkit/chainlink.git" "chainlink"

# 16. Uniswap v4
clone_if_needed "https://github.com/Uniswap/v4-core.git" "uniswap-v4-core"
clone_if_needed "https://github.com/Uniswap/v4-periphery.git" "uniswap-v4-periphery"

# 17. Euler v2
clone_if_needed "https://github.com/euler-xyz/euler-vault-kit.git" "euler-vault-kit"
clone_if_needed "https://github.com/euler-xyz/evk-periphery.git" "euler-evk-periphery"

# 18. CoW Protocol
clone_if_needed "https://github.com/cowprotocol/contracts.git" "cow-contracts"

# 19. UniswapX
clone_if_needed "https://github.com/Uniswap/UniswapX.git" "uniswapx"

# 20. Centrifuge
clone_if_needed "https://github.com/centrifuge/protocol.git" "centrifuge-protocol"

# 21. EtherFi
clone_if_needed "https://github.com/etherfi-protocol/smart-contracts.git" "etherfi-contracts"

# 22. Pendle
clone_if_needed "https://github.com/pendle-finance/pendle-core-v2-public.git" "pendle-core-v2"

# 23. Permit2 + Universal Router
clone_if_needed "https://github.com/Uniswap/permit2.git" "permit2"
clone_if_needed "https://github.com/Uniswap/universal-router.git" "universal-router"

# 24. Polymarket
clone_if_needed "https://github.com/Polymarket/ctf-exchange.git" "polymarket-ctf-exchange"
clone_if_needed "https://github.com/gnosis/conditional-tokens-contracts.git" "gnosis-conditional-tokens"

# 25. Nexus Mutual
clone_if_needed "https://github.com/NexusMutual/smart-contracts.git" "nexus-mutual"

# 26. Arrakis Finance
clone_if_needed "https://github.com/ArrakisFinance/arrakis-modular.git" "arrakis-modular"

# 27. 1inch
clone_if_needed "https://github.com/1inch/fusion-protocol.git" "1inch-fusion"
clone_if_needed "https://github.com/1inch/limit-order-protocol.git" "1inch-limit-order"

# 28. Gearbox v3
clone_if_needed "https://github.com/Gearbox-protocol/core-v3.git" "gearbox-core-v3"

# 29. Ethena
clone_if_needed "https://github.com/ethena-labs/bbp-public-assets.git" "ethena-bbp"

# 30. Maple Finance
clone_if_needed "https://github.com/maple-labs/maple-core-v2.git" "maple-core-v2"

# 31. Gnosis Safe
clone_if_needed "https://github.com/safe-global/safe-smart-account.git" "safe-smart-account"

# 32. Sablier
clone_if_needed "https://github.com/sablier-labs/lockup.git" "sablier-lockup"
clone_if_needed "https://github.com/sablier-labs/flow.git" "sablier-flow"

# 33. Frax Finance
clone_if_needed "https://github.com/FraxFinance/fraxlend.git" "fraxlend"
clone_if_needed "https://github.com/FraxFinance/frxETH-public.git" "frxeth-public"

# 34. Chainlink CCIP
clone_if_needed "https://github.com/smartcontractkit/chainlink-ccip.git" "chainlink-ccip"

echo ""
echo "=== Protocol Git Clones Complete ==="
echo "Total repos:"
ls -d */ | wc -l
ls -la "$BASE_DIR"
