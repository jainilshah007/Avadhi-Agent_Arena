#!/bin/bash
# Clone Web3 Basics git repos (shallow clones to save disk space)
set -e

BASE_DIR="/Users/jainilshah/codenstuff/Avadhi/data/web3_basics/git_repos"
mkdir -p "$BASE_DIR"
cd "$BASE_DIR"

echo "=== Cloning Web3 Basics Git Repos ==="

# Function to clone if not already present
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

clone_if_needed "https://github.com/ethereum/solidity.git" "solidity"
clone_if_needed "https://github.com/ethereum/EIPs.git" "EIPs"
clone_if_needed "https://github.com/ethereum/ERCs.git" "ERCs"
clone_if_needed "https://github.com/OpenZeppelin/openzeppelin-contracts.git" "openzeppelin-contracts"
clone_if_needed "https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable.git" "openzeppelin-contracts-upgradeable"
clone_if_needed "https://github.com/OpenZeppelin/docs.git" "openzeppelin-docs"
clone_if_needed "https://github.com/foundry-rs/book.git" "foundry-book"
clone_if_needed "https://github.com/foundry-rs/forge-std.git" "forge-std"
clone_if_needed "https://github.com/duneanalytics/evm.codes.git" "evm-codes"
clone_if_needed "https://github.com/ethereum/yellowpaper.git" "yellowpaper"
clone_if_needed "https://github.com/ethereum/execution-specs.git" "execution-specs"
clone_if_needed "https://github.com/wolflo/evm-opcodes.git" "evm-opcodes"
clone_if_needed "https://github.com/solidity-by-example/solidity-by-example.github.io.git" "solidity-by-example"
clone_if_needed "https://github.com/andreitoma8/learn-yul.git" "learn-yul"

echo ""
echo "=== Web3 Basics Git Clones Complete ==="
echo "Repos cloned to: $BASE_DIR"
ls -la "$BASE_DIR"
