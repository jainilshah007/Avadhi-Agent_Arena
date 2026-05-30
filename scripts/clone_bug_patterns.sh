#!/bin/bash
# Clone Bug Patterns git repos
set -e

BASE_DIR="/Users/jainilshah/codenstuff/Avadhi/data/bug_patterns/git_repos"
mkdir -p "$BASE_DIR"
cd "$BASE_DIR"

echo "=== Cloning Bug Patterns Git Repos ==="

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

clone_if_needed "https://github.com/Consensys/smart-contract-best-practices.git" "consensys-best-practices"
clone_if_needed "https://github.com/crytic/building-secure-contracts.git" "building-secure-contracts"
clone_if_needed "https://github.com/smartdec/classification.git" "smartdec-classification"
clone_if_needed "https://github.com/SmartContractSecurity/SWC-registry.git" "SWC-registry"
clone_if_needed "https://github.com/CryptoServices/dasp.git" "dasp"
clone_if_needed "https://github.com/OWASP/owasp-scs.git" "owasp-scs"

echo ""
echo "=== Bug Patterns Git Clones Complete ==="
ls -la "$BASE_DIR"
