#!/bin/bash

# Function to get npm version
get_npm_version() {
    if command -v npm >/dev/null 2>&1; then
        npm --version 2>/dev/null || echo "Not Detected"
    else
        echo "Not Detected"
    fi
}

# Function to get pnpm version
get_pnpm_version() {
    if command -v pnpm >/dev/null 2>&1; then
        pnpm -v 2>/dev/null || echo "Not Detected"
    else
        echo "Not Detected"
    fi
}

# Get versions
npm_version=$(get_npm_version)
pnpm_version=$(get_pnpm_version)

# Output in the requested format
echo "${npm_version}|${pnpm_version}"