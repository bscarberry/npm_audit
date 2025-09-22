#!/bin/bash

# Function to get npm version
get_npm_version() {
    if command -v npm >/dev/null 2>&1; then
        version=$(npm --version 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$version" ]; then
            echo "$version"
        else
            echo "Not Detected"
        fi
    else
        echo "Not Detected"
    fi
}

# Function to get pnpm version
get_pnpm_version() {
    if command -v pnpm >/dev/null 2>&1; then
        version=$(pnpm -v 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$version" ]; then
            echo "$version"
        else
            echo "Not Detected"
        fi
    else
        echo "Not Detected"
    fi
}

# Get versions (suppress any potential output from functions)
npm_version=$(get_npm_version 2>/dev/null)
pnpm_version=$(get_pnpm_version 2>/dev/null)

# Output only the final result
echo "${npm_version}|${pnpm_version}"
