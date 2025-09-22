#!/bin/bash

# Get npm version
npm_version=$(npm --version 2>/dev/null || echo "Not Detected")

# Get pnpm version  
pnpm_version=$(pnpm -v 2>/dev/null || echo "Not Detected")

# Output result
echo "${npm_version}|${pnpm_version}"
