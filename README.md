# npm_audit
<#
.SYNOPSIS
    Runs npm audit at scale across Windows workstations
.DESCRIPTION
    Searches the entire C:\ drive for package.json files and runs npm audit on each project,
    reporting vulnerabilities in a pipe-delimited format.
.NOTES
    Version: 1.3
    Author: Security Audit Script
    Requires: npm installed and available in PATH
#>
