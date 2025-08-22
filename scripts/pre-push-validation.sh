#!/bin/bash

# Pre-push validation script for ModelAudit
# This script runs all critical CI checks locally to catch issues before pushing
# Saves 3-5 minutes of waiting for remote CI feedback

set -e  # Exit on any failure

echo "🚀 ModelAudit Pre-Push Validation"
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    case $1 in
        "success") echo -e "${GREEN}✅ $2${NC}" ;;
        "error") echo -e "${RED}❌ $2${NC}" ;;
        "warning") echo -e "${YELLOW}⚠️ $2${NC}" ;;
        "info") echo -e "🔍 $2" ;;
    esac
}

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    print_status "error" "Not in a git repository"
    exit 1
fi

# Check if rye is available
if ! command -v rye &> /dev/null; then
    print_status "error" "Rye is not installed or not in PATH"
    exit 1
fi

print_status "info" "Step 1/5: Checking code formatting..."
if rye run ruff format --check modelaudit/ tests/ > /dev/null 2>&1; then
    print_status "success" "Code formatting is correct"
else
    print_status "warning" "Format issues found - running formatter..."
    rye run ruff format modelaudit/ tests/
    print_status "success" "Code formatted successfully"
fi

print_status "info" "Step 2/5: Checking code quality (linting)..."
if rye run ruff check modelaudit/ tests/ > /dev/null 2>&1; then
    print_status "success" "No linting issues found"
else
    print_status "error" "Lint issues found. Run: rye run ruff check --fix modelaudit/ tests/"
    exit 1
fi

print_status "info" "Step 3/5: Running type checking..."
if rye run mypy modelaudit/ > /dev/null 2>&1; then
    print_status "success" "Type checking passed"
else
    print_status "error" "Type checking failed"
    exit 1
fi

print_status "info" "Step 4/5: Running fast test suite..."
if rye run pytest -n auto -m "not slow and not integration and not performance" --tb=short -q > /dev/null 2>&1; then
    print_status "success" "Fast tests passed"
else
    print_status "error" "Fast tests failed. Run tests manually to see details."
    exit 1
fi

print_status "info" "Step 5/5: Checking documentation formatting..."
if command -v npx &> /dev/null; then
    if npx prettier@latest --check "**/*.{md,yaml,yml,json}" > /dev/null 2>&1; then
        print_status "success" "Documentation formatting is correct"
    else
        print_status "warning" "Documentation format issues found - fixing..."
        npx prettier@latest --write "**/*.{md,yaml,yml,json}"
        print_status "success" "Documentation formatted successfully"
    fi
else
    print_status "warning" "Prettier not available - skipping documentation format check"
fi

echo ""
print_status "success" "All validation checks passed! 🎉"
echo ""
echo "Your changes are ready to push. The CI should pass without issues."
echo "Local validation completed in ~30 seconds vs 3-5 minutes in CI."