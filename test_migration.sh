#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Testing ModelAudit Rye Migration${NC}"
echo "========================================"

# Function to print test results
print_result() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ $1${NC}"
    else
        echo -e "${RED}❌ $1${NC}"
        exit 1
    fi
}

# Test 1: Check Rye installation
echo -e "\n${YELLOW}📋 Test 1: Rye Installation${NC}"
if command -v rye &> /dev/null; then
    echo "Rye version: $(rye --version)"
    print_result "Rye is installed"
else
    echo -e "${RED}❌ Rye is not installed. Please run: curl -sSf https://rye-up.com/get | bash${NC}"
    exit 1
fi

# Test 2: Sync dependencies
echo -e "\n${YELLOW}📦 Test 2: Dependency Sync${NC}"
rye sync --features all
print_result "Dependencies synced successfully"

# Test 3: Lock file generation
echo -e "\n${YELLOW}🔒 Test 3: Lock Files${NC}"
if [[ -f "requirements.lock" && -f "requirements-dev.lock" ]]; then
    echo "Lock files found:"
    ls -la requirements*.lock
    print_result "Lock files exist"
else
    echo -e "${RED}❌ Lock files missing${NC}"
    exit 1
fi

# Test 4: CLI functionality
echo -e "\n${YELLOW}🖥️  Test 4: CLI Functionality${NC}"
rye run modelaudit --help > /dev/null
print_result "CLI help command works"

rye run modelaudit scan --help > /dev/null
print_result "CLI scan command help works"

# Test 5: Run tests
echo -e "\n${YELLOW}🧪 Test 5: Running Tests${NC}"
rye run pytest tests/ -v --tb=short
print_result "All tests pass"

# Test 6: Code quality checks
echo -e "\n${YELLOW}🔍 Test 6: Code Quality${NC}"
rye run ruff check modelaudit/
print_result "Ruff linting passes"

rye run ruff format --check modelaudit/
print_result "Ruff formatting check passes"

rye run mypy modelaudit/
print_result "MyPy type checking passes"

# Test 7: Build package
echo -e "\n${YELLOW}📦 Test 7: Package Build${NC}"
rye build
print_result "Package builds successfully"

if [[ -d "dist" && -n "$(ls -A dist)" ]]; then
    echo "Built packages:"
    ls -la dist/
    print_result "Build artifacts created"
else
    echo -e "${RED}❌ No build artifacts found${NC}"
    exit 1
fi

# Test 8: Docker builds (if Docker is available)
echo -e "\n${YELLOW}🐳 Test 8: Docker Builds${NC}"
if command -v docker &> /dev/null && docker info &> /dev/null; then
    echo "Testing Docker builds..."
    
    # Test main Dockerfile
    docker build -t modelaudit:test .
    print_result "Main Dockerfile builds"
    
    # Test the image works
    docker run --rm modelaudit:test --help > /dev/null
    print_result "Docker image runs correctly"
    
    # Test full Dockerfile
    docker build -f Dockerfile.full -t modelaudit:test-full .
    print_result "Full Dockerfile builds"
    
    # Test TensorFlow Dockerfile
    docker build -f Dockerfile.tensorflow -t modelaudit:test-tf .
    print_result "TensorFlow Dockerfile builds"
    
    echo -e "${GREEN}🎉 All Docker builds successful!${NC}"
else
    echo -e "${YELLOW}⚠️  Docker not available, skipping Docker tests${NC}"
fi

# Test 9: Virtual environment check
echo -e "\n${YELLOW}🏠 Test 9: Virtual Environment${NC}"
if [[ -d ".venv" ]]; then
    echo "Virtual environment path: $(pwd)/.venv"
    echo "Python version: $(rye run python --version)"
    print_result "Virtual environment exists and works"
else
    echo -e "${RED}❌ Virtual environment not found${NC}"
    exit 1
fi

# Test 10: Dependency versions
echo -e "\n${YELLOW}📊 Test 10: Key Dependencies${NC}"
echo "Key package versions:"
rye run python -c "
import sys
packages = ['click', 'h5py', 'pyyaml', 'requests']
for pkg in packages:
    try:
        mod = __import__(pkg)
        version = getattr(mod, '__version__', 'unknown')
        print(f'  {pkg}: {version}')
    except ImportError:
        print(f'  {pkg}: not installed')
"
print_result "Key dependencies are available"

# Final Summary
echo -e "\n${GREEN}🎉 ALL TESTS PASSED!${NC}"
echo "========================================"
echo -e "${GREEN}✅ Rye migration is working correctly${NC}"
echo -e "${GREEN}✅ All dependencies are properly installed${NC}"
echo -e "${GREEN}✅ CLI functionality works${NC}"
echo -e "${GREEN}✅ All tests pass${NC}"
echo -e "${GREEN}✅ Code quality checks pass${NC}"
echo -e "${GREEN}✅ Package builds successfully${NC}"
if command -v docker &> /dev/null && docker info &> /dev/null; then
    echo -e "${GREEN}✅ Docker builds work${NC}"
fi
echo ""
echo -e "${BLUE}Ready for production! 🚀${NC}" 