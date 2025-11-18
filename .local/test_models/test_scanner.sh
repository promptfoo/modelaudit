#!/bin/bash
# Scan each model file individually and report warnings/errors

echo "=" | head -c 80 | tr ' ' '='
echo
echo "ModelAudit Test Scanner - Individual File Results"
echo "=" | head -c 80 | tr ' ' '='
echo
echo

cd "$(dirname "$0")"

# Find all model files (exclude scripts, docs, and directories)
find . -maxdepth 1 -type f \
  ! -name "*.py" \
  ! -name "*.md" \
  ! -name "*.sh" \
  ! -name ".*" \
  -print0 | sort -z | while IFS= read -r -d '' file; do

  filename=$(basename "$file")
  echo "Testing: $filename"
  echo "-" | head -c 80 | tr ' ' '-'

  # Run modelaudit and capture output
  output=$(rye run modelaudit "$file" 2>&1)
  exit_code=$?

  # Check for issues
  if echo "$output" | grep -q "CRITICAL\|ERROR"; then
    echo "❌ ERRORS FOUND:"
    echo "$output" | grep "CRITICAL\|ERROR"
  elif echo "$output" | grep -q "WARNING"; then
    echo "⚠️  WARNINGS FOUND:"
    echo "$output" | grep "WARNING"
  elif [ $exit_code -ne 0 ]; then
    echo "❌ SCAN FAILED (exit code: $exit_code)"
    echo "$output" | tail -10
  else
    # Count issues
    issues=$(echo "$output" | grep -c "\[.\]" || echo "0")
    if [ "$issues" -gt 0 ]; then
      echo "ℹ️  $issues issues found (INFO level)"
    else
      echo "✅ CLEAN - No issues found"
    fi
  fi

  echo
  echo
done

echo "=" | head -c 80 | tr ' ' '='
echo
echo "Scan Complete!"
echo
