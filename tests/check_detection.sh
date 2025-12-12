#!/bin/bash
# Wrapper script for detection tests in CI
# Runs the test and checks if expected pattern appears in output
# Returns 0 (success) if pattern found, 1 (failure) otherwise

TEST_BINARY="$1"
EXPECTED_PATTERN="$2"

# Save and clear LD_PRELOAD so it doesn't affect this script
SAVED_LD_PRELOAD="$LD_PRELOAD"
unset LD_PRELOAD

# Run test with LD_PRELOAD restored, capturing both stdout and stderr
OUTPUT=$(LD_PRELOAD="$SAVED_LD_PRELOAD" "$TEST_BINARY" 2>&1)
EXIT_CODE=$?

# Check if expected pattern is in output
if echo "$OUTPUT" | grep -q "$EXPECTED_PATTERN"; then
    echo "PASS: Detection test triggered expected error"
    echo "Pattern found: $EXPECTED_PATTERN"
    exit 0
else
    echo "FAIL: Expected pattern not found in output"
    echo "Expected: $EXPECTED_PATTERN"
    echo "---OUTPUT START---"
    echo "$OUTPUT"
    echo "---OUTPUT END---"
    exit 1
fi
