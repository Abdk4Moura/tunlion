#!/bin/bash
# Filament reliability test script
# Tests file transfer reliability between dovm and jade (same machine)
# Usage: ./tests/reliability_test.sh

PEER="jade"
FILAMENT="/root/.local/bin/filament"
TMPDIR="/tmp/filament_reliability_test"
RESULTS_FILE="$TMPDIR/results.txt"

echo "=== Filament Reliability Test ==="
echo "Peer: $PEER"
echo "Time: $(date)"
echo ""

# Create temp directory
rm -rf "$TMPDIR"
mkdir -p "$TMPDIR"

# Create unique test files using /dev/urandom with unique seeds
echo "Creating test files..."
for i in $(seq 1 10); do
    # Use different sizes and unique random data
    dd if=/dev/urandom of="$TMPDIR/file_${i}.bin" bs=1K count=$((i * 100)) 2>/dev/null
done
dd if=/dev/urandom of="$TMPDIR/large.bin" bs=1M count=10 2>/dev/null
dd if=/dev/urandom of="$TMPDIR/verylarge.bin" bs=1M count=100 2>/dev/null
echo "Test files created (all unique)."
echo ""

# Test 1: Connectivity
echo "--- Test 1: Connectivity ---"
echo -n "Ping: "
if $FILAMENT ping "$PEER" --count 3 2>&1 | grep -q "pong"; then
    echo "PASS"
    echo "ping: PASS" >> "$RESULTS_FILE"
else
    echo "FAIL"
    echo "ping: FAIL" >> "$RESULTS_FILE"
fi

# Test 2: Small files (unique)
echo ""
echo "--- Test 2: Small files (10 unique) ---"
success=0; fail=0
for i in $(seq 1 10); do
    if timeout 10 $FILAMENT send "$TMPDIR/file_${i}.bin" --to "$PEER" 2>&1 | grep -q "delivered"; then
        success=$((success+1))
    else
        fail=$((fail+1))
    fi
done
echo "  Result: $success/$((success+fail)) success"
echo "small_unique: $success/$((success+fail))" >> "$RESULTS_FILE"

# Test 3: Large file (10MB)
echo ""
echo "--- Test 3: Large file (10MB) ---"
echo -n "Transfer: "
if timeout 60 $FILAMENT send "$TMPDIR/large.bin" --to "$PEER" 2>&1 | grep -q "delivered"; then
    echo "PASS"
    echo "large_10m: PASS" >> "$RESULTS_FILE"
else
    echo "FAIL"
    echo "large_10m: FAIL" >> "$RESULTS_FILE"
fi

# Test 4: Very large file (100MB)
echo ""
echo "--- Test 4: Very large file (100MB) ---"
echo -n "Transfer: "
if timeout 300 $FILAMENT send "$TMPDIR/verylarge.bin" --to "$PEER" 2>&1 | grep -q "delivered"; then
    echo "PASS"
    echo "verylarge_100m: PASS" >> "$RESULTS_FILE"
else
    echo "FAIL"
    echo "verylarge_100m: FAIL" >> "$RESULTS_FILE"
fi

# Summary
echo ""
echo "=== Test Summary ==="
cat "$RESULTS_FILE"

# Cleanup
rm -rf "$TMPDIR"
