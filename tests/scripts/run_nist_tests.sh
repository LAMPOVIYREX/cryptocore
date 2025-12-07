#!/bin/bash

echo "=== NIST Statistical Test Suite Runner ==="

# Check if NIST STS is available
NIST_DIR="../../../sts-2.1.2"
NIST_BIN="$NIST_DIR/assess"

if [ ! -f "$NIST_BIN" ]; then
    echo "Error: NIST STS not found at $NIST_DIR"
    echo "Please download and compile NIST STS first:"
    echo "1. Download from https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software"
    echo "2. Extract to sts-2.1.2 directory in project root"
    echo "3. Run 'make' in the sts-2.1.2 directory"
    echo ""
    echo "For now, we'll generate the test data for manual NIST testing."
    echo "You can run NIST tests later when you install the test suite."
fi

echo "Generating test data for NIST..."
../bin/test_csprng

TEST_DATA="../results/nist_test_data.bin"
if [ ! -f "$TEST_DATA" ]; then
    echo "Error: Failed to generate test data"
    exit 1
fi

echo "✓ Test data ready: $TEST_DATA ($(stat -c%s "$TEST_DATA") bytes)"

if [ -f "$NIST_BIN" ]; then
    echo "Running NIST Statistical Test Suite..."
    cd "$NIST_DIR"

    # Create assessment configuration
    cat > assess_config.txt << EOF
../../tests/$TEST_DATA
0
1
1000000
EOF

    ./assess 1000000 < assess_config.txt

    echo ""
    echo "=== NIST Tests Complete ==="
    echo "Results available in: $NIST_DIR/experiments/AlgorithmTesting/finalAnalysisReport.txt"
    echo "Summary of results:"

    # Extract and display summary
    if [ -f "experiments/AlgorithmTesting/finalAnalysisReport.txt" ]; then
        grep -E "(TEST|passed|failed)" "experiments/AlgorithmTesting/finalAnalysisReport.txt" | head -20
    fi
else
    echo ""
    echo "=== NIST Test Data Generated ==="
    echo "Test file: $TEST_DATA"
    echo "To run full NIST tests:"
    echo "1. Download NIST STS from: https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software"
    echo "2. Extract and compile: tar -xzf sts-2.1.2.tar.gz && cd sts-2.1.2 && make"
    echo "3. Run: ./assess 1000000"
    echo "4. Use $TEST_DATA as input when prompted"
fi