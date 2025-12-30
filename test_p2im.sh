#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Set library path based on Unicorn version
if [ -d "$SCRIPT_DIR/emulator/unicorn/fuzzware-unicorn/build" ]; then
    # Unicorn 2.x
    VERSION="Unicorn 2.x"
    export LD_LIBRARY_PATH="$SCRIPT_DIR/emulator/unicorn/fuzzware-unicorn/build:$LD_LIBRARY_PATH"
else
    # Unicorn 1.x
    VERSION="Unicorn 1.x"
    export LD_LIBRARY_PATH="$SCRIPT_DIR/emulator/unicorn/fuzzware-unicorn:$LD_LIBRARY_PATH"
fi

cd "$SCRIPT_DIR/examples/P2IM"

echo "=== P2IM Benchmark ($VERSION) ==="
echo ""
printf "%-20s %8s %8s\n" "Test" "Status" "Time"
printf "%-20s %8s %8s\n" "----" "------" "----"

passed=0
failed=0
total_time=0

for dir in */; do
    name="${dir%/}"
    input_file=$(ls "$dir/base_inputs/" 2>/dev/null | head -1)
    if [ -n "$input_file" ]; then
        start=$(date +%s.%N)
        fuzzware emu -c "$dir/config.yml" -l 1000000 "$dir/base_inputs/$input_file" > /tmp/fuzz_output.txt 2>&1
        status=$?
        end=$(date +%s.%N)
        elapsed=$(awk "BEGIN {printf \"%.3f\", $end - $start}")
        total_time=$(awk "BEGIN {printf \"%.3f\", $total_time + $elapsed}")
        time_str="${elapsed}s"

        if [ $status -eq 0 ]; then
            printf "%-20s %8s %8s\n" "$name" "✓ PASS" "$time_str"
            ((passed++))
        else
            printf "%-20s %8s %8s\n" "$name" "✗ FAIL" "$time_str"
            ((failed++))
        fi
    else
        printf "%-20s %8s %8s\n" "$name" "? SKIP" "-"
    fi
done

echo ""
printf "%-20s %8s %8s\n" "----" "------" "----"
printf "%-20s %8s %8s\n" "Total" "$passed/$((passed+failed))" "${total_time}s"
