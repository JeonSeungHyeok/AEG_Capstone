#!/bin/bash

# Check root directory location
PROJECT_DIR=~/projects/aixcc-mvp
if [ "$(pwd)" != "$PROJECT_DIR" ]; then
    echo "Warning: The current directory is not $PROJECT_DIR"
    exit
fi

# Create output directory if not
mkdir -p output
mkdir -p fuzz

# Recursive all file in challenge directory
for file in challenge/*; do
    filename=$(basename "$file")
    target="${filename%.*}"

    echo "=========================================="
    echo "Processing Target: $target"
    echo "=========================================="

    # 1. Create Libfuzzer harness on LLM
    echo "[*] Running LLM Generator..."
    python tools/create_fuzz_via_llm.py "$target"

    if [ $? -ne 0 ]; then
        echo "[!] Error: Python script failed for $target"
        exit
    fi

    # 2. Compile clang
    echo "[*] Compiling with Clang..."
    clang -o "fuzz/harness_$target" "harness/create_fuzz_${target}.c" -fsanitize=fuzzer,address -g -m32

    if [ ! -f "fuzz/harness_$target" ]; then
        echo "[!] Error: Compilation failed. Harness executable not found."
        exit
    fi

    # 3. Execute fuzzer
    echo "[*] Running Fuzzer (Timeout: 60s)..."
    ./fuzz/harness_$target seeds/corpus_seed/ seeds/basic_seed/ \
        -artifact_prefix="./output/${target}_" \
        -max_total_time=90 \
        > "./output/${target}.txt" 2>&1

    echo "[+] Fuzzing finished for $target. Output saved to ./output/${target}.txt"
    
    echo ""
done

echo "All tasks completed."
