#!/bin/bash

set -euo pipefail
shopt -s nullglob

INITIAL_DIR="initial_files"
CHALLENGE_DIR="challenge"
BACKUP_DIR="backup_files"

safe_mv() {
    if [ -e "$1" ]; then
        mv "$1" "$2" 2>/dev/null
    fi
}

mkdir -p "$CHALLENGE_DIR"

# Clean challenge directory
if [ -d "$CHALLENGE_DIR" ] && [ "$(find "$CHALLENGE_DIR" -mindepth 1 -print -quit 2>/dev/null)" ]; then
    echo "[!] Warning: '$CHALLENGE_DIR' is not empty. Moving leftovers'..."
    mkdir -p "$BACKUP_DIR/leftovers"
    mv "$CHALLENGE_DIR"/* "$BACKUP_DIR/leftovers"/ 2> /dev/null
    mv "$CHALLENGE_DIR"/.[!.]* "$BACKUP_DIR/leftovers"/ 2> /dev/null
fi

# Recursive all file in challenge directory
for file_path in "$INITIAL_DIR"/*.c; do
    filename=$(basename "$file_path")
    target="${filename%.*}"

    TARGET_DIR="$CHALLENGE_DIR/$target"
    HARNESS_DIR="$TARGET_DIR/harness"
    OUTPUT_DIR="$TARGET_DIR/output"
    FUZZ_DIR="$TARGET_DIR/fuzz"
    PATCH_DIR="$TARGET_DIR/patch"

    SEED_ROOT="$TARGET_DIR/seeds"
    SEED_CORPUS="$SEED_ROOT/corpus_seed"
    SEED_BASIC="$SEED_ROOT/basic_seed"
    SEED_CRASH="$SEED_ROOT/crash_seed"

    BACKUP_TARGET_DIR="$BACKUP_DIR/$target"

    # Create output directory
    mkdir -p "$TARGET_DIR" "$BACKUP_DIR" "$HARNESS_DIR" "$OUTPUT_DIR" "$FUZZ_DIR" "$PATCH_DIR" "$BACKUP_TARGET_DIR"
    mkdir -p "$SEED_CORPUS" "$SEED_BASIC" "$SEED_CRASH"

    echo "=========================================="
    echo "Processing Target: $target"
    echo "=========================================="

    echo "[*] Moving $filename to $TARGET_DIR..."
    mv "$file_path" "$TARGET_DIR"

    # 1. Create Seed Generator and Libfuzzer harness on LLM
    echo "[*] Running LLM Generator..."
    
    python3 tools/generate_seeds.py $target || {
        echo "[!] Error: Python script failed for $target"
        mkdir -p "$BACKUP_TARGET_DIR"
        mv "$TARGET_DIR" "$BACKUP_DIR" 2> /dev/null
        continue
    }
    
    python3 tools/create_fuzz_harness.py $target || {
        echo "[!] Error: Python script failed for $target"
        mkdir -p "$BACKUP_TARGET_DIR"
        mv "$TARGET_DIR" "$BACKUP_DIR" 2> /dev/null
        continue
    }

    harness="$HARNESS_DIR/harness_${filename}"
    fuzz="$FUZZ_DIR/fuzz_$target"
    log_file="$OUTPUT_DIR/result_${target}.txt"
    patch="$PATCH_DIR/patch_$filename"

    # # 2. Compile clang & Execute fuzzer
    if [ -f "$harness" ]; then
        echo "[*] Compiling with Clang..."
        if clang -o "$fuzz" "$harness" -fsanitize=fuzzer,address,undefined -g -m32; then
            echo "=========================================="
            echo "[*] Running Fuzzer (Timeout: 90s)..."
            set +e
            "$fuzz" "$SEED_CORPUS" "$SEED_BASIC" \
                -artifact_prefix="$SEED_CRASH/${target}_" \
                -max_total_time=90 \
                -fork=3 \
                -timeout=20 \
                -print_final_stats=1 \
                2>&1 | tee "$log_file"
            set -e

            echo "=========================================="
            echo ""
            echo "[+] Fuzzing finished for $target."
        else
            echo "[!] Error: Compilation failed."
        fi
    else
        echo "[!] Error: Harness not found"
    fi

    echo "[*] Archiving results to $BACKUP_TARGET_DIR..."

    #python3 tools/patch_vuln.py

    mv "$TARGET_DIR" "$BACKUP_DIR"

    echo ""
    sleep 1
done

echo "All tasks completed."
