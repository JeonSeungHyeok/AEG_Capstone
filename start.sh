#!/bin/bash

# Check root directory location
PROJECT_DIR=~/projects/aixcc-mvp
if [ "$(pwd)" != "$PROJECT_DIR" ]; then
    echo "Warning: The current directory is not $PROJECT_DIR"
    exit
fi

INITIAL_DIR="initial_files"
CHALLENGE_DIR="challenge"
BACKUP_DIR="backup_files"
HARNESS_DIR="harness"
OUTPUT_DIR="output"
FUZZ_DIR="fuzz"

SEED_ROOT="seeds"
SEED_CORPUS="$SEED_ROOT/corpus_seed"
SEED_BASIC="$SEED_ROOT/basic_seed"
SEED_CRASH="$SEED_ROOT/crash_seed"

safe_mv() {
    local src="$1"
    local dest="$2"
    if [ -e "$src" ]; then
        mv "$src" "$dest"
    fi
}


# Create output directory
mkdir -p "$INITIAL_DIR" "$CHALLENGE_DIR" "$BACKUP_DIR" "$HARNESS_DIR" "$OUTPUT_DIR" "$FUZZ_DIR"
mkdir -p "$SEED_CORPUS" "$SEED_BASIC" "$SEED_CRASH"

# Clean challenge directory
if [ "$(ls -A $CHALLENGE_DIR)" ]; then
    echo "[!] Warning: '$CHALLENGE_DIR' is not empty. Moving leftovers'..."
    mkdir -p "$BACKUP_DIR/leftovers"
    mv "$CHALLENGE_DIR"/* "$BACKUP_DIR/leftovers"/ 2>/dev/null
fi

shopt -s nullglob

# Recursive all file in challenge directory
for file_path in "$INITIAL_DIR"/*.c; do
    filename=$(basename "$file_path")
    target="${filename%.*}"

    echo "=========================================="
    echo "Processing Target: $target"
    echo "=========================================="

    echo "[*] Moving $filename to $CHALLENGE_DIR..."
    mv "$file_path" "$CHALLENGE_DIR/"

    # 1. Create Seed Generator and Libfuzzer harness on LLM
    echo "[*] Running LLM Generator..."
    rm -rf "$SEED_BASIC"/*
    python tools/generate_seeds.py
    python tools/create_fuzz_harness.py
    
    if [ $? -ne 0 ]; then
        echo "[!] Error: Python script failed for $target"
        mv "$CHALLENGE_DIR/$filename" "$BACKUP_DIR/" 2>/dev/null
        continue
    fi

    harness="$HARNESS_DIR/create_fuzz_${filename}"
    fuzz="$FUZZ_DIR/harness_$target"
    log_file="$OUTPUT_DIR/${target}.txt"

    # 2. Compile clang
    if [ -f "$harness" ]; then
        echo "[*] Compiling with Clang..."
        clang -o "$fuzz" "$harness" -fsanitize=fuzzer,address,undefined -g -m32

        # 3. Execute fuzzer
        if [ -f "$fuzz" ]; then
            echo "[*] Running Fuzzer (Timeout: 90s)..."
            ./"$fuzz" "$SEED_CORPUS" "$SEED_BASIC" \
                -artifact_prefix="$SEED_CRASH/${target}_" \
                -max_total_time=90 -fork=3 \
                > "$log_file" 2>&1
        
            echo "[+] Fuzzing finished for $target."
        else
            echo "[!] Error: Compilation failed."
        fi
    else
        echo "[!] Error: Harness not found"
    fi

    echo "[*] Archiving results to $BACKUP_DIR/$target..."

    TARGET_BACKUP="$BACKUP_DIR/$target"
    mkdir -p "$TARGET_BACKUP"/{harness,fuzz,output,seeds}

    safe_mv "$CHALLENGE_DIR/$filename" "$TARGET_BACKUP/"
    safe_mv "$harness"                 "$TARGET_BACKUP/harness/"
    safe_mv "$fuzz"                    "$TARGET_BACKUP/fuzz/"
    safe_mv "$log_file"                "$TARGET_BACKUP/output/"
    
    for seed_dir in "$SEED_BASIC" "$SEED_CORPUS" "$SEED_CRASH"; do
        if [ "$(ls -A "$seed_dir")" ]; then
            mv "$seed_dir" "$TARGET_BACKUP/seeds/"
            mkdir -p "$seed_dir"
        fi
    done

    echo ""
    sleep 1
done

echo "All tasks completed."
