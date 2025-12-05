import os
import sys
import glob
import textwrap
import re
from openai import OpenAI

BASE_DIR = os.getcwd()
CHALLENGE_DIR = os.path.join(BASE_DIR, "challenge")
HARNESS_DIR = os.path.join(BASE_DIR, "harness")

MODEL_NAME = "gpt-4o"
MAX_TOKENS = 2500
TEMPERATURE = 0.0

FIXED_HEADER ="""// clang -o harness harness.c -fsanitize=fuzzer,address -g
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>

// 1. Remove unnecessary output to improve purging speed
#define printf(...) ((void)0)
#define puts(s) ((void)0)
#define fprintf(stream, ...) ((void)0)

// 2. Prevent shell execution (safety device)
#define system(x) ((void)0)
"""

def check_api_key():
    if not os.getenv("OPENAI_API_KEY"):
        print("[ERROR] OPENAI_API_KEY environment variable is not set.")
        print("Please run: export OPENAI_API_KEY='sk-...'")
        sys.exit(1)

def read_source(path):
    try:
        with open(path, "r", errors="replace", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        print(f"[WARN] Could not read file {path}: {e}")
        return None

def sanitize_response(resp_text: str) -> str:
    if not resp_text:
        return ""

    m = re.search(r"```[\w]*\n([\s\S]*?)```", resp_text)
    if m:
        return m.group(1).strip()
    
    idx = re.search(r"(#include|void\s+\w+|int\s+LLVMFuzzerTestOneInput)", resp_text)
    if idx:
        return resp_text[idx.start():].strip()

    return resp_text.strip()

def build_system_prompt():
    return textwrap.dedent("""
        You are an expert Security Engineer for libFuzzer. 
        Task: Create a harness testing the vulnerable function DIRECTLY.
        
        INSTRUCTIONS:
        1. Analyze 'Target Source Code' (w/ line numbers).
        2. Extract ONLY the vulnerable function (e.g., strcpy, buffer overflow) and dependencies.
        3. **CRITICAL**: Prepend `#line <orig_line> \"<orig_filename>\"` to the extracted function.
        5. Implement `LLVMFuzzerTestOneInput` to call it.
        
        EXAMPLE:
        [INPUT]
        20 | void vuln(char *s) {
        21 |    strcpy(buf, s);
        22 | }
        
        [OUTPUT]:
        #include ...
        #line 20 "CWE_example.c"
        void vuln(char *s) {
            strcpy(buf, s);
        }
        int LLVMFuzzerTestOneInput(...) { ... }
    """)

def build_user_prompt(filename, source_text):
    name = os.path.basename(filename)
    
    lines = source_text.split('\n')
    numbered_source = "\n".join([f"{i+1} | {line}" for i, line in enumerate(lines)])
    return textwrap.dedent(f"""
        Target Filename: `{name}`
        SOURCE CODE:
        {numbered_source}
        
        Request:
        1. Extract vulnerable function prefixed with `#line <line> "{name}"`.
        3. Write `LLVMFuzzerTestOneInput`.
    """)

def generate_harness(client, system_msg, user_msg, filename):
    print(f"  > Generating harness for '{filename}'...")
    try:
        resp = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_msg},
            ],
            max_tokens=MAX_TOKENS,
            temperature=TEMPERATURE,
        )
        
        code = sanitize_response(resp.choices[0].message.content)
        
        if not code:
            print(f"  [WARN] Generated code is empty for {filename}")
            return
        
        out_fname = os.path.join(HARNESS_DIR, f"harness_{filename}.c")
        
        with open(out_fname, "w", encoding="utf-8") as f:
            f.write(FIXED_HEADER)
            f.write("\n// [INFO] LLM output below. It should contain #line directives.\n")
            f.write(code)
            
        print(f"  [OK] Saved harness: {out_fname}")

        if "LLVMFuzzerTestOneInput" not in code:
            print(f"  [WARN] {filename}: Missing 'LLVMFuzzerTestOneInput' entry point.")
        if "#line" not in code:
            print(f"  [WARN] {filename}: LLM did not generate #line directives.")

    except Exception as e:
        print(f"  [ERROR] Harness generation failed for {filename}: {e}")

def main():
    check_api_key()
    os.makedirs(HARNESS_DIR, exist_ok=True)
    client = OpenAI()

    c_files = glob.glob(os.path.join(CHALLENGE_DIR, "*.c"))
    if not c_files:
        print(f"[ERROR] No .c files found in {CHALLENGE_DIR}")
        return

    path = c_files[0]
    basename = os.path.splitext(os.path.basename(path))[0]
    print(f"[INFO] Processing {basename} ...")
    
    src = read_source(path)
    if not src:
        print(f"[WARN] Failed to read source {basename}")
        return
    
    system_msg = build_system_prompt()
    user_msg = build_user_prompt(path, src)
    generate_harness(client, system_msg, user_msg, basename)

    print("\n[INFO] All harness generation completed.")

if __name__ == "__main__":
    main()