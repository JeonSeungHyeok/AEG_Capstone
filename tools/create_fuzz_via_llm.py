#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import glob
import textwrap
import re
from openai import OpenAI

# 설정
BASE_DIR = os.path.expanduser("~/projects/aixcc-mvp")
CHALLENGE_DIR = os.path.join(BASE_DIR, "challenge")
HARNESS_DIR = os.path.join(BASE_DIR, "harness")
TOOLS_DIR = os.path.join(BASE_DIR, "tools")

MODEL_NAME = "gpt-4o"
MAX_CHARS_TO_SEND = 100000
MAX_TOKENS = 2500
TEMPERATURE = 0.0

# 유틸
def read_source(path, max_chars=MAX_CHARS_TO_SEND):
    with open(path, "r", errors="replace") as f:
        txt = f.read()
    if len(txt) <= max_chars:
        return txt

    head = txt[: max_chars // 2]
    tail = txt[- (max_chars // 2) :]
    return head + "\n/* ...TRUNCATED... (middle omitted) */\n" + tail

def sanitize_response(resp_text: str) -> str:
    if not resp_text:
        return resp_text

    code_block_pattern = re.compile(r"```(?:c|C|cpp|)\s*([\s\S]*?)```", re.IGNORECASE)
    m = code_block_pattern.search(resp_text)
    if m:
        return m.group(1).strip()

    if "LLVMFuzzerTestOneInput" in resp_text:
        idx = resp_text.find("#include")
        if idx == -1:
            idx = resp_text.find("int LLVMFuzzerTestOneInput")
        return resp_text[idx:].strip()

    return resp_text.strip()

def build_system_prompt():
    return (
        "You are an expert Security Engineer specializing in Fuzzing. "
        "Your goal is to generate a robust, secure, and compilable libFuzzer harness."
    )

def build_user_prompt(filename, source_text):
    name = os.path.basename(filename)
    
    # [수정됨] read와 scanf를 모두 후킹하는 고성능 하네스 예시
    harness_template = textwrap.dedent("""
    // [TEMPLATE - SKELETON CODE]
    // clang -o harness harness.c -fsanitize=fuzzer,address -g
    #include <stdint.h>
    #include <string.h>
    #include <stdio.h>
    #include <unistd.h>
    #include <stdlib.h>
    #include <stdarg.h>
    
    // [SAFETY] Neutralize dangerous functions
    #define system(x) ((void)0)
    #define printf(...) ((void)0)
    
    // ------------------------------------------------------------------
    // [SPEED OPTIMIZATION INFRASTRUCTURE]
    // Global variables to hold fuzzer data
    // ------------------------------------------------------------------
    const uint8_t *g_data;
    size_t g_size;
    size_t g_pos;
    
    // Custom read implementation (Memory copy instead of system call)
    ssize_t my_read(int fd, void *buf, size_t count) {
        if (fd != 0) return 0; // Only mock stdin
        if (g_pos >= g_size) return 0;
        size_t remain = g_size - g_pos;
        size_t len = (count < remain) ? count : remain;
        memcpy(buf, g_data + g_pos, len);
        g_pos += len;
        return len;
    }

    // Custom scanf implementation (Inject bytes directly from fuzzer data)
    int my_scanf(const char *format, ...) {
        va_list args;
        va_start(args, format);
        // Basic logic: if format expects integers, copy bytes from g_data
        if (strstr(format, "d") || strstr(format, "u") || strstr(format, "x")) {
             int *ptr = va_arg(args, int *);
             if (g_pos + sizeof(int) <= g_size) {
                 memcpy(ptr, g_data + g_pos, sizeof(int));
                 g_pos += sizeof(int);
             }
        }
        va_end(args);
        return 1;
    }
    
    // [HOOKING] Redirect slow I/O to fast in-memory functions
    #define read my_read
    #define scanf my_scanf
    
    // [DEPENDENCY]
    // !!! PASTE THE FULL TARGET FUNCTION HERE !!!
    // IF TARGET IS 'main', RENAME it to 'target_main' (int target_main(...))
    
    // [HARNESS]
    int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        // 1. Initialize Global State
        g_data = data;
        g_size = size;
        g_pos = 0;
        
        // 2. Call Target (Implement logic based on source analysis)
        // Case A: target_main(argc, fake_argv)
        // Case B: func(buf)
        // Case C: func() (stdin used via hooks)
        
        return 0;
    }
    """)
    
    s = textwrap.dedent(f"""
    Role: Expert Fuzzing Engineer.
    
    Task: Create a **SINGLE, SELF-CONTAINED, HIGH-PERFORMANCE** libFuzzer harness for {name}.
    
    ==================================================
    [INSTRUCTION: USE THE TEMPLATE]
    1. Adopt the **Speed Optimization Infrastructure** (`my_read`, `my_scanf`, `g_data`) from the template below EXACTLY.
    2. **DO NOT HALLUCINATE LOGIC.** Do not invent variables or functions (like `snprintf`) unless they exist in the actual target source.
    3. Analyze the [TARGET SOURCE CODE] and fill in the `[DEPENDENCY]` and `[HARNESS]` sections of the template accordingly.
    ==================================================

    [STEP 1: ANALYZE TARGET FUNCTION STRATEGY]
    
    **Case A: Target is `int main(int argc, char *argv[])`**
    - **CRITICAL:** You MUST rename `main` to `target_main` to avoid conflict with LibFuzzer's main.
    - Inside `LLVMFuzzerTestOneInput`:
        1. Allocate a buffer using `malloc(size + 1)` and copy `data`.
        2. Create a `fake_argv` array: `{{ "program", buffer, NULL }}`.
        3. Call `target_main(2, fake_argv)`.
        4. Free the buffer.

    **Case B: Target uses Standard Input (`read(0)`, `scanf`)**
    - Copy the function code as is.
    - Ensure `#define read my_read` and `#define scanf my_scanf` are active.
    - Inside `LLVMFuzzerTestOneInput`: Just call the target function.

    **Case C: Target takes buffer arguments (`void func(char *input)`)**
    - Inside `LLVMFuzzerTestOneInput`: Allocate a buffer, copy `data`, Null-terminate, and pass it to `func`.

    ==================================================
    [REFERENCE: HARNESS TEMPLATE]
    {harness_template}
    ==================================================

    [TARGET SOURCE CODE]
    {source_text}
    
    Output ONLY the C source code.
    """)
    return s

def call_llm_and_get_code(system_msg, user_msg):
    client = OpenAI()
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
        content = resp.choices[0].message.content
        return sanitize_response(content)
    except Exception as e:
        print(f"[API ERROR] {e}")
        return ""

# 메인 작업
def main():
    os.makedirs(HARNESS_DIR, exist_ok=True)

    c_files = sorted(glob.glob(os.path.join(CHALLENGE_DIR, "*.c")))
    if not c_files:
        print(f"[ERROR] No .c files found in {CHALLENGE_DIR}")
        return

    system_msg = build_system_prompt()

    for path in c_files:
        basename = os.path.splitext(os.path.basename(path))[0]
        print(f"[INFO] Processing {basename} ...")
        
        src = read_source(path)
        if not src:
            print(f"[WARN] Failed to read {basename}")
            continue
        
        user_msg = build_user_prompt(path, src)
        
        code = call_llm_and_get_code(system_msg, user_msg)
        if not code:
            print(f"[WARN] Empty code returned for {basename}")
            continue

        out_fname = os.path.join(HARNESS_DIR, f"create_fuzz_{basename}.c")
        with open(out_fname, "w", encoding="utf-8") as f:
            f.write(code)
        print(f"[OK] Wrote harness: {out_fname}")

        # 기본 검사
        if "LLVMFuzzerTestOneInput" not in code:
            print(f"[WARN] {basename}: Harness might be invalid (missing entry point).")
        if "#define read" not in code and "read(" in src:
             print(f"[CHECK] {basename}: Source uses read(), ensure it's hooked for speed.")

    print("[DONE] All files processed.")

if __name__ == "__main__":
    main()