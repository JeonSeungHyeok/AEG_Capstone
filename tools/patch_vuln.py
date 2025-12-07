import os
import sys
import glob
import textwrap
import re
from openai import OpenAI

BASE_DIR = os.getcwd()
CHALLENGE_DIR = os.path.join(BASE_DIR, "challenge")
OUTPUT_DIR = os.path.join(BASE_DIR, "output") 
PATCH_DIR = os.path.join(BASE_DIR, "patch")
MODEL_NAME = "gpt-4o"
MAX_TOKENS = 3000
TEMPERATURE = 0.0

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
    
    idx = re.search(r"(#include|void\s+\w+|int\s+main)", resp_text)
    if idx:
        return resp_text[idx.start():].strip()

    return resp_text.strip()

def build_system_prompt():
    return textwrap.dedent("""
        You are an expert Secure Code Repair Engineer.
        Your task is to fix security vulnerabilities in C code based on AddressSanitizer (ASan) crash logs.
        
        YOUR GOAL:
        Fix the identified vulnerability (e.g., Buffer Overflow) while preserving the original logic and functionality.
        
        INSTRUCTIONS:
        1. Analyze the [SOURCE CODE] and [ASAN LOG].
        2. Locate the specific line and function causing the crash (e.g., stack-buffer-overflow in strcpy).
        3. Apply a secure fix:
           - Replace unsafe functions (strcpy -> strncpy, sprintf -> snprintf).
           - Add explicit length checks before memory operations.
           - Ensure null-termination is preserved.
        4. Do NOT remove the vulnerability simply by deleting the feature; secure it instead.
        5. Output ONLY the complete, compilable C source code.
    """)

def build_user_prompt(filename, source_text, log_text):
    name = os.path.basename(filename)
    
    lines = source_text.split('\n')
    numbered_source = "\n".join([f"{i+1} | {line}" for i, line in enumerate(lines)])
    
    return textwrap.dedent(f"""
        Target Filename: `{name}`
        
        [VULNERABLE SOURCE CODE]
        {numbered_source}
        
        [ASAN CRASH LOG]
        {log_text}
        
        Request:
        1. Identify the stack-buffer-overflow or vulnerability shown in the log.
        2. Fix the code to prevent this crash.
        3. Provide the FULL fixed C code.
    """)

def generate_patch(client, system_msg, user_msg, filename):
    print(f"  > Generating patch for '{filename}'...")
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
        code = sanitize_response(content)
        
        if not code:
            print(f"  [WARN] Generated patch is empty for {filename}")
            return
        
        out_fname = os.path.join(PATCH_DIR, f"patch_{filename}")
        
        with open(out_fname, "w", encoding="utf-8") as f:
            f.write(code)
            
        print(f"  [OK] Saved patched code: {out_fname}")

    except Exception as e:
        print(f"  [ERROR] Patch generation failed for {filename}: {e}")

def main():
    check_api_key()
    os.makedirs(PATCH_DIR, exist_ok=True)
    client = OpenAI()

    c_files = glob.glob(os.path.join(CHALLENGE_DIR, "*.c"))
    if not c_files:
        print(f"[ERROR] No .c files found in {CHALLENGE_DIR}")
        return
    
    path = c_files[0]
    basename = os.path.basename(path)
    filename_no_ext = os.path.splitext(basename)[0]
    
    print(f"[INFO] Processing {basename} ...")
    
    src = read_source(path)
    if not src:
        print(f"  [WARN] Failed to read source {basename}")
        return
    
    log_path = os.path.join(OUTPUT_DIR, f"{filename_no_ext}_result.txt")
    log_content = read_source(log_path)
    
    if not log_content:
        print(f"  [SKIP] No valid ASan crash log found for {basename}. Skipping patch.")
        return
    
    if not "ERROR: AddressSanitizer" in log_content:
        print(f"  [SKIP] Log file exists but contains no ASan crash report.")
        return
            
    system_msg = build_system_prompt()
    user_msg = build_user_prompt(basename, src, log_content)
    generate_patch(client, system_msg, user_msg, basename)

    print("\n[INFO] All patch tasks completed.")

if __name__ == "__main__":
    main()