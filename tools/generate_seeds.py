import os
import sys
import glob
import codecs
import re
from openai import OpenAI

BASE_DIR = os.getcwd()
CHALLENGE_DIR = os.path.join(BASE_DIR, "challenge", sys.argv[1])
SEED_DIR = os.path.join(CHALLENGE_DIR, "seeds", "basic_seed")

MODEL_NAME = "gpt-4o"
MAX_TOKENS = 2500
TEMPERATURE = 1.0

def check_api_key():
    if not os.getenv("OPENAI_API_KEY"):
        print("[ERROR] OPENAI_API_KEY environment variable is not set.")
        print("Please run: export OPENAI_API_KEY='sk-...'(your key)")
        sys.exit(1)

def read_source(path):
    try:
        with open(path, "r", errors="replace", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        print(f"[WARN] Could not read file {path}: {e}")
        return None

def build_system_prompt():
    return (
        "You are an expert vulnerability researcher. "
        "Analyze the C code logic and buffer constraints. "
        "Generate a SINGLE raw input string (payload) that triggers a segmentation fault or memory corruption. "
        "Use standard Python escape sequences (e.g., \\x41, \\xff) for non-printable bytes. "
        "Output ONLY the raw string. Do NOT use markdown, code blocks, or surrounding quotes."
    )

def gen_seeds(client, system_msg, filename, target_code, n):
    print(f"  > Generating {n} seeds to '{SEED_DIR}'...")

    for i in range(n):
        try:
            resp = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {"role": "system", "content": system_msg},
                    {
                        "role": "user", 
                        "content": (
                            f"Code:\n{target_code}\n\nTask: Generate exploit payload #{i+1} to crash this."
                        )
                    }
                ],
                max_tokens=MAX_TOKENS,
                temperature=TEMPERATURE,
            )
            content = resp.choices[0].message.content
            if content:
                content = re.sub(r"^```[a-zA-Z]*\n", "", content)
                content = content.replace("```", "").strip()                
                try:
                    final_data = codecs.decode(content, 'unicode_escape').encode('latin-1')
                except Exception:
                    final_data = content.encode('utf-8', errors='ignore')

                fname = f'{SEED_DIR}/{filename}_seed_{i}.bin'
                with open(fname, 'wb') as f:
                    f.write(final_data)
                
                preview = repr(final_data[:40]) 
                if len(final_data) > 40: preview += "..."
                print(f"  [{i}] Saved: {preview}")

        except Exception as e:
            print(f"  [ERROR] Seed {i} failed: {e}")
            
def main():
    check_api_key()
    os.makedirs(SEED_DIR, exist_ok=True)
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
        print(f"[WARN] Failed to read {basename}")
        return
    
    system_msg = build_system_prompt()
    gen_seeds(client, system_msg, basename, src, n=5)
        
    print("[INFO] All seed generation completed.")

if __name__ == '__main__':
    main()