import os
import sys
from openai import OpenAI

api_key = os.getenv("OPENAI_API_KEY")

if not api_key:
    print("Error: OPENAI_API_KEY environment variable is not set.")
    print("Usage: export OPENAI_API_KEY='sk-...'")
    sys.exit(1)

client = OpenAI(api_key=api_key)

def gen_seeds(prompt, n=5, outdir='./seeds/basic_seed'):
    os.makedirs(outdir, exist_ok=True)
    print(f"Generating {n} seeds to '{outdir}'...")

    for i in range(n):
        try:
            resp = client.chat.completions.create(
                model='gpt-4o',
                messages=[
                    {
                        "role": "system", 
                        "content": (
                            "You are a dumb fuzzing input generator. "
                            "You must output ONLY raw string data. "
                            "Do not write a list. Do not explain. "
                            "Do not use markdown. Do not use newlines to separate items. "
                            "Output exactly ONE single test case."
                        )
                    },
                    {
                        "role": "user", 
                        "content": (
                            f"{prompt}\n"
                            f"Generate a RANDOM input for iteration {i}. "
                            "Make it strictly ONE single string."
                        )
                    }
                ],
                temperature=1.0
            )
            content = resp.choices[0].message.content

            if content:
                if content.startswith("```"):
                    lines = content.splitlines()
                    if len(lines) >= 2:
                        content = "\n".join(lines[1:-1])

                fname = f'{outdir}/seed_{i}.bin'
                with open(fname, 'wb') as f:
                    f.write(content.encode('utf-8', errors='ignore'))
                    
                display_content = (content[:50] + '...') if len(content) > 50 else content
                print(f'seed saved [{i}]: {repr(display_content)}')

        except Exception as e:
            print(f"Error generating seed {i}: {e}")

if __name__ == '__main__':
    prompt = (
        'Target: A C-program vulnerable to gets() (buffer size 64) and scanf(). '
        'Task: Generate ONE single raw input string causing a crash or edge case. '
        'Choose ONE from: very long string, format string (%x, %n), null byte injection, or random ASCII garbage. '
        'OUTPUT RAW DATA ONLY.'
    )
    
    gen_seeds(prompt, n=5)