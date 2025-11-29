import os, json
from openai import OpenAI
from dotenv import load_dotenv
from utils.config import *

load_dotenv()
client = OpenAI(api_key=API_KEY)

def gen_seeds(prompt, n=10, outdir='../basic_seed'):
    os.makedirs(outdir, exist_ok=True)
    for i in range(n):
        resp = client.responses.create(
            model='gpt-4o-mini',
            input=f'{prompt}\nProduce a single raw input (no extra text).'
        )

        txt = resp.output_text if hasattr(resp, 'output_text') else ''.join([m['content'][0]['text'] for m in resp.output])
        fname = f'{outdir}/seed_{i}.bin'
        with open(fname, 'wb') as f:
            f.write(txt.encode('utf-8', errors='ignore'))
        print('seed saved: ', fname)

if __name__ == '__main__':
    prompt = (
        'Generate inputs for this C-challenge: '
        'The program reads input with scanf("%s", buf) and expects a string '
        'with no newline. Max bytes. Try extremely short and very long strings.'
        'The vulnerable program reads input with gets() into char buf[64]. '
        'The input must be raw ASCII (or bytes). Produce short and long patterns, '
        'including edge cases: overflow attempts, null bytes, format strings like %x, '
        'and random byte sequences. No explanations, only raw outputs.'
        )
    gen_seeds(prompt, n=5)