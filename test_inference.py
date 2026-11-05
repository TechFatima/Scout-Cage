import os, sys
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv(override=True)

client = OpenAI(
    base_url="https://api.vultrinference.com/v1",
    api_key=os.environ["VULTR_INFERENCE_API_KEY"],
)

r = client.chat.completions.create(
    model=sys.argv[1],
    messages=[{"role": "user", "content": "Say hi in five words."}],
    max_tokens=500,
)
c = r.choices[0]
print("finish_reason:", c.finish_reason)
print("content:", repr(c.message.content))
print("usage:", r.usage)
