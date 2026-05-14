import openai
import time

client = openai.OpenAI(base_url="http://localhost:8080/v1")

print("Sending 12 identical requests (threshold = 5 warn, 10 block)...")
for i in range(12):
    try:
        r = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "What is 2+2?"}],
            max_tokens=10,
        )
        print(f"  [{i+1:2d}] ✓ Passed")
    except openai.APIStatusError as e:
        print(f"  [{i+1:2d}] ✗ {e.status_code}: blocked")
        if e.status_code == 403:
            print("  → Loop detection working! Stopping.")
            break
    time.sleep(0.5)

print("\n→ Проверь dashboard: Shield → Events (loop warnings)")