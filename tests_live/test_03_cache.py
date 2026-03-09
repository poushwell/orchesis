import openai
import time
import json
from urllib.request import urlopen
import httpx

client = openai.OpenAI(base_url="http://localhost:8080/v1")

def timed_request(label, content):
    start = time.time()
    r = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": content}],
        max_tokens=100,
    )
    elapsed = time.time() - start
    print(f"  {label}: {elapsed:.2f}s — {r.choices[0].message.content[:60]}...")
    return elapsed


def fetch_proxy_stats():
    with urlopen("http://localhost:8080/stats", timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def probe_cache_header(content: str):
    payload = {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": content}],
        "max_tokens": 100,
    }
    with httpx.Client(timeout=20.0) as c:
        r = c.post("http://localhost:8080/v1/chat/completions", json=payload, headers={"Authorization": "Bearer x"})
        return r.status_code, r.headers.get("X-Orchesis-Cache", ""), r.headers.get("X-Orchesis-Cache-Similarity", "")

print("=== Exact cache test ===")
t1 = timed_request("Request 1 (miss)", "What is the capital of France?")
time.sleep(1)
t2 = timed_request("Request 2 (exact hit?)", "What is the capital of France?")
print(f"  Speedup: {t1/max(t2, 0.001):.1f}x")

print("\n=== Semantic cache test ===")
time.sleep(1)
t3 = timed_request("Request 3 (semantic?)", "Tell me the capital city of France")
print(f"  Speedup: {t1/max(t3, 0.001):.1f}x")

print("\n=== Different question (miss) ===")
t4 = timed_request("Request 4 (miss)", "What is quantum computing?")

print("\n=== Proxy cache stats (/stats) ===")
try:
    stats = fetch_proxy_stats()
    sc = stats.get("semantic_cache", {}) if isinstance(stats, dict) else {}
    if not sc:
        print("  semantic_cache section is missing in /stats")
        print("  Проверь, что proxy запущен с policy, где semantic_cache.enabled: true")
    else:
        print(f"  enabled: {sc.get('enabled', False)}")
        print(f"  exact_hits: {sc.get('exact_hits', 0)}")
        print(f"  semantic_hits: {sc.get('semantic_hits', 0)}")
        print(f"  misses: {sc.get('misses', 0)}")
        print(f"  hit_rate_percent: {sc.get('hit_rate_percent', 0.0):.1f}%")
        print(f"  entries: {sc.get('entries', 0)}/{sc.get('max_entries', 0)}")
        print(f"  cascade_cache_hit_rate: {stats.get('cache_hit_rate_percent', 0.0):.1f}%")
        print(f"  cascade_cache_entries: {stats.get('cache_entries_count', 0)}")
except Exception as e:
    print(f"  Не удалось прочитать /stats: {e}")

print("\n=== Header probe (X-Orchesis-Cache) ===")
try:
    code, cache_hdr, sim_hdr = probe_cache_header("What is the capital of France?")
    print(f"  status: {code}")
    print(f"  X-Orchesis-Cache: {cache_hdr or '(absent)'}")
    print(f"  X-Orchesis-Cache-Similarity: {sim_hdr or '(absent)'}")
except Exception as e:
    print(f"  Header probe failed: {e}")

print("\n→ Проверь dashboard: Cache tab")
print(f"  Если t2 << t1 → exact cache работает")
print(f"  Если t3 << t1 → semantic cache работает")
