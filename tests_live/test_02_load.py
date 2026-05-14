import openai
import time

client = openai.OpenAI(base_url="http://localhost:8080/v1")

questions = [
    "What is Python?",
    "Explain REST API briefly",
    "What is Docker?",
    "How does Git work?",
    "What is a database index?",
    "Explain OAuth 2.0 in one sentence",
    "What is WebSocket?",
    "How does DNS work?",
    "What is a load balancer?",
    "Explain microservices briefly",
    "What is Kubernetes?",
    "How does HTTPS work?",
    "What is a CDN?",
    "Explain CI/CD",
    "What is GraphQL?",
    "How does caching work?",
    "What is a message queue?",
    "Explain serverless",
    "What is an API gateway?",
    "How does rate limiting work?",
]

errors = 0
for i, q in enumerate(questions):
    print(f"[{i+1}/20] {q[:40]}...", end=" ")
    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": q}],
            max_tokens=100,
        )
        print(f"✓ {resp.usage.total_tokens} tokens")
    except Exception as e:
        print(f"✗ {e}")
        errors += 1
    time.sleep(1)

print(f"\nDone: {20 - errors}/20 OK, {errors} errors")
print("→ Проверь dashboard: Shield tab, sparklines, Cost")